//! Windows primitives for durable publication on local NTFS.
#![allow(unsafe_code)]

use super::{Error, Result};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle};
use std::path::Path;
use windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_NAME_OPENED, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetFinalPathNameByHandleW, GetVolumeInformationByHandleW, LOCKFILE_EXCLUSIVE_LOCK,
    LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, VOLUME_NAME_GUID,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

pub(super) fn directory_for_sync(path: &Path) -> Result<File> {
    let directory = OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    let mut filesystem = [0_u16; 32];
    // SAFETY: directory owns a live handle and filesystem is writable for the
    // specified number of UTF-16 units. The other outputs are optional.
    let queried = unsafe {
        GetVolumeInformationByHandleW(
            directory.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    };
    if queried == 0 {
        return Err(io::Error::last_os_error().into());
    }
    // A volume GUID path is available for local NTFS, including mounted NTFS
    // volumes. SMB can report NTFS but does not provide a volume GUID path.
    // SAFETY: with a zero buffer length this asks only for the required size.
    let local = unsafe {
        GetFinalPathNameByHandleW(
            directory.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            VOLUME_NAME_GUID | FILE_NAME_OPENED,
        )
    } != 0;
    if !local || !filesystem.starts_with(&[b'N' as u16, b'T' as u16, b'F' as u16, b'S' as u16, 0]) {
        return Err(Error::Unsupported(
            "native writable publication on Windows requires local NTFS".into(),
        ));
    }
    Ok(directory)
}

pub(super) fn open_fence(parent: &Path, name: &std::ffi::OsStr) -> Result<File> {
    if name.encode_wide().any(|unit| unit == u16::from(b':')) {
        return Err(Error::Unsupported(
            "native writable publication requires a file path, without an alternate data stream"
                .into(),
        ));
    }
    // Let NTFS compare destination names. A hash of the input spelling would
    // give differently cased names distinct locks in a case-insensitive directory.
    let directory = parent.join(".sac1-publication");
    match std::fs::create_dir(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(directory.join(name))?)
}

pub(super) fn lock_data(file: &File) -> Result<()> {
    // NTFS byte locks deny reads by independent handles. Lock one byte beyond
    // every supported NTFS file extent so pins can read the published data.
    let mut range = OVERLAPPED::default();
    range.Anonymous.Anonymous.Offset = u32::MAX - 1;
    range.Anonymous.Anonymous.OffsetHigh = i32::MAX as u32;
    // SAFETY: file is a synchronous handle and range lives through the call.
    let locked = unsafe {
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &mut range,
        )
    };
    if locked != 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
        return Err(Error::Busy);
    }
    Err(error.into())
}
