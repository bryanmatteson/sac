//! Narrow native syscall boundary. All range/descriptor ownership checks stay
//! in safe Rust; no pointer or borrowed storage escapes a syscall.
#![allow(unsafe_code)]
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::{fs::File, io};

/// Native containers address immutable frames by explicit offsets. Speculative
/// sequential reads amplify cold index lookups; large byte reads already issue
/// their own complete bounded requests. Advice never changes file authority.
pub(super) fn random_reads(file: &File) {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: file owns a live descriptor. F_RDAHEAD takes an integer, not
        // a pointer; zero disables only speculative reads for this descriptor.
        let _ = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_RDAHEAD, 0) };
    }
    #[cfg(target_os = "linux")]
    {
        let _ = rustix::fs::fadvise(file, 0, 0, rustix::fs::Advice::Random);
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let _ = file;
}

pub(super) fn uid() -> u32 {
    #[cfg(unix)]
    // SAFETY: geteuid takes no arguments and has no memory preconditions.
    {
        unsafe { libc::geteuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}
pub(super) fn punch(file: &File, offset: u64, length: u64) -> io::Result<()> {
    let offset = i64::try_from(offset).map_err(|_| io::ErrorKind::InvalidInput)?;
    let length = i64::try_from(length).map_err(|_| io::ErrorKind::InvalidInput)?;
    #[cfg(target_os = "macos")]
    let result = {
        let range = libc::fpunchhole_t {
            fp_flags: 0,
            reserved: 0,
            fp_offset: offset,
            fp_length: length,
        };
        // SAFETY: file owns a live descriptor, and F_PUNCHHOLE reads exactly
        // one initialized fpunchhole_t during this synchronous call.
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PUNCHHOLE, &range) }
    };
    #[cfg(target_os = "linux")]
    // SAFETY: live descriptor; checked nonnegative representable range. No
    // pointers are involved. KEEP_SIZE prevents changes to logical offsets.
    let result = unsafe {
        libc::fallocate(
            file.as_raw_fd(),
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            offset,
            length,
        )
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (file, offset, length);
        return Err(io::ErrorKind::Unsupported.into());
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
