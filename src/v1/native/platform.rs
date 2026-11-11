//! Narrow native syscall boundary. All range/descriptor ownership checks stay
//! in safe Rust. No pointer or borrowed storage escapes a syscall, except the
//! bytes of a [`Mapping`], which owns its storage.
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
        // No length: the advice applies from offset 0 to the end of the file.
        let _ = rustix::fs::fadvise(file, 0, None, rustix::fs::Advice::Random);
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

/// A shared read/write mapping of a temporary file that one table owns. The
/// file has no name, so no other holder can shorten it or change its bytes.
/// Its blocks are allocated before it is mapped: a full disk is an error from
/// [`Mapping::allocate`], not a fault on a later write.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) struct Mapping {
    pointer: std::ptr::NonNull<u8>,
    length: usize,
}
// SAFETY: a mapping is owned memory, like a boxed slice. Shared access only
// reads it and exclusive access is necessary to write it.
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe impl Send for Mapping {}
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe impl Sync for Mapping {}
#[cfg(any(target_os = "macos", target_os = "linux"))]
impl Mapping {
    /// Give the empty `file` exactly `length` allocated zero bytes and map
    /// them. `Unsupported` means that the filesystem cannot reserve blocks;
    /// the caller then uses positional I/O on a sparse file.
    pub(super) fn allocate(file: &File, length: u64) -> io::Result<Self> {
        let size = usize::try_from(length).map_err(|_| io::ErrorKind::InvalidInput)?;
        let signed = i64::try_from(length).map_err(|_| io::ErrorKind::InvalidInput)?;
        if size == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        #[cfg(target_os = "macos")]
        {
            let mut store = libc::fstore_t {
                fst_flags: libc::F_ALLOCATEALL,
                fst_posmode: libc::F_PEOFPOSMODE,
                fst_offset: 0,
                fst_length: signed,
                fst_bytesalloc: 0,
            };
            // SAFETY: file owns a live descriptor, and F_PREALLOCATE reads and
            // writes exactly one initialized fstore_t during this call.
            if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PREALLOCATE, &mut store) } != 0 {
                return Err(io::Error::last_os_error());
            }
            file.set_len(length)?;
        }
        #[cfg(target_os = "linux")]
        // SAFETY: live descriptor; checked nonnegative representable range. No
        // pointers are involved. Mode 0 also sets the file length.
        if unsafe { libc::fallocate(file.as_raw_fd(), 0, 0, signed) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a null hint, a checked nonzero length and a live descriptor
        // whose file has that length. The result is checked before use.
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let pointer = std::ptr::NonNull::new(pointer.cast::<u8>())
            .ok_or_else(|| io::Error::other("null file mapping"))?;
        Ok(Self {
            pointer,
            length: size,
        })
    }
    pub(super) fn bytes(&self) -> &[u8] {
        // SAFETY: the mapping has `length` readable bytes until drop, and the
        // borrow of self prevents a concurrent write through `bytes_mut`.
        unsafe { std::slice::from_raw_parts(self.pointer.as_ptr(), self.length) }
    }
    pub(super) fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as `bytes`; the exclusive borrow of self gives sole access.
        unsafe { std::slice::from_raw_parts_mut(self.pointer.as_ptr(), self.length) }
    }
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: this is the address and length that mmap returned, and no
        // borrow of the bytes can outlive self.
        let _ = unsafe { libc::munmap(self.pointer.as_ptr().cast(), self.length) };
    }
}
