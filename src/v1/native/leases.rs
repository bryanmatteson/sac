//! Cooperative same-host native reader admission, keyed by device/inode so
//! hard-link aliases and open_file readers join the same reclamation domain.
use super::*;
use std::fs::DirBuilder;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt};

pub(super) fn domain(file: &File) -> Result<PathBuf> {
    #[cfg(unix)]
    {
        let base = PathBuf::from(std::env::var_os("HOME").ok_or_else(|| {
            Error::Unsupported("native maintenance requires a persistent home directory".into())
        })?)
        .join(".sac-native");
        private_directory(&base)?;
        let m = file.metadata()?;
        let dir = base.join(format!("{}-{}", m.dev(), m.ino()));
        private_directory(&dir)?;
        Ok(dir)
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Err(Error::Unsupported(
            "native reclamation reader domain".into(),
        ))
    }
}
fn private_directory(path: &Path) -> Result<()> {
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => sync_parent(path)?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    let m = std::fs::symlink_metadata(path)?;
    if !m.is_dir() {
        return Err(corrupt("reader domain is not a directory"));
    }
    #[cfg(unix)]
    if m.uid() != platform::uid() || m.mode() & 0o077 != 0 {
        return Err(corrupt("reader domain permissions"));
    }
    Ok(())
}
pub(super) fn gate(dir: &Path, exclusive: bool) -> Result<File> {
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(dir.join("gate"))?;
    if exclusive {
        f.try_lock().map_err(lock_error)?;
    } else {
        f.try_lock_shared().map_err(lock_error)?;
    }
    Ok(f)
}
pub(super) fn pending(dir: &Path) -> bool {
    dir.join("manifest").exists() || dir.join("reuse").exists()
}
pub(super) struct Lease {
    file: File,
    path: PathBuf,
    dir: PathBuf,
}
impl Lease {
    pub(super) fn register(file: &File, reader: &Reader) -> Result<Self> {
        let dir = domain(file)?;
        let _gate = gate(&dir, false)?;
        if pending(&dir) {
            return Err(Error::RecoveryRequired);
        }
        let path = dir.join(format!(
            "pin-{}-{}",
            std::process::id(),
            next_file_identity()
        ));
        let f = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        f.try_lock().map_err(lock_error)?;
        let mut lease = Self {
            file: f,
            path,
            dir: dir.clone(),
        };
        lease.write(reader)?;
        Ok(lease)
    }
    fn write(&mut self, reader: &Reader) -> Result<()> {
        let mut bytes = vec![u8::from(reader.publication.is_some())];
        bytes.extend(reader.committed_end().to_le_bytes());
        if let Some(p) = reader.publication {
            bytes.extend(spill::encode_ref(p.root));
        }
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&bytes)?;
        self.file.set_len(bytes.len() as u64)?;
        Ok(())
    }
    pub(super) fn refresh(&mut self, reader: &Reader) -> Result<()> {
        let _gate = gate(&self.dir, false)?;
        self.write(reader)
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
pub(super) fn roots(dir: &Path, max: u64) -> Result<(Vec<ObjectRef>, u64)> {
    let mut roots = Vec::new();
    let mut protected = 0;
    let mut active = 0u64;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_name().as_encoded_bytes().starts_with(b"pin-") {
            continue;
        }
        let mut f = match options(false).open(entry.path()) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        match f.try_lock() {
            Ok(()) => {
                let _ = std::fs::remove_file(entry.path());
                continue;
            }
            Err(std::fs::TryLockError::WouldBlock) => (),
            Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
        }
        active += 1;
        if active > max {
            return Err(Error::Limit("active native readers"));
        }
        let len = f.metadata()?.len();
        if len != 9 && len != 53 {
            return Err(corrupt("active reader registration"));
        }
        let mut bytes = [0; 53];
        f.read_exact(&mut bytes[..len as usize])?;
        if bytes[0] == 0 && len == 9 {
            protected = protected.max(u64::from_le_bytes(bytes[1..9].try_into().unwrap()));
        } else if bytes[0] == 1 && len == 53 {
            roots.push(spill::decode_ref(&bytes[9..])?);
        } else {
            return Err(corrupt("reader registration shape"));
        }
    }
    Ok((roots, protected))
}
