use super::read::ArchiveReader;
use super::*;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct ExtractionEntry {
    pub logical_path: ResourcePath,
    pub destination: Vec<String>,
    pub kind: EntryKind,
    pub digest: Option<[u8; 32]>,
    pub mapped: bool,
}
#[derive(Clone, Debug)]
pub struct ExtractionReport {
    pub snapshot_id: [u8; 32],
    pub entries: u64,
    pub files: u64,
    pub logical_bytes: u64,
    pub mapped_entries: u64,
    pub report_path: PathBuf,
    pub physical_checked: bool,
    pub core_checked: bool,
    pub profile_checked: bool,
}

/// Conservative native mapping. Lowercase portable ASCII names are retained.
/// Every other byte name uses a fixed ASCII hash and is reversible via report.
#[cfg(all(feature = "native", unix))]
fn mapped_path(path: &[Vec<u8>]) -> Vec<String> {
    path.iter()
        .enumerate()
        .map(|(i, key)| {
            if portable_name(key) {
                String::from_utf8(key.clone()).expect("ASCII checked")
            } else {
                let value = array(path[..=i].iter().cloned().map(Value::Bytes).collect());
                let mut h = blake3::Hasher::new();
                h.update(b"SAC1/extract-name\0");
                h.update(&cbor::encode(&value));
                format!("sac-{}", h.finalize().to_hex())
            }
        })
        .collect()
}
#[cfg(all(feature = "native", unix))]
fn portable_name(key: &[u8]) -> bool {
    if key.is_empty() || key.len() > 200 || key.starts_with(b"sac-") || key.last() == Some(&b'.') {
        return false;
    }
    if !key
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(*b, b'.' | b'_' | b'-'))
    {
        return false;
    }
    let base = key.split(|b| *b == b'.').next().unwrap_or_default();
    if matches!(base, b"con" | b"prn" | b"aux" | b"nul" | b"clock$") {
        return false;
    }
    if base.len() == 4
        && (base.starts_with(b"com") || base.starts_with(b"lpt"))
        && base[3].is_ascii_digit()
    {
        return false;
    }
    true
}

impl<'a, S: ObjectStore + ?Sized> ArchiveReader<'a, S> {
    /// Extract atomically into a previously absent destination directory.
    /// All raw names, link targets, metadata and checksums are retained in the
    /// sibling report. Links and stored executable permissions are not applied.
    pub fn extract(&self, destination: &Path) -> Result<ExtractionReport> {
        #[cfg(all(feature = "native", unix))]
        {
            native::extract(self, destination, native::Layout::Contained)
        }
        #[cfg(not(all(feature = "native", unix)))]
        {
            let _ = destination;
            Err(Error::Unsupported(
                "confined atomic extraction requires the native Unix host".into(),
            ))
        }
    }
    /// Restore the tree itself as a previously absent destination directory.
    ///
    /// Entries keep their recorded names. Symbolic links are created, and
    /// recorded `mode` permission bits and `mtime` are applied. The process
    /// file-creation mask applies, as it does to new files. Set-user-ID,
    /// set-group-ID and sticky bits are never applied, and a directory always
    /// stays accessible to its owner. No report file is written, and
    /// `report_path` names the destination.
    ///
    /// The archive is not changed to fit the host: a name the destination
    /// filesystem cannot hold, or two names it does not distinguish, is an
    /// `Unsupported` error and nothing is installed. `extract` handles such
    /// archives. A symbolic link target is restored as recorded and can name a
    /// path outside the tree. No entry is written through a link.
    pub fn extract_tree(&self, destination: &Path) -> Result<ExtractionReport> {
        #[cfg(all(feature = "native", unix))]
        {
            native::extract(self, destination, native::Layout::Tree)
        }
        #[cfg(not(all(feature = "native", unix)))]
        {
            let _ = destination;
            Err(Error::Unsupported(
                "confined atomic extraction requires the native Unix host".into(),
            ))
        }
    }
}

#[cfg(all(feature = "native", unix))]
mod native {
    use super::*;
    use rustix::fs::{self, AtFlags, Mode, OFlags, RenameFlags};
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    static NONCE: AtomicU64 = AtomicU64::new(1);

    /// `Contained` is `content/` plus `report.cbor` with host-neutral names.
    /// `Tree` is the recorded tree itself.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum Layout {
        Contained,
        Tree,
    }

    pub fn extract<S: ObjectStore + ?Sized>(
        reader: &ArchiveReader<'_, S>,
        destination: &Path,
        layout: Layout,
    ) -> Result<ExtractionReport> {
        let parent_path = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = destination
            .file_name()
            .ok_or_else(|| corrupt("extraction destination needs a final component"))?;
        if name == "." || name == ".." {
            return Err(corrupt("invalid extraction destination"));
        }
        // Every limit on entries, logical bytes and depth is checked before the
        // first directory is created. Shared subtrees expand a small archive
        // into many entries; that expansion must not become filesystem work.
        let mut budget = Budget::new(reader.limits.clone());
        let mut counting = Budget::new(reader.limits.clone());
        counting.start = budget.start;
        reader.visit_internal(&mut counting, true, &mut |entry, budget| {
            check_native_path(&native_path(&entry.path, layout), budget)
        })?;
        let parent = File::open(parent_path)?;
        let stage_name = make_stage(&parent)?;
        let result = extract_stage(
            reader,
            &parent,
            &stage_name,
            name,
            destination,
            layout,
            &mut budget,
        );
        if result.is_err() {
            let cap = cap_std::fs::Dir::from_std_file(parent.try_clone()?);
            let _ = cap.remove_dir_all(&stage_name);
        }
        result
    }
    fn native_path(path: &[Vec<u8>], layout: Layout) -> Vec<Vec<u8>> {
        match layout {
            Layout::Contained => mapped_path(path)
                .into_iter()
                .map(String::into_bytes)
                .collect(),
            Layout::Tree => path.to_vec(),
        }
    }
    fn make_stage(parent: &File) -> Result<String> {
        for _ in 0..32 {
            let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
            let time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let text = format!("{}-{time}-{nonce}", std::process::id());
            let name = format!(
                ".sac-extract-{}",
                &blake3::hash(text.as_bytes()).to_hex()[..24]
            );
            match fs::mkdirat(parent, &name, Mode::from_bits_truncate(0o700)) {
                Ok(()) => return Ok(name),
                Err(rustix::io::Errno::EXIST) => continue,
                Err(e) => return Err(std::io::Error::from(e).into()),
            }
        }
        Err(Error::Busy)
    }
    fn open_dir<F: AsFd>(parent: &F, name: impl rustix::path::Arg) -> Result<File> {
        Ok(fs::openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?
        .into())
    }
    fn create_dir(parent: &File, name: &[u8]) -> Result<File> {
        fs::mkdirat(parent, name, Mode::from_bits_truncate(0o700)).map_err(std::io::Error::from)?;
        open_dir(parent, name)
    }
    fn descend(root: &File, components: &[Vec<u8>]) -> Result<File> {
        let mut current = root.try_clone()?;
        for name in components {
            current = open_dir(&current, name.as_slice())?;
        }
        Ok(current)
    }
    /// Permission bits the process file-creation mask leaves to a new entry.
    fn creation_mask(stage: &File) -> Result<u32> {
        fs::mkdirat(stage, "mask", Mode::from_bits_truncate(0o777))
            .map_err(std::io::Error::from)?;
        let mode = fs::statat(stage, "mask", AtFlags::SYMLINK_NOFOLLOW)
            .map_err(std::io::Error::from)?
            .st_mode;
        fs::unlinkat(stage, "mask", AtFlags::REMOVEDIR).map_err(std::io::Error::from)?;
        Ok(mode as u32 & 0o777)
    }
    /// Recorded permission bits and modification time, when present. Core
    /// schema validation has already bounded both values.
    fn recorded(metadata: &Value) -> (Option<u32>, Option<SystemTime>) {
        let mut mode = None;
        let mut modified = None;
        let Value::Map(entries) = metadata else {
            return (mode, modified);
        };
        for entry in entries {
            match (&entry.key, &entry.value) {
                (Value::Text(key), Value::Uint(bits)) if key == "mode" => {
                    mode = Some(*bits as u32 & 0o777);
                }
                (Value::Text(key), Value::Array(fields)) if key == "mtime" => {
                    modified = match fields.as_slice() {
                        [Value::Uint(seconds), Value::Uint(nanoseconds)] => {
                            UNIX_EPOCH.checked_add(Duration::new(*seconds, *nanoseconds as u32))
                        }
                        // The encoded integer is `-1 - argument` seconds.
                        [Value::NInt(argument), Value::Uint(nanoseconds)] => argument
                            .checked_add(1)
                            .and_then(|seconds| {
                                UNIX_EPOCH.checked_sub(Duration::from_secs(seconds))
                            })
                            .and_then(|time| time.checked_add(Duration::from_nanos(*nanoseconds))),
                        _ => None,
                    };
                }
                _ => {}
            }
        }
        (mode, modified)
    }
    /// A restored directory whose entries are all in place.
    struct OpenDirectory {
        depth: usize,
        handle: File,
        mode: u32,
        modified: Option<SystemTime>,
    }
    impl OpenDirectory {
        fn finish(self) -> Result<()> {
            if let Some(modified) = self.modified {
                self.handle.set_modified(modified)?;
            }
            self.handle
                .set_permissions(std::fs::Permissions::from_mode(self.mode))?;
            flush(&self.handle)
        }
    }
    fn extract_stage<S: ObjectStore + ?Sized>(
        reader: &ArchiveReader<'_, S>,
        parent: &File,
        stage_name: &str,
        destination_name: &std::ffi::OsStr,
        destination: &Path,
        layout: Layout,
        budget: &mut Budget,
    ) -> Result<ExtractionReport> {
        let stage = open_dir(parent, stage_name)?;
        let preflight = create_dir(&stage, b"preflight")?;
        let mut entries = 0u64;
        let mut logical = 0u64;
        let mut temporary = 0u64;
        // Placeholders are directories regardless of logical type. This is a
        // disk-backed collision inventory that also tests the actual host names.
        reader.visit_internal(budget, true, &mut |entry, budget| {
            let mapped = native_path(&entry.path, layout);
            check_native_path(&mapped, budget)?;
            let parent = descend(&preflight, &mapped[..mapped.len() - 1])?;
            charge(
                &mut temporary,
                4096,
                budget.limits.max_temp_bytes,
                "preflight temporary storage",
            )?;
            match create_dir(&parent, mapped.last().unwrap()) {
                Ok(_) => {}
                Err(Error::Io(error)) if layout == Layout::Tree => {
                    return Err(unrepresentable(error));
                }
                Err(error) => return Err(error),
            }
            entries = entries
                .checked_add(1)
                .ok_or(Error::Limit("output entries"))?;
            if entry.kind == EntryKind::File {
                logical = logical
                    .checked_add(entry.length)
                    .ok_or(Error::Limit("output logical bytes"))?;
            }
            Ok(())
        })?;
        drop(preflight);
        cap_std::fs::Dir::from_std_file(stage.try_clone()?).remove_dir_all("preflight")?;
        let content = create_dir(&stage, b"content")?;
        let mut result = ExtractionReport {
            snapshot_id: reader.snapshot.hash.0,
            entries,
            files: 0,
            logical_bytes: logical,
            mapped_entries: 0,
            report_path: match layout {
                Layout::Contained => destination.join("report.cbor"),
                Layout::Tree => destination.to_path_buf(),
            },
            physical_checked: false,
            core_checked: false,
            profile_checked: false,
        };
        if layout == Layout::Tree {
            let mask = creation_mask(&stage)?;
            let mut open: Vec<OpenDirectory> = Vec::new();
            reader.visit_raw_with_budget(budget, false, &mut |path, inner, budget| {
                while open.last().is_some_and(|d| d.depth >= path.len()) {
                    open.pop().unwrap().finish()?;
                }
                let entry = inner.public(path.clone());
                let parent = match open.last() {
                    Some(directory) => directory.handle.try_clone()?,
                    None => content.try_clone()?,
                };
                let name = path.last().unwrap().as_slice();
                let (mode, modified) = recorded(&entry.metadata);
                match entry.kind {
                    EntryKind::Directory => open.push(OpenDirectory {
                        depth: path.len(),
                        handle: create_dir(&parent, name)?,
                        mode: (mode.unwrap_or(0o777) & mask) | 0o700,
                        modified,
                    }),
                    EntryKind::Symlink => fs::symlinkat(
                        entry.link_target.as_deref().unwrap_or_default(),
                        &parent,
                        name,
                    )
                    .map_err(std::io::Error::from)?,
                    EntryKind::File => {
                        charge(
                            &mut temporary,
                            entry.length,
                            budget.limits.max_temp_bytes,
                            "staged output bytes",
                        )?;
                        let mut output = HashWriter {
                            file: create_file(&parent, name)?,
                            hash: blake3::Hasher::new(),
                        };
                        reader.read_entry(&inner, 0, entry.length, &mut output, budget)?;
                        tree::check_declared_digest(
                            &entry.metadata,
                            output.hash.finalize().as_bytes(),
                        )?;
                        if let Some(modified) = modified {
                            output.file.set_modified(modified)?;
                        }
                        output
                            .file
                            .set_permissions(std::fs::Permissions::from_mode(
                                mode.unwrap_or(0o666) & mask,
                            ))?;
                        flush(&output.file)?;
                        result.files += 1;
                    }
                }
                budget.time()
            })?;
            while let Some(directory) = open.pop() {
                directory.finish()?;
            }
            OpenDirectory {
                depth: 0,
                handle: content,
                mode: (0o777 & mask) | 0o700,
                modified: None,
            }
            .finish()?;
            barrier(&stage)?;
            fs::renameat_with(
                &stage,
                "content",
                parent,
                destination_name,
                RenameFlags::NOREPLACE,
            )
            .map_err(std::io::Error::from)?;
            // The stage is empty and private. Failing to remove it must not
            // report an installed tree as an error.
            let _ = fs::unlinkat(parent, stage_name, AtFlags::REMOVEDIR);
            barrier(parent)?;
            return Ok(result);
        }
        let mut report_file: File = fs::openat(
            &stage,
            "report.cbor",
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(std::io::Error::from)?
        .into();
        report_file.write_all(&[0x84])?;
        report_file.write_all(&cbor::encode(&Value::Text("sac.extract-report.v1".into())))?;
        report_file.write_all(&cbor::encode(&Value::Bytes(
            reader.snapshot.hash.0.to_vec(),
        )))?;
        report_file.write_all(&cbor::encode(&uint(entries)))?;
        write_array_head(&mut report_file, entries)?;
        let mut report_bytes = 0u64;
        reader.visit_raw_with_budget(budget, false, &mut |path, inner, budget| {
            let entry = inner.public(path.clone());
            let mapped = mapped_path(&entry.path);
            let ancestors: Vec<Vec<u8>> = mapped[..mapped.len() - 1]
                .iter()
                .map(|name| name.as_bytes().to_vec())
                .collect();
            let parent = descend(&content, &ancestors)?;
            let name = mapped.last().unwrap();
            let digest = match entry.kind {
                EntryKind::Directory => {
                    create_dir(&parent, name.as_bytes())?;
                    None
                }
                EntryKind::Symlink => None,
                EntryKind::File => {
                    charge(
                        &mut temporary,
                        entry.length,
                        budget.limits.max_temp_bytes,
                        "staged output bytes",
                    )?;
                    let mut output = HashWriter {
                        file: create_file(&parent, name.as_bytes())?,
                        hash: blake3::Hasher::new(),
                    };
                    reader.read_entry(&inner, 0, entry.length, &mut output, budget)?;
                    let digest = *output.hash.finalize().as_bytes();
                    tree::check_declared_digest(&entry.metadata, &digest)?;
                    flush(&output.file)?;
                    result.files += 1;
                    Some(digest)
                }
            };
            let was_mapped = entry
                .path
                .iter()
                .zip(&mapped)
                .any(|(a, b)| a.as_slice() != b.as_bytes());
            if was_mapped {
                result.mapped_entries += 1;
            }
            let row = array(vec![
                array(entry.path.into_iter().map(Value::Bytes).collect()),
                array(mapped.into_iter().map(Value::Text).collect()),
                uint(match entry.kind {
                    EntryKind::File => 0,
                    EntryKind::Directory => 1,
                    EntryKind::Symlink => 2,
                }),
                entry.metadata,
                entry.link_target.map(Value::Bytes).unwrap_or(Value::Null),
                digest
                    .map(|d| Value::Bytes(d.to_vec()))
                    .unwrap_or(Value::Null),
                Value::Bool(was_mapped),
            ]);
            let encoded = cbor::encode(&row);
            charge(
                &mut report_bytes,
                encoded.len() as u64,
                budget.limits.max_temp_bytes.saturating_sub(temporary),
                "extraction report bytes",
            )?;
            report_file.write_all(&encoded)?;
            budget.time()?;
            Ok(())
        })?;
        flush(&report_file)?;
        sync_directories(&content, budget, 0)?;
        barrier(&stage)?;
        fs::renameat_with(
            parent,
            stage_name,
            parent,
            destination_name,
            RenameFlags::NOREPLACE,
        )
        .map_err(std::io::Error::from)?;
        barrier(parent)?;
        Ok(result)
    }
    fn create_file(parent: &File, name: &[u8]) -> Result<File> {
        Ok(fs::openat(
            parent,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(std::io::Error::from)?
        .into())
    }
    /// A recorded name the destination filesystem refused as a placeholder.
    fn unrepresentable(error: std::io::Error) -> Error {
        use rustix::io::Errno;
        let code = error.raw_os_error();
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            Error::Unsupported(
                "two entry names are the same name on the destination filesystem; \
                 use the contained extraction, which maps such names"
                    .into(),
            )
        } else if [Errno::ILSEQ, Errno::INVAL, Errno::NAMETOOLONG]
            .iter()
            .any(|errno| code == Some(errno.raw_os_error()))
        {
            Error::Unsupported(
                "an entry name cannot be stored on the destination filesystem; \
                 use the contained extraction, which maps such names"
                    .into(),
            )
        } else {
            error.into()
        }
    }
    fn check_native_path(path: &[Vec<u8>], budget: &Budget) -> Result<()> {
        budget.depth(path.len())?;
        let bytes = path.iter().try_fold(0usize, |n, p| {
            n.checked_add(p.len() + 1)
                .ok_or(Error::Limit("destination path length"))
        })?;
        if bytes > 4096 || path.iter().any(|p| p.len() > 255) {
            return Err(Error::Limit("destination path length"));
        }
        budget.memory(bytes.saturating_mul(4))
    }
    fn sync_directories(dir: &File, budget: &Budget, depth: usize) -> Result<()> {
        budget.depth(depth)?;
        let capability = cap_std::fs::Dir::from_std_file(dir.try_clone()?);
        for entry in capability.entries()? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let child = open_dir(dir, entry.file_name())?;
                sync_directories(&child, budget, depth + 1)?;
            }
        }
        flush(dir)?;
        Ok(())
    }
    /// Hand one file or directory to the storage device. On macOS this does
    /// not ask the device to empty its own write cache: `barrier` does that
    /// once, for every earlier `flush`, before the result is installed.
    fn flush(file: &File) -> Result<()> {
        #[cfg(target_os = "macos")]
        fs::fsync(file).map_err(std::io::Error::from)?;
        #[cfg(not(target_os = "macos"))]
        file.sync_all()?;
        Ok(())
    }
    /// Make this object and all data flushed before it durable on the device.
    fn barrier(file: &File) -> Result<()> {
        #[cfg(target_os = "macos")]
        fs::fcntl_fullfsync(file).map_err(std::io::Error::from)?;
        #[cfg(not(target_os = "macos"))]
        file.sync_all()?;
        Ok(())
    }
    fn write_array_head(out: &mut impl Write, n: u64) -> Result<()> {
        if n < 24 {
            out.write_all(&[0x80 | n as u8])?;
        } else if n <= 255 {
            out.write_all(&[0x98, n as u8])?;
        } else if n <= 65535 {
            out.write_all(&[0x99])?;
            out.write_all(&(n as u16).to_be_bytes())?;
        } else if n <= u32::MAX as u64 {
            out.write_all(&[0x9a])?;
            out.write_all(&(n as u32).to_be_bytes())?;
        } else {
            out.write_all(&[0x9b])?;
            out.write_all(&n.to_be_bytes())?;
        }
        Ok(())
    }
    struct HashWriter {
        file: File,
        hash: blake3::Hasher,
    }
    impl Write for HashWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let n = self.file.write(bytes)?;
            self.hash.update(&bytes[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.file.flush()
        }
    }
}
