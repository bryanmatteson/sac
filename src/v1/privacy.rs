//! Standard age encryption of a complete sealed SAC1 stream.
//!
//! Keys remain external. This API accepts native X25519 age recipients and
//! unencrypted native identity files only; no plugins, passwords or subprocesses.
//! One wrapper is opened per call, and nested wrappers are deliberately rejected.
use super::{
    cbor::{self, Value},
    resources::{self, ArchiveReader, EntryKind, ExtentAccumulator, Feature, Limits},
    *,
};
use std::{
    cell::Cell,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::Instant,
};

const CAPABILITY: &str = "sac.privacy.age";
const PAYLOAD: &[u8] = b"payload.age";

#[derive(Clone, Debug)]
pub struct PrivacyLimits {
    pub resources: Limits,
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
    /// Aggregate private staging bytes, including ciphertext and archive output.
    pub max_temp_bytes: u64,
    pub max_key_bytes: u64,
    pub max_age_header_bytes: u64,
    pub max_keys: usize,
    /// Zero disables opening/wrapping; this API supports exactly one level.
    pub max_nesting: usize,
}
impl Default for PrivacyLimits {
    fn default() -> Self {
        Self {
            resources: Limits::default(),
            max_input_bytes: 64 << 30,
            max_output_bytes: 64 << 30,
            max_temp_bytes: 192 << 30,
            max_key_bytes: 1 << 20,
            max_age_header_bytes: 64 << 10,
            max_keys: 64,
            max_nesting: 1,
        }
    }
}
struct Work<'a> {
    limits: &'a PrivacyLimits,
    start: Instant,
    temp: Cell<u64>,
}
impl Work<'_> {
    fn check(&self) -> Result<()> {
        if self.start.elapsed() >= self.limits.resources.max_elapsed {
            return Err(Error::Limit("privacy elapsed time"));
        }
        Ok(())
    }
    fn resources(&self) -> Result<Limits> {
        self.check()?;
        let mut l = self.limits.resources.clone();
        l.max_elapsed = l.max_elapsed.saturating_sub(self.start.elapsed());
        l.max_temp_bytes = l
            .max_temp_bytes
            .min(self.limits.max_temp_bytes.saturating_sub(self.temp.get()));
        Ok(l)
    }
}
struct Output<'a, W> {
    inner: W,
    work: &'a Work<'a>,
    bytes: u64,
    limit: u64,
}
impl<W: Write> Write for Output<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.work.check().map_err(io::Error::other)?;
        let n = u64::try_from(bytes.len()).map_err(io::Error::other)?;
        let end = self
            .bytes
            .checked_add(n)
            .ok_or_else(|| io::Error::other("privacy byte overflow"))?;
        let total = self
            .work
            .temp
            .get()
            .checked_add(n)
            .ok_or_else(|| io::Error::other("privacy temporary byte overflow"))?;
        if end > self.limit || total > self.work.limits.max_temp_bytes {
            return Err(io::Error::other("privacy output/temporary byte quota"));
        }
        let written = self.inner.write(bytes)?;
        self.bytes += written as u64;
        self.work.temp.set(self.work.temp.get() + written as u64);
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
fn output<'a, W>(inner: W, work: &'a Work<'a>, limit: u64) -> Output<'a, W> {
    Output {
        inner,
        work,
        limit,
        bytes: 0,
    }
}
struct Input<'a, R> {
    inner: R,
    work: &'a Work<'a>,
    header: &'a Cell<bool>,
    bytes: u64,
}
impl<R: Read> Read for Input<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.work.check().map_err(io::Error::other)?;
        let length = if self.header.get() {
            let remaining = self
                .work
                .limits
                .max_age_header_bytes
                .saturating_sub(self.bytes);
            if remaining == 0 && !out.is_empty() {
                return Err(io::Error::other("age header byte quota"));
            }
            out.len()
                .min(usize::try_from(remaining).unwrap_or(usize::MAX))
        } else {
            out.len()
        };
        let n = self.inner.read(&mut out[..length])?;
        self.bytes += n as u64;
        Ok(n)
    }
}
fn temporary(parent: &Path) -> Result<tempfile::NamedTempFile> {
    Ok(tempfile::Builder::new()
        .prefix(".sac1-private-")
        .tempfile_in(parent)?)
}
fn destination(path: &Path, limits: &PrivacyLimits) -> Result<PathBuf> {
    if limits.max_nesting == 0 {
        return Err(Error::Limit("privacy nesting"));
    }
    if path.try_exists()? {
        return Err(io::Error::from(io::ErrorKind::AlreadyExists).into());
    }
    Ok(path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .to_path_buf())
}
fn stage(input: &Path, parent: &Path, work: &Work<'_>) -> Result<tempfile::NamedTempFile> {
    if !std::fs::metadata(input)?.is_file() {
        return Err(corrupt("privacy input must be a regular file"));
    }
    let mut source = File::open(input)?;
    if !source.metadata()?.is_file() {
        return Err(corrupt("privacy input must be a regular file"));
    }
    if source.metadata()?.len() > work.limits.max_input_bytes {
        return Err(Error::Limit("privacy input bytes"));
    }
    let mut temp = temporary(parent)?;
    io::copy(
        &mut source,
        &mut output(temp.as_file_mut(), work, work.limits.max_input_bytes),
    )?;
    temp.as_file_mut().seek(SeekFrom::Start(0))?;
    Ok(temp)
}
fn fields(object: &CanonicalObject) -> Result<Vec<Value>> {
    match cbor::decode(&object.bytes)? {
        Value::Array(a) => Ok(a),
        _ => Err(corrupt("privacy object tuple")),
    }
}
fn privacy(snapshot: &CanonicalObject) -> Result<bool> {
    let a = fields(snapshot)?;
    Ok(a.get(2)
        .and_then(|v| {
            if let Value::Array(a) = v {
                Some(a)
            } else {
                None
            }
        })
        .is_some_and(|a| {
            a.iter().any(
                |v| matches!(v, Value::Array(f) if f.get(1)==Some(&Value::Text(CAPABILITY.into()))),
            )
        }))
}
/// Full physical/core/resource admission. Domain-specific application semantics
/// remain the responsibility of the included profile's validator.
fn sealed(file: &File, work: &Work<'_>, wrapper: bool) -> Result<NativeReader> {
    work.check()?;
    let source = NativeReader::open_file(file.try_clone()?)?;
    if source.reader().header.policy != LocatorPolicy::Sealed
        || source.reader().committed_end() != file.metadata()?.len()
    {
        return Err(corrupt("privacy requires one complete sealed SAC1 stream"));
    }
    let selected = source.root().ok_or(Error::Missing)?;
    let snapshot = source.reader().snapshot().ok_or(Error::Missing)?;
    let commit = source.get(selected.root)?;
    let cf = fields(&commit)?;
    if cf.len() != 3 || cf[2] != Value::Null {
        return Err(corrupt("sealed privacy stream has local authority"));
    }
    let object = source.get(snapshot)?;
    if wrapper {
        let f = fields(&object)?;
        let expected = Value::Array(vec![Value::Array(vec![
            Value::Null,
            Value::Text(CAPABILITY.into()),
            Value::Uint(1),
            Value::Bool(false),
        ])]);
        if cf[1] != Value::Null
            || f.len() != 3
            || f[1] != Value::Array(vec![])
            || f[2] != expected
            || object.children.len() != 1
        {
            return Err(corrupt(
                "privacy wrapper profile/capability/attachment shape",
            ));
        }
    } else if privacy(&object)? {
        return Err(Error::Limit("nested privacy wrapper"));
    }
    let physical = source.validate_with_limits(&work.resources()?)?;
    if wrapper {
        // An exact privacy wrapper cannot conceal plaintext in unreachable
        // frames or earlier publications outside its one-resource closure.
        let mut offset = source.reader().first_record_offset();
        let mut objects = 0u64;
        while offset < source.reader().trailer_offset() {
            work.check()?;
            let mut header = [0u8; 56];
            ReadAt::read_exact_at(file, offset, &mut header)?;
            if &header[..8] == b"SAC1END\0" {
                return Err(corrupt("privacy wrapper has an extra publication"));
            }
            objects = objects
                .checked_add(1)
                .ok_or(Error::Limit("privacy frames"))?;
            if objects > work.limits.resources.max_frames {
                return Err(Error::Limit("privacy frames"));
            }
            offset = offset
                .checked_add(wire::frame_span(&header)? as u64)
                .ok_or(Error::Limit("privacy frame offset"))?;
        }
        if offset != source.reader().trailer_offset() || objects != physical.objects {
            return Err(corrupt("privacy wrapper has unreachable frames"));
        }
    }
    let reader = ArchiveReader::open(&source, snapshot, work.resources()?)?;
    reader.verify_commit(selected.root)?;
    if wrapper {
        let mut count = 0u64;
        reader.visit_entries(&mut |entry| {
            count += 1;
            if count != 1
                || entry.path != vec![PAYLOAD.to_vec()]
                || entry.kind != EntryKind::File
                || entry.metadata != Value::Map(vec![])
                || entry.length == 0
            {
                return Err(corrupt("privacy wrapper must contain only payload.age"));
            }
            Ok(())
        })?;
        if count != 1 {
            return Err(corrupt("missing age payload"));
        }
    }
    work.check()?;
    Ok(source)
}
fn install(temp: tempfile::NamedTempFile, destination: &Path, work: &Work<'_>) -> Result<()> {
    work.check()?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(destination)
        .map_err(|e| Error::Io(e.error))?;
    File::open(
        destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}
/// Encrypt a fully admitted sealed archive to explicit native age recipients.
/// Existing destinations are never replaced. All private staging uses mode0600.
pub fn wrap_file(
    input: impl AsRef<Path>,
    destination_path: impl AsRef<Path>,
    recipients: &[String],
    limits: PrivacyLimits,
) -> Result<()> {
    let destination_path = destination_path.as_ref();
    let parent = destination(destination_path, &limits)?;
    if recipients.is_empty() || recipients.len() > limits.max_keys {
        return Err(Error::Limit("privacy recipient count"));
    }
    let keys = recipients
        .iter()
        .map(|r| {
            if r.len() > 256 {
                return Err(Error::Limit("privacy recipient length"));
            }
            r.parse::<age::x25519::Recipient>()
                .map_err(|_| corrupt("invalid native age recipient"))
        })
        .collect::<Result<Vec<_>>>()?;
    let work = Work {
        limits: &limits,
        start: Instant::now(),
        temp: Cell::new(0),
    };
    let mut plaintext = stage(input.as_ref(), &parent, &work)?;
    sealed(plaintext.as_file(), &work, false)?;
    let mut ciphertext = temporary(&parent)?;
    let encryptor = age::Encryptor::with_recipients(keys.iter().map(|k| k as &dyn age::Recipient))
        .map_err(|_| corrupt("age recipient set rejected"))?;
    let mut writer = encryptor
        .wrap_output(output(
            ciphertext.as_file_mut(),
            &work,
            limits.max_output_bytes,
        ))
        .map_err(|_| corrupt("age encryption initialization failed"))?;
    plaintext.as_file_mut().seek(SeekFrom::Start(0))?;
    io::copy(plaintext.as_file_mut(), &mut writer)?;
    writer
        .finish()
        .map_err(|_| corrupt("age encryption failed"))?;
    ciphertext.as_file_mut().seek(SeekFrom::Start(0))?;
    let mut archive = temporary(&parent)?;
    {
        let mut store = SealedWriter::new(output(
            archive.as_file_mut(),
            &work,
            limits.max_output_bytes,
        ))?;
        let length = ciphertext.as_file().metadata()?.len();
        let (storage, data, children) = if length <= 8192 {
            let mut bytes = Vec::with_capacity(length as usize);
            ciphertext.as_file_mut().read_to_end(&mut bytes)?;
            (0, Value::Bytes(bytes), vec![])
        } else {
            let mut extents = ExtentAccumulator::new();
            let mut buffer = vec![0; resources::DEFAULT_CHUNK_SIZE];
            loop {
                work.check()?;
                let n = ciphertext.as_file_mut().read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                extents.push_data(&mut store, &buffer[..n])?;
            }
            let extent = extents.finish(&mut store)?.ok_or(Error::Missing)?;
            (1, Value::Uint(0), vec![extent])
        };
        let entry = Value::Array(vec![
            Value::Bytes(PAYLOAD.to_vec()),
            Value::Uint(0),
            Value::Map(vec![]),
            Value::Array(vec![Value::Uint(length), Value::Uint(storage), data]),
        ]);
        let directory = store.put(3, 1, &cbor::encode(&Value::Array(vec![entry])), &children)?;
        let snapshot = resources::snapshot(
            &mut store,
            directory,
            vec![],
            vec![Feature {
                scope: None,
                id: CAPABILITY.into(),
                version: 1,
                required: false,
            }],
        )?;
        store.finish(snapshot)?;
    }
    sealed(archive.as_file(), &work, true)?;
    install(archive, destination_path, &work)
}
/// Open exactly one standard age privacy wrapper using explicit external native
/// identity files. No plaintext output becomes visible before full validation.
pub fn open_file(
    input: impl AsRef<Path>,
    destination_path: impl AsRef<Path>,
    identities: &[PathBuf],
    limits: PrivacyLimits,
) -> Result<()> {
    let destination_path = destination_path.as_ref();
    let parent = destination(destination_path, &limits)?;
    if identities.is_empty() || identities.len() > limits.max_keys {
        return Err(Error::Limit("privacy identity file count"));
    }
    let work = Work {
        limits: &limits,
        start: Instant::now(),
        temp: Cell::new(0),
    };
    let mut keys = Vec::new();
    let mut key_bytes = 0u64;
    for path in identities {
        if !std::fs::metadata(path)?.is_file() {
            return Err(corrupt("privacy identity must be a regular file"));
        }
        let mut data = Vec::new();
        File::open(path)?
            .take(
                limits
                    .max_key_bytes
                    .saturating_sub(key_bytes)
                    .saturating_add(1),
            )
            .read_to_end(&mut data)?;
        key_bytes = key_bytes
            .checked_add(data.len() as u64)
            .ok_or(Error::Limit("privacy key bytes"))?;
        if key_bytes > limits.max_key_bytes {
            return Err(Error::Limit("privacy key bytes"));
        }
        let text =
            std::str::from_utf8(&data).map_err(|_| corrupt("invalid native age identity file"))?;
        for line in text
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
        {
            if keys.len() >= limits.max_keys {
                return Err(Error::Limit("privacy identity count"));
            }
            keys.push(
                line.parse::<age::x25519::Identity>()
                    .map_err(|_| corrupt("invalid native age identity file"))?,
            );
        }
        work.check()?;
    }
    if keys.is_empty() {
        return Err(corrupt("no native age identities"));
    }
    let outer = stage(input.as_ref(), &parent, &work)?;
    let source = sealed(outer.as_file(), &work, true)?;
    let reader = ArchiveReader::open(
        &source,
        source.reader().snapshot().ok_or(Error::Missing)?,
        work.resources()?,
    )?;
    let mut ciphertext = temporary(&parent)?;
    reader.read_to(
        &[PAYLOAD.to_vec()],
        &mut output(ciphertext.as_file_mut(), &work, limits.max_input_bytes),
    )?;
    ciphertext.as_file_mut().seek(SeekFrom::Start(0))?;
    let header = Cell::new(true);
    let guarded = Input {
        inner: ciphertext.as_file_mut(),
        work: &work,
        header: &header,
        bytes: 0,
    };
    let decryptor =
        age::Decryptor::new(guarded).map_err(|_| corrupt("invalid or oversized age header"))?;
    header.set(false);
    let mut decrypted = decryptor
        .decrypt(keys.iter().map(|k| k as &dyn age::Identity))
        .map_err(|_| corrupt("age identity did not decrypt payload"))?;
    let mut plaintext = temporary(&parent)?;
    io::copy(
        &mut decrypted,
        &mut output(plaintext.as_file_mut(), &work, limits.max_output_bytes),
    )?;
    sealed(plaintext.as_file(), &work, false)?;
    install(plaintext, destination_path, &work)
}
