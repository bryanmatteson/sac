use crate::{
    Annotation, Artifact, Error, MAX_BLOB_BYTES, MAX_FRAMES, MAX_LAYOUT_BYTES, MAX_LIST_BYTES,
    MAX_RECORD_BYTES, MAX_RELEASES, Profile, Reference, Release, Result, check_digest, sha256,
    transfer::CappedReader,
};
use sac::v1::{metadata::MetadataReader, profiles::SnapshotProfiles, resources::Limits, wire};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

// Layout records hold the physical bytes between bodies inline. Each frame body
// is independently addressed under its SAC object ID and encoded byte digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum Part {
    Inline {
        hex: String,
    },
    Blob {
        object: String,
        sha256: String,
        bytes: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Layout {
    pub format: String,
    pub artifact: Artifact,
    pub parts: Vec<Part>,
}

impl Layout {
    pub fn validate(&self, maximum: u64) -> Result<()> {
        self.artifact.validate()?;
        if self.format != "sac.registry.layout/v1" || self.parts.len() > 2 * MAX_FRAMES + 1 {
            return Err(Error::Invalid("unsupported archive layout".into()));
        }
        let mut length = 0u64;
        for (index, part) in self.parts.iter().enumerate() {
            let len = match part {
                Part::Inline { hex } if index % 2 == 0 && hex.len() <= 2 * (16 << 10) => {
                    let data =
                        hex::decode(hex).map_err(|_| Error::Integrity("inline layout bytes"))?;
                    if data.is_empty() {
                        return Err(Error::Integrity("empty inline layout part"));
                    }
                    data.len() as u64
                }
                Part::Blob {
                    object,
                    sha256,
                    bytes,
                } if index % 2 == 1 && (1..=MAX_BLOB_BYTES).contains(bytes) => {
                    check_digest(object)?;
                    check_digest(sha256)?;
                    *bytes
                }
                _ => return Err(Error::Integrity("invalid layout part")),
            };
            length = length
                .checked_add(len)
                .ok_or(Error::Limit("artifact length"))?;
            if length > maximum {
                return Err(Error::Limit("artifact length"));
            }
        }
        if self.parts.len() < 3 || self.parts.len() % 2 != 1 || length != self.artifact.bytes {
            return Err(Error::Integrity("archive layout length"));
        }
        Ok(())
    }

    pub fn frame_headers(&self) -> Result<BTreeMap<BodyRef, &str>> {
        let mut bodies = BTreeMap::new();
        for pair in self.parts.chunks_exact(2) {
            let [
                Part::Inline { hex },
                Part::Blob {
                    object,
                    sha256,
                    bytes,
                },
            ] = pair
            else {
                return Err(Error::Integrity("frame header and body order"));
            };
            let header = hex
                .get(hex.len().saturating_sub(2 * wire::FRAME)..)
                .filter(|header| header.len() == 2 * wire::FRAME)
                .ok_or(Error::Integrity("missing frame header in layout"))?;
            bodies
                .entry(BodyRef {
                    object: object.clone(),
                    sha256: sha256.clone(),
                    bytes: *bytes,
                })
                .or_insert(header);
        }
        Ok(bodies)
    }

    pub fn blobs(&self) -> impl Iterator<Item = (&str, &str, u64)> {
        self.parts.iter().filter_map(|part| match part {
            Part::Blob {
                object,
                sha256,
                bytes,
            } => Some((object.as_str(), sha256.as_str(), *bytes)),
            Part::Inline { .. } => None,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BodyRef {
    pub object: String,
    pub sha256: String,
    pub bytes: u64,
}

impl BodyRef {
    pub fn validate(&self) -> Result<()> {
        check_digest(&self.object)?;
        check_digest(&self.sha256)?;
        if !(1..=MAX_BLOB_BYTES).contains(&self.bytes) {
            return Err(Error::Limit("encoded frame body size"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Registry {
    root: PathBuf,
    maximum: u64,
}

impl Registry {
    pub fn open(path: impl AsRef<Path>, maximum: u64) -> Result<Self> {
        if maximum == 0 {
            return Err(Error::Invalid(
                "maximum artifact size must be positive".into(),
            ));
        }
        fs::create_dir_all(&path)?;
        let root = fs::canonicalize(path)?;
        for name in ["objects", "archives", "releases", "staging"] {
            ensure_dir(&root.join(name))?;
        }
        Ok(Self { root, maximum })
    }

    pub fn maximum(&self) -> u64 {
        self.maximum
    }

    pub fn publish(
        &self,
        reference: &Reference,
        profile: Option<&str>,
        input: impl Read,
    ) -> Result<Release> {
        let mut staging = self.stage()?;
        copy_bounded(input, &mut staging, self.maximum)?;
        self.publish_staged(reference, profile, staging, None)
    }

    pub(crate) fn stage(&self) -> Result<tempfile::NamedTempFile> {
        Ok(tempfile::NamedTempFile::new_in(self.root.join("staging"))?)
    }

    pub(crate) fn publish_staged(
        &self,
        reference: &Reference,
        profile: Option<&str>,
        staging: tempfile::NamedTempFile,
        expected: Option<(&Release, &Layout)>,
    ) -> Result<Release> {
        let key = reference.key()?;
        let file = staging.reopen()?;
        let length = file.metadata()?.len();
        if length > self.maximum {
            return Err(Error::Limit("artifact length"));
        }
        if length < (wire::PREAMBLE_SIZE + wire::TRAILER_SIZE) as u64 {
            return Err(Error::Invalid("truncated sealed SAC1 archive".into()));
        }
        let mut file = BufReader::new(file);
        let mut preamble = [0; wire::PREAMBLE_SIZE];
        file.read_exact(&mut preamble)?;
        if wire::Preamble::decode(&preamble)?.policy != wire::LocatorPolicy::Sealed {
            return Err(Error::Invalid("publish a sealed SAC1 archive".into()));
        }
        let source = sac::NativeReader::open_file(staging.reopen()?)?;
        let limits = Limits {
            max_frames: MAX_FRAMES as u64,
            ..Limits::default()
        };
        source.validate_with_limits(&limits)?;
        let snapshot = source
            .reader()
            .snapshot()
            .ok_or(Error::Integrity("missing SAC snapshot"))?;
        let commit = source
            .root()
            .ok_or(Error::Integrity("missing SAC commit"))?
            .root;
        sac::resources::ArchiveReader::open(&source, snapshot, limits.clone())?
            .verify_commit(commit)?;
        let profiles = SnapshotProfiles::discover(&source, snapshot, &limits)?
            .profiles()
            .iter()
            .map(|profile| Profile {
                id: profile.id.clone(),
                version: profile.version,
                root_id: hex::encode(profile.root.hash.0),
            })
            .collect();

        let mut digest = Sha256::new();
        digest.update(preamble);
        let end = source.reader().trailer_offset();
        let mut inline = preamble.to_vec();
        let mut parts = Vec::new();
        let mut offset = wire::PREAMBLE_SIZE as u64;
        let mut body = Vec::new();
        let mut layout_bytes = 0usize;
        let mut admitted = BTreeSet::new();
        while offset < end {
            if parts.len() / 2 >= MAX_FRAMES {
                return Err(Error::Limit("frame count"));
            }
            let mut header = [0; wire::FRAME];
            file.read_exact(&mut header)?;
            let span = wire::frame_span(&header)?;
            let start = offset;
            offset = offset
                .checked_add(span as u64)
                .ok_or(Error::Limit("frame offset"))?;
            if offset > end {
                return Err(Error::Integrity("frame overlaps SAC trailer"));
            }
            let stored = wire::le32(&header, 8) as usize;
            let object = hex::encode(&header[16..48]);
            inline.extend_from_slice(&header);
            digest.update(header);
            layout_bytes = layout_bytes.saturating_add(inline.len() * 2 + 240);
            if layout_bytes as u64 > MAX_LAYOUT_BYTES {
                return Err(Error::Limit("archive layout size"));
            }
            parts.push(Part::Inline {
                hex: hex::encode(&inline),
            });
            body.resize(stored, 0);
            file.read_exact(&mut body)?;
            digest.update(&body);
            let encoded = sha256(&body);
            inline.resize(span - wire::FRAME - stored, 0);
            file.read_exact(&mut inline)?;
            let mut frame = Vec::with_capacity(span);
            frame.extend_from_slice(&header);
            frame.extend_from_slice(&body);
            frame.extend_from_slice(&inline);
            // Verify even physical frames outside the selected snapshot closure.
            let reference = sac::ObjectRef {
                hash: sac::ObjectHash(header[16..48].try_into().unwrap()),
                address: sac::ChunkAddress {
                    offset: start,
                    length: span as u32,
                },
            };
            wire::decode_frame(reference, &frame, wire::PREAMBLE_SIZE as u64, end)?;
            if admitted.insert((object.clone(), encoded.clone())) {
                self.store_body(&object, &encoded, &body)?;
            }
            digest.update(&inline);
            parts.push(Part::Blob {
                object,
                sha256: encoded,
                bytes: stored as u64,
            });
        }
        let mut trailer = [0; wire::TRAILER_SIZE];
        file.read_exact(&mut trailer)?;
        digest.update(trailer);
        inline.extend_from_slice(&trailer);
        parts.push(Part::Inline {
            hex: hex::encode(inline),
        });

        let artifact = Artifact {
            sha256: hex::encode(digest.finalize()),
            bytes: length,
            snapshot_id: hex::encode(snapshot.hash.0),
            commit_id: hex::encode(commit.hash.0),
            profiles,
            annotations: annotations(&source, snapshot, &limits)?,
        };
        let release = Release {
            reference: reference.to_string(),
            artifact: artifact.clone(),
            profile: profile.map(str::to_owned),
        };
        release.validate()?;
        let layout = Layout {
            format: "sac.registry.layout/v1".into(),
            artifact,
            parts,
        };
        layout.validate(self.maximum)?;
        if expected.is_some_and(|(expected_release, expected_layout)| {
            expected_release != &release || expected_layout != &layout
        }) {
            return Err(Error::Integrity(
                "received release or layout differs from archive",
            ));
        }
        save_json(
            &self.archive_path(&release.artifact.sha256)?,
            &layout,
            MAX_LAYOUT_BYTES,
        )?;
        save_json(
            &self.root.join("releases").join(key),
            &release,
            MAX_RECORD_BYTES,
        )?;
        Ok(release)
    }

    pub fn resolve(&self, reference: &Reference) -> Result<Release> {
        let row: Release = read_json(
            &self.root.join("releases").join(reference.key()?),
            MAX_RECORD_BYTES,
        )?;
        if row.validate()? != *reference
            || row.artifact != self.layout(&row.artifact.sha256)?.artifact
        {
            return Err(Error::Integrity("release binding"));
        }
        Ok(row)
    }

    pub fn list(
        &self,
        profile: Option<&str>,
        version: Option<u32>,
        tag: Option<&str>,
    ) -> Result<Vec<Release>> {
        if version.is_some() && profile.is_none() {
            return Err(Error::Invalid("select a profile before its version".into()));
        }
        let mut releases = Vec::new();
        let mut count = 0;
        let mut bytes = 2;
        for entry in fs::read_dir(self.root.join("releases"))? {
            let entry = entry?;
            let key = entry.file_name();
            let Some(key) = key.to_str().filter(|key| check_digest(key).is_ok()) else {
                continue;
            };
            count += 1;
            if count > MAX_RELEASES {
                return Err(Error::Limit("release listing count"));
            }
            let row: Release = read_json(&entry.path(), MAX_RECORD_BYTES)?;
            if row.validate()?.key()? != key {
                return Err(Error::Integrity("release name binding"));
            }
            if row.matches(profile, version, tag) {
                bytes += 1 + entry.metadata()?.len();
                if bytes > MAX_LIST_BYTES {
                    return Err(Error::Limit("release listing size"));
                }
                releases.push(row);
            }
        }
        releases.sort_by(|a, b| a.reference.cmp(&b.reference));
        Ok(releases)
    }

    pub fn archive(&self, digest: &str) -> Result<ArchiveReader> {
        ArchiveReader::new(self.clone(), self.layout(digest)?)
    }

    pub fn fetch(&self, reference: &Reference, output: impl AsRef<Path>) -> Result<Release> {
        let release = self.resolve(reference)?;
        write_download(
            self.archive(&release.artifact.sha256)?,
            &release.artifact,
            output.as_ref(),
        )?;
        Ok(release)
    }

    pub(crate) fn layout(&self, digest: &str) -> Result<Layout> {
        let layout: Layout = read_json(&self.archive_path(digest)?, MAX_LAYOUT_BYTES)?;
        layout.validate(self.maximum)?;
        if layout.artifact.sha256 != digest {
            return Err(Error::Integrity("transport digest binding"));
        }
        Ok(layout)
    }

    pub(crate) fn publish_layout(
        &self,
        reference: &Reference,
        release: &Release,
        layout: &Layout,
        load: impl Fn(&str, &str, u64) -> Result<Vec<u8>>,
    ) -> Result<Release> {
        layout.validate(self.maximum)?;
        if release.validate()? != *reference || release.artifact != layout.artifact {
            return Err(Error::Integrity("release and layout binding"));
        }
        let mut staging = self.stage()?;
        for part in &layout.parts {
            match part {
                Part::Inline { hex } => staging.write_all(
                    &hex::decode(hex).map_err(|_| Error::Integrity("inline layout bytes"))?,
                )?,
                Part::Blob {
                    object,
                    sha256,
                    bytes,
                } => {
                    staging.write_all(&load(object, sha256, *bytes)?)?;
                }
            }
        }
        self.publish_staged(
            reference,
            release.profile.as_deref(),
            staging,
            Some((release, layout)),
        )
    }

    pub(crate) fn has_body(&self, body: &BodyRef) -> Result<bool> {
        body.validate()?;
        let path = self.blob_path(&body.object, &body.sha256)?;
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.is_file() && meta.len() == body.bytes => Ok(true),
            Ok(_) => Err(Error::Integrity("stored frame body length or type")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn read_body(&self, object: &str, digest: &str, size: u64) -> Result<Vec<u8>> {
        let file = File::open(self.blob_path(object, digest)?).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                Error::NotFound(format!("frame body {object}/{digest}"))
            } else {
                error.into()
            }
        })?;
        let mut data = Vec::new();
        copy_bounded(file, &mut data, size)?;
        if data.len() as u64 != size || sha256(&data) != digest {
            return Err(Error::Integrity("stored frame body digest or length"));
        }
        Ok(data)
    }

    pub(crate) fn put_body(
        &self,
        object: &str,
        digest: &str,
        header: &[u8],
        bytes: &[u8],
    ) -> Result<()> {
        check_digest(object)?;
        check_digest(digest)?;
        if header.len() != wire::FRAME || sha256(bytes) != digest {
            return Err(Error::Integrity("encoded frame body or header"));
        }
        let span = wire::frame_span(header)?;
        if wire::le32(header, 8) as usize != bytes.len() {
            return Err(Error::Integrity("encoded frame body length"));
        }
        let mut frame = Vec::with_capacity(span);
        frame.extend_from_slice(header);
        frame.extend_from_slice(bytes);
        frame.resize(span, 0);
        let id = sac::ObjectHash(
            hex::decode(object)
                .map_err(|_| Error::Integrity("SAC object ID"))?
                .try_into()
                .map_err(|_| Error::Integrity("SAC object ID"))?,
        );
        // CAS entries authenticate canonical bytes. Physical locators arrive with the layout.
        wire::decode_detached_frame(id, &frame)?;
        self.store_body(object, digest, bytes)
    }

    fn store_body(&self, object: &str, digest: &str, bytes: &[u8]) -> Result<()> {
        let path = self.blob_path(object, digest)?;
        ensure_dir(path.parent().unwrap())?;
        save_bytes(&path, bytes)
    }

    fn archive_path(&self, digest: &str) -> Result<PathBuf> {
        check_digest(digest)?;
        Ok(self.root.join("archives").join(digest))
    }

    pub(crate) fn blob_path(&self, object: &str, digest: &str) -> Result<PathBuf> {
        check_digest(object)?;
        check_digest(digest)?;
        Ok(self.root.join("objects").join(object).join(digest))
    }
}

fn annotations(
    source: &sac::NativeReader,
    snapshot: sac::ObjectRef,
    limits: &Limits,
) -> Result<BTreeMap<String, Annotation>> {
    let mut values = BTreeMap::new();
    let reader = match MetadataReader::open(source, snapshot, limits.clone()) {
        Ok(reader) => reader,
        Err(sac::Error::Unsupported(_)) => None,
        Err(error) => return Err(error.into()),
    };
    if let Some(reader) = reader {
        for key in [
            "sac.registry.title",
            "sac.registry.description",
            "sac.registry.tags",
        ] {
            // Oversized values remain in the archive and are skipped by the catalog.
            let Some(encoded) = reader.get_encoded(key)? else {
                continue;
            };
            if encoded.len() > 4096 {
                continue;
            }
            use sac::cbor::Value;
            let value = match sac::cbor::decode(&encoded)? {
                Value::Text(text) if key != "sac.registry.tags" => Some(Annotation::Text(text)),
                Value::Array(items) if key == "sac.registry.tags" => items
                    .into_iter()
                    .map(|item| match item {
                        Value::Text(text) => Some(text),
                        _ => None,
                    })
                    .collect::<Option<Vec<_>>>()
                    .map(Annotation::List),
                _ => None,
            };
            if let Some(value) = value {
                values.insert(key.into(), value);
            }
        }
    }
    Ok(values)
}

enum Bytes {
    Inline(Vec<u8>),
    Blob(PathBuf),
}

struct Segment {
    offset: u64,
    bytes: Bytes,
}

pub struct ArchiveReader {
    artifact: Artifact,
    segments: Vec<Segment>,
    position: u64,
    file: Option<(usize, File)>,
}

impl ArchiveReader {
    fn new(registry: Registry, layout: Layout) -> Result<Self> {
        let mut offset = 0;
        let mut segments = Vec::with_capacity(layout.parts.len());
        for part in layout.parts {
            let (bytes, len) = match part {
                Part::Inline { hex } => {
                    let data =
                        hex::decode(hex).map_err(|_| Error::Integrity("inline layout bytes"))?;
                    let len = data.len() as u64;
                    (Bytes::Inline(data), len)
                }
                Part::Blob {
                    object,
                    sha256,
                    bytes,
                } => (Bytes::Blob(registry.blob_path(&object, &sha256)?), bytes),
            };
            segments.push(Segment { offset, bytes });
            offset += len;
        }
        Ok(Self {
            artifact: layout.artifact,
            segments,
            position: 0,
            file: None,
        })
    }

    pub fn artifact(&self) -> &Artifact {
        &self.artifact
    }
}

impl Read for ArchiveReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.artifact.bytes || output.is_empty() {
            return Ok(0);
        }
        let index = self
            .segments
            .partition_point(|part| part.offset <= self.position)
            - 1;
        let segment = &self.segments[index];
        let end = self
            .segments
            .get(index + 1)
            .map_or(self.artifact.bytes, |part| part.offset);
        let length = output.len().min((end - self.position) as usize);
        let offset = self.position - segment.offset;
        match &segment.bytes {
            Bytes::Inline(bytes) => {
                output[..length].copy_from_slice(&bytes[offset as usize..][..length])
            }
            Bytes::Blob(path) => {
                if self.file.as_ref().is_none_or(|(open, _)| *open != index) {
                    self.file = Some((index, File::open(path)?));
                }
                let (_, file) = self.file.as_mut().unwrap();
                file.seek(SeekFrom::Start(offset))?;
                file.read_exact(&mut output[..length])?;
            }
        }
        self.position += length as u64;
        Ok(length)
    }
}

impl Seek for ArchiveReader {
    fn seek(&mut self, target: SeekFrom) -> io::Result<u64> {
        let position = match target {
            SeekFrom::Start(value) => Some(value),
            SeekFrom::End(value) => self.artifact.bytes.checked_add_signed(value),
            SeekFrom::Current(value) => self.position.checked_add_signed(value),
        };
        self.position = position.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid archive position")
        })?;
        Ok(self.position)
    }
}

pub(crate) fn write_download(
    input: impl Read,
    artifact: &Artifact,
    destination: &Path,
) -> Result<()> {
    let parent = parent_directory(destination);
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    let mut hash = Sha256::new();
    let mut input = CappedReader::new(input, artifact.bytes);
    let mut buffer = [0; 64 << 10];
    let mut length = 0u64;
    loop {
        let size = input.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
        file.write_all(&buffer[..size])?;
        length += size as u64;
    }
    if length != artifact.bytes || hex::encode(hash.finalize()) != artifact.sha256 {
        return Err(Error::Integrity("download digest or length"));
    }
    file.as_file().sync_all()?;
    file.persist_noclobber(destination)
        .map_err(|err| err.error)?;
    sync_directory(parent)?;
    Ok(())
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn ensure_dir(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => (),
        Err(err)
            if err.kind() == io::ErrorKind::AlreadyExists
                && fs::symlink_metadata(path)?.is_dir() => {}
        Err(err) => return Err(err.into()),
    }
    sync_directory(parent_directory(path))?;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_: &Path) -> io::Result<()> {
    Ok(())
}

pub(crate) fn copy_bounded(input: impl Read, output: &mut impl Write, maximum: u64) -> Result<u64> {
    io::copy(&mut CappedReader::new(input, maximum), output).map_err(|err| {
        if err.kind() == io::ErrorKind::InvalidData {
            Error::Limit("transfer byte count")
        } else {
            Error::Io(err)
        }
    })
}

pub(crate) fn read_json<T: DeserializeOwned>(path: &Path, max: u64) -> Result<T> {
    let file = File::open(path).map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            Error::NotFound(path.file_name().unwrap().to_string_lossy().into())
        } else {
            Error::Io(err)
        }
    })?;
    let mut bytes = Vec::new();
    copy_bounded(file, &mut bytes, max)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn save_json(path: &Path, value: &impl Serialize, max: u64) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() as u64 > max {
        return Err(Error::Limit("serialized registry record size"));
    }
    save_bytes(path, &bytes)
}

fn save_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = parent_directory(path);
    let check_existing = |file| {
        if equal_bytes(file, bytes)? {
            // A concurrent publisher may have installed the link before syncing it.
            sync_directory(parent)?;
            Ok(())
        } else {
            Err(Error::Conflict(
                path.file_name().unwrap().to_string_lossy().into(),
            ))
        }
    };
    match File::open(path) {
        Ok(file) => return check_existing(file),
        Err(err) if err.kind() == io::ErrorKind::NotFound => (),
        Err(err) => return Err(err.into()),
    }
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    match file.persist_noclobber(path) {
        Ok(_) => sync_directory(parent).map_err(Error::from),
        Err(err) if err.error.kind() == io::ErrorKind::AlreadyExists => {
            check_existing(File::open(path)?)
        }
        Err(err) => Err(err.error.into()),
    }
}

fn equal_bytes(mut file: File, expected: &[u8]) -> io::Result<bool> {
    if file.metadata()?.len() != expected.len() as u64 {
        return Ok(false);
    }
    let mut buffer = [0; 64 << 10];
    for chunk in expected.chunks(buffer.len()) {
        file.read_exact(&mut buffer[..chunk.len()])?;
        if &buffer[..chunk.len()] != chunk {
            return Ok(false);
        }
    }
    Ok(true)
}
