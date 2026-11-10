//! Optional `sac.recovery.v1` profile and independent physical discovery.
//! Recovery restores a sealed checkpoint without its subsequently added parity.
use super::*;
use crate::v1::ObjectHash;
#[cfg(feature = "native")]
use crate::v1::{
    CanonicalObject, ObjectRef, ObjectStore,
    cbor::{self, Value},
    resources,
};
use std::cell::RefCell;

pub const PROFILE_ID: &str = "sac.recovery.v1";
const SEGMENT_MAGIC: &[u8; 8] = b"SAC1RSEG";
const SEGMENT_HEADER: usize = 320;
const SEGMENT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmbeddedInfo {
    pub recovery: RecoveryInfo,
    pub protected_snapshot: ObjectHash,
    pub segments: u64,
}
#[derive(Clone, PartialEq, Eq)]
struct Identity {
    source_digest: [u8; 32],
    source_bytes: u64,
    record_bytes: u64,
    trailer: [u8; 160],
    snapshot: ObjectHash,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Segment {
    offset: u64,
    length: u64,
    physical: u64,
}

#[cfg(feature = "native")]
fn segment_header(identity: &Identity, segment: Segment, position: u64) -> [u8; SEGMENT_HEADER] {
    let mut b = [0; SEGMENT_HEADER];
    b[..8].copy_from_slice(SEGMENT_MAGIC);
    b[8..12].copy_from_slice(&1u32.to_le_bytes());
    b[12..16].copy_from_slice(&(SEGMENT_HEADER as u32).to_le_bytes());
    b[16..48].copy_from_slice(&identity.source_digest);
    b[48..56].copy_from_slice(&identity.source_bytes.to_le_bytes());
    b[56..64].copy_from_slice(&identity.record_bytes.to_le_bytes());
    b[64..72].copy_from_slice(&segment.offset.to_le_bytes());
    b[72..76].copy_from_slice(&(segment.length as u32).to_le_bytes());
    b[76..84].copy_from_slice(&position.to_le_bytes());
    b[84..92].copy_from_slice(&segment.physical.to_le_bytes());
    b[96..256].copy_from_slice(&identity.trailer);
    b[256..288].copy_from_slice(&identity.snapshot.0);
    let hash = domain_hash(b"SAC1/recovery-segment\0", &b[..288]);
    b[288..].copy_from_slice(&hash.0);
    b
}
fn decode_segment(
    b: &[u8; SEGMENT_HEADER],
    position: u64,
    file_len: u64,
    limits: &RecoveryLimits,
) -> Option<(Identity, Segment)> {
    use crate::v1::wire::{le32, le64};
    if &b[..8] != SEGMENT_MAGIC
        || le32(b, 8) != 1
        || le32(b, 12) != SEGMENT_HEADER as u32
        || le64(b, 76) != position
        || b[92..96] != [0; 4]
        || domain_hash(b"SAC1/recovery-segment\0", &b[..288]).0 != b[288..]
    {
        return None;
    }
    let identity = Identity {
        source_digest: b[16..48].try_into().ok()?,
        source_bytes: le64(b, 48),
        record_bytes: le64(b, 56),
        trailer: b[96..256].try_into().ok()?,
        snapshot: ObjectHash(b[256..288].try_into().ok()?),
    };
    let segment = Segment {
        offset: le64(b, 64),
        length: u64::from(le32(b, 72)),
        physical: le64(b, 84),
    };
    if identity.source_bytes < 288
        || identity.source_bytes > limits.max_source_bytes
        || identity.record_bytes > limits.max_record_bytes
        || segment.length == 0
        || segment.length > SEGMENT_BYTES as u64
        || segment.offset.checked_add(segment.length)? > identity.record_bytes
        || segment.physical > file_len
        || !(segment.physical == position.checked_add(SEGMENT_HEADER as u64)?
            || segment.physical.checked_add(segment.length)? == position)
        || segment.physical < identity.source_bytes - 160
    {
        return None;
    }
    Some((identity, segment))
}

fn discover<R: Read + Seek>(
    source: &mut R,
    limits: &RecoveryLimits,
) -> Result<(Identity, Vec<Segment>)> {
    let start = Instant::now();
    let size = source.seek(SeekFrom::End(0))?;
    if size > limits.max_source_bytes {
        return Err(Error::Limit("embedded recovery input"));
    }
    if limits.max_memory_bytes < 4 << 20 {
        return Err(Error::Limit("embedded discovery memory"));
    }
    let mut identity = None;
    let mut segments = Vec::new();
    let mut position = 0;
    let mut candidates = 0u64;
    let mut buffer = vec![0; SEGMENT_BYTES + 7];
    while position < size {
        time_check(start, limits)?;
        let n = (size - position).min(buffer.len() as u64) as usize;
        read_at(source, position, &mut buffer[..n])?;
        for i in 0..n.saturating_sub(7) {
            if &buffer[i..i + 8] != SEGMENT_MAGIC {
                continue;
            }
            let at = position + i as u64;
            candidates = candidates.saturating_add(1);
            if candidates > limits.max_stripes.saturating_mul(4) {
                return Err(Error::Limit("embedded discovery candidates"));
            }
            if candidates.is_multiple_of(64) {
                time_check(start, limits)?;
            }
            let mut header = [0; SEGMENT_HEADER];
            if read_at(source, at, &mut header)? != SEGMENT_HEADER {
                continue;
            }
            if let Some((candidate, segment)) = decode_segment(&header, at, size, limits) {
                if identity.as_ref().is_some_and(|old| old != &candidate) {
                    return Err(corrupt("ambiguous embedded recovery checkpoints"));
                }
                identity = Some(candidate);
                segments.push(segment);
                if segments.len() as u64 > limits.max_stripes.saturating_mul(2)
                    || segments.capacity() * std::mem::size_of::<Segment>()
                        > limits.max_memory_bytes.saturating_sub(4 << 20) as usize
                {
                    return Err(Error::Limit("embedded recovery discovery index"));
                }
            }
        }
        position += (n.saturating_sub(7).max(1)) as u64;
    }
    let identity =
        identity.ok_or_else(|| corrupt("no embedded recovery records for this layout"))?;
    segments.sort_by_key(|s| s.offset);
    segments.dedup();
    for pair in segments.windows(2) {
        if pair[0].offset + pair[0].length > pair[1].offset {
            return Err(corrupt("overlapping embedded recovery segments"));
        }
    }
    Ok((identity, segments))
}

struct View<'a, 'r, R> {
    source: &'a RefCell<&'r mut R>,
    position: u64,
    identity: &'a Identity,
    segments: Option<&'a [Segment]>,
}
impl<R: Read + Seek> Seek for View<'_, '_, R> {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        let len = if self.segments.is_some() {
            self.identity.record_bytes
        } else {
            self.identity.source_bytes
        };
        let next = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => i128::from(len) + i128::from(n),
        };
        self.position = u64::try_from(next).map_err(std::io::Error::other)?;
        Ok(self.position)
    }
}
impl<R: Read + Seek> Read for View<'_, '_, R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let len = if self.segments.is_some() {
            self.identity.record_bytes
        } else {
            self.identity.source_bytes
        };
        let n = (len.saturating_sub(self.position)).min(out.len() as u64) as usize;
        if n == 0 {
            return Ok(0);
        }
        let mut done = 0;
        while done < n {
            let at = self.position + done as u64;
            if let Some(segments) = self.segments {
                let i = segments.partition_point(|s| s.offset + s.length <= at);
                if let Some(s) = segments.get(i).filter(|s| s.offset <= at) {
                    let count = (s.offset + s.length - at).min((n - done) as u64) as usize;
                    let mut source = self.source.borrow_mut();
                    let got = read_at(
                        &mut **source,
                        s.physical + at - s.offset,
                        &mut out[done..done + count],
                    )
                    .map_err(std::io::Error::other)?;
                    out[done + got..done + count].fill(0);
                    done += count;
                } else {
                    let count = segments.get(i).map_or(n - done, |s| {
                        (s.offset - at).min((n - done) as u64) as usize
                    });
                    out[done..done + count].fill(0);
                    done += count;
                }
            } else if at >= self.identity.source_bytes - 160 {
                let offset = (at - (self.identity.source_bytes - 160)) as usize;
                out[done..n].copy_from_slice(&self.identity.trailer[offset..offset + n - done]);
                done = n;
            } else {
                let count = (self.identity.source_bytes - 160 - at).min((n - done) as u64) as usize;
                let mut source = self.source.borrow_mut();
                let got = read_at(&mut **source, at, &mut out[done..done + count])
                    .map_err(std::io::Error::other)?;
                out[done + got..done + count].fill(0);
                done += count;
            }
        }
        self.position += n as u64;
        Ok(n)
    }
}
fn checked_info<R: Read + Seek>(
    source: &RefCell<&mut R>,
    identity: &Identity,
    segments: &[Segment],
    limits: &RecoveryLimits,
) -> Result<EmbeddedInfo> {
    let mut records = View {
        source,
        position: 0,
        identity,
        segments: Some(segments),
    };
    let recovery = super::inspect(&mut records, limits)?;
    if recovery.source_digest != identity.source_digest
        || recovery.source_bytes != identity.source_bytes
        || recovery.record_bytes != identity.record_bytes
    {
        return Err(corrupt("embedded recovery checkpoint binding"));
    }
    Ok(EmbeddedInfo {
        recovery,
        protected_snapshot: identity.snapshot,
        segments: segments.len() as u64,
    })
}
/// Explicit bounded scan. Ordinary container admission never scans for parity.
pub fn inspect<R: Read + Seek>(source: &mut R, limits: &RecoveryLimits) -> Result<EmbeddedInfo> {
    let (identity, segments) = discover(source, limits)?;
    checked_info(&RefCell::new(source), &identity, &segments, limits)
}
/// Restore the protected checkpoint to provisional output, without its profile.
/// Discard output on error. Works even if normal SAC admission fails.
pub fn repair<R: Read + Seek, W: Write>(
    source: &mut R,
    output: &mut W,
    limits: &RecoveryLimits,
) -> Result<RecoveryReport> {
    let start = Instant::now();
    let (identity, segments) = discover(source, limits)?;
    let source = RefCell::new(source);
    checked_info(&source, &identity, &segments, limits)?;
    let mut image = View {
        source: &source,
        position: 0,
        identity: &identity,
        segments: None,
    };
    let mut records = View {
        source: &source,
        position: 0,
        identity: &identity,
        segments: Some(&segments),
    };
    let mut remaining = limits.clone();
    remaining.max_duration = remaining.max_duration.saturating_sub(start.elapsed());
    remaining.max_memory_bytes = remaining
        .max_memory_bytes
        .saturating_sub((segments.capacity() * std::mem::size_of::<Segment>()) as u64);
    super::repair(&mut image, &mut records, output, &remaining)
}

#[cfg(feature = "native")]
pub struct EmbeddedLimits {
    pub recovery: RecoveryLimits,
    pub resources: resources::Limits,
    pub max_temp_bytes: u64,
}
#[cfg(feature = "native")]
impl Default for EmbeddedLimits {
    fn default() -> Self {
        Self {
            recovery: RecoveryLimits::default(),
            resources: resources::Limits::default(),
            max_temp_bytes: 128 << 30,
        }
    }
}

#[cfg(feature = "native")]
mod writer {
    use super::*;
    use crate::v1::{ChunkAddress, NativeReader, SealedWriter};
    use std::{collections::BTreeMap, fs::File, path::Path, sync::Arc};

    struct Overlay<'a> {
        source: &'a NativeReader,
        objects: BTreeMap<ObjectHash, Arc<CanonicalObject>>,
        end: u64,
    }
    impl ObjectStore for Overlay<'_> {
        fn get(&self, r: ObjectRef) -> Result<CanonicalObject> {
            self.get_shared(r).map(|o| (*o).clone())
        }
        fn get_shared(&self, r: ObjectRef) -> Result<Arc<CanonicalObject>> {
            match self.objects.get(&r.hash) {
                Some(o) => Ok(o.clone()),
                None => self.source.get_shared(r),
            }
        }
        fn put(
            &mut self,
            kind: u16,
            version: u16,
            bytes: &[u8],
            children: &[ObjectRef],
        ) -> Result<ObjectRef> {
            let o = CanonicalObject {
                kind,
                version,
                bytes: bytes.to_vec(),
                children: children.to_vec(),
            };
            o.validate_size()?;
            let hash = o.hash();
            let length = crate::v1::wire::encode_frame(&o, 0)?.len() as u32;
            let address = ChunkAddress {
                offset: self.end,
                length,
            };
            self.end = self
                .end
                .checked_add(u64::from(length))
                .ok_or(Error::Limit("checkpoint overlay extent"))?;
            self.objects.insert(hash, Arc::new(o));
            Ok(ObjectRef { hash, address })
        }
    }
    fn record<W: Write>(
        writer: &mut SealedWriter<W>,
        kind: &str,
        payload: Vec<u8>,
        children: &[ObjectRef],
    ) -> Result<ObjectRef> {
        writer.put(
            8,
            1,
            &cbor::encode(&Value::Array(vec![
                Value::text(PROFILE_ID),
                Value::text(kind),
                Value::Uint(1),
                Value::bytes(payload),
            ])),
            children,
        )
    }
    fn parts(
        source: &impl ObjectStore,
        snapshot: ObjectRef,
    ) -> Result<(
        ObjectRef,
        Vec<resources::Profile>,
        Vec<resources::Feature>,
        bool,
    )> {
        let o = source.get(snapshot)?;
        let value = cbor::decode(&o.bytes)?;
        let f = resources::values(&value)?;
        let mut profiles = Vec::new();
        let mut removed = false;
        for p in resources::values(&f[1])? {
            let p = resources::values(p)?;
            let Value::Text(id) = &p[0] else {
                return Err(corrupt("profile id"));
            };
            if id == PROFILE_ID {
                if resources::number(&p[1])? != 1 {
                    return Err(Error::Unsupported(
                        "embedded recovery profile version".into(),
                    ));
                }
                removed = true;
                continue;
            }
            profiles.push(resources::Profile {
                id: id.clone(),
                version: resources::number(&p[1])? as u32,
                root: resources::child(&o, &p[2])?,
            });
        }
        let mut features = Vec::new();
        for f in resources::values(&f[2])? {
            let f = resources::values(f)?;
            let scope = match &f[0] {
                Value::Null => None,
                Value::Text(s) => Some(s.clone()),
                _ => return Err(corrupt("feature scope")),
            };
            if scope.as_deref() == Some(PROFILE_ID) {
                if f[3] == Value::Bool(true) {
                    return Err(Error::Unsupported("required recovery capability".into()));
                }
                continue;
            }
            let Value::Text(id) = &f[1] else {
                return Err(corrupt("feature id"));
            };
            features.push(resources::Feature {
                scope,
                id: id.clone(),
                version: resources::number(&f[2])? as u32,
                required: f[3] == Value::Bool(true),
            });
        }
        Ok((resources::child(&o, &f[0])?, profiles, features, removed))
    }

    /// Build a new sealed container with ordinary resources/profiles and embedded
    /// recovery. Previous recovery is stripped before checkpoint packing. Local
    /// attachments require explicit opt-in to their removal. Existing signatures
    /// remain on the protected commit, not the newly changed outer snapshot.
    pub fn embed_file(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        options: RecoveryOptions,
        limits: &EmbeddedLimits,
        strip_local: bool,
    ) -> Result<EmbeddedInfo> {
        let mut resource_limits = limits.resources.clone();
        resource_limits.max_temp_bytes = resource_limits
            .max_temp_bytes
            .min(limits.max_temp_bytes / 8);
        let source = NativeReader::open(source)?;
        source.set_decoded_cache_budget(4 << 20);
        if source.reader().committed_end() > limits.recovery.max_source_bytes {
            return Err(Error::Limit("embedded source"));
        }
        source.validate_with_limits(&resource_limits)?;
        let commit = source.root().ok_or(Error::Missing)?.root;
        let commit_object = source.get(commit)?;
        let value = cbor::decode(&commit_object.bytes)?;
        let fields = resources::values(&value)?;
        if fields[2] != Value::Null && !strip_local {
            return Err(Error::Unsupported(
                "embedding requires --strip-local for a local attachment".into(),
            ));
        }
        let snapshot = source.reader().snapshot().ok_or(Error::Missing)?;
        let (directory, profiles, features, removed) = parts(&source, snapshot)?;
        let destination = destination.as_ref();
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut base = tempfile::NamedTempFile::new_in(parent)?;
        struct Bounded<'a, W> {
            inner: W,
            used: u64,
            limit: u64,
            start: Instant,
            limits: &'a RecoveryLimits,
        }
        impl<W: Write> Write for Bounded<'_, W> {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                time_check(self.start, self.limits).map_err(std::io::Error::other)?;
                if self.used.saturating_add(b.len() as u64) > self.limit {
                    return Err(std::io::Error::other(
                        "LimitExceeded: embedded output/temporary byte quota",
                    ));
                }
                let n = self.inner.write(b)?;
                self.used += n as u64;
                Ok(n)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.inner.flush()
            }
        }
        let start = Instant::now();
        let mut base_out = Bounded {
            inner: base.as_file_mut(),
            used: 0,
            limit: limits.recovery.max_source_bytes.min(
                limits
                    .max_temp_bytes
                    .saturating_sub(resource_limits.max_temp_bytes),
            ),
            start,
            limits: &limits.recovery,
        };
        if removed {
            if fields[1] != Value::Null {
                return Err(Error::Unsupported(
                    "cannot strip an attested recovery profile; use external records".into(),
                ));
            }
            let mut overlay = Overlay {
                source: &source,
                objects: BTreeMap::new(),
                end: source.reader().committed_end(),
            };
            let stripped = resources::snapshot(&mut overlay, directory, profiles, features)?;
            // Retain signatures on an unchanged protected checkpoint during refresh.
            let original = source.get(snapshot)?;
            let v = cbor::decode(&original.bytes)?;
            let f = resources::values(&v)?;
            let mut attestation = None;
            for p in resources::values(&f[1])? {
                let p = resources::values(p)?;
                if p[0] != Value::text(PROFILE_ID) {
                    continue;
                }
                let root = source.get(resources::child(&original, &p[2])?)?;
                let payload = resources::values(&cbor::decode(&root.bytes)?)?
                    .get(3)
                    .cloned()
                    .ok_or_else(|| corrupt("recovery root"))?;
                let Value::Bytes(payload) = payload else {
                    return Err(corrupt("recovery root payload"));
                };
                let v = cbor::decode(&payload)?;
                let f = resources::values(&v)?;
                if f.len() != 6
                    || f[0] != Value::Uint(0)
                    || f[1] != Value::Uint(1)
                    || root.children.len() != 2
                {
                    return Err(corrupt("recovery root shape"));
                }
                let protected = source.get(root.children[0])?;
                let v = cbor::decode(&protected.bytes)?;
                let f = resources::values(&v)?;
                if protected.kind != 1 || f.len() != 3 {
                    return Err(corrupt("protected commit"));
                }
                if f[1] != Value::Null {
                    if resources::child(&protected, &f[0])?.hash != stripped.hash {
                        return Err(Error::Unsupported("refresh would discard an attested older checkpoint; use external records".into()));
                    }
                    attestation = Some(resources::child(&protected, &f[1])?);
                }
            }
            let portable_commit = resources::commit(&mut overlay, stripped, attestation, None)?;
            crate::v1::pack_commit_with_limits(
                &overlay,
                portable_commit,
                &mut base_out,
                resource_limits.clone(),
            )?;
        } else {
            crate::v1::pack_commit_with_limits(
                &source,
                commit,
                &mut base_out,
                resource_limits.clone(),
            )?;
        }
        base.as_file().sync_all()?;
        let checkpoint = NativeReader::open(base.path())?;
        checkpoint.set_decoded_cache_budget(4 << 20);
        let snapshot = checkpoint.reader().snapshot().ok_or(Error::Missing)?;
        let commit = checkpoint.root().ok_or(Error::Missing)?.root;
        let (directory, mut profiles, features, _) = parts(&checkpoint, snapshot)?;
        let len = base.as_file().metadata()?.len();
        let mut records = tempfile::NamedTempFile::new_in(parent)?;
        let mut recovery_limits = limits.recovery.clone();
        recovery_limits.max_output_bytes = recovery_limits.max_output_bytes.min(
            limits
                .max_temp_bytes
                .saturating_sub(len)
                .saturating_sub(resource_limits.max_temp_bytes),
        );
        recovery_limits.max_duration = recovery_limits.max_duration.saturating_sub(start.elapsed());
        let info = super::super::create(
            base.as_file_mut(),
            records.as_file_mut(),
            options,
            &recovery_limits,
        )?;
        let mut trailer = [0; 160];
        read_at(base.as_file_mut(), len - 160, &mut trailer)?;
        let identity = Identity {
            source_digest: info.source_digest,
            source_bytes: len,
            record_bytes: info.record_bytes,
            trailer,
            snapshot: snapshot.hash,
        };
        let mut output = tempfile::NamedTempFile::new_in(parent)?;
        let available = limits
            .max_temp_bytes
            .saturating_sub(len)
            .saturating_sub(info.record_bytes)
            .saturating_sub(resource_limits.max_temp_bytes);
        let mut out = Bounded {
            inner: output.as_file_mut(),
            used: 0,
            limit: limits.recovery.max_output_bytes.min(available),
            start,
            limits: &limits.recovery,
        };
        base.as_file_mut().seek(SeekFrom::Start(0))?;
        std::io::copy(&mut base.as_file_mut().take(len - 160), &mut out)?;
        let mut writer = SealedWriter {
            output: out,
            end: len - 160,
            last: None,
            compression_level: 0,
            encoder: crate::v1::wire::FrameEncoder::default(),
        };
        let count = info.record_bytes.div_ceil(SEGMENT_BYTES as u64);
        if count > limits.recovery.max_stripes
            || count.saturating_mul(64).saturating_add(5 << 20) > limits.recovery.max_memory_bytes
        {
            return Err(Error::Limit("embedded recovery segments/memory"));
        }
        let mut roots = Vec::new();
        records.as_file_mut().seek(SeekFrom::Start(0))?;
        for offset in (0..info.record_bytes).step_by(SEGMENT_BYTES) {
            time_check(start, &limits.recovery)?;
            let n = (info.record_bytes - offset).min(SEGMENT_BYTES as u64) as usize;
            let mut body = Value::Array(vec![
                Value::text(PROFILE_ID),
                Value::text("segment"),
                Value::Uint(1),
                Value::bytes(vec![0; n + 2 * SEGMENT_HEADER]),
            ]);
            let prefix = cbor::encoded_len(&body) - (n + 2 * SEGMENT_HEADER);
            let position = writer.end + 64 + prefix as u64;
            let segment = Segment {
                offset,
                length: n as u64,
                physical: position + SEGMENT_HEADER as u64,
            };
            let Value::Array(fields) = &mut body else {
                unreachable!()
            };
            let Value::Bytes(payload) = &mut fields[3] else {
                unreachable!()
            };
            payload[..SEGMENT_HEADER]
                .copy_from_slice(&segment_header(&identity, segment, position));
            records
                .as_file_mut()
                .read_exact(&mut payload[SEGMENT_HEADER..SEGMENT_HEADER + n])?;
            payload[SEGMENT_HEADER + n..].copy_from_slice(&segment_header(
                &identity,
                segment,
                segment.physical + n as u64,
            ));
            roots.push(writer.put(8, 1, &cbor::encode(&body), &[])?);
        }
        while roots.len() > 512 {
            let mut next = Vec::new();
            for group in roots.chunks(512) {
                next.push(record(
                    &mut writer,
                    "segments",
                    cbor::encode(&Value::Array(vec![])),
                    group,
                )?);
            }
            roots = next;
        }
        let tree = record(
            &mut writer,
            "segments",
            cbor::encode(&Value::Array(vec![])),
            &roots,
        )?;
        let payload = cbor::encode(&Value::Array(vec![
            Value::Uint(0),
            Value::Uint(1),
            Value::Uint(len),
            Value::bytes(info.source_digest),
            Value::Uint(info.record_bytes),
            Value::bytes(trailer),
        ]));
        let root = record(&mut writer, "root", payload, &[commit, tree])?;
        profiles.push(resources::Profile {
            id: PROFILE_ID.into(),
            version: 1,
            root,
        });
        let snapshot = resources::snapshot(&mut writer, directory, profiles, features)?;
        writer.finish(snapshot)?;
        output.as_file().sync_all()?;
        NativeReader::open(output.path())?.validate_with_limits(&resource_limits)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(output.path(), std::fs::Permissions::from_mode(0o600))?;
        }
        output
            .persist_noclobber(destination)
            .map_err(|e| Error::Io(e.error))?;
        File::open(parent)?.sync_all()?;
        Ok(EmbeddedInfo {
            recovery: info,
            protected_snapshot: identity.snapshot,
            segments: count,
        })
    }
}
#[cfg(feature = "native")]
pub use writer::embed_file;
