//! SAC1 immutable objects, bounded positional admission and forward production.
pub mod attestation;
pub mod cbor;
pub mod cbor_view;
#[cfg(feature = "http")]
pub mod http;
pub mod metadata;
#[cfg(feature = "native")]
pub mod native;
#[cfg(feature = "privacy-age")]
pub mod privacy;
pub mod recovery;
pub mod resources;
mod schema;
pub mod wire;
#[cfg(feature = "native")]
pub use native::*;
pub use schema::{validate_core_edges, validate_core_object};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::sync::Arc;
pub use wire::{
    LocatorPolicy, Preamble, Slot, Trailer, decode_frame, encode_frame, validate_address,
};

pub const PAGE_SIZE: usize = 4096;
pub const BOOTSTRAP_SIZE: usize = PAGE_SIZE * 3;
pub const MAX_CHUNK_SIZE: usize = 8 * 1024 * 1024;
pub const MAX_CHILDREN: usize = 1024;
pub const BULK_COMPRESSION_LEVEL: i32 = 16;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("corrupt SAC1: {0}")]
    Corrupt(String),
    #[error("unsupported SAC1: {0}")]
    Unsupported(String),
    #[error("SAC1 limit exceeded: {0}")]
    Limit(&'static str),
    #[error("object not found")]
    Missing,
    #[error("writer requires recovery")]
    Poisoned,
    #[error("damaged publication requires recovery")]
    RecoveryRequired,
    #[error("publication admission is busy")]
    Busy,
}
pub type Result<T> = std::result::Result<T, Error>;
pub(crate) fn corrupt(message: &str) -> Error {
    Error::Corrupt(message.into())
}
pub fn domain_hash(domain: &[u8], bytes: &[u8]) -> ObjectHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    ObjectHash(*hasher.finalize().as_bytes())
}
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectHash(pub [u8; 32]);
impl ObjectHash {
    pub fn digest(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }
}
impl std::fmt::Display for ObjectHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChunkAddress {
    pub offset: u64,
    pub length: u32,
}
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectRef {
    pub hash: ObjectHash,
    pub address: ChunkAddress,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalObject {
    pub kind: u16,
    pub version: u16,
    pub bytes: Vec<u8>,
    pub children: Vec<ObjectRef>,
}
impl CanonicalObject {
    /// Check the canonical byte and child-count limits without encoding or
    /// hashing. Custom staging stores must enforce the same limits as writers.
    pub fn validate_size(&self) -> Result<()> {
        check_input(&self.bytes, &self.children)
    }
    pub fn canonical_len(&self) -> usize {
        8 + 32 * self.children.len() + self.bytes.len()
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.canonical_len());
        self.write_canonical(&mut out);
        out
    }
    pub(crate) fn write_canonical(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.kind.to_le_bytes());
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&(self.children.len() as u32).to_le_bytes());
        for child in &self.children {
            out.extend_from_slice(&child.hash.0);
        }
        out.extend_from_slice(&self.bytes);
    }

    pub fn hash(&self) -> ObjectHash {
        let mut hash = blake3::Hasher::new();
        hash.update(b"SAC1/object\0");
        hash.update(&self.kind.to_le_bytes());
        hash.update(&self.version.to_le_bytes());
        hash.update(&(self.children.len() as u32).to_le_bytes());
        for child in &self.children {
            hash.update(&child.hash.0);
        }
        hash.update(&self.bytes);
        ObjectHash(*hash.finalize().as_bytes())
    }
}
pub(crate) fn check_input(bytes: &[u8], children: &[ObjectRef]) -> Result<()> {
    if children.len() > MAX_CHILDREN
        || children
            .len()
            .checked_mul(32)
            .and_then(|n| n.checked_add(8))
            .and_then(|n| n.checked_add(bytes.len()))
            .is_none_or(|n| n > MAX_CHUNK_SIZE)
    {
        return Err(Error::Limit("canonical object"));
    }
    Ok(())
}
/// One authenticated immutable parent occurrence for a checked persistent-tree
/// rewrite. This carries the prior parent's deferred subtree/layout status; it
/// does not certify its child payloads or confer full-closure validation. Native
/// bindings are issued only by the owning store, never from caller-supplied IDs.
/// Staged directory sources additionally retain writer-recorded full-edge layout
/// provenance and a captured append pin; neither grants shared layout authority.
#[derive(Clone)]
#[cfg_attr(not(feature = "native"), allow(dead_code))]
pub struct RewriteSource {
    parent: ObjectRef,
    object: Arc<CanonicalObject>,
    identity: u64,
    committed_end: u64,
    readable_end: u64,
    staged_layout: Option<[u8; 32]>,
}

/// One physical cache capability captured from a reader or writer.
/// Bounds match that source's readable top-level frame extent, excluding the
/// selected trailer. Different pins may share identity but have smaller ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhysicalReadScope {
    pub identity: u64,
    pub first: u64,
    pub end: u64,
}

/// Immutable canonical bytes whose identity was authenticated by a store read.
/// Physical locators remain source-specific: a copy may change them only while
/// preserving the complete ordered child identity sequence. This capability
/// confers no authority over those destination occurrences or their closure.
pub struct VerifiedObject {
    hash: ObjectHash,
    object: Arc<CanonicalObject>,
    // The Zstandard bytes of the frame that the source read and
    // authenticated as this object. A native destination stores them again
    // instead of compressing the same canonical bytes.
    #[cfg_attr(not(feature = "native"), allow(dead_code))]
    compressed: Option<Arc<Vec<u8>>>,
}
/// One object without children that a store encoded before its put. Only a
/// store makes this value, so its identity is the hash of its own bytes.
pub struct PreparedObject {
    object: CanonicalObject,
    #[cfg_attr(not(feature = "native"), allow(dead_code))]
    hash: ObjectHash,
    #[cfg_attr(not(feature = "native"), allow(dead_code))]
    frame: Vec<u8>,
    #[cfg_attr(not(feature = "native"), allow(dead_code))]
    level: i32,
}
impl PreparedObject {
    /// The body bytes that the caller gave to [`ObjectStore::prepare`].
    pub fn body(&self) -> &[u8] {
        &self.object.bytes
    }
}
impl VerifiedObject {
    pub fn hash(&self) -> ObjectHash {
        self.hash
    }
    pub fn object(&self) -> &CanonicalObject {
        &self.object
    }
    fn validate_children(&self, children: &[ObjectRef]) -> Result<()> {
        if children.len() != self.object.children.len()
            || children
                .iter()
                .zip(&self.object.children)
                .any(|(a, b)| a.hash != b.hash)
        {
            return Err(corrupt("verified copy changed child identities"));
        }
        Ok(())
    }
    pub fn relocated(&self, children: &[ObjectRef]) -> Result<CanonicalObject> {
        self.validate_children(children)?;
        Ok(CanonicalObject {
            kind: self.object.kind,
            version: self.object.version,
            bytes: self.object.bytes.clone(),
            children: children.to_vec(),
        })
    }
}

pub trait ObjectStore {
    fn get(&self, reference: ObjectRef) -> Result<CanonicalObject>;
    fn get_shared(&self, reference: ObjectRef) -> Result<Arc<CanonicalObject>> {
        self.get(reference).map(Arc::new)
    }
    /// An authenticated immutable object. Untrusted adapters retain the default
    /// identity/schema check; wire-authenticating stores may reuse their result.
    fn get_verified_shared(&self, reference: ObjectRef) -> Result<Arc<CanonicalObject>> {
        let object = self.get_shared(reference)?;
        check_input(&object.bytes, &object.children)?;
        if object.hash() != reference.hash {
            return Err(corrupt("object expected identity"));
        }
        validate_core_object(&object)?;
        Ok(object)
    }
    /// Capture the result of this source's authenticated read without exposing
    /// a caller-supplied known-hash write API.
    fn verified_object(&self, reference: ObjectRef) -> Result<VerifiedObject> {
        Ok(VerifiedObject {
            hash: reference.hash,
            object: self.get_verified_shared(reference)?,
            compressed: None,
        })
    }
    /// Authenticated kind and version of one exact physical occurrence. Native
    /// stores may retain this small result after evicting the decoded payload;
    /// it grants no authority over outgoing edges or other physical locators.
    fn object_type(&self, reference: ObjectRef) -> Result<(u16, u16)> {
        let object = self.get_verified_shared(reference)?;
        Ok((object.kind, object.version))
    }
    /// Previously authenticated type, without reading the payload on a miss.
    /// A hit has the same exact-reference and current-bound requirements as
    /// `object_type`. Generic stores return None so callers can fetch once and
    /// use both the type and body from that single authenticated read.
    fn cached_object_type(&self, _reference: ObjectRef) -> Result<Option<(u16, u16)>> {
        Ok(None)
    }
    /// Authenticate one exact reference without retaining its payload. This
    /// does not attest outgoing edges or a whole closure. Immutable stores may
    /// reuse prior authentication only within the same physical capability and
    /// its current readable bounds; other stores perform an ordinary read.
    fn validate_reference(&self, reference: ObjectRef) -> Result<()> {
        self.get_verified_shared(reference).map(|_| ())
    }
    #[cfg(feature = "native")]
    fn rehint_native(
        &self,
        _source: &native::NativeReader,
        _reference: ObjectRef,
    ) -> Result<Option<ObjectRef>> {
        Ok(None)
    }
    fn physical_identity(&self) -> Option<u64> {
        None
    }
    /// Capture identity and readable frame bounds together. A caller retaining
    /// authenticated bytes must key them by this identity and the full ObjectRef,
    /// then validate the address against current [first, end) bounds BEFORE any
    /// cache hit. None retains the ordinary uncached/conservative path.
    fn physical_read_scope(&self) -> Option<PhysicalReadScope> {
        None
    }
    fn physical_dependencies(&self, _reference: ObjectRef) -> Result<Vec<ObjectRef>> {
        Ok(Vec::new())
    }
    fn put(
        &mut self,
        kind: u16,
        version: u16,
        bytes: &[u8],
        children: &[ObjectRef],
    ) -> Result<ObjectRef>;
    /// The number of objects that [`ObjectStore::prepare`] encodes at the same
    /// time. One means that this store encodes each object in its put.
    fn prepare_width(&self) -> usize {
        1
    }
    /// Encode objects that have no children before their puts. A store with
    /// several encoder threads hashes and compresses the bodies together; the
    /// caller then gives each result to [`ObjectStore::put_prepared`] in the
    /// order in which it would have put the body, so the stored bytes do not
    /// change. `None` means that this store does not encode ahead: use `put`.
    fn prepare(
        &self,
        _kind: u16,
        _version: u16,
        _bodies: &[&[u8]],
    ) -> Result<Option<Vec<PreparedObject>>> {
        Ok(None)
    }
    /// Put one result of [`ObjectStore::prepare`]. The result is the same
    /// reference that `put` returns for the same kind, version and body.
    fn put_prepared(&mut self, prepared: PreparedObject) -> Result<ObjectRef> {
        let object = prepared.object;
        self.put(object.kind, object.version, &object.bytes, &[])
    }
    /// Copy authenticated canonical bytes, relocating only child occurrences.
    /// The destination still admits every physical child normally. Adapters
    /// retain strict put unless they explicitly support this capability.
    fn put_verified(
        &mut self,
        source: &VerifiedObject,
        children: &[ObjectRef],
    ) -> Result<ObjectRef> {
        let object = source.relocated(children)?;
        self.put(object.kind, object.version, &object.bytes, &object.children)
    }
    /// Obtain a bounded, source-bound prior parent for a checked tree update.
    /// None means use ordinary put. Native stores may also bind pages appended
    /// by this writer when their original full physical-edge layout is retained.
    /// Callers preserve their existing tree validation scope and validate changed
    /// roles, shape and boundaries; this never upgrades deferred child integrity.
    fn rewrite_source(&self, _parent: ObjectRef) -> Result<Option<RewriteSource>> {
        Ok(None)
    }
    /// Rewrite a checked persistent page, preserving exact unchanged edges.
    /// Generic stores retain strict put. Native stores may carry an identical
    /// (expected ID, offset, span) edge from the authenticated prior occurrence
    /// without rereading that child. Every new or relocated edge is authenticated
    /// normally. Skipped edges do not become verified-child cache entries.
    fn rewrite(
        &mut self,
        _source: &RewriteSource,
        kind: u16,
        version: u16,
        bytes: &[u8],
        children: &[ObjectRef],
    ) -> Result<ObjectRef> {
        self.put(kind, version, bytes, children)
    }
    fn put_bulk(
        &mut self,
        kind: u16,
        version: u16,
        payloads: Vec<Vec<u8>>,
    ) -> Result<Vec<ObjectRef>> {
        payloads
            .iter()
            .map(|bytes| self.put(kind, version, bytes, &[]))
            .collect()
    }
}

/// Transitional source-level constructor. SAC1 persists only the incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub lineage: [u8; 16],
    pub instance: [u8; 16],
    pub optional_features: u64,
}
impl Header {
    pub fn new(lineage: [u8; 16], instance: [u8; 16]) -> Self {
        Self {
            lineage,
            instance,
            optional_features: 0,
        }
    }
    pub fn preamble(self) -> Result<Preamble> {
        if self.optional_features != 0 {
            return Err(Error::Unsupported("legacy header feature bits".into()));
        }
        Preamble::live(self.instance)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Publication {
    pub generation: u64,
    pub root: ObjectRef,
    pub committed_end: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadRequest {
    pub offset: u64,
    pub length: u32,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReadStatistics {
    pub requests: u64,
    pub requested_bytes: u64,
    pub decoded_bytes: u64,
}
#[derive(Default, Debug)]
struct Counters {
    requests: std::sync::atomic::AtomicU64,
    requested_bytes: std::sync::atomic::AtomicU64,
    decoded_bytes: std::sync::atomic::AtomicU64,
}

pub trait ReadAt {
    fn len(&self) -> Result<u64>;
    fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<()>;
    fn is_empty(&self) -> Result<bool> {
        self.len().map(|n| n == 0)
    }
}
impl ReadAt for [u8] {
    fn len(&self) -> Result<u64> {
        Ok(self.len() as u64)
    }
    fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<()> {
        let start = usize::try_from(offset).map_err(|_| Error::Limit("host offset"))?;
        let end = start
            .checked_add(bytes.len())
            .ok_or(Error::Limit("host offset"))?;
        bytes.copy_from_slice(
            self.get(start..end)
                .ok_or_else(|| corrupt("short positional read"))?,
        );
        Ok(())
    }
}
impl ReadAt for Vec<u8> {
    fn len(&self) -> Result<u64> {
        Ok(self.len() as u64)
    }
    fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<()> {
        self.as_slice().read_exact_at(offset, bytes)
    }
}
impl<T: ReadAt + ?Sized> ReadAt for &T {
    fn len(&self) -> Result<u64> {
        (**self).len()
    }
    fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<()> {
        (**self).read_exact_at(offset, bytes)
    }
}
impl ReadAt for std::fs::File {
    fn len(&self) -> Result<u64> {
        Ok(self.metadata()?.len())
    }
    fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<()> {
        #[cfg(unix)]
        {
            std::os::unix::fs::FileExt::read_exact_at(self, bytes, offset)?;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::FileExt;
            let mut read = 0;
            while read < bytes.len() {
                let n = self.seek_read(&mut bytes[read..], offset + read as u64)?;
                if n == 0 {
                    return Err(corrupt("short positional read"));
                }
                read += n;
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (offset, bytes);
            return Err(Error::Unsupported("native positional reads".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Reader {
    pub header: Preamble,
    pub publication: Option<Publication>,
    pub recovery_diagnostics: Vec<String>,
    pub(super) end: u64,
    trailer_offset: u64,
    snapshot: Option<ObjectRef>,
    counters: Arc<Counters>,
}
impl Reader {
    pub fn from_parts(
        header: Preamble,
        publication: Option<Publication>,
        trailer_offset: u64,
        recovery_diagnostics: Vec<String>,
    ) -> Self {
        Self {
            header,
            publication,
            recovery_diagnostics,
            end: publication.map_or(header.first_record_offset(), |p| p.committed_end),
            trailer_offset,
            snapshot: None,
            counters: Arc::default(),
        }
    }
    pub fn open_at<S: ReadAt + ?Sized>(source: &S) -> Result<Self> {
        let len = source.len()?;
        if len < 128 {
            return Err(corrupt("short preamble"));
        }
        let mut bootstrap = vec![0; len.min(BOOTSTRAP_SIZE as u64) as usize];
        source.read_exact_at(0, &mut bootstrap)?;
        let header = Preamble::decode(&bootstrap[..128])?;
        let mut diagnostics = Vec::new();
        let (offset, slot) = if header.policy == LocatorPolicy::Sealed {
            (
                len.checked_sub(160)
                    .ok_or_else(|| corrupt("short sealed file"))?,
                None,
            )
        } else {
            if bootstrap.len() != BOOTSTRAP_SIZE {
                return Err(corrupt("short live bootstrap"));
            }
            let mut selected = None;
            for attempt in 0..3 {
                if attempt > 0 {
                    source.read_exact_at(0, &mut bootstrap)?;
                }
                diagnostics.clear();
                let mut slots = Vec::new();
                if Preamble::decode(&bootstrap[..128])? != header
                    || bootstrap[128..PAGE_SIZE].iter().any(|b| *b != 0)
                {
                    return Err(corrupt("live bootstrap changed or padding"));
                }
                for index in 0..2 {
                    match Slot::decode(
                        &bootstrap[(index + 1) * PAGE_SIZE..(index + 2) * PAGE_SIZE],
                        &header,
                        index,
                    ) {
                        Ok(Some(slot)) => slots.push(slot),
                        Ok(None) => {}
                        Err(Error::Corrupt(message)) if message == "slot checksum" => {
                            diagnostics.push(format!("damaged slot {index}"))
                        }
                        Err(error) => return Err(error),
                    }
                }
                slots.sort_by_key(|slot| slot.generation);
                if let Some(slot) = slots.last() {
                    selected = Some(*slot);
                    break;
                }
            }
            let slot = selected.ok_or(Error::Busy)?;
            (slot.trailer_offset, Some(slot))
        };
        let end = offset
            .checked_add(160)
            .ok_or(Error::Limit("committed extent"))?;
        let start = wire::control_start(header.first_record_offset(), end)?;
        // The immutable publication is admitted from one bounded positional read.
        // Sampling length again admits a publication completed after the bootstrap read.
        let current_len = source.len()?;
        if end > current_len {
            return Err(corrupt("publication beyond file"));
        }
        let mut control = vec![0; (end - start) as usize];
        source.read_exact_at(start, &mut control)?;
        let trailer = Trailer::decode(
            &control[(offset - start) as usize..],
            &header,
            offset,
            current_len,
        )?;
        if slot.is_some_and(|slot| {
            slot.generation != trailer.generation || slot.trailer_digest != trailer.digest()
        }) {
            return Err(corrupt("slot trailer mismatch"));
        }
        let publication = Publication {
            generation: trailer.generation,
            root: trailer.commit,
            committed_end: trailer.committed_end,
        };
        let mut reader = Self::from_parts(header, Some(publication), offset, diagnostics);
        struct Control<'a> {
            start: u64,
            bytes: &'a [u8],
        }
        impl ReadAt for Control<'_> {
            fn len(&self) -> Result<u64> {
                Ok(self.start + self.bytes.len() as u64)
            }
            fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<()> {
                let relative = offset
                    .checked_sub(self.start)
                    .ok_or_else(|| corrupt("control read outside bound"))?;
                self.bytes.read_exact_at(relative, bytes)
            }
        }
        reader.admit_control(&Control {
            start,
            bytes: &control,
        })?;
        Ok(reader)
    }
    pub fn admit_control<S: ReadAt + ?Sized>(&mut self, source: &S) -> Result<()> {
        let root = self.publication.ok_or(Error::Missing)?.root;
        let start = wire::control_start(self.first_record_offset(), self.end)?;
        validate_address(root.address, start, self.trailer_offset)?;
        let commit = self.get_at(source, root)?;
        if commit.kind != 1 || commit.version != 1 || commit.canonical_len() > 16384 {
            return Err(corrupt("commit kind or bound"));
        }
        let body = cbor::decode(&commit.bytes)?;
        let fields = schema::array(&body, 3)?;
        if self.header.policy == LocatorPolicy::Sealed && fields[2] != cbor::Value::Null {
            return Err(corrupt("sealed commit local data"));
        }
        let snapshot = commit.children[schema::uint(&fields[0])? as usize];
        validate_address(snapshot.address, start, root.address.offset)?;
        let object = self.get_at(source, snapshot)?;
        if object.kind != 2 || object.version != 1 || object.canonical_len() > 16384 {
            return Err(corrupt("snapshot kind or bound"));
        }
        self.snapshot = Some(snapshot);
        Ok(())
    }
    pub fn first_record_offset(&self) -> u64 {
        self.header.first_record_offset()
    }
    pub fn trailer_offset(&self) -> u64 {
        self.trailer_offset
    }
    pub fn committed_end(&self) -> u64 {
        self.end
    }
    pub fn snapshot(&self) -> Option<ObjectRef> {
        self.snapshot
    }
    pub fn request(&self, reference: ObjectRef) -> Result<ReadRequest> {
        validate_address(
            reference.address,
            self.first_record_offset(),
            self.trailer_offset,
        )?;
        use std::sync::atomic::Ordering::Relaxed;
        self.counters.requests.fetch_add(1, Relaxed);
        self.counters
            .requested_bytes
            .fetch_add(u64::from(reference.address.length), Relaxed);
        Ok(ReadRequest {
            offset: reference.address.offset,
            length: reference.address.length,
        })
    }
    pub fn decode(&self, reference: ObjectRef, bytes: &[u8]) -> Result<CanonicalObject> {
        let object = decode_frame(
            reference,
            bytes,
            self.first_record_offset(),
            self.trailer_offset,
        )?;
        self.counters.decoded_bytes.fetch_add(
            object.canonical_len() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        Ok(object)
    }
    pub fn get_at<S: ReadAt + ?Sized>(
        &self,
        source: &S,
        reference: ObjectRef,
    ) -> Result<CanonicalObject> {
        let request = self.request(reference)?;
        let mut bytes = vec![0; request.length as usize];
        source.read_exact_at(request.offset, &mut bytes)?;
        let object = wire::decode_frame_owned(
            reference,
            bytes,
            self.first_record_offset(),
            self.trailer_offset,
        )?;
        self.counters.decoded_bytes.fetch_add(
            object.canonical_len() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        Ok(object)
    }
    pub fn statistics(&self) -> ReadStatistics {
        use std::sync::atomic::Ordering::Relaxed;
        ReadStatistics {
            requests: self.counters.requests.load(Relaxed),
            requested_bytes: self.counters.requested_bytes.load(Relaxed),
            decoded_bytes: self.counters.decoded_bytes.load(Relaxed),
        }
    }
}
pub struct PositionalStore<S: ReadAt> {
    pub source: S,
    reader: Reader,
}
impl<S: ReadAt> PositionalStore<S> {
    pub fn open(source: S) -> Result<Self> {
        let reader = Reader::open_at(&source)?;
        Ok(Self { source, reader })
    }
    pub fn reader(&self) -> &Reader {
        &self.reader
    }
}
impl<S: ReadAt> ObjectStore for PositionalStore<S> {
    fn get_verified_shared(&self, r: ObjectRef) -> Result<Arc<CanonicalObject>> {
        self.get_shared(r)
    }
    fn get(&self, r: ObjectRef) -> Result<CanonicalObject> {
        self.reader.get_at(&self.source, r)
    }
    fn put(&mut self, _: u16, _: u16, _: &[u8], _: &[ObjectRef]) -> Result<ObjectRef> {
        Err(Error::Unsupported("read-only store".into()))
    }
}

#[derive(Clone)]
pub struct MemoryStore {
    bytes: Vec<u8>,
    header: Preamble,
    publication: Option<Publication>,
    recent: BTreeMap<ObjectHash, ObjectRef>,
    compression_level: i32,
    encoder: wire::FrameEncoder,
}
impl MemoryStore {
    pub fn new(header: Header) -> Self {
        Self::with_preamble(header.preamble().expect("valid live Header"))
    }
    pub fn sealed() -> Self {
        Self::with_preamble(Preamble::sealed())
    }
    pub fn with_preamble(header: Preamble) -> Self {
        let mut bytes = vec![0; header.first_record_offset() as usize];
        bytes[..128].copy_from_slice(&header.encode());
        Self {
            bytes,
            header,
            publication: None,
            recent: BTreeMap::new(),
            compression_level: 1,
            encoder: wire::FrameEncoder::default(),
        }
    }
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let reader = Reader::open_at(&bytes)?;
        if !reader.recovery_diagnostics.is_empty() {
            return Err(Error::RecoveryRequired);
        }
        let mut bytes = bytes;
        bytes.truncate(
            usize::try_from(reader.committed_end()).map_err(|_| Error::Limit("host offset"))?,
        );
        Ok(Self {
            bytes,
            header: reader.header,
            publication: reader.publication,
            recent: BTreeMap::new(),
            compression_level: 1,
            encoder: wire::FrameEncoder::default(),
        })
    }
    pub fn set_compression_level(&mut self, level: i32) {
        self.compression_level = level;
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn root(&self) -> Option<Publication> {
        self.publication
    }
    pub fn reader(&self) -> Result<Reader> {
        Reader::open_at(&self.bytes)
    }
    fn append(&mut self, object: &CanonicalObject) -> Result<ObjectRef> {
        self.append_hashed(object, object.hash())
    }
    fn append_hashed(&mut self, object: &CanonicalObject, hash: ObjectHash) -> Result<ObjectRef> {
        if self.header.policy == LocatorPolicy::Sealed && self.publication.is_some() {
            return Err(Error::Unsupported(
                "sealed publication already complete".into(),
            ));
        }
        for child in &object.children {
            validate_address(
                child.address,
                self.header.first_record_offset(),
                self.bytes.len() as u64,
            )?;
        }
        let frame = self
            .encoder
            .encode_hashed(object, self.compression_level, hash)?;
        let r = ObjectRef {
            hash,
            address: ChunkAddress {
                offset: self.bytes.len() as u64,
                length: frame.len() as u32,
            },
        };
        self.bytes.extend_from_slice(frame);
        Ok(r)
    }
    pub fn publish(&mut self, snapshot: ObjectRef) -> Result<Publication> {
        let selected = self.get_verified_shared(snapshot)?;
        if selected.kind != 2 {
            return Err(corrupt("publication needs snapshot"));
        }
        validate_core_edges(&selected, |child| self.get_verified_shared(child))?;
        let body = cbor::encode(&cbor::Value::Array(vec![
            cbor::Value::Uint(0),
            cbor::Value::Null,
            cbor::Value::Null,
        ]));
        let commit = self.put(1, 1, &body, &[snapshot])?;
        self.publish_commit(commit)
    }
    pub fn publish_commit(&mut self, reference: ObjectRef) -> Result<Publication> {
        let control = self.get_verified_shared(reference)?;
        validate_core_edges(&control, |child| self.get_verified_shared(child))?;
        if control.kind != 1 {
            return Err(corrupt("publication needs commit"));
        }
        let body = cbor::decode(&control.bytes)?;
        let fields = schema::array(&body, 3)?;
        let selected = control.children[schema::uint(&fields[0])? as usize];
        let snapshot = self.get_verified_shared(selected)?;
        validate_core_edges(&snapshot, |child| self.get_verified_shared(child))?;
        if self.header.policy == LocatorPolicy::Sealed {
            if fields[2] != cbor::Value::Null {
                return Err(corrupt("sealed commit local data"));
            }
            if self.publication.is_some() {
                return Err(Error::Unsupported(
                    "sealed publication already complete".into(),
                ));
            }
            let bytes = pack_commit_at_level(
                self,
                reference,
                Vec::new(),
                resources::Limits::default(),
                self.compression_level,
            )?;
            let admitted = Reader::open_at(&bytes)?;
            let publication = admitted.publication.ok_or(Error::Missing)?;
            self.bytes = bytes;
            self.publication = Some(publication);
            self.recent.clear();
            return Ok(publication);
        }
        let mut commit = self.get(reference)?;
        if commit.kind != 1 {
            return Err(corrupt("publication needs commit"));
        }
        let body = cbor::decode(&commit.bytes)?;
        let fields = schema::array(&body, 3)?;
        let index = schema::uint(&fields[0])? as usize;
        if self.header.policy == LocatorPolicy::Sealed && fields[2] != cbor::Value::Null {
            return Err(corrupt("sealed local data"));
        }
        let snapshot = self.get(commit.children[index])?;
        if snapshot.kind != 2 {
            return Err(corrupt("publication needs snapshot"));
        }
        if snapshot.canonical_len() > 16384 || commit.canonical_len() > 16384 {
            return Err(Error::Limit("control object"));
        }
        commit.children[index] = self.append(&snapshot)?;
        let root = self.append(&commit)?;
        let generation = self.publication.map_or(Ok(1), |p| {
            p.generation
                .checked_add(1)
                .ok_or(Error::Limit("generation"))
        })?;
        let trailer_offset = self.bytes.len() as u64;
        let trailer = Trailer {
            preamble_digest: self.header.digest(),
            generation,
            committed_end: trailer_offset + 160,
            commit: root,
        };
        self.bytes.extend(trailer.encode());
        if self.header.policy == LocatorPolicy::Live {
            let slot = Slot {
                preamble_digest: self.header.digest(),
                generation,
                trailer_offset,
                trailer_digest: trailer.digest(),
            };
            let at = (1 + generation as usize % 2) * PAGE_SIZE;
            self.bytes[at..at + PAGE_SIZE].copy_from_slice(&slot.encode());
        }
        let publication = Publication {
            generation,
            root,
            committed_end: trailer.committed_end,
        };
        self.publication = Some(publication);
        Ok(publication)
    }
    pub fn validate(&self) -> Result<ValidationReport> {
        validate_closure(self, self.publication.map(|p| p.root))
    }
}
impl ObjectStore for MemoryStore {
    fn get_verified_shared(&self, r: ObjectRef) -> Result<Arc<CanonicalObject>> {
        self.get_shared(r)
    }
    fn get(&self, r: ObjectRef) -> Result<CanonicalObject> {
        validate_address(
            r.address,
            self.header.first_record_offset(),
            self.bytes.len() as u64,
        )?;
        let at = usize::try_from(r.address.offset).map_err(|_| Error::Limit("host offset"))?;
        decode_frame(
            r,
            &self.bytes[at..at + r.address.length as usize],
            self.header.first_record_offset(),
            self.bytes.len() as u64,
        )
    }
    fn put(
        &mut self,
        kind: u16,
        version: u16,
        bytes: &[u8],
        children: &[ObjectRef],
    ) -> Result<ObjectRef> {
        let object = CanonicalObject {
            kind,
            version,
            bytes: bytes.to_vec(),
            children: children.to_vec(),
        };
        check_input(bytes, children)?;
        validate_core_object(&object)?;
        for child in children {
            self.get(*child)?;
        }
        let hash = object.hash();
        if let Some(r) = self.recent.get(&hash) {
            return Ok(*r);
        }
        let r = self.append_hashed(&object, hash)?;
        if self.recent.len() >= 4096 {
            self.recent.clear();
        }
        self.recent.insert(hash, r);
        Ok(r)
    }
}

#[derive(Clone, Debug)]
pub struct TraversalLimits {
    pub max_objects: u64,
    pub max_decoded_bytes: u64,
    pub max_edges: u64,
    /// Graph depth, independent of resource path depth. The finite object and
    /// index budgets usually bind first; traversal uses no Rust recursion.
    pub max_depth: usize,
    /// Memory reserved for traversal indexes; decoded object buffers are separate.
    pub max_index_bytes: usize,
}
impl Default for TraversalLimits {
    fn default() -> Self {
        Self {
            max_objects: 1_000_000,
            max_decoded_bytes: 64 << 30,
            max_edges: 8_000_000,
            max_depth: 1_000_000,
            max_index_bytes: 16 * 1024 * 1024,
        }
    }
}
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub objects: u64,
    pub decoded_bytes: u64,
}
pub fn validate_closure<S: ObjectStore + ?Sized>(
    store: &S,
    root: Option<ObjectRef>,
) -> Result<ValidationReport> {
    let mut stack: Vec<_> = root.into_iter().map(|r| (r, 0)).collect();
    let mut seen = BTreeSet::new();
    let mut report = ValidationReport::default();
    let limits = TraversalLimits::default();
    let mut edges = 0;
    while let Some((r, depth)) = stack.pop() {
        if depth > limits.max_depth || edges >= limits.max_edges {
            return Err(Error::Limit("closure traversal"));
        }
        edges += 1;
        let object = store.get_verified_shared(r)?;
        validate_core_edges(&object, |child| store.get_verified_shared(child))?;
        if !seen.insert(r) {
            continue;
        }
        report.objects += 1;
        report.decoded_bytes = report
            .decoded_bytes
            .checked_add(object.canonical_len() as u64)
            .ok_or(Error::Limit("decoded bytes"))?;
        if report.objects > limits.max_objects || report.decoded_bytes > limits.max_decoded_bytes {
            return Err(Error::Limit("closure objects or bytes"));
        }
        if seen
            .len()
            .saturating_add(stack.len())
            .saturating_add(object.children.len())
            .saturating_mul(128)
            > limits.max_index_bytes
        {
            return Err(Error::Limit("closure index memory"));
        }
        for child in &object.children {
            if child
                .address
                .offset
                .checked_add(u64::from(child.address.length))
                .is_none_or(|end| end > r.address.offset)
            {
                return Err(corrupt("closure child locator is not backward"));
            }
        }
        stack.extend(object.children.iter().copied().map(|r| (r, depth + 1)));
    }
    Ok(report)
}
pub fn copy_closure<S: ObjectStore + ?Sized, D: ObjectStore + ?Sized>(
    source: &S,
    destination: &mut D,
    root: ObjectRef,
) -> Result<ObjectRef> {
    copy_closure_with_cache(source, destination, root, &mut BTreeMap::new())
}
pub fn copy_closure_with_cache<S: ObjectStore + ?Sized, D: ObjectStore + ?Sized>(
    source: &S,
    destination: &mut D,
    root: ObjectRef,
    copied: &mut BTreeMap<ObjectHash, ObjectRef>,
) -> Result<ObjectRef> {
    let mut pending = vec![(root, false, 0usize)];
    let mut active = BTreeSet::new();
    let mut completed = BTreeSet::new();
    let limits = TraversalLimits::default();
    let mut visits = 0u64;
    let mut decoded_bytes = 0u64;
    while let Some((reference, expanded, depth)) = pending.pop() {
        visits = visits.checked_add(1).ok_or(Error::Limit("copy visits"))?;
        if visits > limits.max_edges || depth > limits.max_depth {
            return Err(Error::Limit("copy traversal"));
        }
        if expanded {
            active.remove(&reference.hash);
            completed.insert(reference);
            if copied.contains_key(&reference.hash) {
                continue;
            }
        } else if completed.contains(&reference) {
            continue;
        } else if !active.insert(reference.hash) {
            return Err(corrupt("copy graph cycle"));
        }
        let object = source.get_verified_shared(reference)?;
        decoded_bytes = decoded_bytes
            .checked_add(object.canonical_len() as u64)
            .ok_or(Error::Limit("copy decoded bytes"))?;
        if decoded_bytes > limits.max_decoded_bytes || copied.len() as u64 >= limits.max_objects {
            return Err(Error::Limit("copy objects or bytes"));
        }
        if copied
            .len()
            .saturating_add(completed.len())
            .saturating_add(active.len())
            .saturating_add(pending.len())
            .saturating_add(object.children.len() + 1)
            .saturating_mul(128)
            > limits.max_index_bytes
        {
            return Err(Error::Limit("copy index memory"));
        }
        if expanded {
            let children = object
                .children
                .iter()
                .map(|r| copied.get(&r.hash).copied().ok_or(Error::Missing))
                .collect::<Result<Vec<_>>>()?;
            let result = destination.put(object.kind, object.version, &object.bytes, &children)?;
            if result.hash != reference.hash {
                return Err(corrupt("copy identity"));
            }
            copied.insert(reference.hash, result);
        } else {
            validate_core_edges(&object, |child| source.get_verified_shared(child))?;
            for child in &object.children {
                if child
                    .address
                    .offset
                    .checked_add(u64::from(child.address.length))
                    .is_none_or(|end| end > reference.address.offset)
                {
                    return Err(corrupt("copy child locator is not backward"));
                }
            }
            pending.push((reference, true, depth));
            pending.extend(object.children.iter().rev().map(|r| (*r, false, depth + 1)));
        }
    }
    copied.get(&root.hash).copied().ok_or(Error::Missing)
}
#[derive(Default, Clone, Debug)]
pub struct CompactionLayout {
    pub front: Vec<ObjectHash>,
    pub bundles: Vec<Vec<ObjectHash>>,
}
#[derive(Default, Clone, Debug)]
pub struct CompactionRanges {
    pub front: Vec<ReadRequest>,
    pub bundles: Vec<ReadRequest>,
}

/// Forward-only destination for an already traversed, children-first closure.
pub struct SealedWriter<W: Write> {
    output: W,
    end: u64,
    last: Option<(ObjectRef, u16, usize)>,
    compression_level: i32,
    encoder: wire::FrameEncoder,
}
impl<W: Write> SealedWriter<W> {
    pub fn new(mut output: W) -> Result<Self> {
        output.write_all(&Preamble::sealed().encode())?;
        Ok(Self {
            output,
            end: 128,
            last: None,
            compression_level: 1,
            encoder: wire::FrameEncoder::default(),
        })
    }
    pub fn set_compression_level(&mut self, level: i32) {
        self.compression_level = level;
    }
    pub fn finish(self, snapshot: ObjectRef) -> Result<W> {
        self.finish_attested(snapshot, None)
    }
    pub fn finish_attested(
        mut self,
        snapshot: ObjectRef,
        attestations: Option<ObjectRef>,
    ) -> Result<W> {
        match self.last {
            Some((reference, 2, length)) if reference == snapshot && length <= 16384 => {}
            _ => return Err(corrupt("sealed snapshot must be last control object")),
        }
        let mut children = vec![snapshot];
        let att = if let Some(reference) = attestations {
            children.push(reference);
            cbor::Value::Uint(1)
        } else {
            cbor::Value::Null
        };
        let body = cbor::encode(&cbor::Value::Array(vec![
            cbor::Value::Uint(0),
            att,
            cbor::Value::Null,
        ]));
        let commit = self.put(1, 1, &body, &children)?;
        let end = self.end.checked_add(160).ok_or(Error::Limit("file size"))?;
        self.output.write_all(
            &Trailer {
                preamble_digest: Preamble::sealed().digest(),
                generation: 1,
                committed_end: end,
                commit,
            }
            .encode(),
        )?;
        self.output.flush()?;
        Ok(self.output)
    }
}
impl<W: Write> ObjectStore for SealedWriter<W> {
    fn get(&self, _: ObjectRef) -> Result<CanonicalObject> {
        Err(Error::Unsupported("forward writer has no readback".into()))
    }
    fn put(
        &mut self,
        kind: u16,
        version: u16,
        bytes: &[u8],
        children: &[ObjectRef],
    ) -> Result<ObjectRef> {
        for child in children {
            validate_address(child.address, 128, self.end)?;
        }
        let object = CanonicalObject {
            kind,
            version,
            bytes: bytes.to_vec(),
            children: children.to_vec(),
        };
        let hash = object.hash();
        let frame = self
            .encoder
            .encode_hashed(&object, self.compression_level, hash)?;
        let reference = ObjectRef {
            hash,
            address: ChunkAddress {
                offset: self.end,
                length: frame.len() as u32,
            },
        };
        self.end = self
            .end
            .checked_add(frame.len() as u64)
            .ok_or(Error::Limit("file size"))?;
        self.output.write_all(frame)?;
        self.last = Some((reference, kind, object.canonical_len()));
        Ok(reference)
    }
}
/// Copy the complete snapshot closure into a sealed forward-only representation.
pub fn pack_snapshot<S: ObjectStore + ?Sized, W: Write>(
    source: &S,
    snapshot: ObjectRef,
    output: W,
) -> Result<W> {
    pack_snapshot_with_limits(source, snapshot, output, resources::Limits::default())
}
pub fn pack_snapshot_with_limits<S: ObjectStore + ?Sized, W: Write>(
    source: &S,
    snapshot: ObjectRef,
    output: W,
    limits: resources::Limits,
) -> Result<W> {
    let object = source.get(snapshot)?;
    if object.kind != 2 || object.version != 1 {
        return Err(corrupt("pack needs snapshot"));
    }
    let mut writer = SealedWriter::new(output)?;
    let copied = resources::copy_snapshot(source, &mut writer, snapshot, limits)?;
    writer.finish(copied)
}
/// Preserve portable attestations while removing the live-local commit attachment.
pub fn pack_commit<S: ObjectStore + ?Sized, W: Write>(
    source: &S,
    commit: ObjectRef,
    output: W,
) -> Result<W> {
    pack_commit_with_limits(source, commit, output, resources::Limits::default())
}
pub fn pack_commit_with_limits<S: ObjectStore + ?Sized, W: Write>(
    source: &S,
    commit: ObjectRef,
    output: W,
    limits: resources::Limits,
) -> Result<W> {
    pack_commit_at_level(source, commit, output, limits, 1)
}
fn pack_commit_at_level<S: ObjectStore + ?Sized, W: Write>(
    source: &S,
    commit: ObjectRef,
    output: W,
    limits: resources::Limits,
    level: i32,
) -> Result<W> {
    let object = source.get(commit)?;
    validate_core_object(&object)?;
    if object.kind != 1 || object.version != 1 {
        return Err(corrupt("pack needs commit"));
    }
    let body = cbor::decode(&object.bytes)?;
    let fields = schema::array(&body, 3)?;
    let snapshot = object.children[schema::uint(&fields[0])? as usize];
    let mut writer = SealedWriter::new(output)?;
    writer.set_compression_level(level);
    let att = if fields[1] == cbor::Value::Null {
        None
    } else {
        let reference = object.children[schema::uint(&fields[1])? as usize];
        let att = source.get(reference)?;
        if att.kind != 9 || att.version != 1 {
            return Err(corrupt("attestation kind"));
        }
        Some(writer.put(att.kind, att.version, &att.bytes, &att.children)?)
    };
    let copied = resources::copy_snapshot(source, &mut writer, snapshot, limits)?;
    writer.finish_attested(copied, att)
}

#[cfg(test)]
mod tests;
