//! Decoded copies of the payload objects a writer appended most recently.
use super::*;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Larger payloads are not copied: reading one back costs little per byte,
/// and one copy would displace many small objects.
pub(super) const MAX_COPIED_PAYLOAD: usize = 64 * 1024;
/// A copy of an object whose canonical encoding is at least this long also
/// keeps its frame's Zstandard bytes. A closure copy into a store that keeps
/// frames stores those again instead of compressing or expanding the object;
/// for a smaller object they would add much of its charge for little work.
pub(super) const MIN_COMPRESSED_COPY: usize = 4096;

struct AppendCopy {
    object: Arc<CanonicalObject>,
    compressed: Option<Arc<Vec<u8>>>,
    charge: usize,
}

/// The payload objects this writer appended most recently, as it encoded
/// them, for a writer that reads its new objects back (a public projection
/// visits every object of the flush that wrote it, and a closure copy of a
/// flush's new objects reads each one). Such a read takes neither
/// the shared decoded cache and its lock, nor the file lock, a positional
/// read, decompression or a hash check. The writer framed each object under
/// the hash that authenticated its canonical content: the same authority by
/// which it admits its own appended structural pages to the shared cache and
/// its appended frames as child edges. Only this writer reads the table.
///
/// Entries name exact occurrences in one file; a new file and a reused frame
/// clear the table. The budget evicts the oldest entries and never refuses an
/// append; zero keeps none.
#[derive(Default)]
pub(super) struct FreshAppends {
    identity: u64,
    objects: HashMap<ObjectRef, AppendCopy>,
    order: VecDeque<ObjectRef>,
    bytes: usize,
    budget: usize,
    kept: u64,
    evicted: u64,
    skipped: u64,
    hits: AtomicU64,
    cache_hits: AtomicU64,
    file_reads: AtomicU64,
}
impl FreshAppends {
    pub(super) fn budget(&self) -> usize {
        self.budget
    }
    pub(super) fn set_budget(&mut self, budget: usize) {
        self.budget = budget;
        self.evict();
    }
    /// Whether a copy of an object with this canonical and payload length
    /// keeps its frame's compressed bytes (`MIN_COMPRESSED_COPY`).
    pub(super) fn keeps_compressed(&self, canonical_len: usize, payload_len: usize) -> bool {
        self.budget != 0
            && payload_len <= MAX_COPIED_PAYLOAD
            && canonical_len >= MIN_COMPRESSED_COPY
    }
    /// Remember `object`, just appended at `reference` in file `identity`,
    /// with the Zstandard bytes of its frame when `keeps_compressed`.
    pub(super) fn admit(
        &mut self,
        identity: u64,
        reference: ObjectRef,
        object: CanonicalObject,
        compressed: Option<Vec<u8>>,
    ) {
        if identity != self.identity {
            self.clear();
            self.identity = identity;
        }
        let charge = object.bytes.len()
            + object.children.len() * std::mem::size_of::<ObjectRef>()
            + compressed.as_ref().map_or(0, Vec::len)
            + DECODED_ENTRY_METADATA;
        if object.bytes.len() > MAX_COPIED_PAYLOAD || charge > self.budget {
            self.skipped += 1;
            return;
        }
        let copy = AppendCopy {
            object: Arc::new(object),
            compressed: compressed.map(Arc::new),
            charge,
        };
        match self.objects.insert(reference, copy) {
            Some(previous) => self.bytes -= previous.charge,
            None => self.order.push_back(reference),
        }
        self.kept += 1;
        self.bytes += charge;
        self.evict();
    }
    fn evict(&mut self) {
        while self.bytes > self.budget {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some(copy) = self.objects.remove(&oldest) {
                self.bytes -= copy.charge;
                self.evicted += 1;
            }
        }
    }
    /// The object at `reference` when this writer appended it to file
    /// `identity` and still has its copy.
    pub(super) fn get(&self, identity: u64, reference: ObjectRef) -> Option<&Arc<CanonicalObject>> {
        self.copy(identity, reference).map(|copy| &copy.object)
    }
    /// `get`, with the frame's compressed bytes when the copy kept them.
    pub(super) fn get_encoded(&self, identity: u64, reference: ObjectRef) -> Option<ObjectRead> {
        self.copy(identity, reference)
            .map(|copy| (Arc::clone(&copy.object), copy.compressed.clone()))
    }
    fn copy(&self, identity: u64, reference: ObjectRef) -> Option<&AppendCopy> {
        if identity != self.identity {
            return None;
        }
        self.objects.get(&reference)
    }
    /// A read a copy served.
    pub(super) fn note_copy_hit(&self) {
        self.hits.fetch_add(1, Relaxed);
    }
    /// A read the shared decoded cache served instead.
    pub(super) fn note_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Relaxed);
    }
    /// A read that read and authenticated the file.
    pub(super) fn note_file_read(&self) {
        self.file_reads.fetch_add(1, Relaxed);
    }
    pub(super) fn statistics(&self) -> WriterReadStatistics {
        WriterReadStatistics {
            copy_hits: self.hits.load(Relaxed),
            cache_hits: self.cache_hits.load(Relaxed),
            file_reads: self.file_reads.load(Relaxed),
            copies_kept: self.kept,
            copies_evicted: self.evicted,
            copies_skipped: self.skipped,
            copy_bytes: self.bytes as u64,
        }
    }
    pub(super) fn clear(&mut self) {
        self.objects = HashMap::new();
        self.order = VecDeque::new();
        self.bytes = 0;
    }
}
