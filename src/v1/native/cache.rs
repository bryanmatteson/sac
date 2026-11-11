#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheUsage {
    pub budget: usize,
    /// Resident decoded payloads, physical read windows, indexes and idle codec workspace.
    pub decoded_bytes: usize,
    pub pinned_metadata_bytes: usize,
}
fn next_file_identity() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}
fn new_cache() -> Arc<Mutex<DecodedCache>> {
    Arc::new(Mutex::new(DecodedCache {
        budget: 32 * 1024 * 1024,
        ..Default::default()
    }))
}
#[derive(Default)]
struct FileGeneration {
    // Live append extent belongs to this physical file, never its replacement.
    // Updated after the same successful effects that advance end/publication.
    unpublished: std::sync::atomic::AtomicU64,
    next: Mutex<Option<Arc<ForwardRemap>>>,
}
struct ForwardRemap {
    copied: Mutex<ClosureCopy>,
    target_identity: u64,
    target: Arc<FileGeneration>,
    _charge: MetadataReservation,
}
impl Drop for FileGeneration {
    fn drop(&mut self) {
        // A long-lived old pin may span arbitrarily many compactions. Retire
        // uniquely owned forwarding links iteratively, without recursive drop.
        let mut next = self.next.get_mut().unwrap().take();
        while let Some(link) = next {
            let Ok(link) = Arc::try_unwrap(link) else {
                break;
            };
            let ForwardRemap {
                copied,
                target,
                _charge,
                ..
            } = link;
            drop(copied);
            drop(_charge);
            let Ok(mut generation) = Arc::try_unwrap(target) else {
                break;
            };
            next = generation.next.get_mut().unwrap().take();
        }
    }
}
struct MetadataReservation {
    cache: Arc<Mutex<DecodedCache>>,
    bytes: usize,
}
impl MetadataReservation {
    fn new(cache: Arc<Mutex<DecodedCache>>, bytes: usize) -> Result<Self> {
        {
            let mut governing = cache.lock().unwrap();
            if governing.budget > 0
                && governing.pinned_metadata.saturating_add(bytes) > governing.budget
            {
                return Err(Error::Limit("compaction remap metadata budget"));
            }
            governing.pinned_metadata += bytes;
            let budget = governing.budget;
            governing.set_budget(budget);
        }
        Ok(Self { cache, bytes })
    }
}
impl Drop for MetadataReservation {
    fn drop(&mut self) {
        let mut cache = self.cache.lock().unwrap();
        cache.pinned_metadata -= self.bytes;
    }
}
/// A pinned immutable reader. Its independent file description survives path replacement.
pub struct NativeReader {
    #[cfg(unix)]
    lease: Option<leases::Lease>,
    file: File,
    reader: Reader,
    cache: Arc<Mutex<DecodedCache>>,
    file_identity: u64,
    generation: Arc<FileGeneration>,
    metadata_charge: usize,
    io: Arc<PhysicalCounters>,
}
/// Keyed hash for the native lookup tables. Their keys are object identities
/// and physical references, which are already uniform unless an archive is
/// built to collide; the random seed keeps such an archive from choosing slots.
#[derive(Clone)]
struct TableHash(u64);
impl Default for TableHash {
    fn default() -> Self {
        use std::hash::BuildHasher;
        Self(std::hash::RandomState::new().hash_one(0u64))
    }
}
impl std::hash::BuildHasher for TableHash {
    type Hasher = TableHasher;
    fn build_hasher(&self) -> TableHasher {
        TableHasher(self.0)
    }
}
struct TableHasher(u64);
impl TableHasher {
    #[inline]
    fn mix(&mut self, word: u64) {
        let product = u128::from(self.0 ^ word) * 0x2d35_8dcc_aa6c_78a5;
        self.0 = (product as u64) ^ ((product >> 64) as u64);
    }
}
impl std::hash::Hasher for TableHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut words = bytes.chunks_exact(8);
        for word in &mut words {
            self.mix(u64::from_le_bytes(word.try_into().unwrap()));
        }
        let rest = words.remainder();
        if !rest.is_empty() {
            let mut word = [0; 8];
            word[..rest.len()].copy_from_slice(rest);
            self.mix(u64::from_le_bytes(word) ^ ((rest.len() as u64) << 56));
        }
    }
    #[inline]
    fn write_u8(&mut self, value: u8) {
        self.mix(u64::from(value));
    }
    #[inline]
    fn write_u16(&mut self, value: u16) {
        self.mix(u64::from(value));
    }
    #[inline]
    fn write_u32(&mut self, value: u32) {
        self.mix(u64::from(value));
    }
    #[inline]
    fn write_u64(&mut self, value: u64) {
        self.mix(value);
    }
    #[inline]
    fn write_usize(&mut self, value: usize) {
        self.mix(value as u64);
    }
}

/// Exact least-recently-used order with constant-time hit, insert and evict.
/// A hit moves its entry to the newest end, so the list order is the age order
/// and no ordering index needs repair at eviction.
struct Lru<V> {
    slots: std::collections::HashMap<DecodedKey, u32, TableHash>,
    nodes: Vec<LruNode<V>>,
    free: Vec<u32>,
    oldest: u32,
    newest: u32,
}
struct LruNode<V> {
    key: DecodedKey,
    value: Option<V>,
    age: u64,
    older: u32,
    newer: u32,
}
const NO_NODE: u32 = u32::MAX;
impl<V> Default for Lru<V> {
    fn default() -> Self {
        Self {
            slots: Default::default(),
            nodes: Vec::new(),
            free: Vec::new(),
            oldest: NO_NODE,
            newest: NO_NODE,
        }
    }
}
impl<V> Lru<V> {
    fn len(&self) -> usize {
        self.slots.len()
    }
    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
    fn clear(&mut self) {
        *self = Self::default();
    }
    fn unlink(&mut self, slot: u32) {
        let (older, newer) = {
            let node = &self.nodes[slot as usize];
            (node.older, node.newer)
        };
        match older {
            NO_NODE => self.oldest = newer,
            older => self.nodes[older as usize].newer = newer,
        }
        match newer {
            NO_NODE => self.newest = older,
            newer => self.nodes[newer as usize].older = older,
        }
    }
    fn link_newest(&mut self, slot: u32) {
        let previous = self.newest;
        {
            let node = &mut self.nodes[slot as usize];
            node.older = previous;
            node.newer = NO_NODE;
        }
        match previous {
            NO_NODE => self.oldest = slot,
            previous => self.nodes[previous as usize].newer = slot,
        }
        self.newest = slot;
    }
    /// A hit: record the age and make the entry the newest.
    fn touch(&mut self, key: &DecodedKey, age: u64) -> Option<&V> {
        let slot = *self.slots.get(key)?;
        if self.newest != slot {
            self.unlink(slot);
            self.link_newest(slot);
        }
        let node = &mut self.nodes[slot as usize];
        node.age = age;
        node.value.as_ref()
    }
    /// The caller removes an existing entry for the key first.
    fn insert(&mut self, key: DecodedKey, value: V, age: u64) {
        let node = LruNode {
            key,
            value: Some(value),
            age,
            older: NO_NODE,
            newer: NO_NODE,
        };
        let slot = match self.free.pop() {
            Some(slot) => {
                self.nodes[slot as usize] = node;
                slot
            }
            None => {
                self.nodes.push(node);
                (self.nodes.len() - 1) as u32
            }
        };
        self.slots.insert(key, slot);
        self.link_newest(slot);
    }
    fn remove(&mut self, key: &DecodedKey) -> Option<V> {
        let slot = self.slots.remove(key)?;
        self.unlink(slot);
        self.free.push(slot);
        self.nodes[slot as usize].value.take()
    }
    fn oldest_age(&self) -> Option<u64> {
        (self.oldest != NO_NODE).then(|| self.nodes[self.oldest as usize].age)
    }
    fn remove_oldest(&mut self) -> Option<V> {
        if self.oldest == NO_NODE {
            return None;
        }
        let key = self.nodes[self.oldest as usize].key;
        self.remove(&key)
    }
    /// Entries from the oldest to the newest.
    fn oldest_first(&self) -> impl Iterator<Item = (&DecodedKey, &V)> {
        let mut slot = self.oldest;
        std::iter::from_fn(move || {
            let node = self.nodes.get(slot as usize)?;
            slot = node.newer;
            Some((&node.key, node.value.as_ref()?))
        })
    }
}

#[derive(Default)]
struct DecodedCache {
    budget: usize,
    bytes: usize,
    pinned_metadata: usize,
    clock: u64,
    // A decoded object and its charged size.
    objects: Lru<(Arc<CanonicalObject>, usize)>,
    // The authenticated kind and version of one physical occurrence.
    verified: Lru<(u16, u16)>,
    windows: BTreeMap<(u64, u64), (Vec<u8>, u64, u64)>,
    window_oldest: BTreeSet<(u64, (u64, u64))>,
    window_bytes: usize,
    decoder:Option<wire::FrameDecoder>,
}
type DecodedKey = (u64, ObjectHash, u64, u32);
// Charge both the physical-key lookup and exact LRU order, including their
// node allowance, to the existing decoded budget. Object and authentication
// hits relink one node. Read windows keep an ordered index for their interval
// lookup; their stale ages are repaired only at eviction. No access history
// queue can grow beyond the live cache.
// Successful frame authentication may outlive its decoded payload. Preserve a
// small metadata working set under payload churn, within the same byte budget.
const DECODED_ENTRY_METADATA: usize = 384;
// The reader coalesces at most two adjacent 16 KiB windows. Smaller windows may
// overlap a wider one, so an interval lookup must look past those inner starts.
const MAX_READ_WINDOW_BYTES: usize = 32 * 1024;
impl DecodedCache {
    fn clear(&mut self) {
        self.decoder=None;
        self.objects.clear();
        self.verified.clear();
        self.windows.clear();
        self.window_oldest.clear();
        self.window_bytes = 0;
        self.bytes = 0;
        self.clock = 0;
    }
    fn usage(&self) -> CacheUsage {
        CacheUsage {
            budget: self.budget,
            decoded_bytes: self.bytes,
            pinned_metadata_bytes: self.pinned_metadata,
        }
    }
    fn set_budget(&mut self, bytes: usize) {
        self.budget = bytes;
        let window_limit = (self.budget.saturating_sub(self.pinned_metadata) / 8).min(1024 * 1024);
        while self.window_bytes > window_limit {
            if !self.evict_window() {
                break;
            }
        }
        while self.bytes > self.budget.saturating_sub(self.pinned_metadata) {
            if !self.evict_oldest() {
                break;
            }
        }
    }
    fn tick(&mut self) -> u64 {
        if self.clock == u64::MAX {
            // Cache residency is optional. Reset on clock exhaustion instead
            // of wrapping ages or allocating a second full ordering index.
            self.clear();
        }
        self.clock += 1;
        self.clock
    }
    fn remove(&mut self, key: &DecodedKey) {
        if let Some((_, size)) = self.objects.remove(key) {
            self.bytes -= size;
        }
    }
    fn refresh_order(&mut self) {
        while let Some((indexed,key))=self.window_oldest.first().copied(){
            let entry=self.windows.get_mut(&key).expect("window cache age index");
            if indexed==entry.1{break;}self.window_oldest.pop_first();entry.2=entry.1;self.window_oldest.insert((entry.1,key));
        }
    }
    fn evict_oldest(&mut self) -> bool {
        self.refresh_order();
        let decoded = self.objects.oldest_age();
        let metadata_allowance = (self.budget.saturating_sub(self.pinned_metadata) / 8)
            .min(4 * 1024 * 1024);
        let protect_verified = self.verified.len().saturating_mul(DECODED_ENTRY_METADATA)
            <= metadata_allowance
            && (decoded.is_some() || !self.windows.is_empty());
        let verified = if protect_verified {
            None
        } else {
            self.verified.oldest_age()
        };
        if let Some((age, _)) = self.window_oldest.first()
            && decoded.is_none_or(|other| *age < other)
            && verified.is_none_or(|other| *age < other)
        {
            return self.evict_window();
        }
        // Every hit and insert takes its own clock value, so two ages differ.
        if verified.is_some() && (decoded.is_none() || verified < decoded) {
            self.verified
                .remove_oldest()
                .expect("verified cache age order");
            self.bytes -= DECODED_ENTRY_METADATA;
            return true;
        }
        let Some((_, size)) = self.objects.remove_oldest() else {
            // The idle decoder is the last victim. A new codec context for
            // each read costs more than the entries that its bytes displace.
            return match self.decoder.take() {
                Some(decoder) => {
                    self.bytes -= decoder.retained_bytes();
                    true
                }
                None => false,
            };
        };
        self.bytes -= size;
        true
    }
    fn evict_window(&mut self) -> bool {
        self.refresh_order();
        let Some((_, key)) = self.window_oldest.pop_first() else {
            return false;
        };
        let (bytes, _, _) = self.windows.remove(&key).expect("window cache age index");
        let charge = bytes.capacity() + DECODED_ENTRY_METADATA;
        self.window_bytes -= charge;
        self.bytes -= charge;
        true
    }
    fn can_read_window(&self, length: usize) -> bool {
        length.saturating_add(DECODED_ENTRY_METADATA)
            <= (self.budget.saturating_sub(self.pinned_metadata) / 8).min(1024 * 1024)
    }
    /// Raw bytes grant no object authority. Callers validate the reference's
    /// complete committed range first and authenticate the extracted frame.
    fn read_window(&mut self, identity: u64, offset: u64, output: &mut [u8]) -> bool {
        let age = self.tick();
        let key = self
            .windows
            .range((identity, offset.saturating_sub(MAX_READ_WINDOW_BYTES as u64))..=(identity, offset))
            .rev()
            .find_map(|(key, (bytes, _, _))| {
                let start = usize::try_from(offset - key.1).ok()?;
                start
                    .checked_add(output.len())
                    .filter(|end| *end <= bytes.len())?;
                Some((*key, start))
            });
        let Some((key, start)) = key else {
            return false;
        };
        let (bytes, previous, _) = self.windows.get_mut(&key).unwrap();
        output.copy_from_slice(&bytes[start..start + output.len()]);
        *previous = age;
        true
    }
    fn insert_window(&mut self, identity: u64, offset: u64, bytes: Vec<u8>) {
        if bytes.len() > MAX_READ_WINDOW_BYTES {
            return;
        }
        let charge = bytes.capacity() + DECODED_ENTRY_METADATA;
        let available = self.budget.saturating_sub(self.pinned_metadata);
        let limit = (available / 8).min(1024 * 1024);
        if charge > limit {
            return;
        }
        let age = self.tick();
        let key = (identity, offset);
        if let Some((old, _, previous)) = self.windows.remove(&key) {
            self.window_oldest.remove(&(previous, key));
            let charge = old.capacity() + DECODED_ENTRY_METADATA;
            self.window_bytes -= charge;
            self.bytes -= charge;
        }
        while self.window_bytes + charge > limit {
            if !self.evict_window() {
                break;
            }
        }
        while self.bytes + charge > available {
            if !self.evict_oldest() {
                break;
            }
        }
        self.windows.insert(key, (bytes, age, age));
        self.window_oldest.insert((age, key));
        self.window_bytes += charge;
        self.bytes += charge;
    }
    fn verified(&mut self, file_identity: u64, reference: ObjectRef) -> bool {
        self.verified_type(file_identity, reference).is_some()
    }
    fn verified_type(&mut self, file_identity: u64, reference: ObjectRef) -> Option<(u16, u16)> {
        let age = self.tick();
        let key = (
            file_identity,
            reference.hash,
            reference.address.offset,
            reference.address.length,
        );
        self.verified.touch(&key, age).copied()
    }
    fn verify(&mut self, file_identity: u64, reference: ObjectRef, object_type: (u16, u16)) {
        let available = self.budget.saturating_sub(self.pinned_metadata);
        if DECODED_ENTRY_METADATA > available {
            return;
        }
        let age = self.tick();
        let key = (
            file_identity,
            reference.hash,
            reference.address.offset,
            reference.address.length,
        );
        if self.verified.remove(&key).is_some() {
            self.bytes -= DECODED_ENTRY_METADATA;
        }
        while self.bytes + DECODED_ENTRY_METADATA > available {
            if !self.evict_oldest() {
                break;
            }
        }
        self.verified.insert(key, object_type, age);
        self.bytes += DECODED_ENTRY_METADATA;
    }
    fn take_decoder(&mut self)->wire::FrameDecoder{
        match self.decoder.take(){Some(decoder)=>{self.bytes-=decoder.retained_bytes();decoder},None=>wire::FrameDecoder::default()}
    }
    fn return_decoder(&mut self,decoder:wire::FrameDecoder){
        let charge = decoder.retained_bytes();
        let available = self.budget.saturating_sub(self.pinned_metadata);
        // Keep the idle decoder within one quarter of the cache, and make
        // room for it instead of releasing its codec context.
        if self.decoder.is_some() || charge == 0 || charge > available / 4 {
            return;
        }
        while self.bytes.saturating_add(charge) > available {
            if !self.evict_oldest() {
                break;
            }
        }
        if self.bytes.saturating_add(charge) <= available {
            self.bytes += charge;
            self.decoder = Some(decoder);
        }
    }
    fn get(&mut self, file_identity: u64, r: ObjectRef) -> Option<Arc<CanonicalObject>> {
        let age = self.tick();
        let key = (file_identity, r.hash, r.address.offset, r.address.length);
        self.objects
            .touch(&key, age)
            .map(|(object, _)| Arc::clone(object))
    }
    /// Transfer an LRU victim into the one in-flight positional read. Its
    /// allocation leaves the cache charge; it is never retained as a spare.
    /// Existing caller pins remain immutable and make a victim ineligible.
    fn take_read_buffer(&mut self, length: usize) -> Option<Vec<u8>> {
        let available = self.budget.saturating_sub(self.pinned_metadata);
        if length < 256 * 1024
            || self
                .bytes
                .saturating_add(length)
                .saturating_add(DECODED_ENTRY_METADATA)
                <= available
        {
            return None;
        }
        let key = self
            .objects
            .oldest_first()
            .take(8)
            .find(|(_, (object, _))| {
                object.kind == 7
                    && object.children.is_empty()
                    && object.bytes.capacity() >= length
                    && Arc::strong_count(object) == 1
            })
            .map(|(key, _)| *key)?;
        let (object, size) = self.objects.remove(&key)?;
        self.bytes -= size;
        // The cache held the only reference, and it is locked for this call.
        Arc::try_unwrap(object).ok().map(|object| object.bytes)
    }
    fn insert_shared(&mut self, file_identity: u64, r: ObjectRef, object: &Arc<CanonicalObject>) {
        let size = DECODED_ENTRY_METADATA
            + object.bytes.capacity()
            + object.children.capacity() * std::mem::size_of::<ObjectRef>();
        if size > self.budget.saturating_sub(self.pinned_metadata) {
            return;
        }
        let age = self.tick();
        let key = (file_identity, r.hash, r.address.offset, r.address.length);
        self.remove(&key);
        while self.bytes + size > self.budget.saturating_sub(self.pinned_metadata) {
            if !self.evict_oldest() {
                break;
            }
        }
        self.objects.insert(key, (Arc::clone(object), size), age);
        self.bytes += size;
    }
}

#[cfg(test)]
mod buffer_tests {
    use super::*;

    #[test]
    fn payload_churn_preserves_bounded_exact_occurrence_authentication() {
        let mut cache = DecodedCache { budget: 2 * 1024 * 1024, ..Default::default() };
        let reference = |ordinal: u64| ObjectRef {
            hash: ObjectHash::digest(&ordinal.to_le_bytes()),
            address: ChunkAddress { offset: 128 + ordinal * 128, length: 128 },
        };
        for ordinal in 0..16u64 { cache.verify(7, reference(ordinal), (7, 1)); }
        let object = Arc::new(CanonicalObject {
            kind: 7, version: 1, bytes: vec![3; 1024 * 1024], children: vec![],
        });
        for ordinal in 16..80u64 {
            cache.insert_shared(7, reference(ordinal), &object);
            cache.verify(7, reference(ordinal), (7, 1));
            assert!(cache.bytes <= cache.budget);
        }
        for ordinal in 0..16u64 {
            assert!(cache.verified(7, reference(ordinal)));
            assert!(!cache.verified(8, reference(ordinal)));
            let mut other = reference(ordinal);
            other.address.offset += 1;
            assert!(!cache.verified(7, other));
        }
        cache.set_budget(0);
        assert_eq!(cache.bytes, 0);
        assert!(cache.verified.is_empty());
    }

    #[test]
    fn lazy_recency_preserves_exact_victims_without_hit_history_growth() {
        let object = Arc::new(CanonicalObject { kind: 7, version: 1, bytes: vec![1; 32], children: vec![] });
        let reference = |offset| ObjectRef { hash: object.hash(), address: ChunkAddress { offset, length: 96 } };
        let mut cache = DecodedCache { budget: 4 * (DECODED_ENTRY_METADATA + 32), ..Default::default() };
        cache.insert_shared(1, reference(128), &object);
        cache.insert_shared(1, reference(224), &object);
        cache.verify(1, reference(320), (7, 1));
        for _ in 0..10_000 {
            assert!(cache.get(1, reference(128)).is_some());
            assert!(cache.verified(1, reference(320)));
        }
        assert_eq!(cache.objects.len(), 2);
        assert_eq!(cache.objects.nodes.len(), 2);
        assert_eq!(cache.verified.len(), 1);
        assert_eq!(cache.verified.nodes.len(), 1);
        assert!(cache.evict_oldest());
        assert!(cache.get(1, reference(224)).is_none());
        assert!(cache.get(1, reference(128)).is_some());
        assert!(cache.verified(1, reference(320)));
        cache.set_budget(0);
        assert_eq!(cache.bytes, 0);
        assert!(cache.objects.is_empty() && cache.verified.is_empty());
    }

    #[test]
    fn overlapping_small_windows_do_not_hide_a_containing_window() {
        let mut cache = DecodedCache { budget: 256 * 1024, ..Default::default() };
        cache.insert_window(1, 0, vec![7; 16 * 1024]);
        for offset in [1024, 2048, 3072, 4096] {
            cache.insert_window(1, offset, vec![7; 1024]);
        }
        let mut output = vec![0; 8192];
        assert!(cache.read_window(1, 4100, &mut output));
        assert_eq!(output, vec![7; 8192]);
        assert!(!cache.read_window(2, 4100, &mut output));
        assert!(!cache.read_window(1, 12 * 1024, &mut output));
        assert!(!cache.verified(1, ObjectRef {
            hash: ObjectHash::digest(b"unverified window"),
            address: ChunkAddress { offset: 4096, length: 128 },
        }));
        cache.insert_window(1, 32 * 1024, vec![0; MAX_READ_WINDOW_BYTES + 1]);
        assert!(!cache.windows.contains_key(&(1, 32 * 1024)));
    }
    #[test]
    fn physical_windows_share_the_budget_and_never_confer_identity_or_extent() {
        let mut cache = DecodedCache {
            budget: 64 * 1024,
            ..Default::default()
        };
        cache.insert_window(1, 2048, vec![7; 2048]);
        let mut output = [0; 16];
        assert!(cache.read_window(1, 2056, &mut output));
        assert_eq!(output, [7; 16]);
        assert!(!cache.read_window(2, 2056, &mut output));
        assert!(!cache.read_window(1, 4090, &mut output));
        for i in 2..100 {
            cache.insert_window(1, i * 2048, vec![i as u8; 2048]);
            assert!(cache.window_bytes <= cache.budget / 8);
            assert!(cache.bytes <= cache.budget);
        }
        assert_eq!(cache.windows.len(), cache.window_oldest.len());
        cache.set_budget(1024);
        assert!(cache.windows.is_empty());
        assert_eq!(cache.bytes, 0);
        assert!(!cache.can_read_window(2048));
        cache.set_budget(64 * 1024);
        cache.insert_window(1, 2048, vec![7; 2048]);
        cache.clock = u64::MAX;
        assert!(!cache.read_window(1, 2056, &mut output));
        assert_eq!(cache.bytes, 0);
        assert_eq!(cache.window_bytes, 0);
    }
    #[test]
    fn read_buffer_reuse_is_pressure_bounded_and_never_mutates_pins() {
        let mut bytes = Vec::with_capacity(1024 * 1024 + 64);
        bytes.resize(1024 * 1024, 7);
        let object = Arc::new(CanonicalObject {
            kind: 7,
            version: 1,
            bytes,
            children: vec![],
        });
        let r = ObjectRef {
            hash: object.hash(),
            address: ChunkAddress {
                offset: 128,
                length: 1024 * 1024 + 64,
            },
        };
        let mut cache = DecodedCache {
            budget: 2 * 1024 * 1024,
            ..Default::default()
        };
        cache.insert_shared(1, r, &object);
        let charge = cache.bytes;
        assert!(cache.take_read_buffer(1024 * 1024 + 64).is_none());
        assert_eq!(object.bytes[0], 7);
        assert_eq!(cache.bytes, charge);
        drop(object);
        let buffer = cache.take_read_buffer(1024 * 1024 + 64).unwrap();
        assert_eq!(buffer.len(), 1024 * 1024);
        assert!(buffer.capacity() >= 1024 * 1024 + 64);
        assert_eq!(cache.bytes, 0);
        assert!(cache.objects.is_empty());
        assert_eq!(cache.objects.oldest, NO_NODE);
        assert!(cache.take_read_buffer(1024 * 1024 + 64).is_none());
    }
}
