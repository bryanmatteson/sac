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
fn new_cache() -> Arc<CacheLock> {
    Arc::new(CacheLock::new(DecodedCache {
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
    cache: Arc<CacheLock>,
    bytes: usize,
}
impl MetadataReservation {
    fn new(cache: Arc<CacheLock>, bytes: usize) -> Result<Self> {
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
    cache: Arc<CacheLock>,
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
    // Unique to this residency of the entry; a recorded hit names it.
    serial: u64,
    // The reader shards hold a copy of this entry.
    fronted: bool,
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
        self.touch_slot(slot, age);
        self.nodes[slot as usize].value.as_ref()
    }
    /// A hit on the entry that `slot` holds.
    #[inline]
    fn touch_slot(&mut self, slot: u32, age: u64) {
        if self.newest != slot {
            self.unlink(slot);
            self.link_newest(slot);
        }
        self.nodes[slot as usize].age = age;
    }
    /// A hit that a reader recorded. False when that residency has ended.
    fn touch_recorded(&mut self, slot: u32, serial: u64, age: u64) -> bool {
        match self.nodes.get(slot as usize) {
            Some(node) if node.serial == serial && node.value.is_some() => {}
            _ => return false,
        }
        self.touch_slot(slot, age);
        true
    }
    /// Note that the reader shards take a copy. Gives the slot and serial
    /// of an entry that had no copy.
    fn mark_front(&mut self, key: &DecodedKey) -> Option<(u32, u64)> {
        let slot = *self.slots.get(key)?;
        let node = &mut self.nodes[slot as usize];
        (!std::mem::replace(&mut node.fronted, true)).then_some((slot, node.serial))
    }
    /// The caller removes an existing entry for the key first.
    fn insert(&mut self, key: DecodedKey, value: V, age: u64, serial: u64) {
        let node = LruNode {
            key,
            value: Some(value),
            age,
            serial,
            fronted: false,
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
    /// The value, and whether the reader shards hold a copy of it.
    fn remove(&mut self, key: &DecodedKey) -> Option<(V, bool)> {
        let slot = self.slots.remove(key)?;
        self.unlink(slot);
        self.free.push(slot);
        let node = &mut self.nodes[slot as usize];
        Some((node.value.take()?, node.fronted))
    }
    fn oldest_age(&self) -> Option<u64> {
        (self.oldest != NO_NODE).then(|| self.nodes[self.oldest as usize].age)
    }
    fn remove_oldest(&mut self) -> Option<(DecodedKey, V, bool)> {
        if self.oldest == NO_NODE {
            return None;
        }
        let key = self.nodes[self.oldest as usize].key;
        let (value, fronted) = self.remove(&key)?;
        Some((key, value, fronted))
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

/// Copies of resident entries that a reader can hit while another thread has
/// the cache. One thread, or threads that never meet, use the cache alone, as
/// before. A reader that finds the cache busy changes it to shared hits: a
/// hit then takes the lock of one shard of the keys and adds its entry to
/// the record of its thread. [`CacheLock::lock`] gives the recorded hits
/// their ages before any other change, so an eviction has the same victims.
/// The hits that several threads make between two exclusive accesses keep
/// the order of each thread. A thread whose record is full while the cache
/// is busy does not record its hit. Only the cache changes the shards.
struct Front {
    // Readers have met a busy cache. Read by each hit; changed seldom.
    shared: std::sync::atomic::AtomicBool,
    hasher: TableHash,
    tables: std::sync::OnceLock<FrontTables>,
    counters: FrontCounters,
}
#[repr(align(128))]
#[derive(Default)]
struct FrontCounters {
    // The threads whose record of hits is not empty.
    dirty: std::sync::atomic::AtomicU32,
    // Full records in sequence that found the cache free.
    calm: std::sync::atomic::AtomicU32,
}
struct FrontTables {
    shards: Box<[FrontShard]>,
    records: Box<[FrontRecord]>,
}
// Readers of one shard do not wait for each other.
#[repr(align(128))]
#[derive(Default)]
struct FrontShard(std::sync::RwLock<FrontMaps>);
// The slot and serial of each entry in the cache, and its value.
#[derive(Default)]
struct FrontMaps {
    objects: std::collections::HashMap<DecodedKey, (u32, u64, Arc<CanonicalObject>), TableHash>,
    verified: std::collections::HashMap<DecodedKey, (u32, u64, (u16, u16)), TableHash>,
}
#[repr(align(128))]
#[derive(Default)]
struct FrontRecord(Mutex<FrontHits>);
#[derive(Default)]
struct FrontHits {
    // The slot and serial of each hit of one thread, in the order of the hits.
    hits: Vec<(u32, u64)>,
    // Hits that found the record full.
    lost: u32,
}
const FRONT_SHARDS: usize = 256;
const FRONT_RECORDS: usize = 32;
const FRONT_HITS: usize = 256;
// A thread with a full record asks for the cache again after this number
// of lost hits.
const FRONT_LOST: u32 = 64;
// This number of full records with a free cache ends shared hits.
const FRONT_CALM: u32 = 64;
// A byte leaf of this capacity stays with the cache alone, which can then
// give its allocation to a read (`take_read_buffer`).
const FRONT_PAYLOAD_LIMIT: usize = 256 * 1024;
/// Marks a recorded slot of the authentication entries.
const VERIFIED_HIT: u32 = 1 << 31;
impl Front {
    fn new() -> Self {
        Self {
            shared: Default::default(),
            hasher: TableHash::default(),
            tables: Default::default(),
            counters: Default::default(),
        }
    }
    fn tables(&self) -> &FrontTables {
        self.tables.get_or_init(|| FrontTables {
            shards: (0..FRONT_SHARDS).map(|_| Default::default()).collect(),
            records: (0..FRONT_RECORDS).map(|_| Default::default()).collect(),
        })
    }
    fn shard<'a>(&self, tables: &'a FrontTables, key: &DecodedKey) -> &'a FrontShard {
        let hash = std::hash::BuildHasher::hash_one(&self.hasher, key);
        &tables.shards[(hash >> (64 - FRONT_SHARDS.trailing_zeros())) as usize]
    }
    /// The record of the calling thread. More threads than records share.
    fn record_index() -> usize {
        use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        thread_local! {
            static RECORD: usize = NEXT.fetch_add(1, Relaxed) % FRONT_RECORDS;
        }
        RECORD.try_with(|record| *record).unwrap_or(0)
    }
    fn object(&self, key: &DecodedKey) -> Option<(Arc<CanonicalObject>, u32, u64)> {
        let tables = self.tables.get()?;
        let maps = self.shard(tables, key).0.read().unwrap();
        let (slot, serial, object) = maps.objects.get(key)?;
        Some((Arc::clone(object), *slot, *serial))
    }
    fn verified(&self, key: &DecodedKey) -> Option<((u16, u16), u32, u64)> {
        let tables = self.tables.get()?;
        let maps = self.shard(tables, key).0.read().unwrap();
        let (slot, serial, value) = maps.verified.get(key)?;
        Some((*value, *slot, *serial))
    }
    /// Add a hit to the record of this thread. False when the caller must
    /// apply the records: this hit filled the record, or the record was
    /// full, the hit is lost and enough hits were lost since the last time.
    fn record(&self, slot: u32, serial: u64) -> bool {
        let index = Self::record_index();
        let mut record = self.tables().records[index].0.lock().unwrap();
        if record.hits.len() >= FRONT_HITS {
            record.lost = record.lost.wrapping_add(1);
            return !record.lost.is_multiple_of(FRONT_LOST);
        }
        if record.hits.is_empty() {
            // In one order with the exclusive access that reads the mask.
            self.counters
                .dirty
                .fetch_or(1 << index, std::sync::atomic::Ordering::SeqCst);
        }
        record.hits.push((slot, serial));
        record.hits.len() < FRONT_HITS
    }
}
/// The decoded cache of one store and its readers.
struct CacheLock {
    cache: Mutex<DecodedCache>,
    front: Arc<Front>,
}
impl CacheLock {
    fn new(mut cache: DecodedCache) -> Self {
        let front = Arc::new(Front::new());
        cache.front = Some(Arc::clone(&front));
        Self {
            cache: Mutex::new(cache),
            front,
        }
    }
    /// Exclusive access, after the recorded hits have taken effect.
    #[inline]
    fn lock(&self) -> std::sync::LockResult<std::sync::MutexGuard<'_, DecodedCache>> {
        let mut cache = self.cache.lock()?;
        self.apply_hits(&mut cache);
        Ok(cache)
    }
    #[inline]
    fn apply_hits(&self, cache: &mut DecodedCache) {
        // In one order with the reader that sets the mask for its record.
        if self.front.counters.dirty.load(std::sync::atomic::Ordering::SeqCst) != 0 {
            cache.apply_hits();
        }
    }
    /// Exclusive access when no other thread has the cache.
    #[inline]
    fn free(&self) -> Option<std::sync::MutexGuard<'_, DecodedCache>> {
        match self.cache.try_lock() {
            Ok(mut cache) => {
                self.apply_hits(&mut cache);
                Some(cache)
            }
            Err(std::sync::TryLockError::WouldBlock) => None,
            Err(std::sync::TryLockError::Poisoned(error)) => panic!("decoded cache: {error}"),
        }
    }
    /// Exclusive access for a hit while hits are not shared. A busy cache
    /// starts shared hits.
    #[inline]
    fn alone(&self) -> Option<std::sync::MutexGuard<'_, DecodedCache>> {
        use std::sync::atomic::Ordering::Relaxed;
        if self.front.shared.load(Relaxed) {
            return None;
        }
        let cache = self.free();
        if cache.is_none() {
            self.front.counters.calm.store(0, Relaxed);
            self.front.shared.store(true, Relaxed);
        }
        cache
    }
    /// Record a shared hit. A thread with a full record applies the records
    /// when the cache is free; enough of these in sequence end shared hits.
    fn note(&self, slot: u32, serial: u64) {
        use std::sync::atomic::Ordering::Relaxed;
        if self.front.record(slot, serial) {
            return;
        }
        let counters = &self.front.counters;
        if self.free().is_none() {
            counters.calm.store(0, Relaxed);
        } else if counters.calm.fetch_add(1, Relaxed) >= FRONT_CALM {
            counters.calm.store(0, Relaxed);
            self.front.shared.store(false, Relaxed);
        }
    }
    /// A resident object. For an object that is not resident, the result of
    /// `miss` within the same exclusive access.
    fn get_or<T>(
        &self,
        file_identity: u64,
        r: ObjectRef,
        miss: impl FnOnce(&mut DecodedCache) -> T,
    ) -> std::result::Result<Arc<CanonicalObject>, T> {
        if let Some(mut cache) = self.alone() {
            return cache.get(file_identity, r).ok_or_else(|| miss(&mut cache));
        }
        let key = (file_identity, r.hash, r.address.offset, r.address.length);
        if let Some((object, slot, serial)) = self.front.object(&key) {
            self.note(slot, serial);
            return Ok(object);
        }
        let mut cache = self.lock().unwrap();
        cache
            .get_fronted(file_identity, r)
            .ok_or_else(|| miss(&mut cache))
    }
    fn get(&self, file_identity: u64, r: ObjectRef) -> Option<Arc<CanonicalObject>> {
        self.get_or(file_identity, r, |_| ()).ok()
    }
    /// The authenticated type of one physical occurrence, as [`Self::get`].
    fn verified_type(&self, file_identity: u64, reference: ObjectRef) -> Option<(u16, u16)> {
        if let Some(mut cache) = self.alone() {
            return cache.verified_type(file_identity, reference);
        }
        let key = (
            file_identity,
            reference.hash,
            reference.address.offset,
            reference.address.length,
        );
        if let Some((value, slot, serial)) = self.front.verified(&key) {
            self.note(slot | VERIFIED_HIT, serial);
            return Some(value);
        }
        self.lock()
            .unwrap()
            .verified_type_fronted(file_identity, reference)
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
    // The next entry serial. A clear does not start it again.
    serial: u64,
    // The reader shards of a shared cache, and a spare record of hits.
    front: Option<Arc<Front>>,
    hits: Vec<(u32, u64)>,
}
type DecodedKey = (u64, ObjectHash, u64, u32);
// Charge both the physical-key lookup and exact LRU order, including their
// node allowance and the copy that the reader shards may hold, to the
// existing decoded budget. Object and authentication
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
        if let Some(tables) = self.front.as_ref().and_then(|front| front.tables.get()) {
            for shard in &tables.shards {
                *shard.0.write().unwrap() = FrontMaps::default();
            }
        }
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
    /// Give each recorded hit the next age, in the order of its thread. A
    /// record whose entry has left the cache since is no access.
    #[cold]
    fn apply_hits(&mut self) {
        use std::sync::atomic::Ordering::SeqCst;
        let Self { front: Some(front), objects, verified, clock, hits, .. } = self else {
            return;
        };
        let Some(tables) = front.tables.get() else {
            return;
        };
        let mut dirty = front.counters.dirty.swap(0, SeqCst);
        while dirty != 0 {
            let index = dirty.trailing_zeros() as usize;
            dirty &= dirty - 1;
            hits.reserve_exact(FRONT_HITS);
            std::mem::swap(&mut tables.records[index].0.lock().unwrap().hits, hits);
            for (slot, serial) in hits.drain(..) {
                // The ages do not wrap: `tick` clears the cache first.
                let age = clock.saturating_add(1);
                let touched = if slot & VERIFIED_HIT == 0 {
                    objects.touch_recorded(slot, serial, age)
                } else {
                    verified.touch_recorded(slot & !VERIFIED_HIT, serial, age)
                };
                if touched {
                    *clock = age;
                }
            }
        }
    }
    /// Remove the copy of an entry that has left the cache.
    fn unfront(&self, key: &DecodedKey, verified: bool) {
        let Some(front) = &self.front else {
            return;
        };
        let Some(tables) = front.tables.get() else {
            return;
        };
        let mut maps = front.shard(tables, key).0.write().unwrap();
        if verified {
            maps.verified.remove(key);
        } else {
            maps.objects.remove(key);
        }
    }
    /// A hit, which also gives the reader shards a copy of the entry.
    fn get_fronted(&mut self, file_identity: u64, r: ObjectRef) -> Option<Arc<CanonicalObject>> {
        let object = self.get(file_identity, r)?;
        let key = (file_identity, r.hash, r.address.offset, r.address.length);
        if object.bytes.capacity() < FRONT_PAYLOAD_LIMIT
            && let Some(front) = &self.front
            && let Some((slot, serial)) = self.objects.mark_front(&key)
        {
            let mut maps = front.shard(front.tables(), &key).0.write().unwrap();
            maps.objects.insert(key, (slot, serial, Arc::clone(&object)));
        }
        Some(object)
    }
    fn verified_type_fronted(
        &mut self,
        file_identity: u64,
        reference: ObjectRef,
    ) -> Option<(u16, u16)> {
        let key = (
            file_identity,
            reference.hash,
            reference.address.offset,
            reference.address.length,
        );
        let value = if !self.verified.slots.contains_key(&key) {
            // Keep the decoded entry as the authority. Type queries take the
            // cache lock so a separate verified entry, if later admitted,
            // retains the same precedence and eviction age as exclusive hits.
            let object = self.get_fronted(file_identity, reference)?;
            let value = (object.kind, object.version);
            if object.bytes.capacity() < FRONT_PAYLOAD_LIMIT {
                return Some(value);
            }
            // Large payloads stay out of the reader shards. Give shared type
            // queries their small independent entry only when first needed.
            self.verify(file_identity, reference, value);
            value
        } else {
            self.verified_type(file_identity, reference)?
        };
        if let Some(front) = &self.front
            && let Some((slot, serial)) = self.verified.mark_front(&key)
        {
            let mut maps = front.shard(front.tables(), &key).0.write().unwrap();
            maps.verified.insert(key, (slot, serial, value));
        }
        Some(value)
    }
    fn remove(&mut self, key: &DecodedKey) {
        if let Some(((_, size), fronted)) = self.objects.remove(key) {
            if fronted {
                self.unfront(key, false);
            }
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
        self.evict_oldest_for_append(None)
    }
    fn evict_oldest_for_append(
        &mut self,
        recycle: Option<(&mut Option<Arc<CanonicalObject>>, usize, usize)>,
    ) -> bool {
        self.refresh_order();
        let decoded = self.objects.oldest_age();
        let metadata_allowance =
            (self.budget.saturating_sub(self.pinned_metadata) / 8).min(4 * 1024 * 1024);
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
            let (key, _, fronted) = self
                .verified
                .remove_oldest()
                .expect("verified cache age order");
            if fronted {
                self.unfront(&key, true);
            }
            self.bytes -= DECODED_ENTRY_METADATA;
            return true;
        }
        let Some((key, (mut object, size), fronted)) = self.objects.remove_oldest() else {
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
        if fronted {
            self.unfront(&key, false);
        }
        self.bytes -= size;
        if let Some((slot, bytes, children)) = recycle
            && slot.is_none()
            && object.bytes.capacity() == bytes
            && object.children.capacity() == children
            && Arc::get_mut(&mut object).is_some()
        {
            *slot = Some(object);
        }
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
    fn admits_child(&mut self, identity: u64, reference: ObjectRef) -> bool {
        let key = (
            identity,
            reference.hash,
            reference.address.offset,
            reference.address.length,
        );
        // A decoded entry already authenticates the complete physical
        // occurrence, even if its separate type entry has been evicted.
        self.objects.slots.contains_key(&key) || self.verified(identity, reference)
    }
    fn verified_type(&mut self, file_identity: u64, reference: ObjectRef) -> Option<(u16, u16)> {
        let age = self.tick();
        let key = (
            file_identity,
            reference.hash,
            reference.address.offset,
            reference.address.length,
        );
        self.verified.touch(&key, age).copied().or_else(|| {
            self.objects
                .touch(&key, age)
                .map(|(object, _)| (object.kind, object.version))
        })
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
        if let Some((_, fronted)) = self.verified.remove(&key) {
            if fronted {
                self.unfront(&key, true);
            }
            self.bytes -= DECODED_ENTRY_METADATA;
        }
        while self.bytes + DECODED_ENTRY_METADATA > available {
            if !self.evict_oldest() {
                break;
            }
        }
        self.serial += 1;
        self.verified.insert(key, object_type, age, self.serial);
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
        // An object of this capacity has no copy in the reader shards.
        let ((object, size), _) = self.objects.remove(&key)?;
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
        self.serial += 1;
        self.objects
            .insert(key, (Arc::clone(object), size), age, self.serial);
        self.bytes += size;
    }
    fn admit_append(
        &mut self,
        identity: u64,
        reference: ObjectRef,
        append: AppendObject<'_>,
    ) -> bool {
        let available = self.budget.saturating_sub(self.pinned_metadata);
        let (bytes, children) = (append.bytes.len(), append.children.len());
        // Leave room for a type-only admission if the payload is later evicted.
        // The decoded occurrence already authenticates its own type and edges.
        let target =
            2 * DECODED_ENTRY_METADATA + bytes + children * std::mem::size_of::<ObjectRef>();
        if target > available {
            return false;
        }
        let mut recycled = None;
        while self.bytes + target > available {
            let victim = if recycled.is_none() {
                Some((&mut recycled, bytes, children))
            } else {
                None
            };
            if !self.evict_oldest_for_append(victim) {
                break;
            }
        }
        let object = match recycled {
            Some(mut recycled) => {
                // Removed from both lookup tables. Any outstanding reader pin
                // made this victim ineligible for reuse.
                let object = Arc::get_mut(&mut recycled).unwrap();
                object.kind = append.kind;
                object.version = append.version;
                object.bytes.clear();
                object.bytes.extend_from_slice(&append.bytes);
                object.children.clear();
                object.children.extend_from_slice(&append.children);
                recycled
            }
            None => Arc::new(CanonicalObject {
                kind: append.kind,
                version: append.version,
                bytes: append.bytes.into_owned(),
                children: append.children.into_owned(),
            }),
        };
        if DECODED_ENTRY_METADATA
            + object.bytes.capacity()
            + object.children.capacity() * std::mem::size_of::<ObjectRef>()
            > available
        {
            return false;
        }
        self.insert_shared(identity, reference, &object);
        true
    }
}

#[cfg(test)]
mod buffer_tests {
    use super::*;

    #[test]
    fn decoded_append_types_need_no_duplicate_metadata_and_front_exact_occurrences() {
        use std::sync::atomic::Ordering::Relaxed;
        for size in [32, FRONT_PAYLOAD_LIMIT] {
            let cache = CacheLock::new(DecodedCache {
                budget: 4 * FRONT_PAYLOAD_LIMIT + 4096,
                ..Default::default()
            });
            let bytes = vec![7; size];
            let reference = ObjectRef {
                hash: ObjectHash::digest(&bytes),
                address: ChunkAddress {
                    offset: 128,
                    length: 256,
                },
            };
            assert!(cache.lock().unwrap().admit_append(
                3,
                reference,
                AppendObject {
                    kind: 42000,
                    version: 9,
                    bytes: Cow::Borrowed(&bytes),
                    children: Cow::Borrowed(&[]),
                }
            ));
            assert_eq!(cache.lock().unwrap().verified.len(), 0);
            assert_eq!(cache.verified_type(3, reference), Some((42000, 9)));
            assert_eq!(cache.lock().unwrap().verified.len(), 0);
            cache.front.shared.store(true, Relaxed);
            assert_eq!(cache.verified_type(3, reference), Some((42000, 9)));
            let key = (
                3,
                reference.hash,
                reference.address.offset,
                reference.address.length,
            );
            if size < FRONT_PAYLOAD_LIMIT {
                assert!(cache.front.object(&key).is_some());
                assert_eq!(cache.lock().unwrap().verified.len(), 0);
            } else {
                assert!(cache.front.verified(&key).is_some());
            }
            for _ in 0..8 {
                assert_eq!(cache.verified_type(3, reference), Some((42000, 9)));
            }
            assert_eq!(cache.verified_type(4, reference), None);
            let mut other = reference;
            other.address.offset += 8;
            assert_eq!(cache.verified_type(3, other), None);
            other = reference;
            other.address.length += 8;
            assert_eq!(cache.verified_type(3, other), None);
            other = reference;
            other.hash.0[0] ^= 1;
            assert_eq!(cache.verified_type(3, other), None);
            cache.lock().unwrap().set_budget(0);
            assert_eq!(cache.verified_type(3, reference), None);
        }
        let mut cache = DecodedCache {
            budget: 1024,
            ..Default::default()
        };
        let mut bytes = Vec::with_capacity(4096);
        bytes.extend_from_slice(b"small body with an oversized owned reservation");
        let reference = ObjectRef {
            hash: ObjectHash::digest(&bytes),
            address: ChunkAddress {
                offset: 128,
                length: 256,
            },
        };
        assert!(!cache.admit_append(
            3,
            reference,
            AppendObject {
                kind: 42000,
                version: 9,
                bytes: Cow::Owned(bytes),
                children: Cow::Borrowed(&[]),
            }
        ));
        assert_eq!(cache.verified_type(3, reference), None);
    }

    #[test]
    fn append_reuses_an_unpinned_victim_and_preserves_a_pinned_one() {
        let mut cache = DecodedCache {
            budget: 2 * DECODED_ENTRY_METADATA + 32,
            ..Default::default()
        };
        let put = |cache: &mut DecodedCache, byte| {
            let bytes = [byte; 32];
            let reference = ObjectRef {
                hash: ObjectHash::digest(&bytes),
                address: ChunkAddress {
                    offset: 128 + u64::from(byte) * 128,
                    length: 128,
                },
            };
            cache.admit_append(
                1,
                reference,
                AppendObject {
                    kind: 7,
                    version: 1,
                    bytes: Cow::Borrowed(&bytes),
                    children: Cow::Borrowed(&[]),
                },
            );
            cache.verify(1, reference, (7, 1));
            reference
        };
        let first = put(&mut cache, 1);
        let first_ptr = Arc::as_ptr(&cache.get(1, first).unwrap());
        let second = put(&mut cache, 2);
        let pinned = cache.get(1, second).unwrap();
        assert_eq!(Arc::as_ptr(&pinned), first_ptr);
        assert!(cache.get(1, first).is_none());
        let third = put(&mut cache, 3);
        assert!(!Arc::ptr_eq(&pinned, &cache.get(1, third).unwrap()));
        assert_eq!(pinned.bytes, [2; 32]);
        assert_eq!(cache.bytes, cache.budget);
    }

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

    fn occurrence(ordinal: u64) -> ObjectRef {
        ObjectRef {
            hash: ObjectHash::digest(&ordinal.to_le_bytes()),
            address: ChunkAddress { offset: 128 + ordinal * 128, length: 128 },
        }
    }
    fn ages<V>(lru: &Lru<V>) -> Vec<(DecodedKey, u64)> {
        lru.oldest_first()
            .map(|(key, _)| (*key, lru.nodes[lru.slots[key] as usize].age))
            .collect()
    }
    fn order(cache: &DecodedCache) -> (u64, usize, [Vec<(DecodedKey, u64)>; 2]) {
        (cache.clock, cache.bytes, [ages(&cache.objects), ages(&cache.verified)])
    }

    #[test]
    fn shared_hits_give_the_ages_and_victims_of_exclusive_hits() {
        use std::sync::atomic::Ordering::Relaxed;
        // Room for 24 of the 64 objects, so the inserts evict; runs of hits
        // pass the length of a record between two inserts.
        let budget = 24 * (DECODED_ENTRY_METADATA + 64);
        let shared = CacheLock::new(DecodedCache { budget, ..Default::default() });
        let exclusive = CacheLock::new(DecodedCache { budget, ..Default::default() });
        let object = Arc::new(CanonicalObject { kind: 7, version: 1, bytes: vec![1; 64], children: vec![] });
        let mut state = 7u64;
        let mut next = |bound: u64| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) % bound
        };
        let mut front_hits = 0;
        for step in 0..40_000u64 {
            // As a reader that found the cache busy.
            shared.front.shared.store(true, Relaxed);
            let r = occurrence(next(64));
            let key = (1, r.hash, r.address.offset, r.address.length);
            match next(if step % 5000 < 2500 { 400 } else { 8 }) {
                0 => {
                    shared.lock().unwrap().insert_shared(1, r, &object);
                    exclusive.lock().unwrap().insert_shared(1, r, &object);
                }
                1 => {
                    shared.lock().unwrap().verify(1, r, (7, 1));
                    exclusive.lock().unwrap().verify(1, r, (7, 1));
                }
                choice if choice % 2 == 0 => {
                    front_hits += usize::from(shared.front.object(&key).is_some());
                    assert_eq!(
                        shared.get(1, r).is_some(),
                        exclusive.lock().unwrap().get(1, r).is_some()
                    );
                }
                _ => assert_eq!(
                    shared.verified_type(1, r),
                    exclusive.lock().unwrap().verified_type(1, r)
                ),
            }
        }
        assert!(front_hits > 1000);
        assert!(!exclusive.front.shared.load(Relaxed) && exclusive.front.tables.get().is_none());
        assert_eq!(order(&shared.lock().unwrap()), order(&exclusive.lock().unwrap()));
        assert!(shared.get(2, occurrence(1)).is_none());
        // Enough full records with a free cache end the shared hits.
        let resident = *shared.lock().unwrap().objects.oldest_first().next().unwrap().0;
        let r = ObjectRef {
            hash: resident.1,
            address: ChunkAddress { offset: resident.2, length: resident.3 },
        };
        for _ in 0..(FRONT_CALM as usize + 2) * FRONT_HITS {
            assert!(shared.get(1, r).is_some());
        }
        assert!(!shared.front.shared.load(Relaxed));
        shared.lock().unwrap().clear();
        assert!(shared.front.object(&resident).is_none());
    }

    #[test]
    fn readers_hit_while_another_thread_replaces_entries() {
        let budget = 48 * (DECODED_ENTRY_METADATA + 64);
        let cache = CacheLock::new(DecodedCache { budget, ..Default::default() });
        let object = |ordinal: u64| {
            Arc::new(CanonicalObject {
                kind: 7,
                version: 1,
                bytes: ordinal.to_le_bytes().repeat(8),
                children: vec![],
            })
        };
        for ordinal in 0..32 {
            cache.lock().unwrap().insert_shared(1, occurrence(ordinal), &object(ordinal));
            cache.lock().unwrap().verify(1, occurrence(ordinal), (7, 1));
        }
        cache.front.shared.store(true, std::sync::atomic::Ordering::Relaxed);
        std::thread::scope(|scope| {
            for thread in 0..8u64 {
                let (cache, object) = (&cache, &object);
                scope.spawn(move || {
                    let mut state = thread | 1;
                    for _ in 0..50_000 {
                        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                        let ordinal = (state >> 33) % 96;
                        if thread == 0 && state >> 60 == 0 {
                            let mut cache = cache.lock().unwrap();
                            cache.insert_shared(1, occurrence(ordinal), &object(ordinal));
                            cache.verify(1, occurrence(ordinal), (7, 1));
                        } else if let Some(found) = cache.get(1, occurrence(ordinal)) {
                            assert_eq!(found.bytes[..8], ordinal.to_le_bytes());
                        } else if let Some(found) = cache.verified_type(1, occurrence(ordinal)) {
                            assert_eq!(found, (7, 1));
                        }
                    }
                });
            }
        });
        let tables = cache.front.tables.get().unwrap();
        let cache = cache.lock().unwrap();
        assert!(cache.bytes <= cache.budget);
        let charged: usize = cache.objects.oldest_first().map(|(_, (_, size))| size).sum();
        assert_eq!(
            cache.bytes,
            charged + cache.verified.len() * DECODED_ENTRY_METADATA
        );
        // Each copy in the shards is an entry of the cache, and each entry
        // that the cache marks has its copy.
        let (mut objects, mut verified) = (0, 0);
        for shard in &tables.shards {
            let maps = shard.0.read().unwrap();
            for (key, (slot, serial, _)) in &maps.objects {
                assert_eq!(cache.objects.slots[key], *slot);
                assert_eq!(cache.objects.nodes[*slot as usize].serial, *serial);
            }
            for (key, (slot, serial, _)) in &maps.verified {
                assert_eq!(cache.verified.slots[key], *slot);
                assert_eq!(cache.verified.nodes[*slot as usize].serial, *serial);
            }
            objects += maps.objects.len();
            verified += maps.verified.len();
        }
        let marked = |fronted: &mut dyn Iterator<Item = bool>| fronted.filter(|fronted| *fronted).count();
        assert!(objects > 0);
        assert_eq!(
            objects,
            marked(&mut cache.objects.slots.values().map(|slot| cache.objects.nodes[*slot as usize].fronted))
        );
        assert_eq!(
            verified,
            marked(&mut cache.verified.slots.values().map(|slot| cache.verified.nodes[*slot as usize].fronted))
        );
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
