//! Same-inode maintenance. Destructive writes use durable redo records;
//! frames are never changed while reachable from either slot or a native pin.
use super::*;
use std::os::unix::fs::MetadataExt;

const PLAN_ROW: usize = 52;
const MAX_REDO: usize = 2 * (8 * 1024 * 1024 + 16384);
#[derive(Clone, Debug)]
pub struct ReclamationOptions {
    pub limits: resources::Limits,
    pub punch_holes: bool,
    pub max_free_sizes: usize,
    /// A frame can exceed this batching target, but never the SAC frame bound.
    pub journal_batch_bytes: usize,
}
impl Default for ReclamationOptions {
    fn default() -> Self {
        Self {
            limits: resources::Limits::default(),
            punch_holes: true,
            max_free_sizes: 256,
            journal_batch_bytes: 4 << 20,
        }
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub struct ReclamationStatistics {
    pub file_bytes_before: u64,
    pub file_bytes_after: u64,
    pub allocated_bytes_before: u64,
    pub allocated_bytes_after: u64,
    pub retained_frames: u64,
    pub dead_frames: u64,
    pub punched_bytes: u64,
    pub indexed_reuse_bytes: u64,
    pub moved_bytes: u64,
    pub journal_peak_bytes: u64,
    pub elapsed_ns: u64,
}
pub(super) struct FreeFrames {
    buckets: BTreeMap<u32, temporary::FixedRecordStack<8>>,
    budget: temporary::Budget,
    maximum: usize,
}
impl FreeFrames {
    fn new(o: &ReclamationOptions) -> Self {
        Self {
            buckets: BTreeMap::new(),
            budget: temporary::Budget::new(o.limits.max_temp_bytes),
            maximum: o.max_free_sizes,
        }
    }
    fn add(&mut self, r: ObjectRef) -> Result<bool> {
        let size = r.address.length;
        if !self.buckets.contains_key(&size) {
            if self.buckets.len() >= self.maximum {
                return Ok(false);
            }
            self.buckets.insert(
                size,
                temporary::FixedRecordStack::with_budget(self.budget.clone())?,
            );
        }
        self.buckets
            .get_mut(&size)
            .unwrap()
            .push(&r.address.offset.to_le_bytes())?;
        Ok(true)
    }
    pub(super) fn take(&mut self, size: u32) -> Result<Option<u64>> {
        let Some(bucket) = self.buckets.get_mut(&size) else {
            return Ok(None);
        };
        Ok(bucket.pop()?.map(u64::from_le_bytes))
    }
}
fn allocated(f: &File) -> Result<u64> {
    Ok(f.metadata()?.blocks().saturating_mul(512))
}
fn checked_write(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut f = tempfile::Builder::new()
        .prefix(".sac-tmp-")
        .tempfile_in(dir)?;
    f.write_all(bytes)?;
    f.write_all(blake3::hash(bytes).as_bytes())?;
    durable(f.as_file())?;
    f.persist(dir.join(name)).map_err(|e| Error::Io(e.error))?;
    sync_parent(&dir.join(name))
}
fn checked_read(dir: &Path, name: &str, max: usize) -> Result<Vec<u8>> {
    let f = File::open(dir.join(name))?;
    let n = usize::try_from(f.metadata()?.len())
        .map_err(|_| Error::Limit("maintenance record bytes"))?;
    if n < 32 || n > max + 32 {
        return Err(corrupt("maintenance record size"));
    }
    let mut bytes = Vec::with_capacity(n);
    f.take(n as u64).read_to_end(&mut bytes)?;
    if bytes.len() != n || blake3::hash(&bytes[..n - 32]).as_bytes() != &bytes[n - 32..] {
        return Err(corrupt("maintenance record checksum"));
    }
    bytes.truncate(n - 32);
    Ok(bytes)
}
fn remove(dir: &Path, name: &str) -> Result<()> {
    match std::fs::remove_file(dir.join(name)) {
        Ok(()) => sync_parent(&dir.join(name)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn tick(start: Instant, o: &ReclamationOptions) -> Result<()> {
    if start.elapsed() > o.limits.max_elapsed {
        Err(Error::Limit("same-file maintenance elapsed work"))
    } else {
        Ok(())
    }
}
struct FrozenFile {
    file: File,
    header: wire::Preamble,
    end: u64,
}
impl FrozenFile {
    fn capture(store: &NativeStore) -> Result<Self> {
        Ok(Self {
            file: store.file.lock().unwrap().try_clone()?,
            header: store.reader.header,
            end: store.end,
        })
    }
}
fn prepare(
    store: &FrozenFile,
    o: &ReclamationOptions,
    disk: temporary::Budget,
) -> Result<temporary::GraphTable> {
    // Includes decoder, largest frame and redo buffers, fixed resident tables,
    // and bounded reader registrations. The store cache is released first.
    if o.limits.max_memory_bytes < 64 << 20 || o.max_free_sizes > 1024 {
        return Err(Error::Limit("maintenance memory budget"));
    }
    if store
        .end
        .checked_mul(3)
        .is_none_or(|n| n > o.limits.max_source_bytes)
    {
        return Err(Error::Limit("maintenance source bytes"));
    }
    let mut inventory = temporary::GraphTable::with_budget(256, disk);
    let start = Instant::now();
    let mut at = store.header.first_record_offset();
    let mut count = 0;
    let f = &store.file;
    while at < store.end {
        tick(start, o)?;
        let (span, header) = record(f, at, store.end)?;
        if let Some(h) = header {
            count += 1;
            if count > o.limits.max_frames {
                return Err(Error::Limit("maintenance source frames"));
            }
            let r = ObjectRef {
                hash: ObjectHash(h[16..48].try_into().unwrap()),
                address: ChunkAddress {
                    offset: at,
                    length: span as u32,
                },
            };
            inventory.insert_cancellable(&at.to_le_bytes(), &spill::encode_ref(r), &|| false)?;
        }
        at += span;
    }
    Ok(inventory)
}
fn mark(
    store: &FrozenFile,
    roots: &[ObjectRef],
    o: &ReclamationOptions,
    disk: temporary::Budget,
) -> Result<temporary::GraphTable> {
    let inventory = prepare(store, o, disk.clone())?;
    let start = Instant::now();
    let mut seen = temporary::GraphTable::with_budget(256, disk.clone());
    let mut stack = DiskStack::with_budget(256, disk)?;
    for r in roots {
        stack.push(*r, false)?;
    }
    let mut decoded = 0u64;
    let mut edges = 0u64;
    let file = &store.file;
    let mut decoder = wire::FrameDecoder::default();
    let mut frame = Vec::new();
    while let Some((r, _)) = stack.pop()? {
        tick(start, o)?;
        let encoded = spill::encode_ref(r);
        if inventory.get(&r.address.offset.to_le_bytes())?.as_deref() != Some(&encoded) {
            return Err(corrupt("maintenance reference is not a top-level frame"));
        }
        if seen.get(&r.address.offset.to_le_bytes())?.is_some() {
            continue;
        }
        frame.resize(r.address.length as usize, 0);
        read_at(file, &mut frame, r.address.offset)?;
        let view = decoder.decode(r, &frame, store.header.first_record_offset(), store.end)?;
        decoded = decoded
            .checked_add((8 + 32 * view.child_count() + view.body.len()) as u64)
            .ok_or(Error::Limit("maintenance decoded bytes"))?;
        edges = edges
            .checked_add(view.child_count() as u64)
            .ok_or(Error::Limit("maintenance edges"))?;
        if decoded > o.limits.max_decoded_bytes || edges > o.limits.max_edges {
            return Err(Error::Limit("maintenance graph work"));
        }
        seen.insert_cancellable(&r.address.offset.to_le_bytes(), &encoded, &|| false)?;
        for i in 0..view.child_count() {
            stack.push(view.child(i).ok_or(Error::Missing)?, false)?;
        }
    }
    Ok(seen)
}
fn selected_roots(store: &NativeStore) -> Result<Vec<ObjectRef>> {
    let mut roots = vec![store.root().ok_or(Error::Missing)?.root];
    let f = store.file.lock().unwrap();
    let length = f.metadata()?.len();
    for i in 0..2 {
        let mut b = [0; 4096];
        read_at(&f, &mut b, 4096 + i as u64 * 4096)?;
        if let Some(slot) = wire::Slot::decode(&b, &store.reader.header, i)? {
            let trailer = read_trailer(&f, &store.reader.header, slot.trailer_offset, &store.io)?;
            if trailer.digest() != slot.trailer_digest
                || trailer.generation != slot.generation
                || trailer.committed_end > length
            {
                return Err(corrupt("maintenance slot authority"));
            }
            roots.push(trailer.commit);
        }
    }
    Ok(roots)
}
fn record(f: &File, offset: u64, end: u64) -> Result<(u64, Option<[u8; 56]>)> {
    let mut h = [0; 56];
    read_at(f, &mut h, offset)?;
    let span = if &h[..8] == b"SAC1END\0" {
        160
    } else {
        wire::frame_span(&h)? as u64
    };
    if offset.checked_add(span).is_none_or(|n| n > end) {
        return Err(corrupt("maintenance record extent"));
    }
    Ok((
        span,
        if span == 160 && &h[..8] == b"SAC1END\0" {
            None
        } else {
            Some(h)
        },
    ))
}
fn owner_private(file: &File) -> Result<()> {
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != platform::uid() || m.mode() & 0o077 != 0 {
        return Err(Error::Unsupported(
            "same-file maintenance requires an owner-private file".into(),
        ));
    }
    Ok(())
}
impl NativeStore {
    /// Capture the old prefix and reader roots, then release writer ownership.
    /// The returned job may mark and punch on a background thread while normal
    /// publications append. Call finish_reclamation to install its free index.
    pub fn begin_reclamation(&mut self, options: ReclamationOptions) -> Result<OnlineReclamation> {
        if self
            .compaction_active
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(Error::Busy);
        }
        self.check_writable()?;
        if self.reader.header.policy != wire::LocatorPolicy::Live {
            return Err(Error::Unsupported(
                "same-file maintenance requires a live container".into(),
            ));
        }
        self.verify_current_path()?;
        if self.reused_unpublished
            || self.pending.is_some()
            || self.end != self.reader.committed_end()
            || self.file_len() != self.end
        {
            return Err(Error::Busy);
        }
        owner_private(self.file.get_mut().unwrap())?;
        let dir = leases::domain(self.file.get_mut().unwrap())?;
        let _gate = leases::gate(&dir, true)?;
        if leases::pending(&dir) {
            return Err(Error::RecoveryRequired);
        }
        if self.end > options.limits.max_file_bytes {
            return Err(Error::Limit("maintenance file bytes"));
        }
        let start = Instant::now();
        self.discard_disposable_caches();
        self.encoder = wire::FrameEncoder::default();
        self.free_frames = None;
        let (mut pins, protected) = leases::roots(&dir, 4096.min(options.limits.max_frames))?;
        pins.extend(selected_roots(self)?);
        self.file_identity = next_file_identity();
        let source = FrozenFile::capture(self)?;
        let stats = ReclamationStatistics {
            file_bytes_before: source.end,
            allocated_bytes_before: allocated(&source.file)?,
            ..Default::default()
        };
        if self
            .compaction_active
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return Err(Error::Busy);
        }
        Ok(OnlineReclamation {
            source,
            options,
            roots: pins,
            protected,
            stats,
            start,
            active: self.compaction_active.clone(),
            identity: self.file_identity,
            free: None,
            completed: false,
            attempted: false,
        })
    }
    pub fn finish_reclamation(
        &mut self,
        mut job: OnlineReclamation,
    ) -> Result<ReclamationStatistics> {
        self.check_writable()?;
        self.verify_current_path()?;
        if !job.completed
            || !Arc::ptr_eq(&self.compaction_active, &job.active)
            || self.file_identity != job.identity
        {
            return Err(corrupt("reclamation job owner or completion"));
        }
        self.free_frames = job.free.take();
        job.stats.file_bytes_after = self.file_len();
        job.stats.allocated_bytes_after = allocated(self.file.get_mut().unwrap())?;
        Ok(job.stats)
    }
    /// Synchronous convenience. Use begin/finish_reclamation to publish while
    /// the background job is marking and punching the captured old prefix.
    pub fn reclaim_online(&mut self, options: ReclamationOptions) -> Result<ReclamationStatistics> {
        let mut job = self.begin_reclamation(options)?;
        job.reclaim()?;
        self.finish_reclamation(job)
    }
    /// Offline sliding compaction preserves the inode. A durable plan and one
    /// bounded redo batch make every destructive write resumable after a crash.
    pub fn compact_in_place(
        &mut self,
        options: ReclamationOptions,
    ) -> Result<ReclamationStatistics> {
        self.check_writable()?;
        if self.reader.header.policy != wire::LocatorPolicy::Live {
            return Err(Error::Unsupported(
                "same-file maintenance requires a live container".into(),
            ));
        }
        self.verify_current_path()?;
        if self.reused_unpublished
            || self.pending.is_some()
            || self.end != self.reader.committed_end()
            || self.file_len() != self.end
        {
            return Err(Error::Busy);
        }
        if self
            .compaction_active
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(Error::Busy);
        }
        owner_private(self.file.get_mut().unwrap())?;
        let dir = leases::domain(self.file.get_mut().unwrap())?;
        let _gate = leases::gate(&dir, true)?;
        if leases::pending(&dir) {
            return Err(Error::RecoveryRequired);
        }
        let (pins, protected) = leases::roots(&dir, options.limits.max_frames)?;
        if !pins.is_empty() || protected != 0 {
            return Err(Error::Busy);
        }
        if options.journal_batch_bytes == 0 || options.journal_batch_bytes > 8 << 20 {
            return Err(Error::Limit("journal batching bytes"));
        }
        let start = Instant::now();
        let root = self.root().ok_or(Error::Missing)?;
        self.discard_disposable_caches();
        self.encoder = wire::FrameEncoder::default();
        self.free_frames = None;
        let disk = temporary::Budget::new(options.limits.max_temp_bytes);
        let live = mark(
            &FrozenFile::capture(self)?,
            &[root.root],
            &options,
            disk.clone(),
        )?;
        // Residue after a committed transaction must never become a new redo.
        for name in ["plan", "progress", "redo"] {
            remove(&dir, name)?;
        }
        let mut journal_reservation = disk.reserve(0)?;
        let mut stats = ReclamationStatistics {
            file_bytes_before: self.file_len(),
            allocated_bytes_before: allocated(self.file.get_mut().unwrap())?,
            ..Default::default()
        };
        let mut plan = tempfile::Builder::new()
            .prefix(".sac-tmp-")
            .tempfile_in(&dir)?;
        let mut at = self.reader.first_record_offset();
        let mut dest = at;
        let mut count = 0u64;
        let mut maximum_span = 0u64;
        let mut new_root = None;
        let mut hash = blake3::Hasher::new();
        while at < self.end {
            tick(start, &options)?;
            let (span, header) = record(self.file.get_mut().unwrap(), at, self.end)?;
            if header.is_some() {
                if let Some(encoded) = live.get(&at.to_le_bytes())? {
                    let r = spill::decode_ref(&encoded)?;
                    if r.address.length as u64 != span {
                        return Err(corrupt("plan physical span"));
                    }
                    let mut row = [0; PLAN_ROW];
                    row[..44].copy_from_slice(&encoded);
                    row[44..].copy_from_slice(&dest.to_le_bytes());
                    plan.write_all(&row)?;
                    hash.update(&row);
                    count += 1;
                    maximum_span = maximum_span.max(span);
                    journal_reservation.grow_to(count * PLAN_ROW as u64)?;
                    if r == root.root {
                        new_root = Some(ObjectRef {
                            hash: r.hash,
                            address: ChunkAddress {
                                offset: dest,
                                length: r.address.length,
                            },
                        });
                    }
                    dest += span;
                    stats.retained_frames += 1;
                } else {
                    stats.dead_frames += 1;
                }
            }
            at += span;
        }
        // Repeating compaction must not rewrite an already compact file or
        // grow a one-head file just to add redundant publication metadata.
        if dest
            .checked_add(320)
            .is_some_and(|end| end >= stats.file_bytes_before)
        {
            stats.file_bytes_after = stats.file_bytes_before;
            stats.allocated_bytes_after = allocated(self.file.get_mut().unwrap())?;
            stats.elapsed_ns = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            return Ok(stats);
        }
        let first_generation = root
            .generation
            .checked_add(2)
            .ok_or(Error::Limit("maintenance generation"))?
            - 1;
        let payload_bound = (options.journal_batch_bytes as u64 + maximum_span)
            .min(dest - self.reader.first_record_offset());
        let journal_bound = count * PLAN_ROW as u64 + 2 * (payload_bound + 48) + 4096;
        journal_reservation.grow_to(journal_bound)?;
        if dest
            .checked_add(320)
            .is_none_or(|n| n > options.limits.max_file_bytes)
        {
            return Err(Error::Limit("maintenance output bytes"));
        }
        durable(plan.as_file())?;
        plan.persist(dir.join("plan"))
            .map_err(|e| Error::Io(e.error))?;
        sync_parent(&dir.join("plan"))?;
        fault("plan");
        let mut incarnation = [0; 16];
        File::open("/dev/urandom")?.read_exact(&mut incarnation)?;
        let new_header = wire::Preamble::live(incarnation)?;
        let mut manifest = Vec::new();
        manifest.extend(self.reader.header.encode());
        manifest.extend(new_header.encode());
        manifest.extend(spill::encode_ref(new_root.ok_or(Error::Missing)?));
        manifest.extend(first_generation.to_le_bytes());
        manifest.extend(count.to_le_bytes());
        manifest.extend(dest.to_le_bytes());
        manifest.extend(hash.finalize().as_bytes());
        manifest.extend(self.end.to_le_bytes());
        manifest.extend((options.journal_batch_bytes as u64).to_le_bytes());
        checked_write(&dir, "progress", &0u64.to_le_bytes())?;
        fault("progress-initial");
        self.poisoned = true;
        checked_write(&dir, "manifest", &manifest)?;
        fault("manifest");
        stats.journal_peak_bytes = journal_bound;
        self.cache.lock().unwrap().clear();
        self.free_frames = None;
        drop(live);
        drop(journal_reservation);
        stats.moved_bytes = resume(self.file.get_mut().unwrap(), &dir)?;
        self.refresh_after_maintenance()?;
        stats.file_bytes_after = self.file_len();
        stats.allocated_bytes_after = allocated(self.file.get_mut().unwrap())?;
        stats.elapsed_ns = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        Ok(stats)
    }
    fn refresh_after_maintenance(&mut self) -> Result<()> {
        self.reader = admit_file(self.file.get_mut().unwrap(), &self.io)?;
        self.end = self.reader.committed_end();
        self.file_identity = next_file_identity();
        self.generation = Arc::new(FileGeneration::default());
        self.discard_disposable_caches();
        self.poisoned = false;
        Ok(())
    }
}
/// Background reclamation of a captured prefix. New writer frames append
/// outside that prefix; old root closures and native pins remain protected.
/// Dropping a job is safe and discards only its optional reuse index.
pub struct OnlineReclamation {
    source: FrozenFile,
    options: ReclamationOptions,
    roots: Vec<ObjectRef>,
    protected: u64,
    stats: ReclamationStatistics,
    start: Instant,
    active: Arc<std::sync::atomic::AtomicBool>,
    identity: u64,
    free: Option<FreeFrames>,
    completed: bool,
    attempted: bool,
}
impl Drop for OnlineReclamation {
    fn drop(&mut self) {
        self.active
            .store(false, std::sync::atomic::Ordering::Release);
    }
}
impl OnlineReclamation {
    pub fn statistics(&self) -> ReclamationStatistics {
        self.stats
    }
    pub fn reclaim(&mut self) -> Result<()> {
        if self.attempted {
            return Err(Error::Busy);
        }
        self.attempted = true;
        let disk = temporary::Budget::new(self.options.limits.max_temp_bytes);
        let live = mark(&self.source, &self.roots, &self.options, disk.clone())?;
        self.sweep(live, disk)
    }
    fn sweep(&mut self, live: temporary::GraphTable, disk: temporary::Budget) -> Result<()> {
        let mut free = FreeFrames::new(&self.options);
        free.budget = disk;
        let mut at = self.source.header.first_record_offset();
        while at < self.source.end {
            tick(self.start, &self.options)?;
            let (span, header) = record(&self.source.file, at, self.source.end)?;
            if let Some(h) = header {
                if at < self.protected || live.get(&at.to_le_bytes())?.is_some() {
                    self.stats.retained_frames += 1;
                } else {
                    self.stats.dead_frames += 1;
                    let r = ObjectRef {
                        hash: ObjectHash(h[16..48].try_into().unwrap()),
                        address: ChunkAddress {
                            offset: at,
                            length: span as u32,
                        },
                    };
                    if free.add(r)? {
                        self.stats.indexed_reuse_bytes += span;
                    }
                    if self.options.punch_holes {
                        // Keep headers, locators, and padding intact: physical
                        // verification of pinned generations still scans them.
                        let stored = u32::from_le_bytes(h[8..12].try_into().unwrap()) as u64;
                        // 16 KiB is aligned on supported native hosts. Only
                        // complete interior allocation units are discarded.
                        let begin = (at + 56).div_ceil(16384) * 16384;
                        let end = (at + 56 + stored) / 16384 * 16384;
                        if end > begin {
                            platform::punch(&self.source.file, begin, end - begin)?;
                            self.stats.punched_bytes += end - begin;
                            fault("punch");
                        }
                    }
                }
            }
            at += span;
        }
        durable(&self.source.file)?;
        self.free = Some(free);
        self.completed = true;
        self.stats.file_bytes_after = self.source.file.metadata()?.len();
        self.stats.allocated_bytes_after = allocated(&self.source.file)?;
        self.stats.elapsed_ns = self.start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        Ok(())
    }
}
// Recovery is invoked before normal admission. No reader can be admitted while
// a committed maintenance manifest or reuse redo record exists.
pub(super) fn recover(file: &mut File) -> Result<()> {
    let dir = leases::domain(file)?;
    let _gate = leases::gate(&dir, true)?;
    if leases::pending(&dir) {
        owner_private(file)?;
    }
    // No active journal producer can coexist with this exclusive gate.
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        if entry
            .file_name()
            .as_encoded_bytes()
            .starts_with(b".sac-tmp-")
        {
            std::fs::remove_file(entry.path())?;
        }
    }
    if !dir.join("manifest").exists() {
        for name in ["plan", "progress", "redo"] {
            remove(&dir, name)?;
        }
    }
    if dir.join("manifest").exists() {
        resume(file, &dir)?;
    }
    if dir.join("reuse").exists() {
        let bytes = checked_read(&dir, "reuse", MAX_REDO)?;
        if bytes.len() < 40 {
            return Err(corrupt("reuse record"));
        }
        let mut header = [0; 128];
        read_at(file, &mut header, 0)?;
        if blake3::hash(&header).as_bytes() != &bytes[..32] {
            return Err(corrupt("reuse file identity"));
        }
        let offset = u64_at(&bytes, 32);
        if offset < 12288
            || wire::frame_span(&bytes[40..])? != bytes.len() - 40
            || offset
                .checked_add((bytes.len() - 40) as u64)
                .is_none_or(|n| n > file.metadata().map(|m| m.len()).unwrap_or(0))
        {
            return Err(corrupt("reuse extent"));
        }
        write_at(file, &bytes[40..], offset)?;
        durable(file)?;
        remove(&dir, "reuse")?;
    }
    Ok(())
}
pub(super) fn reuse(file: &mut File, offset: u64, bytes: &[u8]) -> Result<()> {
    let dir = leases::domain(file)?;
    let _gate = leases::gate(&dir, true)?;
    if leases::pending(&dir) {
        return Err(Error::RecoveryRequired);
    }
    let mut header = [0; 128];
    read_at(file, &mut header, 0)?;
    let mut redo = Vec::with_capacity(40 + bytes.len());
    redo.extend(blake3::hash(&header).as_bytes());
    redo.extend(offset.to_le_bytes());
    redo.extend(bytes);
    checked_write(&dir, "reuse", &redo)?;
    fault("reuse-redo");
    #[cfg(test)]
    if fault_selected("reuse-partial") {
        write_at(file, &bytes[..bytes.len() / 2], offset)?;
        fault("reuse-partial");
    }
    write_at(file, bytes, offset)?;
    durable(file)?;
    remove(&dir, "reuse")
}
fn resume(file: &mut File, dir: &Path) -> Result<u64> {
    let m = checked_read(dir, "manifest", 512)?;
    if m.len() != 372 {
        return Err(corrupt("in-place manifest"));
    }
    let old = wire::Preamble::decode(&m[..128])?;
    let new = wire::Preamble::decode(&m[128..256])?;
    let root = spill::decode_ref(&m[256..300])?;
    let mut current = [0; 128];
    read_at(file, &mut current, 0)?;
    // Until finalization the old preamble is intact. During a torn final write
    // each byte must belong to this transaction's old/new preamble.
    if current
        .iter()
        .enumerate()
        .any(|(i, b)| *b != m[i] && *b != m[128 + i])
    {
        return Err(corrupt("maintenance file identity"));
    }
    let generation = u64_at(&m, 300);
    let count = u64_at(&m, 308);
    let end = u64_at(&m, 316);
    let original_end = u64_at(&m, 356);
    let batch =
        usize::try_from(u64_at(&m, 364)).map_err(|_| corrupt("maintenance batch bounds"))?;
    if old.policy != wire::LocatorPolicy::Live
        || new.policy != wire::LocatorPolicy::Live
        || generation == u64::MAX
        || end > original_end
        || end.checked_add(320).is_none()
        || batch == 0
        || batch > 8 << 20
        || count > u64::MAX / PLAN_ROW as u64
    {
        return Err(corrupt("maintenance bounds"));
    }
    let mut plan = File::open(dir.join("plan"))?;
    if plan.metadata()?.len() != count * PLAN_ROW as u64 {
        return Err(corrupt("maintenance plan length"));
    }
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0; 8192];
    loop {
        let n = plan.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    if hasher.finalize().as_bytes() != &m[324..356] {
        return Err(corrupt("maintenance plan checksum"));
    }
    plan.seek(SeekFrom::Start(0))?;
    let mut mapping =
        temporary::GraphTable::with_budget(256, temporary::Budget::new(temporary::MAX_DISK));
    let mut expected = old.first_record_offset();
    let mut last_source = 0;
    let mut maximum_span = 0usize;
    for _ in 0..count {
        let mut row = [0; PLAN_ROW];
        plan.read_exact(&mut row)?;
        let r = spill::decode_ref(&row[..44])?;
        let dest = u64_at(&row, 44);
        if r.address.length < 64
            || r.address.length as usize > MAX_CHUNK_SIZE + 16384
            || r.address.length % 8 != 0
            || dest != expected
            || dest > r.address.offset
            || r.address.offset < last_source
            || r.address
                .offset
                .checked_add(r.address.length as u64)
                .is_none_or(|n| n > original_end)
        {
            return Err(corrupt("maintenance plan order"));
        }
        maximum_span = maximum_span.max(r.address.length as usize);
        let mut mapped = r;
        mapped.address.offset = dest;
        mapping.insert_cancellable(
            &r.address.offset.to_le_bytes(),
            &spill::encode_ref(mapped),
            &|| false,
        )?;
        expected += r.address.length as u64;
        last_source = r.address.offset + r.address.length as u64;
    }
    if root.address.offset < new.first_record_offset()
        || root
            .address
            .offset
            .checked_add(root.address.length as u64)
            .is_none_or(|n| n > end)
        || expected != end
    {
        return Err(corrupt("maintenance plan output"));
    }
    let p = checked_read(dir, "progress", 8)?;
    if p.len() != 8 {
        return Err(corrupt("maintenance progress"));
    }
    let mut done = u64_at(&p, 0);
    if done > count {
        return Err(corrupt("maintenance progress count"));
    }
    if dir.join("redo").exists() {
        let redo = checked_read(dir, "redo", MAX_REDO)?;
        if redo.len() < 16 {
            return Err(corrupt("maintenance redo"));
        }
        let next = u64_at(&redo, 0);
        if next > done {
            if next > count
                || u64_at(&redo, 8) < old.first_record_offset()
                || u64_at(&redo, 8)
                    .checked_add((redo.len() - 16) as u64)
                    .is_none_or(|n| n > end)
            {
                return Err(corrupt("maintenance redo extent"));
            }
            write_at(file, &redo[16..], u64_at(&redo, 8))?;
            durable(file)?;
            checked_write(dir, "progress", &next.to_le_bytes())?;
            done = next;
        }
    }
    let mut decoder = wire::FrameDecoder::default();
    let mut frame = Vec::with_capacity(maximum_span);
    let capacity = (batch + maximum_span)
        .min(usize::try_from(end - old.first_record_offset()).unwrap_or(usize::MAX));
    let mut payload = Vec::with_capacity(capacity);
    let mut redo = Vec::with_capacity(capacity + 16);
    let mut moved = 0;
    while done < count {
        plan.seek(SeekFrom::Start(done * PLAN_ROW as u64))?;
        let mut next = done;
        let mut begin = 0;
        payload.clear();
        while next < count && (payload.len() < batch || payload.is_empty()) {
            let mut row = [0; PLAN_ROW];
            plan.read_exact(&mut row)?;
            let r = spill::decode_ref(&row[..44])?;
            let dest = u64_at(&row, 44);
            if payload.is_empty() {
                begin = dest;
            }
            frame.resize(r.address.length as usize, 0);
            read_at(file, &mut frame, r.address.offset)?;
            let view = decoder.decode(r, &frame, old.first_record_offset(), original_end)?;
            let mut locators = [[0u8; 12]; 1024];
            for (i, entry) in locators.iter_mut().enumerate().take(view.child_count()) {
                let c = view.child(i).ok_or(Error::Missing)?;
                let mapped = spill::decode_ref(
                    &mapping
                        .get(&c.address.offset.to_le_bytes())?
                        .ok_or(Error::Missing)?,
                )?;
                if c.hash != mapped.hash
                    || mapped.address.offset + mapped.address.length as u64 > dest
                {
                    return Err(corrupt("maintenance child mapping"));
                }
                entry[..8].copy_from_slice(&mapped.address.offset.to_le_bytes());
                entry[8..].copy_from_slice(&mapped.address.length.to_le_bytes());
            }
            let children = view.child_count();
            let start = 56 + u32::from_le_bytes(frame[8..12].try_into().unwrap()) as usize;
            for (i, locator) in locators.iter().take(children).enumerate() {
                frame[start + i * 12..start + (i + 1) * 12].copy_from_slice(locator);
            }
            payload.extend(&frame);
            next += 1;
        }
        redo.clear();
        redo.extend(next.to_le_bytes());
        redo.extend(begin.to_le_bytes());
        redo.extend(&payload);
        checked_write(dir, "redo", &redo)?;
        fault("redo");
        #[cfg(test)]
        if fault_selected("partial-data") {
            write_at(file, &payload[..payload.len() / 2], begin)?;
            fault("partial-data");
        }
        write_at(file, &payload, begin)?;
        durable(file)?;
        fault("data-sync");
        checked_write(dir, "progress", &next.to_le_bytes())?;
        done = next;
        moved += payload.len() as u64;
        fault("progress");
    }
    // Repeating finalization is safe even after a partial preamble, slot write,
    // or truncate. The manifest remains durable until both heads and EOF sync.
    #[cfg(test)]
    if fault_selected("partial-preamble") {
        write_at(file, &new.encode()[..51], 0)?;
        fault("partial-preamble");
    }
    write_at(file, &new.encode(), 0)?;
    fault("preamble");
    for delta in 0..2 {
        let publication_generation = generation
            .checked_add(delta)
            .ok_or(Error::Limit("maintenance generation"))?;
        let at = end + 160 * delta;
        let trailer = wire::Trailer {
            preamble_digest: new.digest(),
            generation: publication_generation,
            committed_end: at + 160,
            commit: root,
        };
        write_at(file, &trailer.encode(), at)?;
        let slot = wire::Slot {
            preamble_digest: new.digest(),
            generation: publication_generation,
            trailer_offset: at,
            trailer_digest: trailer.digest(),
        };
        #[cfg(test)]
        if fault_selected("partial-slot") {
            write_at(
                file,
                &slot.encode()[..900],
                slot_offset(publication_generation),
            )?;
            fault("partial-slot");
        }
        write_at(file, &slot.encode(), slot_offset(publication_generation))?;
        fault("slot");
    }
    durable(file)?;
    file.set_len(end + 320)?;
    durable(file)?;
    fault("truncate");
    // Manifest removal is the commit point for reader admission. Remaining
    // disposable plan/progress/redo files can be removed after it.
    remove(dir, "manifest")?;
    fault("commit");
    for name in ["plan", "progress", "redo"] {
        remove(dir, name)?;
    }
    Ok(moved)
}

#[cfg(test)]
fn fault_selected(point: &str) -> bool {
    std::env::var("SAC_TEST_MAINTENANCE_FAULT").as_deref() == Ok(point)
}
fn fault(point: &str) {
    #[cfg(test)]
    if fault_selected(point) {
        std::process::exit(86);
    }
    let _ = point;
}
#[cfg(test)]
mod tests;
