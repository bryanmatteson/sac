//! Bounded write-back key/value storage with synchronous WAL acknowledgement.
//!
//! The `sac.memtable.v2` profile binds a checkpoint sequence to the resource
//! directory in the same snapshot. A separate WAL holds atomic mutation batches.
//! A worker publishes one immutable generation while a bounded active table and
//! a second durable WAL segment accept writes. Reads use a pinned checkpoint.
use super::{durable, sync_parent, verify_file_path};
use crate::v1::{
    Error, NativeReader, NativeStore, ObjectRef, ObjectStore, Result, cbor, corrupt, resources,
};
use resources::{ArchiveBuilder, ArchiveReader, EntryKind, Limits, Profile};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

mod wal_io;

const PROFILE: &str = "sac.memtable.v2";
const LEGACY_PROFILE: &str = "sac.memtable.v1";
const WAL_MAGIC: &[u8; 8] = b"SACMTW01";
const RECORD_MAGIC: &[u8; 8] = b"SACMTB01";
const HEADER: u64 = 64;
const RECORD_OVERHEAD: u64 = 96;
const ENTRY_OVERHEAD: usize = 512;
/// Hex-encoded keys fit a single SAC resource name, including its `k` prefix.
const MAX_KEY: usize = 2047;
const MAX_BATCH: usize = 1024;
const MAX_VALUE: usize = 8 * 1024 * 1024;
type Table = BTreeMap<Box<[u8]>, Option<Box<[u8]>>>;

/// All limits are finite. The memory bound charges pending keys, values and a
/// conservative 512 bytes per entry (including tombstones and tree nodes).
/// Active, immutable and incoming tables share this single budget.
/// It excludes caller buffers, bounded WAL/encoding scratch and NativeStore's
/// independently bounded caches. A single batch must fit this memory bound.
#[derive(Clone, Debug)]
pub struct MemtableOptions {
    pub max_memory_bytes: usize,
    pub max_wal_bytes: u64,
    pub max_value_bytes: usize,
    /// Maximum dirty age before the worker starts a checkpoint. An in-progress
    /// operation or slow filesystem can delay completion beyond this interval.
    pub flush_interval: Duration,
    /// Bounds SAC reads and checkpoint construction, separately from the overlay.
    pub limits: Limits,
    pub compression_level: i32,
}
impl Default for MemtableOptions {
    fn default() -> Self {
        Self {
            max_memory_bytes: 16 * 1024 * 1024,
            max_wal_bytes: 64 * 1024 * 1024,
            max_value_bytes: 4 * 1024 * 1024,
            flush_interval: Duration::from_secs(1),
            limits: Limits::default(),
            compression_level: 1,
        }
    }
}
impl MemtableOptions {
    fn validate(&self) -> Result<()> {
        if self.max_memory_bytes < ENTRY_OVERHEAD
            || self.max_memory_bytes > 1024 * 1024 * 1024
            || self.max_wal_bytes < HEADER + RECORD_OVERHEAD + 13
            || self.max_wal_bytes > 1024 * 1024 * 1024 * 1024
            || self.max_value_bytes > MAX_VALUE
            || self.flush_interval.is_zero()
            || Instant::now().checked_add(self.flush_interval).is_none()
            || self.max_value_bytes as u64 > self.limits.max_file_bytes
            || self.max_value_bytes > self.limits.max_memory_bytes / 8
            || self.limits.max_depth == 0
        {
            return Err(Error::Limit("memtable options"));
        }
        Ok(())
    }
}

/// A write batch is one checksummed WAL record and one recovery unit. At most
/// 1024 mutations are accepted per call; repeated keys use their last mutation.
#[derive(Clone, Copy, Debug)]
pub enum Mutation<'a> {
    Put { key: &'a [u8], value: &'a [u8] },
    Delete { key: &'a [u8] },
}
impl<'a> Mutation<'a> {
    fn parts(self) -> (&'a [u8], Option<&'a [u8]>) {
        match self {
            Self::Put { key, value } => (key, Some(value)),
            Self::Delete { key } => (key, None),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemtableStatistics {
    pub live_entries: u64,
    pub logical_bytes: u64,
    pub pending_entries: usize,
    pub pending_memory_bytes: usize,
    /// Retained record bytes plus one header. A second segment adds one fixed
    /// 64-byte header on disk while a successor is prepared or in use.
    pub wal_bytes: u64,
    pub active_memory_bytes: usize,
    pub immutable_memory_bytes: usize,
    pub immutable_entries: usize,
    pub flush_in_progress: bool,
    pub backpressure_waits: u64,
    pub sequence: u64,
    pub checkpoint_sequence: u64,
    pub checkpoints: u64,
    pub recovered_batches: u64,
    pub discarded_tail_bytes: u64,
    /// Cumulative wall-clock attribution since open. Timings overlap between
    /// foreground and worker threads; they must not be added as process time.
    pub io: MemtableIoStatistics,
    /// The first WAL/checkpoint failure. Further operations require reopening.
    pub failure: Option<String>,
}

/// Fixed-size diagnostic counters. WAL stage totals cover successful batches;
/// checkpoint totals cover successfully returned work (failed jobs can omit
/// elapsed time). Native publication counters include attempted barriers, as
/// defined by `PublicationStatistics`.
#[derive(Clone, Copy, Debug, Default)]
pub struct MemtableIoStatistics {
    pub wal_batches: u64,
    pub wal_prepare_total_ns: u64,
    pub wal_sync_total_ns: u64,
    pub wal_sync_max_ns: u64,
    pub wal_finish_total_ns: u64,
    pub write_prepare_total_ns: u64,
    pub wal_gate_wait_total_ns: u64,
    pub admission_wait_total_ns: u64,
    pub successor_prepare_total_ns: u64,
    pub successor_sync_total_ns: u64,
    pub successor_directory_sync_total_ns: u64,
    pub handoff_wait_total_ns: u64,
    pub checkpoint_materialize_total_ns: u64,
    pub checkpoint_publish_total_ns: u64,
    pub checkpoint_pin_total_ns: u64,
    pub checkpoint_retire_total_ns: u64,
    pub native_publication: super::PublicationStatistics,
}

struct WalTiming {
    prepare_ns: u64,
    sync_ns: u64,
    finish_ns: u64,
}
#[derive(Default)]
struct CheckpointTiming {
    materialize_ns: u64,
    publish_ns: u64,
    pin_ns: u64,
}
fn elapsed_ns(start: Instant) -> u64 {
    start.elapsed().as_nanos().min(u64::MAX as u128) as u64
}

struct Frozen {
    table: Table,
    sequence: u64,
    memory: usize,
}
struct State {
    #[cfg(test)]
    fault: Option<Fault>,
    base: Arc<NativeReader>,
    snapshot: ObjectRef,
    pending: Table,
    frozen: Option<Arc<Frozen>>,
    stats: MemtableStatistics,
    dirty_since: Option<Instant>,
    requested: u64,
    stop: bool,
    options: MemtableOptions,
}
struct Wal {
    file: File,
    primary: PathBuf,
    id: [u8; 16],
    bytes: u64,
}
struct PreparedWal {
    file: File,
    primary: PathBuf,
    next: PathBuf,
}
struct Checkpoint {
    store: NativeStore,
    directory: ObjectRef,
    id: [u8; 16],
    options: MemtableOptions,
}
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fault {
    WalHeader,
    WalSync,
    WalSynced,
    Published,
    WalRenamed,
}
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Stage {
    Prepared,
    Frozen,
    Published,
    Renamed,
}
struct Shared {
    state: Mutex<State>,
    // Lock order is WAL then state. State is never held for durability barriers
    // or base reads. The WAL gate serializes foreground sync but is released
    // during SAC publication and successor file/namespace synchronization.
    wal: Mutex<Wal>,
    checkpoint: Mutex<Checkpoint>,
    path: PathBuf,
    wake: Condvar,
    #[cfg(test)]
    hook: Mutex<Option<Box<dyn Fn(Stage) + Send + Sync>>>,
}

/// Thread-safe byte-key/value storage with synchronous WAL acknowledgment.
/// Keys are arbitrary bytes, including empty keys, up to 2047 bytes. Reads
/// consult active and immutable tables, then a pinned published SAC snapshot.
/// The worker owns checkpoint I/O; writers wait only for WAL durability and
/// admission when the combined table/WAL budgets are exhausted.
///
/// A dedicated `sac.memtable.v2` profile prevents older writers from ignoring
/// the second WAL segment. `open` recovers and upgrades v1 stores durably before
/// accepting new writes. Backups must include `.wal` and any `.wal.next` file.
/// Drop joins in-flight work, retaining active WAL records; `close` flushes and
/// reports errors. An I/O error may have an indeterminate outcome: reopen before
/// retrying non-idempotent application operations.
pub struct MemtableStore {
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
}
impl MemtableStore {
    pub fn create(
        path: impl AsRef<Path>,
        incarnation: [u8; 16],
        options: MemtableOptions,
    ) -> Result<Self> {
        options.validate()?;
        let mut store = NativeStore::create_live(path, incarnation)?;
        store.set_compression_level(options.compression_level);
        let primary = wal_path(&store.path);
        if primary.try_exists()? || next_wal_path(&primary).try_exists()? {
            return Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists).into());
        }
        let directory =
            ArchiveBuilder::with_limits(&mut store, options.limits.clone()).finish_directory()?;
        let snapshot = checkpoint_snapshot(&mut store, directory, incarnation, 0)?;
        store.publish(snapshot)?;
        let mut file = private_wal(&primary)?;
        file.write_all(&wal_header(incarnation, 0))?;
        durable(&file)?;
        sync_parent(&primary)?;
        Self::start(
            Checkpoint {
                store,
                directory,
                id: incarnation,
                options: options.clone(),
            },
            Wal {
                file,
                primary,
                id: incarnation,
                bytes: HEADER,
            },
            snapshot,
            MemtableStatistics {
                wal_bytes: HEADER,
                ..Default::default()
            },
        )
    }

    /// Fully validate both WAL segments before replay. Only an incomplete last
    /// record can be discarded. Recovery checkpoints retain both original logs
    /// until the entire replay is durable, including under a smaller budget.
    pub fn open(path: impl AsRef<Path>, options: MemtableOptions) -> Result<Self> {
        options.validate()?;
        let mut store = NativeStore::open_with_recovery_check(
            path.as_ref(),
            true,
            Some(&|store| {
                let snapshot = store.reader.snapshot().ok_or(Error::Missing)?;
                let (_, id, sequence, _, _, legacy) = admit_checkpoint(store, snapshot, &options)?;
                validate_logs(&wal_path(&store.path), id, sequence, legacy, &options).map(|_| ())
            }),
        )?;
        store.set_compression_level(options.compression_level);
        let snapshot = store.reader.snapshot().ok_or(Error::Missing)?;
        let (directory, id, sequence, entries, logical_bytes, legacy) =
            admit_checkpoint(&store, snapshot, &options)?;
        let primary = wal_path(&store.path);
        let logs = validate_logs(&primary, id, sequence, legacy, &options)?;
        let stats = MemtableStatistics {
            sequence,
            checkpoint_sequence: sequence,
            live_entries: entries,
            logical_bytes,
            discarded_tail_bytes: logs.iter().map(|log| log.length - log.end).sum(),
            ..Default::default()
        };
        let mut checkpoint = Checkpoint {
            store,
            directory,
            id,
            options: options.clone(),
        };
        let mut state = State::new(Arc::new(checkpoint.store.pin()?), snapshot, stats, options);
        for log in &logs {
            let mut file = log.file.try_clone()?;
            verify_file_path(&file, &log.path)?;
            let mut cursor = HEADER;
            while let Some(record) = read_record(&mut file, cursor, log.end, &state.options)? {
                cursor = record.end;
                if record.sequence <= sequence {
                    continue;
                }
                if state
                    .stats
                    .pending_memory_bytes
                    .saturating_add(record.charge)
                    > state.options.max_memory_bytes
                {
                    checkpoint.replay_checkpoint(&mut state)?;
                }
                let batch = record.decode()?;
                let totals = state.batch_totals(&batch)?;
                state.apply(batch, totals);
                state.stats.sequence = record.sequence;
                state.stats.recovered_batches += 1;
            }
        }
        checkpoint.replay_checkpoint(&mut state)?;
        if legacy {
            // A durable capability change makes v1 writers fail closed before
            // any acknowledged records can be placed in a secondary segment.
            let snapshot = checkpoint_snapshot(
                &mut checkpoint.store,
                checkpoint.directory,
                id,
                state.stats.sequence,
            )?;
            checkpoint.store.publish(snapshot)?;
            state.snapshot = snapshot;
            state.base = Arc::new(checkpoint.store.pin()?);
        }
        // Normalize only after complete replay. Promote an empty next segment
        // FIRST. A crash before/after rename sees either both replayable logs,
        // or the new header-only primary, never an old prefix with a gap.
        let next = next_wal_path(&primary);
        let mut replacement = tempfile::Builder::new()
            .prefix(".sac-memtable-wal-")
            .tempfile_in(primary.parent().unwrap())?;
        replacement
            .as_file()
            .try_lock()
            .map_err(super::lock_error)?;
        replacement.write_all(&wal_header(id, state.stats.sequence))?;
        durable(replacement.as_file())?;
        let (file, temp) = replacement.into_parts();
        std::fs::rename(&temp, &next)?;
        sync_parent(&next)?;
        std::fs::rename(&next, &primary)?;
        sync_parent(&primary)?;
        drop(logs);
        state.stats.wal_bytes = HEADER;
        Self::start_with_state(
            checkpoint,
            Wal {
                file,
                primary,
                id,
                bytes: HEADER,
            },
            state,
        )
    }
    fn start(
        checkpoint: Checkpoint,
        wal: Wal,
        snapshot: ObjectRef,
        stats: MemtableStatistics,
    ) -> Result<Self> {
        let state = State::new(
            Arc::new(checkpoint.store.pin()?),
            snapshot,
            stats,
            checkpoint.options.clone(),
        );
        Self::start_with_state(checkpoint, wal, state)
    }
    fn start_with_state(checkpoint: Checkpoint, wal: Wal, state: State) -> Result<Self> {
        let path = checkpoint.store.path.clone();
        let shared = Arc::new(Shared {
            state: Mutex::new(state),
            wal: Mutex::new(wal),
            checkpoint: Mutex::new(checkpoint),
            wake: Condvar::new(),
            path,
            #[cfg(test)]
            hook: Mutex::new(None),
        });
        let background = shared.clone();
        let worker = thread::Builder::new()
            .name("sac-memtable".into())
            .spawn(move || {
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| worker(&background)));
                if result.is_err() {
                    background.poison("memtable checkpoint worker panicked".into());
                }
            })?;
        Ok(Self {
            shared,
            worker: Some(worker),
        })
    }
    fn state(&self) -> Result<MutexGuard<'_, State>> {
        self.shared.state.lock().map_err(|_| Error::Poisoned)
    }
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        check_key(key)?;
        let state = self.state()?;
        state.healthy()?;
        if let Some(value) = state.lookup(key) {
            return Ok(value.as_ref().map(|bytes| bytes.to_vec()));
        }
        let base = state.base.clone();
        let snapshot = state.snapshot;
        let options = state.options.clone();
        drop(state);
        let archive = ArchiveReader::open(base.as_ref(), snapshot, options.limits)?;
        Ok(archive
            .read_file_bounded(&key_path(key), options.max_value_bytes)?
            .map(|(_, bytes)| bytes))
    }
    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<u64> {
        self.write_batch(&[Mutation::Put { key, value }])
    }
    pub fn delete(&self, key: &[u8]) -> Result<u64> {
        self.write_batch(&[Mutation::Delete { key }])
    }
    pub fn write_batch(&self, mutations: &[Mutation<'_>]) -> Result<u64> {
        let options = {
            let state = self.state()?;
            state.healthy()?;
            state.options.clone()
        };
        if mutations.len() > MAX_BATCH {
            return Err(Error::Limit("memtable batch entries"));
        }
        let mut incoming = 0usize;
        for mutation in mutations {
            let (key, value) = mutation.parts();
            check_key(key)?;
            if value.is_some_and(|v| v.len() > options.max_value_bytes) {
                return Err(Error::Limit("memtable value bytes"));
            }
            incoming = incoming
                .checked_add(charge(key, value))
                .ok_or(Error::Limit("memtable memory"))?;
            if incoming > options.max_memory_bytes {
                return Err(Error::Limit("memtable batch memory"));
            }
        }
        let payload_bound = incoming - mutations.len() * (ENTRY_OVERHEAD - 13);
        if !mutations.is_empty()
            && HEADER + RECORD_OVERHEAD + payload_bound as u64 > options.max_wal_bytes
        {
            return Err(Error::Limit("memtable WAL record bytes"));
        }
        loop {
            let gate_start = Instant::now();
            let mut wal = self.shared.wal.lock().map_err(|_| Error::Poisoned)?;
            let gate_ns = elapsed_ns(gate_start);
            let mut state = self.state()?;
            state.stats.io.wal_gate_wait_total_ns = state
                .stats
                .io
                .wal_gate_wait_total_ns
                .saturating_add(gate_ns);
            state.healthy()?;
            if mutations.is_empty() {
                return Ok(state.stats.sequence);
            }
            if state.stats.pending_memory_bytes.saturating_add(incoming) > options.max_memory_bytes
                || state.stats.wal_bytes + RECORD_OVERHEAD + payload_bound as u64
                    > options.max_wal_bytes
            {
                // An existing immutable generation already promises capacity
                // retirement. Do not turn a temporary wait into a second flush
                // of newer active writes; reassess admission after retirement.
                if !state.stats.flush_in_progress {
                    state.requested = state.requested.max(state.stats.sequence);
                }
                state.stats.backpressure_waits += 1;
                self.shared.wake.notify_all();
                drop(wal);
                let wait_start = Instant::now();
                state = self.shared.wake.wait(state).map_err(|_| Error::Poisoned)?;
                state.stats.io.admission_wait_total_ns = state
                    .stats
                    .io
                    .admission_wait_total_ns
                    .saturating_add(elapsed_ns(wait_start));
                state.healthy()?;
                drop(state);
                continue;
            }
            let sequence = state
                .stats
                .sequence
                .checked_add(1)
                .ok_or(Error::Limit("memtable sequence"))?;
            drop(state);
            let prepare_start = Instant::now();
            let mut batch = Table::new();
            for mutation in mutations {
                let (key, value) = mutation.parts();
                batch.insert(key.into(), value.map(Into::into));
            }
            // The WAL mutex serializes writers and generation handoff. Base
            // lookups and the durability barrier never hold the read-state lock.
            let view = self.state()?.totals_view(&batch);
            let totals = view.calculate(&batch)?;
            let prepare_ns = elapsed_ns(prepare_start);
            let before = wal.bytes;
            let timing = match wal.append(sequence, &batch, &self.shared) {
                Ok(timing) => timing,
                Err(error) => {
                    self.shared.poison(error.to_string());
                    return Err(error);
                }
            };
            let mut state = self.state()?;
            state.healthy()?;
            let previous_bytes = state.stats.wal_bytes;
            state.apply(batch, totals);
            state.stats.sequence = sequence;
            state.stats.wal_bytes = previous_bytes + wal.bytes - before;
            let io = &mut state.stats.io;
            io.wal_batches = io.wal_batches.saturating_add(1);
            io.write_prepare_total_ns = io.write_prepare_total_ns.saturating_add(prepare_ns);
            io.wal_prepare_total_ns = io.wal_prepare_total_ns.saturating_add(timing.prepare_ns);
            io.wal_sync_total_ns = io.wal_sync_total_ns.saturating_add(timing.sync_ns);
            io.wal_sync_max_ns = io.wal_sync_max_ns.max(timing.sync_ns);
            io.wal_finish_total_ns = io.wal_finish_total_ns.saturating_add(timing.finish_ns);
            if state.dirty_since.is_none() {
                state.dirty_since = Some(Instant::now());
            }
            self.shared.wake.notify_all();
            return Ok(sequence);
        }
    }
    /// Schedule a background checkpoint and return the accepted watermark it
    /// must cover. Newer writes may continue while the worker publishes it.
    pub fn request_flush(&self) -> Result<u64> {
        let mut state = self.state()?;
        state.healthy()?;
        let target = state.stats.sequence;
        state.requested = state.requested.max(target);
        self.shared.wake.notify_all();
        Ok(target)
    }
    /// Wait until a background checkpoint covers all batches accepted before
    /// this call. Later batches remain visible in the overlay and durable WAL.
    pub fn flush(&self) -> Result<u64> {
        let target = self.request_flush()?;
        let mut state = self.state()?;
        loop {
            state.healthy()?;
            if state.stats.checkpoint_sequence >= target {
                return Ok(state.stats.checkpoint_sequence);
            }
            state = self.shared.wake.wait(state).map_err(|_| Error::Poisoned)?;
        }
    }
    pub fn statistics(&self) -> Result<MemtableStatistics> {
        let state = self.state()?;
        let mut stats = state.stats.clone();
        let base = state.base.clone();
        drop(state);
        stats.io.native_publication = base.publication_statistics();
        Ok(stats)
    }
    pub fn close(mut self) -> Result<()> {
        let result = self.flush();
        self.stop_worker();
        result.map(|_| ())
    }
    fn stop_worker(&mut self) {
        if let Some(worker) = self.worker.take() {
            let mut state = self.shared.state.lock().unwrap_or_else(|e| e.into_inner());
            state.stop = true;
            self.shared.wake.notify_all();
            drop(state);
            let _ = worker.join();
        }
    }
}
impl Drop for MemtableStore {
    fn drop(&mut self) {
        self.stop_worker();
    }
}
impl Shared {
    fn poison(&self, error: String) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.stats.failure.is_none() {
            state.stats.failure = Some(error);
        }
        self.wake.notify_all();
    }
    #[cfg(test)]
    fn fail(&self, point: Fault) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if state.fault == Some(point) {
            state.fault = None;
            return Err(
                std::io::Error::other(format!("injected memtable failure: {point:?}")).into(),
            );
        }
        Ok(())
    }
    #[cfg(test)]
    fn stage(&self, stage: Stage) {
        if let Some(hook) = self.hook.lock().unwrap().as_ref() {
            hook(stage);
        }
    }
}
impl State {
    fn memory_flush_threshold(&self) -> usize {
        // Reserve an eighth for active writes, without flushing coalescing hot
        // sets at half capacity. Admission still charges the entire incoming
        // batch against active + immutable memory before any allocation.
        self.options.max_memory_bytes - self.options.max_memory_bytes / 8
    }
    fn new(
        base: Arc<NativeReader>,
        snapshot: ObjectRef,
        stats: MemtableStatistics,
        options: MemtableOptions,
    ) -> Self {
        Self {
            #[cfg(test)]
            fault: None,
            base,
            snapshot,
            pending: Table::new(),
            frozen: None,
            stats,
            dirty_since: None,
            requested: 0,
            stop: false,
            options,
        }
    }
    fn healthy(&self) -> Result<()> {
        if self.stats.failure.is_some() {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }
    fn lookup(&self, key: &[u8]) -> Option<&Option<Box<[u8]>>> {
        self.pending
            .get(key)
            .or_else(|| self.frozen.as_ref().and_then(|f| f.table.get(key)))
    }
    fn totals_view(&self, batch: &Table) -> TotalsView {
        TotalsView {
            base: self.base.clone(),
            snapshot: self.snapshot,
            limits: self.options.limits.clone(),
            entries: self.stats.live_entries,
            bytes: self.stats.logical_bytes,
            old: batch
                .keys()
                .map(|key| {
                    self.lookup(key.as_ref())
                        .map(|value| value.as_ref().map(|v| v.len() as u64))
                })
                .collect(),
        }
    }
    fn batch_totals(&self, batch: &Table) -> Result<(u64, u64)> {
        self.totals_view(batch).calculate(batch)
    }
    fn apply(&mut self, batch: Table, totals: (u64, u64)) {
        for (key, value) in batch {
            let new_charge = charge(&key, value.as_deref());
            if let Some((old_key, old_value)) = self.pending.remove_entry(key.as_ref()) {
                self.stats.pending_memory_bytes -= charge(&old_key, old_value.as_deref());
                self.stats.active_memory_bytes -= charge(&old_key, old_value.as_deref());
            }
            self.pending.insert(key, value);
            self.stats.pending_memory_bytes += new_charge;
            self.stats.active_memory_bytes += new_charge;
        }
        self.stats.pending_entries = self.pending.len() + self.stats.immutable_entries;
        self.stats.live_entries = totals.0;
        self.stats.logical_bytes = totals.1;
    }
}
struct TotalsView {
    base: Arc<NativeReader>,
    snapshot: ObjectRef,
    limits: Limits,
    entries: u64,
    bytes: u64,
    old: Vec<Option<Option<u64>>>,
}
impl TotalsView {
    fn calculate(self, batch: &Table) -> Result<(u64, u64)> {
        let mut entries = self.entries;
        let mut bytes = self.bytes;
        let archive = ArchiveReader::open(self.base.as_ref(), self.snapshot, self.limits.clone())?;
        for ((key, value), old) in batch.iter().zip(self.old) {
            let old = match old {
                Some(value) => value,
                None => archive
                    .lookup_shared(&key_path(key))?
                    .map(|entry| {
                        entry
                            .file_length()
                            .ok_or_else(|| corrupt("memtable expected file"))
                    })
                    .transpose()?,
            };
            if let Some(length) = old {
                entries -= 1;
                bytes -= length;
            }
            if let Some(value) = value {
                entries = entries
                    .checked_add(1)
                    .ok_or(Error::Limit("memtable entries"))?;
                bytes = bytes
                    .checked_add(value.len() as u64)
                    .ok_or(Error::Limit("memtable logical bytes"))?;
            }
        }
        if entries > self.limits.max_entries || bytes > self.limits.max_logical_bytes {
            return Err(Error::Limit("memtable collection"));
        }
        Ok((entries, bytes))
    }
}

impl Wal {
    fn verify_path(&self) -> Result<()> {
        // Promotion can rename the active inode while an append is syncing.
        // Both names were durably installed before the first successor ack.
        verify_file_path(&self.file, &self.primary)
            .or_else(|_| verify_file_path(&self.file, &next_wal_path(&self.primary)))
            // Rename can occur between the first two probes. No second
            // generation can hand off while this writer holds the WAL gate.
            .or_else(|_| verify_file_path(&self.file, &self.primary))
    }
    fn append(&mut self, sequence: u64, batch: &Table, shared: &Shared) -> Result<WalTiming> {
        let prepare_start = Instant::now();
        // Native path identity is checked through the immutable descriptor,
        // independent of the checkpoint writer's mutex.
        let base = {
            shared
                .state
                .lock()
                .map_err(|_| Error::Poisoned)?
                .base
                .clone()
        };
        verify_file_path(&base.file, &shared.path)?;
        self.verify_path()?;
        if self.file.metadata()?.len() != self.bytes {
            return Err(corrupt("memtable WAL length changed"));
        }
        let payload_len: usize = batch
            .iter()
            .map(|(k, v)| 13 + k.len() + v.as_ref().map_or(0, |v| v.len()))
            .sum();
        let mut header = [0u8; 64];
        header[..8].copy_from_slice(RECORD_MAGIC);
        header[8..16].copy_from_slice(&sequence.to_le_bytes());
        header[16..24].copy_from_slice(&(payload_len as u64).to_le_bytes());
        header[24..28].copy_from_slice(&(batch.len() as u32).to_le_bytes());
        let check = digest("sac.memtable.wal.record-header.v1", &header[..32]);
        header[32..].copy_from_slice(&check);
        self.file.seek(SeekFrom::Start(self.bytes))?;
        #[cfg(test)]
        if let Err(error) = shared.fail(Fault::WalHeader) {
            // Preserve the injected header-only crash boundary. Production
            // gathers the header with payload slices in the first file write.
            self.file.write_all(&header)?;
            return Err(error);
        }
        wal_io::write_record(&mut self.file, &header, batch)?;
        #[cfg(test)]
        shared.fail(Fault::WalSync)?;
        let prepare_ns = elapsed_ns(prepare_start);
        let sync_start = Instant::now();
        durable(&self.file)?;
        let sync_ns = elapsed_ns(sync_start);
        let finish_start = Instant::now();
        #[cfg(test)]
        shared.fail(Fault::WalSynced)?;
        self.verify_path()?;
        verify_file_path(&base.file, &shared.path)?;
        self.bytes += RECORD_OVERHEAD + payload_len as u64;
        Ok(WalTiming {
            prepare_ns,
            sync_ns,
            finish_ns: elapsed_ns(finish_start),
        })
    }
}

fn private_wal(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    file.try_lock().map_err(super::lock_error)?;
    Ok(file)
}
fn next_wal_path(primary: &Path) -> PathBuf {
    let mut name = primary.as_os_str().to_os_string();
    name.push(".next");
    PathBuf::from(name)
}
fn worker(shared: &Arc<Shared>) {
    let mut prepared = None;
    loop {
        let mut state = match shared.state.lock() {
            Ok(s) => s,
            Err(_) => return,
        };
        loop {
            if state.stop {
                return;
            }
            if state.stats.failure.is_none() && !state.pending.is_empty() {
                if prepared.is_none() {
                    // Install the next empty segment during the dirty interval,
                    // overlapping its barriers with foreground WAL writes.
                    let sequence = state.stats.checkpoint_sequence;
                    drop(state);
                    match prepare_wal(shared, sequence) {
                        Ok(wal) => prepared = Some(wal),
                        Err(error) => shared.poison(error.to_string()),
                    }
                    #[cfg(test)]
                    shared.stage(Stage::Prepared);
                    state = match shared.state.lock() {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    continue;
                }
                let remaining = state
                    .options
                    .flush_interval
                    .saturating_sub(state.dirty_since.unwrap().elapsed());
                if state.requested > state.stats.checkpoint_sequence
                    || remaining.is_zero()
                    || state.stats.active_memory_bytes >= state.memory_flush_threshold()
                {
                    break;
                }
                state = match shared.wake.wait_timeout(state, remaining) {
                    Ok((s, _)) => s,
                    Err(_) => return,
                };
            } else {
                state = match shared.wake.wait(state) {
                    Ok(s) => s,
                    Err(_) => return,
                };
            }
        }
        drop(state);
        if let Err(error) = checkpoint_job(shared, prepared.take().unwrap()) {
            shared.poison(error.to_string());
        }
    }
}
fn prepare_wal(shared: &Shared, base_sequence: u64) -> Result<PreparedWal> {
    let prepare_start = Instant::now();
    let (primary, id) = {
        let wal = shared.wal.lock().map_err(|_| Error::Poisoned)?;
        (wal.primary.clone(), wal.id)
    };
    let next = next_wal_path(&primary);
    if next.try_exists()? {
        return Err(corrupt("unexpected secondary WAL"));
    }
    // Prepare and durably install the empty successor while writers continue
    // appending to the primary. No acknowledged bytes depend on a temporary name.
    let mut prepared = tempfile::Builder::new()
        .prefix(".sac-memtable-wal-")
        .tempfile_in(primary.parent().unwrap())?;
    prepared.as_file().try_lock().map_err(super::lock_error)?;
    prepared.write_all(&wal_header(id, base_sequence))?;
    let sync_start = Instant::now();
    durable(prepared.as_file())?;
    let sync_ns = elapsed_ns(sync_start);
    let file = prepared
        .persist_noclobber(&next)
        .map_err(|error| error.error)?;
    let directory_start = Instant::now();
    sync_parent(&next)?;
    let directory_ns = elapsed_ns(directory_start);
    let mut state = shared.state.lock().map_err(|_| Error::Poisoned)?;
    let io = &mut state.stats.io;
    io.successor_prepare_total_ns = io
        .successor_prepare_total_ns
        .saturating_add(elapsed_ns(prepare_start));
    io.successor_sync_total_ns = io.successor_sync_total_ns.saturating_add(sync_ns);
    io.successor_directory_sync_total_ns = io
        .successor_directory_sync_total_ns
        .saturating_add(directory_ns);
    drop(state);
    Ok(PreparedWal {
        file,
        primary,
        next,
    })
}
fn checkpoint_job(shared: &Shared, prepared: PreparedWal) -> Result<()> {
    let PreparedWal {
        file,
        primary,
        next,
    } = prepared;
    let successor = file.try_clone()?;
    let handoff_start = Instant::now();
    let (frozen, old_file, old_bytes) = {
        let mut wal = shared.wal.lock().map_err(|_| Error::Poisoned)?;
        verify_file_path(&wal.file, &primary)?;
        let mut state = shared.state.lock().map_err(|_| Error::Poisoned)?;
        state.healthy()?;
        state.stats.io.handoff_wait_total_ns = state
            .stats
            .io
            .handoff_wait_total_ns
            .saturating_add(elapsed_ns(handoff_start));
        let frozen = Arc::new(Frozen {
            table: std::mem::take(&mut state.pending),
            sequence: state.stats.sequence,
            memory: state.stats.active_memory_bytes,
        });
        state.frozen = Some(frozen.clone());
        state.dirty_since = None;
        state.stats.immutable_entries = frozen.table.len();
        state.stats.immutable_memory_bytes = frozen.memory;
        state.stats.active_memory_bytes = 0;
        state.stats.flush_in_progress = true;
        let old_file = std::mem::replace(&mut wal.file, file);
        let old_bytes = std::mem::replace(&mut wal.bytes, HEADER);
        (frozen, old_file, old_bytes)
    };
    #[cfg(test)]
    shared.stage(Stage::Frozen);
    let (snapshot, base, timing) = {
        let mut checkpoint = shared.checkpoint.lock().map_err(|_| Error::Poisoned)?;
        checkpoint.publish(&frozen.table, frozen.sequence)?
    };
    {
        let mut state = shared.state.lock().map_err(|_| Error::Poisoned)?;
        let io = &mut state.stats.io;
        io.checkpoint_materialize_total_ns = io
            .checkpoint_materialize_total_ns
            .saturating_add(timing.materialize_ns);
        io.checkpoint_publish_total_ns = io
            .checkpoint_publish_total_ns
            .saturating_add(timing.publish_ns);
        io.checkpoint_pin_total_ns = io.checkpoint_pin_total_ns.saturating_add(timing.pin_ns);
    }
    #[cfg(test)]
    shared.stage(Stage::Published);
    #[cfg(test)]
    shared.fail(Fault::Published)?;
    let retire_start = Instant::now();
    // The writer accepts either installed name for this same inode, so even
    // rename and directory sync require neither the WAL gate nor state lock.
    verify_file_path(&old_file, &primary)?;
    verify_file_path(&successor, &next)?;
    std::fs::rename(&next, &primary)?;
    #[cfg(test)]
    shared.stage(Stage::Renamed);
    #[cfg(test)]
    shared.fail(Fault::WalRenamed)?;
    sync_parent(&primary)?;
    drop(old_file);
    let sequence = frozen.sequence;
    let memory = frozen.memory;
    let (retired, old_base) = {
        let mut state = shared.state.lock().map_err(|_| Error::Poisoned)?;
        let old_base = std::mem::replace(&mut state.base, Arc::new(base));
        state.snapshot = snapshot;
        (state.frozen.take(), old_base)
    };
    // Deallocating a large tree and retiring the old reader's lease can take
    // time. Keep their budget charged, but do both outside the foreground lock.
    drop(frozen);
    drop(retired);
    drop(old_base);
    drop(successor);
    let mut state = shared.state.lock().map_err(|_| Error::Poisoned)?;
    state.stats.pending_memory_bytes -= memory;
    state.stats.pending_entries = state.pending.len();
    state.stats.immutable_entries = 0;
    state.stats.immutable_memory_bytes = 0;
    state.stats.flush_in_progress = false;
    state.stats.wal_bytes -= old_bytes - HEADER;
    state.stats.checkpoint_sequence = sequence;
    state.stats.checkpoints += 1;
    state.stats.io.checkpoint_retire_total_ns = state
        .stats
        .io
        .checkpoint_retire_total_ns
        .saturating_add(elapsed_ns(retire_start));
    shared.wake.notify_all();
    Ok(())
}

impl Checkpoint {
    fn publish(
        &mut self,
        table: &Table,
        sequence: u64,
    ) -> Result<(ObjectRef, NativeReader, CheckpointTiming)> {
        let materialize_start = Instant::now();
        self.store.verify_current_path()?;
        let mut builder = ArchiveBuilder::from_directory(
            &mut self.store,
            self.directory,
            self.options.limits.clone(),
        );
        let mut puts = Vec::new();
        let mut put_memory = 0usize;
        for (key, value) in table {
            let path = key_path(key);
            if let Some(bytes) = value {
                let weight = bytes
                    .len()
                    .saturating_mul(4)
                    .saturating_add(path[0].len().saturating_mul(4))
                    .saturating_add(2048);
                // Reserve half the resource workspace for authenticated pages,
                // recursion and page encoding. Flush chunks without copying
                // value buffers out of the overlay.
                if !puts.is_empty()
                    && (puts.len() == 512
                        || put_memory.saturating_add(weight)
                            > self.options.limits.max_memory_bytes / 2)
                {
                    let edits: Vec<_> = puts
                        .iter()
                        .map(|(name, value): &(Vec<u8>, &[u8])| (name.as_slice(), *value))
                        .collect();
                    builder.set_root_files_batch(&edits)?;
                    puts.clear();
                    put_memory = 0;
                }
                puts.push((path.into_iter().next().unwrap(), bytes.as_ref()));
                put_memory += weight;
            } else if let Err(error) = builder.remove_file(&path)
                && !matches!(error, Error::Missing)
            {
                return Err(error);
            }
        }
        if !puts.is_empty() {
            let edits: Vec<_> = puts
                .iter()
                .map(|(name, value)| (name.as_slice(), *value))
                .collect();
            builder.set_root_files_batch(&edits)?;
        }
        let directory = builder.finish_directory()?;
        let snapshot = checkpoint_snapshot(&mut self.store, directory, self.id, sequence)?;
        let materialize_ns = elapsed_ns(materialize_start);
        let publish_start = Instant::now();
        self.store.publish(snapshot)?;
        let publish_ns = elapsed_ns(publish_start);
        self.directory = directory;
        let pin_start = Instant::now();
        let pin = self.store.pin()?;
        Ok((
            snapshot,
            pin,
            CheckpointTiming {
                materialize_ns,
                publish_ns,
                pin_ns: elapsed_ns(pin_start),
            },
        ))
    }
    fn replay_checkpoint(&mut self, state: &mut State) -> Result<()> {
        if state.pending.is_empty() {
            return Ok(());
        }
        let (snapshot, base, _) = self.publish(&state.pending, state.stats.sequence)?;
        state.snapshot = snapshot;
        state.base = Arc::new(base);
        state.pending.clear();
        state.stats.pending_entries = 0;
        state.stats.pending_memory_bytes = 0;
        state.stats.active_memory_bytes = 0;
        state.stats.checkpoint_sequence = state.stats.sequence;
        state.stats.checkpoints += 1;
        Ok(())
    }
}

fn charge(key: &[u8], value: Option<&[u8]>) -> usize {
    ENTRY_OVERHEAD + key.len() + value.map_or(0, |v| v.len())
}
fn check_key(key: &[u8]) -> Result<()> {
    if key.len() > MAX_KEY {
        Err(Error::Limit("memtable key bytes"))
    } else {
        Ok(())
    }
}
fn key_path(key: &[u8]) -> Vec<Vec<u8>> {
    vec![format!("k{}", hex::encode(key)).into_bytes()]
}
fn wal_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".wal");
    PathBuf::from(name)
}
fn digest(domain: &str, bytes: &[u8]) -> [u8; 32] {
    blake3::derive_key(domain, bytes)
}
fn wal_header(id: [u8; 16], sequence: u64) -> [u8; 64] {
    let mut bytes = [0; 64];
    bytes[..8].copy_from_slice(WAL_MAGIC);
    bytes[8..24].copy_from_slice(&id);
    bytes[24..32].copy_from_slice(&sequence.to_le_bytes());
    let check = digest("sac.memtable.wal.header.v1", &bytes[..32]);
    bytes[32..].copy_from_slice(&check);
    bytes
}
fn checkpoint_snapshot(
    store: &mut NativeStore,
    directory: ObjectRef,
    id: [u8; 16],
    sequence: u64,
) -> Result<ObjectRef> {
    use cbor::Value;
    let payload = cbor::encode(&Value::Array(vec![
        Value::Bytes(id.to_vec()),
        Value::Uint(sequence),
    ]));
    let root = store.put(
        8,
        1,
        &cbor::encode(&Value::Array(vec![
            Value::Text(PROFILE.into()),
            Value::Text("root".into()),
            Value::Uint(1),
            Value::Bytes(payload),
        ])),
        &[directory],
    )?;
    resources::snapshot(
        store,
        directory,
        vec![Profile {
            id: PROFILE.into(),
            version: 1,
            root,
        }],
        Vec::new(),
    )
}

fn admit_checkpoint(
    store: &NativeStore,
    snapshot: ObjectRef,
    options: &MemtableOptions,
) -> Result<(ObjectRef, [u8; 16], u64, u64, u64, bool)> {
    use cbor::Value;
    let object = store.get_verified_shared(snapshot)?;
    let body = cbor::decode(&object.bytes)?;
    let fields = super::super::schema::array(&body, 3)?;
    let profiles = match &fields[1] {
        Value::Array(profiles) => profiles,
        _ => return Err(corrupt("memtable profiles")),
    };
    if profiles.len() != 1 || fields[2] != Value::Array(Vec::new()) {
        return Err(Error::Unsupported(
            "memtable needs its dedicated profile".into(),
        ));
    }
    let profile = super::super::schema::array(&profiles[0], 3)?;
    let legacy = profile[0] == Value::Text(LEGACY_PROFILE.into());
    if (!legacy && profile[0] != Value::Text(PROFILE.into())) || profile[1] != Value::Uint(1) {
        return Err(Error::Unsupported("memtable profile".into()));
    }
    let index = super::super::schema::uint(&profile[2])? as usize;
    let root = store.get_verified_shared(
        *object
            .children
            .get(index)
            .ok_or_else(|| corrupt("memtable profile index"))?,
    )?;
    let body = cbor::decode(&root.bytes)?;
    let fields = super::super::schema::array(&body, 4)?;
    if root.kind != 8
        || root.version != 1
        || root.children.len() != 1
        || fields[0] != profile[0]
        || fields[1] != Value::Text("root".into())
        || fields[2] != Value::Uint(1)
    {
        return Err(corrupt("memtable profile root"));
    }
    let Value::Bytes(payload) = &fields[3] else {
        return Err(corrupt("memtable checkpoint payload"));
    };
    let body = cbor::decode(payload)?;
    let fields = super::super::schema::array(&body, 2)?;
    let Value::Bytes(id) = &fields[0] else {
        return Err(corrupt("memtable identity"));
    };
    let id: [u8; 16] = id
        .as_slice()
        .try_into()
        .map_err(|_| corrupt("memtable identity length"))?;
    if id == [0; 16] {
        return Err(corrupt("memtable zero identity"));
    }
    let sequence = super::super::schema::uint(&fields[1])?;
    let archive = ArchiveReader::open(store, snapshot, options.limits.clone())?;
    if root.children[0].hash != archive.directory_root().hash {
        return Err(corrupt("memtable profile directory binding"));
    }
    store.validate_reference(root.children[0])?;
    // The owning profile certifies flat, canonical key names and routed absence.
    // Walking authenticates directory structure without hydrating file contents.
    let mut entries = 0u64;
    let mut bytes = 0u64;
    archive.visit_entries(&mut |entry| {
        if entry.kind != EntryKind::File
            || entry.path.len() != 1
            || entry.metadata != Value::Map(Vec::new())
        {
            return Err(corrupt("memtable resource shape"));
        }
        let name = &entry.path[0];
        if name.first() != Some(&b'k')
            || name.len() % 2 != 1
            || name[1..]
                .iter()
                .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(b))
        {
            return Err(corrupt("memtable key encoding"));
        }
        if name.len() > MAX_KEY * 2 + 1 || entry.length > options.max_value_bytes as u64 {
            return Err(Error::Limit("memtable checkpoint entry"));
        }
        entries += 1;
        bytes = bytes
            .checked_add(entry.length)
            .ok_or(Error::Limit("memtable logical bytes"))?;
        Ok(())
    })?;
    Ok((
        archive.directory_root(),
        id,
        sequence,
        entries,
        bytes,
        legacy,
    ))
}

struct Record {
    sequence: u64,
    end: u64,
    payload: Vec<u8>,
    charge: usize,
}
struct Log {
    file: File,
    path: PathBuf,
    length: u64,
    end: u64,
}
fn validate_logs(
    primary: &Path,
    id: [u8; 16],
    checkpoint: u64,
    legacy: bool,
    options: &MemtableOptions,
) -> Result<Vec<Log>> {
    let mut logs = Vec::new();
    let mut previous: Option<u64> = None;
    let mut retained = HEADER;
    for path in [primary.to_path_buf(), next_wal_path(primary)] {
        if path != primary && !path.try_exists()? {
            break;
        }
        if path != primary && legacy {
            return Err(corrupt("secondary WAL on legacy store"));
        }
        let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
        file.try_lock().map_err(super::lock_error)?;
        verify_file_path(&file, &path)?;
        let mut header = [0; HEADER as usize];
        file.read_exact(&mut header)?;
        if &header[..8] != WAL_MAGIC
            || header[8..24] != id
            || digest("sac.memtable.wal.header.v1", &header[..32]) != header[32..]
        {
            return Err(corrupt("memtable WAL header"));
        }
        let base = u64::from_le_bytes(header[24..32].try_into().unwrap());
        if base > checkpoint {
            return Err(corrupt("memtable WAL is ahead of SAC checkpoint"));
        }
        let length = file.metadata()?.len();
        retained = retained
            .checked_add(length.saturating_sub(HEADER))
            .ok_or(Error::Limit("memtable WAL bytes"))?;
        if retained > options.max_wal_bytes {
            return Err(Error::Limit("memtable WAL bytes"));
        }
        let mut offset = HEADER;
        while let Some(record) = read_record(&mut file, offset, length, options)? {
            if let Some(previous) = previous {
                if previous.checked_add(1) != Some(record.sequence) {
                    return Err(corrupt("memtable WAL sequence"));
                }
            } else if record.sequence <= base
                || (record.sequence != base + 1
                    && (legacy || record.sequence > checkpoint.saturating_add(1)))
            {
                return Err(corrupt("memtable WAL initial sequence"));
            }
            if logs.last().is_some_and(|log: &Log| log.end != log.length) {
                return Err(corrupt("incomplete WAL before successor records"));
            }
            previous = Some(record.sequence);
            offset = record.end;
        }
        logs.push(Log {
            file,
            path,
            length,
            end: offset,
        });
    }
    Ok(logs)
}

impl Record {
    fn decode(&self) -> Result<Table> {
        let mut batch = Table::new();
        walk_payload(&self.payload, |key, value| {
            batch.insert(key.into(), value.map(Into::into));
            Ok(())
        })?;
        Ok(batch)
    }
}
fn walk_payload<'a>(
    mut payload: &'a [u8],
    mut visit: impl FnMut(&'a [u8], Option<&'a [u8]>) -> Result<()>,
) -> Result<usize> {
    let mut count = 0;
    let mut previous: Option<&[u8]> = None;
    while !payload.is_empty() {
        if payload.len() < 13 || payload[0] > 1 {
            return Err(corrupt("memtable WAL mutation"));
        }
        let key_len = u32::from_le_bytes(payload[1..5].try_into().unwrap()) as usize;
        let value_len = usize::try_from(u64::from_le_bytes(payload[5..13].try_into().unwrap()))
            .map_err(|_| Error::Limit("memtable WAL value"))?;
        let end = 13usize
            .checked_add(key_len)
            .and_then(|n| n.checked_add(value_len))
            .ok_or(Error::Limit("memtable WAL mutation bytes"))?;
        if end > payload.len()
            || key_len > MAX_KEY
            || value_len > MAX_VALUE
            || (payload[0] == 0 && value_len != 0)
        {
            return Err(corrupt("memtable WAL mutation lengths"));
        }
        let key = &payload[13..13 + key_len];
        if previous.is_some_and(|p| p >= key) {
            return Err(corrupt("memtable WAL key order"));
        }
        visit(
            key,
            (payload[0] == 1).then_some(&payload[13 + key_len..end]),
        )?;
        previous = Some(key);
        payload = &payload[end..];
        count += 1;
        if count > MAX_BATCH {
            return Err(Error::Limit("memtable WAL batch entries"));
        }
    }
    Ok(count)
}
fn read_record(
    file: &mut File,
    offset: u64,
    length: u64,
    options: &MemtableOptions,
) -> Result<Option<Record>> {
    if length.saturating_sub(offset) < HEADER {
        return Ok(None);
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut header = [0; 64];
    file.read_exact(&mut header)?;
    if &header[..8] != RECORD_MAGIC
        || header[28..32] != [0; 4]
        || digest("sac.memtable.wal.record-header.v1", &header[..32]) != header[32..]
    {
        return Err(corrupt("memtable WAL record header"));
    }
    let sequence = u64::from_le_bytes(header[8..16].try_into().unwrap());
    let bytes = u64::from_le_bytes(header[16..24].try_into().unwrap());
    let count = u32::from_le_bytes(header[24..28].try_into().unwrap()) as usize;
    if bytes > options.max_memory_bytes as u64
        || bytes > options.max_wal_bytes
        || count == 0
        || count > MAX_BATCH
    {
        return Err(Error::Limit("memtable WAL record"));
    }
    let end = offset
        .checked_add(RECORD_OVERHEAD)
        .and_then(|n| n.checked_add(bytes))
        .ok_or(Error::Limit("memtable WAL offset"))?;
    if end > length {
        return Ok(None);
    }
    let mut payload =
        vec![0; usize::try_from(bytes).map_err(|_| Error::Limit("memtable WAL payload"))?];
    file.read_exact(&mut payload)?;
    let mut check = [0; 32];
    file.read_exact(&mut check)?;
    let mut hash = blake3::Hasher::new_derive_key("sac.memtable.wal.record.v1");
    hash.update(&header[..32]);
    hash.update(&payload);
    if hash.finalize().as_bytes() != &check {
        return Err(corrupt("memtable WAL checksum"));
    }
    let mut charge_bytes = 0usize;
    let actual = walk_payload(&payload, |key, value| {
        if value.is_some_and(|v| v.len() > options.max_value_bytes) {
            return Err(Error::Limit("memtable WAL value bytes"));
        }
        charge_bytes = charge_bytes
            .checked_add(charge(key, value))
            .ok_or(Error::Limit("memtable recovery memory"))?;
        if charge_bytes > options.max_memory_bytes {
            return Err(Error::Limit("memtable recovery memory"));
        }
        Ok(())
    })?;
    if actual != count {
        return Err(corrupt("memtable WAL mutation count"));
    }
    Ok(Some(Record {
        sequence,
        end,
        payload,
        charge: charge_bytes,
    }))
}

#[cfg(test)]
mod tests;
