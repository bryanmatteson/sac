//! Canonical native SAC1 storage. Published objects are immutable; only the
//! fenced alternate slot changes in place. Disposable indexes confer no authority.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
pub(crate) mod graph;
#[cfg(unix)]
mod leases;
#[cfg(unix)]
mod maintenance;
#[cfg(unix)]
mod platform;
mod spill;
mod temporary;
#[cfg(unix)]
pub use maintenance::{OnlineReclamation, ReclamationOptions, ReclamationStatistics};
pub use spill::ClosureCopy;
use spill::{DiskRefs, DiskStack};
pub use temporary::TemporaryIoStatistics;
include!("native/cache.rs");
include!("native/metrics.rs");

pub struct NativeStore {
    #[cfg(unix)]
    free_frames: Option<maintenance::FreeFrames>,
    #[cfg(unix)]
    reader_lease: Option<leases::Lease>,
    reused_unpublished: bool,
    file: Mutex<File>,
    append_buffer: Mutex<AppendBuffer>,
    path: PathBuf,
    reader: Reader,
    end: u64,
    writable: bool,
    poisoned: bool,
    pending: Option<tempfile::TempPath>,
    // Persistent destination-domain fence survives inode replacement. The
    // data-file lock additionally excludes writers through hard-link aliases.
    fence: Option<File>,
    recent: DiskRefs,
    cache: Arc<CacheLock>,
    file_identity: u64,
    generation: Arc<FileGeneration>,
    io: Arc<PhysicalCounters>,
    publication_fault: Option<PublicationFault>,
    compression_level: i32,
    encoder: wire::FrameEncoder,
    compaction_active: Arc<std::sync::atomic::AtomicBool>,
    compaction_target: bool,
    recovery_preserved: Option<PathBuf>,
    last_compaction_statistics: Option<CompactionStatistics>,
    last_compaction_attempt_statistics: Option<CompactionStatistics>,
    compaction_cleanup: Mutex<Option<PendingCompactionCleanup>>,
    max_file_bytes: u64,
    temporary_extent: Option<temporary::Reservation>,
    staging_temporary_budget: Option<temporary::Budget>,
    control_roots: Vec<ObjectRef>,
    encode_threads: usize,
    // The directory that holds the destination, for the check before each
    // write. None for a read-only store and on a host without `fstatat`.
    #[cfg_attr(not(unix), allow(dead_code))]
    directory: Option<File>,
    // The device and inode of `file`, which do not change while it is open.
    // Empty until the first check and after `file` is replaced.
    #[cfg_attr(not(unix), allow(dead_code))]
    node: std::sync::OnceLock<(u64, u64)>,
}
// Coalesce small immutable frames before positional I/O. Reads that miss the
// authenticated object cache drain this buffer only when they need buffered
// bytes; publication drains it before its trailer and durability barrier.
// No unflushed bytes confer durable authority, and a failed drain poisons
// subsequent writes.
const APPEND_BUFFER_BYTES: usize = 64 * 1024;
#[derive(Default)]
struct AppendBuffer {
    offset: u64,
    bytes: Vec<u8>,
    failed: bool,
}
fn flush_append(file: &Mutex<File>, buffer: &Mutex<AppendBuffer>) -> Result<()> {
    let mut buffer = buffer.lock().unwrap();
    if buffer.failed {
        return Err(Error::Poisoned);
    }
    if !buffer.bytes.is_empty() {
        if let Err(error) = write_at(&mut file.lock().unwrap(), &buffer.bytes, buffer.offset) {
            buffer.failed = true;
            return Err(error);
        }
        buffer.bytes.clear();
    }
    Ok(())
}
fn append_frame(
    file: &Mutex<File>,
    buffer: &Mutex<AppendBuffer>,
    offset: u64,
    frame: &[u8],
) -> Result<()> {
    {
        let buffer = buffer.lock().unwrap();
        if buffer.failed {
            return Err(Error::Poisoned);
        }
        if !buffer.bytes.is_empty()
            && buffer.offset.checked_add(buffer.bytes.len() as u64) != Some(offset)
        {
            return Err(corrupt("noncontiguous append buffer"));
        }
    }
    if buffer.lock().unwrap().bytes.len() + frame.len() > APPEND_BUFFER_BYTES {
        flush_append(file, buffer)?;
    }
    let mut buffer = buffer.lock().unwrap();
    if frame.len() >= APPEND_BUFFER_BYTES {
        if let Err(error) = write_at(&mut file.lock().unwrap(), frame, offset) {
            buffer.failed = true;
            return Err(error);
        }
    } else {
        if buffer.bytes.is_empty() {
            buffer.offset = offset;
        }
        buffer.bytes.extend_from_slice(frame);
    }
    Ok(())
}
/// The open directory of a writable destination.
fn destination_directory(path: &Path) -> Result<Option<File>> {
    #[cfg(unix)]
    {
        Ok(Some(File::open(
            path.parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(None)
    }
}
fn options(writable: bool) -> OpenOptions {
    let mut o = OpenOptions::new();
    o.read(true).write(writable);
    o
}
fn lock_error(error: std::fs::TryLockError) -> Error {
    match error {
        std::fs::TryLockError::WouldBlock => Error::Busy,
        std::fs::TryLockError::Error(error) => error.into(),
    }
}
fn publication_fence(path: &Path) -> Result<(PathBuf, File)> {
    #[cfg(not(unix))]
    {
        let _ = path;
        return Err(Error::Unsupported(
            "native writable host requires namespace durability".into(),
        ));
    }
    let parent = std::fs::canonicalize(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?;
    let name = path
        .file_name()
        .ok_or_else(|| corrupt("destination filename"))?;
    let path = parent.join(name);
    let lock_name = format!(
        ".sac1-publication-{}.lock",
        blake3::hash(name.as_encoded_bytes()).to_hex()
    );
    let fence = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(parent.join(lock_name))?;
    fence.try_lock().map_err(lock_error)?;
    Ok((path, fence))
}
impl NativeStore {
    /// Create an unpublished live container. The incarnation binds its physical
    /// locators and must be fresh whenever a file is replaced.
    pub fn create_live(path: impl AsRef<Path>, incarnation: [u8; 16]) -> Result<Self> {
        Self::create_policy(path.as_ref(), wire::Preamble::live(incarnation)?)
    }
    pub fn create(path: impl AsRef<Path>, header: Header) -> Result<Self> {
        Self::create_policy(path.as_ref(), header.preamble()?)
    }
    pub fn create_sealed(path: impl AsRef<Path>, _header: Header) -> Result<Self> {
        Self::create_policy(path.as_ref(), wire::Preamble::sealed())
    }
    fn create_policy(path: &Path, preamble: wire::Preamble) -> Result<Self> {
        let (path, fence) = publication_fence(path)?;
        if path.try_exists()? {
            return Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists).into());
        }
        let directory = destination_directory(&path)?;
        let temporary = tempfile::Builder::new()
            .prefix(".sac1-create-")
            .tempfile_in(path.parent().unwrap())?;
        let (mut file, pending) = temporary.into_parts();
        #[cfg(unix)]
        platform::random_reads(&file);
        file.try_lock().map_err(lock_error)?;
        let first = preamble.first_record_offset();
        let mut bootstrap = vec![0; first as usize];
        bootstrap[..128].copy_from_slice(&preamble.encode());
        file.write_all(&bootstrap)?;
        Ok(Self {
            #[cfg(unix)]
            free_frames: None,
            #[cfg(unix)]
            reader_lease: None,
            reused_unpublished: false,
            file: Mutex::new(file),
            append_buffer: Mutex::new(AppendBuffer::default()),
            path,
            reader: Reader::from_parts(preamble, None, first, Vec::new()),
            end: first,
            writable: true,
            poisoned: false,
            pending: Some(pending),
            fence: Some(fence),
            recent: DiskRefs::new()?,
            cache: new_cache(),
            file_identity: next_file_identity(),
            generation: Arc::new(FileGeneration::default()),
            io: Arc::new(PhysicalCounters::default()),
            publication_fault: None,
            compression_level: 1,
            encoder: wire::FrameEncoder::default(),
            compaction_target: false,
            recovery_preserved: None,
            last_compaction_statistics: None,
            last_compaction_attempt_statistics: None,
            compaction_cleanup: Mutex::new(None),
            max_file_bytes: u64::MAX,
            temporary_extent: None,
            staging_temporary_budget: None,
            control_roots: Vec::new(),
            encode_threads: 1,
            directory,
            node: std::sync::OnceLock::new(),
            compaction_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }
    pub fn open(path: impl AsRef<Path>, writable: bool) -> Result<Self> {
        let (path, fence) = if writable {
            let (p, f) = publication_fence(path.as_ref())?;
            (p, Some(f))
        } else {
            (path.as_ref().into(), None)
        };
        let mut file = options(writable).open(&path)?;
        #[cfg(unix)]
        platform::random_reads(&file);
        if writable {
            file.try_lock().map_err(lock_error)?;
            verify_file_path(&file, &path)?;
        }
        let directory = if writable {
            destination_directory(&path)?
        } else {
            None
        };
        #[cfg(unix)]
        if writable {
            maintenance::recover(&mut file)?;
        }
        #[cfg(unix)]
        let admission = {
            let mut header = [0; 128];
            read_at(&file, &mut header, 0)?;
            if header[8] == 1 {
                let dir = leases::domain(&file)?;
                let gate = leases::gate(&dir, false)?;
                if leases::pending(&dir) {
                    return Err(Error::RecoveryRequired);
                }
                Some(gate)
            } else {
                None
            }
        };
        let io = Arc::new(PhysicalCounters::default());
        let reader = admit_file(&file, &io)?;
        if writable && reader.header.policy != wire::LocatorPolicy::Live {
            return Err(Error::Unsupported("sealed files are immutable".into()));
        }
        if writable && !reader.recovery_diagnostics.is_empty() {
            return Err(Error::RecoveryRequired);
        }
        let end = reader.committed_end();
        let has_suffix = file.metadata()?.len() != end;
        let mut store = Self {
            #[cfg(unix)]
            free_frames: None,
            #[cfg(unix)]
            reader_lease: None,
            reused_unpublished: false,
            file: Mutex::new(file),
            append_buffer: Mutex::new(AppendBuffer::default()),
            path,
            reader,
            end,
            writable,
            poisoned: false,
            pending: None,
            fence,
            recent: DiskRefs::new()?,
            cache: new_cache(),
            file_identity: next_file_identity(),
            generation: Arc::new(FileGeneration::default()),
            io,
            publication_fault: None,
            compression_level: 1,
            encoder: wire::FrameEncoder::default(),
            compaction_target: false,
            recovery_preserved: None,
            last_compaction_statistics: None,
            last_compaction_attempt_statistics: None,
            compaction_cleanup: Mutex::new(None),
            max_file_bytes: u64::MAX,
            temporary_extent: None,
            staging_temporary_budget: None,
            control_roots: Vec::new(),
            encode_threads: 1,
            directory,
            node: std::sync::OnceLock::new(),
            compaction_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        #[cfg(unix)]
        {
            if !writable && store.reader.header.policy == wire::LocatorPolicy::Live {
                store.reader_lease = Some(leases::Lease::register(
                    store.file.get_mut().unwrap(),
                    &store.reader,
                )?);
            }
            drop(admission);
        }
        // A complete cached slot is not evidence of durability. Stabilize both
        // ordered phases before granting a writer a durable no-op baseline.
        if writable && has_suffix {
            let mut job = store.begin_compaction()?;
            job.budget.preserve_recovery_input = true;
            job.budget.max_pause = Duration::from_secs(3600);
            job.budget.max_elapsed = Duration::from_secs(3600);
            job.copy()?;
            store.finish_compaction(job)?;
        }
        if writable {
            let publication = store
                .root()
                .ok_or_else(|| corrupt("live database has no publication"))?;
            let trailer_offset = publication.committed_end - 160;
            let trailer = read_trailer(
                &store.file.lock().unwrap(),
                &store.reader.header,
                trailer_offset,
                &store.io,
            )?;
            let slot = wire::Slot {
                preamble_digest: store.reader.header.digest(),
                generation: publication.generation,
                trailer_offset,
                trailer_digest: trailer.digest(),
            };
            store.barrier(false)?;
            store.write_publication_slot(&slot.encode(), publication.generation)?;
            store.barrier(true)?;
            verify_file_path(store.file.get_mut().unwrap(), &store.path)?;
        }
        Ok(store)
    }
    pub fn verify_current_path(&self) -> Result<()> {
        if self.pending.is_some() {
            if self.path.try_exists()? {
                return Err(corrupt("destination appeared during private creation"));
            }
            Ok(())
        } else {
            verify_file_path(&self.file.lock().unwrap(), &self.path)
        }
    }
    /// Let resource builders hash and compress up to `threads` byte objects
    /// at the same time. The store still appends the frames one at a time, in
    /// the order of the puts, so the file has the same bytes as with one
    /// thread. The default is one thread. Each encoder thread holds one object
    /// and its frame, in addition to the caller's operation memory limit.
    pub fn set_encode_threads(&mut self, threads: usize) {
        self.encode_threads = threads.clamp(1, 64);
    }
    /// The check before each write: the destination name, in the directory
    /// that this writer opened, still names this writer's file. One lookup
    /// from the open directory replaces a walk of the complete path. A
    /// replaced or removed destination file fails here. A replaced ancestor
    /// directory does not; every publication and maintenance operation
    /// examines the complete path with [`Self::verify_current_path`].
    fn verify_destination_entry(&self) -> Result<()> {
        #[cfg(unix)]
        if let (Some(directory), Some(name)) = (&self.directory, self.path.file_name()) {
            use std::os::unix::fs::MetadataExt;
            let named = rustix::fs::statat(directory, name, rustix::fs::AtFlags::empty());
            if self.pending.is_some() {
                return match named {
                    Err(rustix::io::Errno::NOENT) => Ok(()),
                    Err(error) => Err(std::io::Error::from(error).into()),
                    Ok(_) => Err(corrupt("destination appeared during private creation")),
                };
            }
            let named = named.map_err(std::io::Error::from)?;
            let retained = match self.node.get() {
                Some(node) => *node,
                None => {
                    let metadata = self.file.lock().unwrap().metadata()?;
                    *self.node.get_or_init(|| (metadata.dev(), metadata.ino()))
                }
            };
            // The same integer conversions as `MetadataExt`.
            return if (named.st_dev as u64, named.st_ino as u64) == retained {
                Ok(())
            } else {
                Err(corrupt(
                    "stale publication: destination names a different incarnation",
                ))
            };
        }
        self.verify_current_path()
    }
    pub fn preserved_recovery_input(&self) -> Option<&Path> {
        self.recovery_preserved.as_deref()
    }
    /// Most recent fence attempt, including a rejected private candidate.
    pub fn last_compaction_attempt_statistics(&self) -> Option<&CompactionStatistics> {
        self.last_compaction_attempt_statistics.as_ref()
    }
    pub fn last_compaction_statistics(&self) -> Option<&CompactionStatistics> {
        self.last_compaction_statistics.as_ref()
    }
    /// Recovery links awaiting bounded background namespace garbage collection.
    /// A failed cleanup preserves its path and prevents another candidate.
    pub fn compaction_cleanup_statistics(&self) -> CompactionCleanupStatistics {
        let mut pending = self.compaction_cleanup.lock().unwrap();
        if let Some(cleanup) = pending.as_mut()
            && cleanup.task.as_ref().is_some_and(|task| task.is_finished())
        {
            match cleanup.task.take().unwrap().join() {
                Ok(Ok(())) => {
                    *pending = None;
                }
                Ok(Err(error)) => cleanup.error = Some(error.to_string()),
                Err(_) => cleanup.error = Some("cleanup worker panicked".into()),
            }
        }
        pending
            .as_ref()
            .map_or_else(CompactionCleanupStatistics::default, |cleanup| {
                CompactionCleanupStatistics {
                    retained_inode_bytes: cleanup.bytes,
                    recovery_path: Some(cleanup.path.clone()),
                    error: cleanup.error.clone(),
                }
            })
    }
    pub fn root(&self) -> Option<Publication> {
        self.reader.publication
    }
    pub fn reader(&self) -> &Reader {
        &self.reader
    }
    pub fn file_len(&self) -> u64 {
        self.end
    }
    pub fn set_decoded_cache_budget(&self, bytes: usize) {
        self.cache.lock().unwrap().set_budget(bytes);
    }
    /// Release optional decoded/authentication entries and the disposable
    /// append-ID table. No published bytes are read or rewritten, and a later
    /// put may append a duplicate rather than scan historical frames.
    pub fn discard_disposable_caches(&mut self) {
        self.cache.lock().unwrap().clear();
        let budget = self.recent.0.budget.clone();
        self.recent = DiskRefs(temporary::GraphTable::with_budget(
            temporary::GraphTable::RESIDENT_ENTRIES,
            budget,
        ));
    }
    pub fn cache_usage(&self) -> CacheUsage {
        self.cache.lock().unwrap().usage()
    }
    pub fn physical_statistics(&self) -> PhysicalReadStatistics {
        self.io.snapshot()
    }
    pub fn publication_statistics(&self) -> PublicationStatistics {
        *self.io.publications.lock().unwrap()
    }
    pub fn unpublished_append_bytes(&self) -> u64 {
        self.end.saturating_sub(self.reader.committed_end())
    }
    pub fn inject_publication_fault_once(&mut self, fault: PublicationFault) {
        self.publication_fault = Some(fault);
    }
    /// Select bounded immutable roots to co-locate with the next publication.
    /// Publication rewrites only physical locators and preserves every ID.
    pub fn set_control_roots(&mut self, roots: &[ObjectRef]) -> Result<()> {
        if roots.len() > 128 {
            return Err(Error::Limit("control root count"));
        }
        self.control_roots = roots.to_vec();
        Ok(())
    }
    pub fn set_file_byte_limit(&mut self, max_bytes: u64) -> Result<()> {
        if self.end > max_bytes {
            return Err(Error::Limit("native file bytes"));
        }
        self.max_file_bytes = max_bytes;
        Ok(())
    }
    pub fn temporary_bytes(&self) -> Result<u64> {
        Ok(self.recent.0.budget.used())
    }
    pub fn temporary_statistics(&self) -> TemporaryIoStatistics {
        self.recent.0.budget.statistics()
    }
    pub fn set_temporary_disk_budget(&mut self, max_bytes: u64) -> Result<()> {
        self.recent.0.budget.set_limit(max_bytes)
    }
    /// Bound an unpublished staging container's file, disposable index, and
    /// sealing workspace together. Successful publication releases these
    /// temporary reservations because the installed archive becomes durable
    /// output. The limit cannot be configured on an already published store.
    pub fn set_total_temporary_disk_budget(&mut self, max_bytes: u64) -> Result<()> {
        if self.root().is_some() || self.compaction_target {
            return Err(Error::Unsupported(
                "total temporary quota requires unpublished staging".into(),
            ));
        }
        if let Some(budget) = &self.staging_temporary_budget {
            return budget.set_limit(max_bytes);
        }
        let budget = temporary::Budget::new(max_bytes);
        let extent = budget.reserve(self.end)?;
        self.recent.0.budget.attach_aggregate(budget.clone())?;
        self.temporary_extent = Some(extent);
        self.staging_temporary_budget = Some(budget);
        Ok(())
    }
    /// Current and peak staging extent plus scratch reservations. Historical
    /// peaks remain available after successful publication releases them.
    pub fn total_temporary_statistics(&self) -> TemporaryIoStatistics {
        self.staging_temporary_budget.as_ref().map_or_else(
            TemporaryIoStatistics::default,
            temporary::Budget::statistics,
        )
    }
    pub fn appended_reference(&self, hash: ObjectHash) -> Result<Option<ObjectRef>> {
        self.recent.get(hash)
    }
    pub fn validate(&self) -> Result<ValidationReport> {
        self.validate_with_limits(&resources::Limits::default())
    }
    pub fn validate_with_limits(&self, limits: &resources::Limits) -> Result<ValidationReport> {
        flush_append(&self.file, &self.append_buffer)?;
        #[cfg(unix)]
        let _gate = if self.reader.header.policy == wire::LocatorPolicy::Live {
            Some(leases::gate(
                &leases::domain(&self.file.lock().unwrap())?,
                false,
            )?)
        } else {
            None
        };
        let _cache = ValidationCacheGuard::new(self.cache.clone(), limits)?;
        let file = self.file.lock().unwrap().try_clone()?;
        validate_physical_closure(&file, &self.reader, &self.io, self, limits)
    }
    pub fn pin(&self) -> Result<NativeReader> {
        flush_append(&self.file, &self.append_buffer)?;
        let file = if let Some(pending) = &self.pending {
            options(false).open(pending)?
        } else {
            options(false).open(&self.path)?
        };
        if same_file::Handle::from_file(file.try_clone()?)?
            != same_file::Handle::from_file(self.file.lock().unwrap().try_clone()?)?
        {
            return Err(corrupt("path changed while pinning"));
        }
        NativeReader::from_pinned(
            file,
            self.reader.clone(),
            self.cache.clone(),
            self.file_identity,
            self.generation.clone(),
            self.io.clone(),
        )
    }
    pub fn publish_pinned(&mut self, snapshot: ObjectRef) -> Result<(Publication, NativeReader)> {
        let mut pin = self.pin()?;
        let p = self.publish(snapshot)?;
        pin.reader = self.reader.clone();
        #[cfg(unix)]
        if let Some(lease) = &mut pin.lease {
            lease.refresh(&pin.reader)?;
        }
        Ok((p, pin))
    }
    pub fn publish_commit_pinned(
        &mut self,
        commit: ObjectRef,
    ) -> Result<(Publication, NativeReader)> {
        let mut pin = self.pin()?;
        let p = self.publish_commit(commit)?;
        pin.reader = self.reader.clone();
        #[cfg(unix)]
        if let Some(lease) = &mut pin.lease {
            lease.refresh(&pin.reader)?;
        }
        Ok((p, pin))
    }
    pub fn publish(&mut self, snapshot: ObjectRef) -> Result<Publication> {
        let result = self.publish_snapshot_inner(snapshot);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn publish_snapshot_inner(&mut self, snapshot: ObjectRef) -> Result<Publication> {
        let object = self.get(snapshot)?;
        if object.kind != 2 || object.version != 1 {
            return Err(corrupt("publication requires kind-2 snapshot"));
        }
        validate_core_edges(&object, |child| self.get_verified_shared(child))?;
        let commit = self.put(
            1,
            1,
            &cbor::encode(&cbor::Value::Array(vec![
                cbor::Value::Uint(0),
                cbor::Value::Null,
                cbor::Value::Null,
            ])),
            &[snapshot],
        )?;
        self.publish_commit(commit)
    }
    pub fn publish_commit(&mut self, commit: ObjectRef) -> Result<Publication> {
        let result = self.publish_commit_inner(commit);
        if result.is_ok() {
            self.reused_unpublished = false;
        }
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn publish_commit_inner(&mut self, commit: ObjectRef) -> Result<Publication> {
        #[cfg(unix)]
        {
            self.free_frames = None;
        }
        self.check_writable()?;
        self.verify_current_path()?;
        // Validate the selected control graph before staging, writes or barriers.
        let selected = self.get_verified_shared(commit)?;
        if selected.kind != 1 {
            return Err(corrupt("publication requires kind-1 commit"));
        }
        validate_core_edges(&selected, |child| self.get_verified_shared(child))?;
        let selected_body = cbor::decode(&selected.bytes)?;
        let fields = schema::array(&selected_body, 3)?;
        let snapshot = selected.children[schema::uint(&fields[0])? as usize];
        let selected_snapshot = self.get_verified_shared(snapshot)?;
        validate_core_edges(&selected_snapshot, |child| self.get_verified_shared(child))?;
        let commit = if self.reader.header.policy == wire::LocatorPolicy::Sealed {
            self.pack_sealed_staging(commit)?
        } else {
            commit
        };
        let mut object = self.get(commit)?;
        if object.kind != 1 || object.version != 1 {
            return Err(corrupt("publication requires kind-1 commit"));
        }
        validate_core_object(&object)?;
        if self.root().is_some_and(|p| p.root.hash == commit.hash) {
            return Ok(self.root().unwrap());
        }
        let cbor::Value::Array(fields) = cbor::decode(&object.bytes)? else {
            return Err(corrupt("commit body"));
        };
        let Some(cbor::Value::Uint(index)) = fields.first() else {
            return Err(corrupt("commit snapshot index"));
        };
        let snapshot_index = usize::try_from(*index).map_err(|_| Error::Limit("snapshot index"))?;
        let mut snapshot = self.get(
            *object
                .children
                .get(snapshot_index)
                .ok_or_else(|| corrupt("snapshot child index"))?,
        )?;
        if snapshot.kind != 2 || snapshot.version != 1 {
            return Err(corrupt("snapshot child kind"));
        }
        validate_core_object(&snapshot)?;
        if self.reader.header.policy == wire::LocatorPolicy::Sealed
            && fields.get(2) != Some(&cbor::Value::Null)
        {
            return Err(corrupt("sealed commit has local authority"));
        }
        if object.canonical_len() > 16 * 1024 || snapshot.canonical_len() > 16 * 1024 {
            return Err(Error::Limit("control root bytes"));
        }
        let control_begin = self.end;
        let mut pending = BTreeMap::new();
        for reference in self.control_roots.clone() {
            let value = self.get(reference)?;
            if matches!(value.kind, 1 | 2) {
                continue;
            }
            if value.canonical_len() > 16384 {
                return Err(Error::Limit("control root canonical bytes"));
            }
            pending.entry(reference.hash).or_insert(value);
        }
        let mut remapped = BTreeMap::<ObjectHash, ObjectRef>::new();
        while !pending.is_empty() {
            let ready = pending
                .iter()
                .find(|(_, value)| {
                    value
                        .children
                        .iter()
                        .all(|child| !pending.contains_key(&child.hash))
                })
                .map(|(hash, _)| *hash)
                .ok_or_else(|| corrupt("control root dependency cycle"))?;
            let mut value = pending.remove(&ready).unwrap();
            for child in &mut value.children {
                if let Some(replacement) = remapped.get(&child.hash) {
                    *child = *replacement;
                }
            }
            let reference = self.append_object(value)?;
            remapped.insert(ready, reference);
            if self.end - control_begin > 65536 - 160 {
                return Err(Error::Limit("control region bytes"));
            }
        }
        for child in &mut snapshot.children {
            if let Some(replacement) = remapped.get(&child.hash) {
                *child = *replacement;
            }
        }
        for child in &mut object.children {
            if let Some(replacement) = remapped.get(&child.hash) {
                *child = *replacement;
            }
        }
        let generation = self
            .root()
            .map_or(Some(1), |p| p.generation.checked_add(1))
            .ok_or(Error::Limit("publication generation"))?;
        let in_control = commit
            .address
            .offset
            .checked_add(commit.address.length as u64)
            == Some(self.end)
            && object.children[snapshot_index].address.offset
                >= self.end.saturating_sub(65536 - 160);
        let commit = if in_control {
            commit
        } else {
            let snapshot = self.append_object(snapshot)?;
            object.children[snapshot_index] = snapshot;
            self.append_object(object)?
        };
        let trailer_offset = self.end;
        let committed_end = self
            .end
            .checked_add(160)
            .ok_or(Error::Limit("publication extent"))?;
        if committed_end > self.max_file_bytes {
            return Err(Error::Limit("native file bytes"));
        }
        if !self.control_roots.is_empty() && committed_end - control_begin > 65536 {
            return Err(Error::Limit("control region bytes"));
        }
        let trailer = wire::Trailer {
            preamble_digest: self.reader.header.digest(),
            generation,
            committed_end,
            commit,
        };
        self.reserve_temporary_extent(committed_end)?;
        flush_append(&self.file, &self.append_buffer)?;
        write_at(
            self.file.get_mut().unwrap(),
            &trailer.encode(),
            trailer_offset,
        )
        .inspect_err(|_| self.poisoned = true)?;
        self.end = committed_end;
        self.io.publications.lock().unwrap().appended_bytes += 160;
        self.poisoned = true;
        {
            let mut m = self.io.publications.lock().unwrap();
            m.attempts += 1;
            if self.compaction_target {
                m.compaction_attempts += 1;
            }
        }
        let fault = self.publication_fault.take();
        if fault == Some(PublicationFault::ChunksBarrier) {
            return Err(injected_failure());
        }
        self.barrier(false)?;
        if self.reader.header.policy == wire::LocatorPolicy::Live {
            let slot = wire::Slot {
                preamble_digest: self.reader.header.digest(),
                generation,
                trailer_offset,
                trailer_digest: trailer.digest(),
            }
            .encode();
            if let Some(PublicationFault::SlotWrite { bytes }) = fault {
                self.write_publication_slot(&slot[..bytes.min(slot.len())], generation)?;
                return Err(injected_failure());
            }
            self.write_publication_slot(&slot, generation)?;
            if fault == Some(PublicationFault::SlotSync) {
                return Err(injected_failure());
            }
            self.barrier(true)?;
        }
        if let Some(pending) = &self.pending {
            std::fs::hard_link(pending, &self.path)?;
            sync_parent(&self.path)?;
            verify_file_path(self.file.get_mut().unwrap(), &self.path)?;
            self.pending.take();
        }
        self.verify_current_path()?;
        let publication = Publication {
            generation,
            root: commit,
            committed_end,
        };
        self.reader = Reader::from_parts(
            self.reader.header,
            Some(publication),
            trailer_offset,
            Vec::new(),
        );
        self.reader.admit_control(&FileSource {
            file: self.file.get_mut().unwrap(),
            io: &self.io,
        })?;
        self.generation
            .unpublished
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.poisoned = false;
        {
            let mut m = self.io.publications.lock().unwrap();
            m.completed += 1;
            if self.compaction_target {
                m.compaction_completed += 1;
            }
        }
        if self.staging_temporary_budget.is_some() {
            self.temporary_extent = None;
            self.recent.0.budget.detach_aggregate();
        }
        Ok(publication)
    }
    fn pack_sealed_staging(&mut self, commit: ObjectRef) -> Result<ObjectRef> {
        flush_append(&self.file, &self.append_buffer)?;
        if self.staging_temporary_budget.is_none() {
            self.set_total_temporary_disk_budget(temporary::MAX_DISK)?;
        }
        let aggregate = self.staging_temporary_budget.as_ref().unwrap().clone();
        // Declared before the source reader, so its inode stays charged until
        // that reader closes on every success/error path, including unlink.
        let _source_extent;
        let object = self.get(commit)?;
        let cbor::Value::Array(fields) = cbor::decode(&object.bytes)? else {
            return Err(corrupt("commit body"));
        };
        let Some(cbor::Value::Uint(snapshot_index)) = fields.first() else {
            return Err(corrupt("snapshot index"));
        };
        let snapshot_index =
            usize::try_from(*snapshot_index).map_err(|_| Error::Limit("snapshot index"))?;
        if fields.get(2) != Some(&cbor::Value::Null) {
            return Err(corrupt("sealed local authority"));
        }
        let source_file = options(false).open(
            self.pending
                .as_ref()
                .ok_or_else(|| corrupt("sealed staging ownership"))?,
        )?;
        let source = NativeReader::from_pinned(
            source_file,
            Reader::from_parts(self.reader.header, None, self.end, Vec::new()),
            self.cache.clone(),
            self.file_identity,
            self.generation.clone(),
            self.io.clone(),
        )?;
        let temporary = tempfile::Builder::new()
            .prefix(".sac1-seal-")
            .tempfile_in(self.path.parent().unwrap())?;
        let (mut file, pending) = temporary.into_parts();
        let replacement_extent = aggregate.reserve(128)?;
        #[cfg(unix)]
        platform::random_reads(&file);
        file.write_all(&self.reader.header.encode())?;
        file.try_lock().map_err(lock_error)?;
        _source_extent = self.temporary_extent.replace(replacement_extent);
        self.file = Mutex::new(file);
        self.node = std::sync::OnceLock::new();
        self.pending = Some(pending);
        self.end = 128;
        let index_budget = self.recent.0.budget.clone();
        self.recent = DiskRefs(temporary::GraphTable::with_budget(
            temporary::GraphTable::RESIDENT_ENTRIES,
            index_budget,
        ));
        self.file_identity = next_file_identity();
        self.generation = Arc::new(FileGeneration::default());
        // Defer requested bootstrap roots and their ancestors until all other
        // dependencies have been emitted. This produces one physical copy per
        // canonical ID while retaining child-before-parent order and locality.
        let mut controls = self
            .control_roots
            .iter()
            .map(|r| r.hash)
            .collect::<BTreeSet<_>>();
        controls.insert(commit.hash);
        controls.insert(object.children[snapshot_index].hash);
        validate_closure_tracked(&source, Some(commit), &|| false, Some(aggregate.clone()))?;
        let workspace = temporary::Budget::child(temporary::MAX_DISK, aggregate);
        let mut copied = DiskRefs(temporary::GraphTable::with_budget(
            temporary::GraphTable::RESIDENT_ENTRIES,
            workspace.clone(),
        ));
        let mut planned = temporary::GraphTable::with_budget(
            temporary::GraphTable::RESIDENT_ENTRIES,
            workspace.clone(),
        );
        let mut pending_controls = BTreeMap::<ObjectHash, CanonicalObject>::new();
        let mut stack = DiskStack::with_budget(256, workspace)?;
        stack.push(commit, false)?;
        while let Some((reference, expanded)) = stack.pop()? {
            if copied.get(reference.hash)?.is_some()
                || pending_controls.contains_key(&reference.hash)
            {
                continue;
            }
            let mut value = source.get(reference)?;
            if expanded {
                let mut deferred = controls.contains(&reference.hash);
                for child in &value.children {
                    if copied.get(child.hash)?.is_none() {
                        deferred = true;
                    }
                }
                if deferred {
                    if value.canonical_len() > 16384 {
                        return Err(Error::Limit("sealed control root bytes"));
                    }
                    pending_controls.insert(reference.hash, value);
                    if pending_controls.len() > 130 {
                        return Err(Error::Limit("sealed control root count"));
                    }
                } else {
                    for child in &mut value.children {
                        *child = copied
                            .get(child.hash)?
                            .ok_or_else(|| corrupt("sealed copy missing dependency"))?;
                    }
                    let saved =
                        self.put(value.kind, value.version, &value.bytes, &value.children)?;
                    if saved.hash != reference.hash {
                        return Err(corrupt("sealed copy identity"));
                    }
                    copied.insert_cancellable(saved, &|| false)?;
                }
            } else {
                if planned.get(&reference.hash.0)?.is_some() {
                    continue;
                }
                planned.insert_cancellable(&reference.hash.0, &[], &|| false)?;
                stack.push(reference, true)?;
                for child in value.children.iter().rev() {
                    stack.push(*child, false)?;
                }
            }
        }
        let control_begin = self.end;
        while !pending_controls.is_empty() {
            let ready = pending_controls
                .iter()
                .find(|(_, value)| {
                    value
                        .children
                        .iter()
                        .all(|child| !pending_controls.contains_key(&child.hash))
                })
                .map(|(hash, _)| *hash)
                .ok_or_else(|| corrupt("sealed control dependency cycle"))?;
            let mut value = pending_controls.remove(&ready).unwrap();
            for child in &mut value.children {
                *child = copied
                    .get(child.hash)?
                    .ok_or_else(|| corrupt("sealed control missing dependency"))?;
            }
            let saved = self.put(value.kind, value.version, &value.bytes, &value.children)?;
            if saved.hash != ready {
                return Err(corrupt("sealed control copy identity"));
            }
            copied.insert_cancellable(saved, &|| false)?;
            if self.end - control_begin + 160 > 65536 {
                return Err(Error::Limit("sealed control region bytes"));
            }
        }
        for root in &self.control_roots {
            if copied.get(root.hash)?.is_none() {
                return Err(corrupt("sealed control root is not retained"));
            }
        }
        self.control_roots.clear();
        copied
            .get(commit.hash)?
            .ok_or_else(|| corrupt("sealed commit copy missing"))
    }

    fn check_writable(&self) -> Result<()> {
        if !self.writable
            || self.reader.header.policy == wire::LocatorPolicy::Sealed && self.root().is_some()
        {
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into());
        }
        if self.poisoned || self.append_buffer.lock().unwrap().failed {
            return Err(Error::Poisoned);
        }
        Ok(())
    }
    fn write_publication_slot(&mut self, bytes: &[u8], generation: u64) -> Result<()> {
        let mut metrics = self.io.publications.lock().unwrap();
        metrics.slot_writes += 1;
        metrics.slot_write_bytes += bytes.len() as u64;
        drop(metrics);
        write_at(self.file.get_mut().unwrap(), bytes, slot_offset(generation))
    }
    fn barrier(&self, slot: bool) -> Result<()> {
        flush_append(&self.file, &self.append_buffer)?;
        let start = Instant::now();
        let result = durable(&self.file.lock().unwrap());
        let ns = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        let mut m = self.io.publications.lock().unwrap();
        if slot {
            m.slot_syncs += 1;
            if self.compaction_target {
                m.compaction_slot_sync_total_ns =
                    m.compaction_slot_sync_total_ns.saturating_add(ns);
            }
            m.slot_sync_last_ns = ns;
            m.slot_sync_total_ns = m.slot_sync_total_ns.saturating_add(ns);
            m.slot_sync_max_ns = m.slot_sync_max_ns.max(ns);
        } else {
            m.chunk_barriers += 1;
            if self.compaction_target {
                m.compaction_chunk_barrier_total_ns =
                    m.compaction_chunk_barrier_total_ns.saturating_add(ns);
            }
            m.chunk_barrier_last_ns = ns;
            m.chunk_barrier_total_ns = m.chunk_barrier_total_ns.saturating_add(ns);
            m.chunk_barrier_max_ns = m.chunk_barrier_max_ns.max(ns);
        }
        result
    }
    fn reserve_temporary_extent(&mut self, next: u64) -> Result<()> {
        if let Some(reservation) = &mut self.temporary_extent {
            reservation.grow_to(next)?;
        }
        Ok(())
    }
    fn append_object(&mut self, object: CanonicalObject) -> Result<ObjectRef> {
        let hash = object.hash();
        self.append_hashed(object, hash)
    }
    fn append_hashed(&mut self, object: CanonicalObject, hash: ObjectHash) -> Result<ObjectRef> {
        self.append_encoded(object, hash, None, None)
    }
    /// `prepared` is the frame of `object` at this store's compression level.
    /// `compressed` is the Zstandard encoding of its canonical bytes.
    fn append_encoded(
        &mut self,
        object: CanonicalObject,
        hash: ObjectHash,
        prepared: Option<Vec<u8>>,
        compressed: Option<&[u8]>,
    ) -> Result<ObjectRef> {
        let frame: &[u8] = match (&prepared, compressed) {
            (Some(frame), _) => frame,
            (None, Some(compressed)) => self.encoder.encode_stored(&object, hash, compressed)?,
            (None, None) => self
                .encoder
                .encode_hashed(&object, self.compression_level, hash)?,
        };
        #[cfg(unix)]
        if object.kind == 7
            && let Some(offset) = self
                .free_frames
                .as_mut()
                .map(|free| free.take(frame.len() as u32))
                .transpose()?
                .flatten()
        {
            let reference = ObjectRef {
                hash,
                address: ChunkAddress {
                    offset,
                    length: frame.len() as u32,
                },
            };
            maintenance::reuse(self.file.get_mut().unwrap(), offset, frame)
                .inspect_err(|_| self.poisoned = true)?;
            self.reused_unpublished = true;
            self.file_identity = next_file_identity();
            self.cache.lock().unwrap().clear();
            self.recent.insert_cancellable(reference, &|| false)?;
            return Ok(reference);
        }
        let reference = ObjectRef {
            hash,
            address: ChunkAddress {
                offset: self.end,
                length: u32::try_from(frame.len()).map_err(|_| Error::Limit("frame span"))?,
            },
        };
        let next = self
            .end
            .checked_add(frame.len() as u64)
            .ok_or(Error::Limit("file extent"))?;
        if next > self.max_file_bytes {
            return Err(Error::Limit("native file bytes"));
        }
        if let Some(reservation) = &mut self.temporary_extent {
            reservation.grow_to(next)?;
        }
        append_frame(&self.file, &self.append_buffer, self.end, frame)
            .inspect_err(|_| self.poisoned = true)?;
        self.end = next;
        self.io.publications.lock().unwrap().appended_bytes += frame.len() as u64;
        self.generation.unpublished.store(
            self.unpublished_append_bytes(),
            std::sync::atomic::Ordering::Relaxed,
        );
        self.recent
            .insert_cancellable(reference, &|| false)
            .inspect_err(|_| self.poisoned = true)?;
        // Directory pages and expensive generic fanouts can carry exact edges
        // across staged rewrites. The policy depends on physical cost, never a
        // product's kind IDs. Byte objects and cheap fanouts need no index row.
        let costly_fanout = object.children.len() >= 8
            && object
                .children
                .iter()
                .map(|child| u64::from(child.address.length))
                .sum::<u64>()
                > u64::from(reference.address.length) * 2;
        if !object.children.is_empty() && (matches!(object.kind, 3 | 4) || costly_fanout) {
            self.recent
                .record_rewrite_layout(reference, &object.children)
                .inspect_err(|_| self.poisoned = true)?;
        }
        let mut cache = self.cache.lock().unwrap();
        let object_type = (object.kind, object.version);
        cache.insert_shared(self.file_identity, reference, &Arc::new(object));
        cache.verify(self.file_identity, reference, object_type);
        Ok(reference)
    }
    pub fn rehint(&self, source: &NativeReader, reference: ObjectRef) -> Result<Option<ObjectRef>> {
        rehint_to(self, self.file_identity, self.end, source, reference)
    }
}
impl ObjectStore for NativeStore {
    fn get_verified_shared(&self, r: ObjectRef) -> Result<Arc<CanonicalObject>> {
        self.get_shared(r)
    }
    fn cached_object_type(&self, reference: ObjectRef) -> Result<Option<(u16, u16)>> {
        let scope = self.physical_read_scope().unwrap();
        wire::validate_address(reference.address, scope.first, scope.end)?;
        Ok(self.cache.verified_type(self.file_identity, reference))
    }
    fn object_type(&self, reference: ObjectRef) -> Result<(u16, u16)> {
        if let Some(object_type) = self.cached_object_type(reference)? {
            return Ok(object_type);
        }
        let object = self.get_shared(reference)?;
        let object_type = (object.kind, object.version);
        self.cache
            .lock()
            .unwrap()
            .verify(self.file_identity, reference, object_type);
        Ok(object_type)
    }
    fn validate_reference(&self, reference: ObjectRef) -> Result<()> {
        let scope = self.physical_read_scope().unwrap();
        wire::validate_address(reference.address, scope.first, scope.end)?;
        if self
            .cache
            .verified_type(self.file_identity, reference)
            .is_some()
        {
            return Ok(());
        }
        let object = self.get_shared(reference)?;
        self.cache.lock().unwrap().verify(
            self.file_identity,
            reference,
            (object.kind, object.version),
        );
        Ok(())
    }
    fn physical_identity(&self) -> Option<u64> {
        Some(self.file_identity)
    }
    fn physical_read_scope(&self) -> Option<PhysicalReadScope> {
        Some(PhysicalReadScope {
            identity: self.file_identity,
            first: self.reader.first_record_offset(),
            end: if self.end == self.reader.committed_end() {
                self.reader.trailer_offset()
            } else {
                self.end
            },
        })
    }
    fn rehint_native(
        &self,
        source: &NativeReader,
        reference: ObjectRef,
    ) -> Result<Option<ObjectRef>> {
        self.rehint(source, reference)
    }
    fn get(&self, r: ObjectRef) -> Result<CanonicalObject> {
        self.get_shared(r).map(Arc::unwrap_or_clone)
    }
    fn get_shared(&self, r: ObjectRef) -> Result<Arc<CanonicalObject>> {
        self.shared_keeping(r, false).map(|read| read.0)
    }
    fn verified_object(&self, reference: ObjectRef) -> Result<VerifiedObject> {
        let (object, compressed) = self.shared_keeping(reference, true)?;
        Ok(VerifiedObject {
            hash: reference.hash,
            object,
            compressed,
        })
    }
    fn put(
        &mut self,
        kind: u16,
        version: u16,
        bytes: &[u8],
        children: &[ObjectRef],
    ) -> Result<ObjectRef> {
        self.put_checked_edges(kind, version, bytes, children, None, None, None)
    }
    fn prepare_width(&self) -> usize {
        self.encode_threads
    }
    fn prepare(
        &self,
        kind: u16,
        version: u16,
        bodies: &[&[u8]],
    ) -> Result<Option<Vec<PreparedObject>>> {
        let threads = self.encode_threads.min(bodies.len());
        if threads < 2 {
            return Ok(None);
        }
        self.check_writable()?;
        let level = self.compression_level;
        let next = std::sync::atomic::AtomicUsize::new(0);
        let encode = || -> Result<Vec<(usize, PreparedObject)>> {
            let mut encoder = wire::FrameEncoder::default();
            let mut encoded = Vec::new();
            loop {
                let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(body) = bodies.get(index) else {
                    return Ok(encoded);
                };
                check_input(body, &[])?;
                let object = CanonicalObject {
                    kind,
                    version,
                    bytes: body.to_vec(),
                    children: Vec::new(),
                };
                let hash = object.hash();
                let frame = encoder.encode_hashed(&object, level, hash)?.to_vec();
                encoded.push((
                    index,
                    PreparedObject {
                        object,
                        hash,
                        frame,
                        level,
                    },
                ));
            }
        };
        let groups = std::thread::scope(|scope| {
            let workers: Vec<_> = (1..threads).map(|_| scope.spawn(encode)).collect();
            let mut groups = vec![encode()];
            for worker in workers {
                groups.push(
                    worker
                        .join()
                        .unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
                );
            }
            groups
        });
        let mut prepared: Vec<Option<PreparedObject>> = bodies.iter().map(|_| None).collect();
        for group in groups {
            for (index, object) in group? {
                prepared[index] = Some(object);
            }
        }
        prepared
            .into_iter()
            .map(|object| object.ok_or_else(|| corrupt("prepared object missing")))
            .collect::<Result<Vec<_>>>()
            .map(Some)
    }
    fn put_prepared(&mut self, prepared: PreparedObject) -> Result<ObjectRef> {
        let PreparedObject {
            object,
            hash,
            frame,
            level,
        } = prepared;
        if level != self.compression_level || !object.children.is_empty() {
            return self.put(object.kind, object.version, &object.bytes, &object.children);
        }
        // The checks of `put` for an object that has no children.
        self.check_writable()?;
        self.verify_destination_entry()?;
        if let Some(reference) = self
            .root()
            .map(|p| p.root)
            .filter(|r| r.hash == hash)
            .or_else(|| self.reader.snapshot().filter(|r| r.hash == hash))
        {
            self.validate_reference(reference)?;
            return Ok(reference);
        }
        if let Some(reference) = self.recent.get(hash)? {
            self.validate_reference(reference)?;
            return Ok(reference);
        }
        self.append_encoded(object, hash, Some(frame), None)
    }
    fn put_verified(
        &mut self,
        source: &VerifiedObject,
        children: &[ObjectRef],
    ) -> Result<ObjectRef> {
        source.validate_children(children)?;
        let object = source.object();
        self.put_checked_edges(
            object.kind,
            object.version,
            &object.bytes,
            children,
            None,
            Some(source.hash()),
            source.compressed.as_ref().map(|bytes| bytes.as_slice()),
        )
    }
    fn rewrite_source(&self, parent: ObjectRef) -> Result<Option<RewriteSource>> {
        self.check_writable()?;
        self.verify_destination_entry()?;
        let committed_end = self.reader.committed_end();
        let readable_end = self.physical_read_scope().unwrap().end;
        wire::validate_address(
            parent.address,
            self.reader.first_record_offset(),
            readable_end,
        )?;
        let parent_end = parent.address.offset + u64::from(parent.address.length);
        let staged_layout = if parent_end > self.reader.trailer_offset() {
            // A canonical hash authenticates child IDs, not their physical
            // locators. Only exact append provenance can authorize a staged
            // source; losing this disposable entry falls back to strict put.
            if parent.address.offset < committed_end
                || self.recent.get(parent.hash)? != Some(parent)
            {
                return Ok(None);
            }
            let Some((layout, child_bytes)) = self.recent.rewrite_layout(parent)? else {
                return Ok(None);
            };
            // A source fetch plus fresh layout authentication must cost less
            // than checking its edges normally. Tiny/shared extents retain the
            // ordinary strict path without even fetching the prior parent.
            if child_bytes <= u64::from(parent.address.length) * 2 {
                return Ok(None);
            }
            Some(layout)
        } else {
            None
        };
        let object = self.get_verified_shared(parent)?;
        if staged_layout.is_some_and(|layout| layout != spill::rewrite_layout(&object.children)) {
            return Err(corrupt("staged rewrite source layout changed"));
        }
        Ok(Some(RewriteSource {
            parent,
            object,
            identity: self.file_identity,
            committed_end,
            readable_end,
            staged_layout,
        }))
    }
    fn rewrite(
        &mut self,
        source: &RewriteSource,
        kind: u16,
        version: u16,
        bytes: &[u8],
        children: &[ObjectRef],
    ) -> Result<ObjectRef> {
        self.check_writable()?;
        self.verify_destination_entry()?;
        let current_end = self.physical_read_scope().unwrap().end;
        if source.identity != self.file_identity
            || source.committed_end > self.reader.committed_end()
            || source.readable_end > current_end
        {
            return Err(corrupt(
                "rewrite source is not the current writer incarnation",
            ));
        }
        wire::validate_address(
            source.parent.address,
            self.reader.first_record_offset(),
            source.readable_end,
        )?;
        if let Some(layout) = source.staged_layout {
            // Cached children need no waiver. Select the strict path before
            // any parent re-read when its remaining exact inherited edges do
            // not repay the bounded source/layout authentication work.
            let mut prior = source.object.children.iter().collect::<Vec<_>>();
            prior.sort_unstable();
            let mut cache = self.cache.lock().unwrap();
            let unverified_bytes: u64 = children
                .iter()
                .filter(|child| {
                    prior.binary_search(child).is_ok()
                        && !cache.verified(self.file_identity, **child)
                        && cache.get(self.file_identity, **child).is_none()
                })
                .map(|child| u64::from(child.address.length))
                .sum();
            drop(cache);
            if unverified_bytes <= u64::from(source.parent.address.length) * 2 {
                return self.put_checked_edges(kind, version, bytes, children, None, None, None);
            }
            // Reauthenticate this one parent occurrence without inserting any
            // child/layout status into a shared cache. This also detects a
            // changed locator table after the opaque capability was issued.
            flush_append(&self.file, &self.append_buffer)?;
            let mut frame = vec![0; source.parent.address.length as usize];
            counted_read_at(
                &self.file.lock().unwrap(),
                &mut frame,
                source.parent.address.offset,
                &self.io,
                ReadClass::Object,
            )?;
            let actual = wire::decode_frame_owned(
                source.parent,
                frame,
                self.reader.first_record_offset(),
                source.readable_end,
            )?;
            if actual.children != source.object.children
                || spill::rewrite_layout(&actual.children) != layout
            {
                return Err(corrupt("staged rewrite source layout changed"));
            }
        }
        self.put_checked_edges(kind, version, bytes, children, Some(source), None, None)
    }
}

impl NativeStore {
    fn shared_keeping(&self, r: ObjectRef, keep: bool) -> Result<ObjectRead> {
        let end = self.physical_read_scope().unwrap().end;
        wire::validate_address(r.address, self.reader.first_record_offset(), end)?;
        if let Some(object) = self.cache.get(self.file_identity, r) {
            return Ok((object, None));
        }
        let mut disk_end = if self.end == self.reader.committed_end() {
            self.reader.trailer_offset()
        } else {
            self.end
        };
        let needs_flush = {
            let buffer = self.append_buffer.lock().unwrap();
            if buffer.failed {
                return Err(Error::Poisoned);
            }
            if buffer.bytes.is_empty() {
                false
            } else if r.address.offset + u64::from(r.address.length) <= buffer.offset {
                // An inherited lookup cannot observe the pending suffix. Keep
                // small appends coalesced and cap read-ahead at the written
                // prefix, so a metadata window never includes unflushed bytes.
                disk_end = disk_end.min(buffer.offset);
                false
            } else {
                true
            }
        };
        if needs_flush {
            flush_append(&self.file, &self.append_buffer)?;
        }
        read_object_keeping(
            &self.file.lock().unwrap(),
            self.reader.header.first_record_offset(),
            disk_end,
            &self.cache,
            self.file_identity,
            &self.io,
            r,
            keep,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn put_checked_edges(
        &mut self,
        kind: u16,
        version: u16,
        bytes: &[u8],
        children: &[ObjectRef],
        source: Option<&RewriteSource>,
        authenticated_hash: Option<ObjectHash>,
        compressed: Option<&[u8]>,
    ) -> Result<ObjectRef> {
        self.check_writable()?;
        self.verify_destination_entry()?;
        check_input(bytes, children).inspect_err(|error| {
            eprintln!(
                "canonical physical size rejected: kind={kind} version={version} payload_bytes={} children={}: {error}",
                bytes.len(),
                children.len(),
            );
        })?;
        let object = CanonicalObject {
            kind,
            version,
            bytes: bytes.into(),
            children: children.into(),
        };
        // At most 1024 pointers, released before this write returns. No
        // inherited edge is added to the authenticated-child cache.
        let inherited = source.map(|source| {
            let mut references = source.object.children.iter().collect::<Vec<_>>();
            references.sort_unstable();
            references
        });
        for child in children {
            wire::validate_address(child.address, self.reader.first_record_offset(), self.end)?;
            if inherited
                .as_ref()
                .is_some_and(|prior| prior.binary_search(&child).is_ok())
            {
                continue;
            }
            if self
                .cache
                .lock()
                .unwrap()
                .verified(self.file_identity, *child)
            {
                continue;
            }
            // The append index has only the frames that this writer wrote
            // since it last discarded the index, each under the hash that
            // authenticated its object. An entry equal to the complete
            // reference is that authentication without its cache entry: a
            // different offset or length is not equal and is read.
            if self.recent.get(child.hash)? == Some(*child) {
                continue;
            }
            let object = self.get_shared(*child)?;
            self.cache.lock().unwrap().verify(
                self.file_identity,
                *child,
                (object.kind, object.version),
            );
        }
        // The prior occurrence is a bounded exact no-op candidate even when
        // disposable ID lookup was discarded. Compare full physical edges:
        // canonical ID equality alone cannot establish unchanged locators.
        if let Some(source) = source
            && object.kind == source.object.kind
            && object.version == source.object.version
            && object.bytes == source.object.bytes
            && object.children == source.object.children
        {
            return Ok(source.parent);
        }
        let hash = authenticated_hash.unwrap_or_else(|| object.hash());
        if let Some(reference) = self
            .root()
            .map(|p| p.root)
            .filter(|r| r.hash == hash)
            .or_else(|| self.reader.snapshot().filter(|r| r.hash == hash))
        {
            self.validate_reference(reference)?;
            return Ok(reference);
        }
        if let Some(reference) = self.recent.get(hash)? {
            self.validate_reference(reference)?;
            return Ok(reference);
        }
        // Zstandard bytes that a source authenticated as this object are
        // what this store's encoder makes from the same canonical bytes.
        // Store them again unless this store would keep the object raw.
        let compressed = compressed.filter(|bytes| {
            self.compression_level != 0
                && !matches!(object.kind, 1 | 2)
                && <[u8]>::len(bytes) < object.canonical_len()
        });
        self.append_encoded(object, hash, None, compressed)
    }
}

impl NativeReader {
    fn from_pinned(
        file: File,
        reader: Reader,
        cache: Arc<CacheLock>,
        file_identity: u64,
        generation: Arc<FileGeneration>,
        io: Arc<PhysicalCounters>,
    ) -> Result<Self> {
        #[cfg(unix)]
        platform::random_reads(&file);
        #[cfg(unix)]
        let lease = if reader.header.policy == wire::LocatorPolicy::Live {
            Some(leases::Lease::register(&file, &reader)?)
        } else {
            None
        };
        let metadata_charge = std::mem::size_of::<Self>()
            + reader
                .recovery_diagnostics
                .iter()
                .map(|s| s.capacity() + std::mem::size_of::<String>())
                .sum::<usize>();
        {
            let mut c = cache.lock().unwrap();
            if c.budget > 0 && c.pinned_metadata.saturating_add(metadata_charge) > c.budget {
                return Err(Error::Limit("pinned reader memory"));
            }
            c.pinned_metadata += metadata_charge;
            let budget = c.budget;
            c.set_budget(budget);
        }
        Ok(Self {
            #[cfg(unix)]
            lease,
            file,
            reader,
            cache,
            file_identity,
            generation,
            metadata_charge,
            io,
        })
    }
    /// Open an independent descriptor. On Unix, live roots register with the
    /// same-file maintenance domain for the lifetime of this reader.
    pub fn open_file(file: File) -> Result<Self> {
        #[cfg(unix)]
        platform::random_reads(&file);
        #[cfg(unix)]
        let _gate = {
            let mut header = [0; 128];
            read_at(&file, &mut header, 0)?;
            if header[8] == 1 {
                let dir = leases::domain(&file)?;
                let gate = leases::gate(&dir, false)?;
                if leases::pending(&dir) {
                    return Err(Error::RecoveryRequired);
                }
                Some(gate)
            } else {
                None
            }
        };
        let io = Arc::new(PhysicalCounters::default());
        let reader = admit_file(&file, &io)?;
        Self::from_pinned(
            file,
            reader,
            new_cache(),
            next_file_identity(),
            Arc::new(FileGeneration::default()),
            io,
        )
    }
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_file(options(false).open(path)?)
    }
    pub fn reader(&self) -> &Reader {
        &self.reader
    }
    pub fn root(&self) -> Option<Publication> {
        self.reader.publication
    }
    pub fn physical_statistics(&self) -> PhysicalReadStatistics {
        self.io.snapshot()
    }
    pub fn publication_statistics(&self) -> PublicationStatistics {
        *self.io.publications.lock().unwrap()
    }
    pub fn set_decoded_cache_budget(&self, bytes: usize) {
        self.cache.lock().unwrap().set_budget(bytes);
    }
    /// Release shared optional payload and authentication caches, preserving
    /// reader control metadata and the configured resident budget.
    pub fn clear_decoded_cache(&self) {
        self.cache.lock().unwrap().clear();
    }
    pub fn cache_usage(&self) -> CacheUsage {
        self.cache.lock().unwrap().usage()
    }
    pub fn decoded_cache_bytes(&self) -> usize {
        self.cache.lock().unwrap().bytes
    }
    pub fn unpublished_append_bytes(&self) -> u64 {
        self.generation
            .unpublished
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn validate(&self) -> Result<ValidationReport> {
        self.validate_with_limits(&resources::Limits::default())
    }
    pub fn validate_with_limits(&self, limits: &resources::Limits) -> Result<ValidationReport> {
        #[cfg(unix)]
        let _gate = if self.reader.header.policy == wire::LocatorPolicy::Live {
            Some(leases::gate(&leases::domain(&self.file)?, false)?)
        } else {
            None
        };
        let _cache = ValidationCacheGuard::new(self.cache.clone(), limits)?;
        validate_physical_closure(&self.file, &self.reader, &self.io, self, limits)
    }
}
impl Drop for NativeReader {
    fn drop(&mut self) {
        let mut c = self.cache.lock().unwrap();
        c.pinned_metadata = c.pinned_metadata.saturating_sub(self.metadata_charge);
    }
}
impl ObjectStore for NativeReader {
    fn get_verified_shared(&self, r: ObjectRef) -> Result<Arc<CanonicalObject>> {
        self.get_shared(r)
    }
    fn cached_object_type(&self, reference: ObjectRef) -> Result<Option<(u16, u16)>> {
        let scope = self.physical_read_scope().unwrap();
        wire::validate_address(reference.address, scope.first, scope.end)?;
        Ok(self.cache.verified_type(self.file_identity, reference))
    }
    fn object_type(&self, reference: ObjectRef) -> Result<(u16, u16)> {
        if let Some(object_type) = self.cached_object_type(reference)? {
            return Ok(object_type);
        }
        let object = self.get_shared(reference)?;
        let object_type = (object.kind, object.version);
        self.cache
            .lock()
            .unwrap()
            .verify(self.file_identity, reference, object_type);
        Ok(object_type)
    }
    fn validate_reference(&self, reference: ObjectRef) -> Result<()> {
        wire::validate_address(
            reference.address,
            self.reader.first_record_offset(),
            self.reader.trailer_offset(),
        )?;
        if self
            .cache
            .verified_type(self.file_identity, reference)
            .is_some()
        {
            return Ok(());
        }
        let object = self.get_shared(reference)?;
        self.cache.lock().unwrap().verify(
            self.file_identity,
            reference,
            (object.kind, object.version),
        );
        Ok(())
    }
    fn physical_identity(&self) -> Option<u64> {
        Some(self.file_identity)
    }
    fn physical_read_scope(&self) -> Option<PhysicalReadScope> {
        Some(PhysicalReadScope {
            identity: self.file_identity,
            first: self.reader.first_record_offset(),
            end: self.reader.trailer_offset(),
        })
    }
    fn rehint_native(
        &self,
        source: &NativeReader,
        reference: ObjectRef,
    ) -> Result<Option<ObjectRef>> {
        rehint_to(
            self,
            self.file_identity,
            self.reader.trailer_offset(),
            source,
            reference,
        )
    }
    fn get(&self, r: ObjectRef) -> Result<CanonicalObject> {
        self.get_shared(r).map(Arc::unwrap_or_clone)
    }
    fn get_shared(&self, r: ObjectRef) -> Result<Arc<CanonicalObject>> {
        read_object(
            &self.file,
            self.reader.first_record_offset(),
            self.reader.trailer_offset(),
            &self.cache,
            self.file_identity,
            &self.io,
            r,
        )
    }
    fn verified_object(&self, reference: ObjectRef) -> Result<VerifiedObject> {
        let (object, compressed) = read_object_keeping(
            &self.file,
            self.reader.first_record_offset(),
            self.reader.trailer_offset(),
            &self.cache,
            self.file_identity,
            &self.io,
            reference,
            true,
        )?;
        Ok(VerifiedObject {
            hash: reference.hash,
            object,
            compressed,
        })
    }
    fn put(&mut self, _: u16, _: u16, _: &[u8], _: &[ObjectRef]) -> Result<ObjectRef> {
        Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into())
    }
}
fn rehint_to(
    target: &impl ObjectStore,
    target_identity: u64,
    target_end: u64,
    source: &NativeReader,
    mut reference: ObjectRef,
) -> Result<Option<ObjectRef>> {
    source.validate_reference(reference)?;
    let mut identity = source.file_identity;
    let mut generation = source.generation.clone();
    loop {
        if identity == target_identity {
            if reference
                .address
                .offset
                .checked_add(reference.address.length as u64)
                .is_none_or(|end| end > target_end)
            {
                return Ok(None);
            }
            target.validate_reference(reference)?;
            return Ok(Some(reference));
        }
        let Some(next) = generation.next.lock().unwrap().clone() else {
            return Ok(None);
        };
        let Some(rewritten) = next.copied.lock().unwrap().rehint(reference)? else {
            return Ok(None);
        };
        reference = rewritten;
        identity = next.target_identity;
        generation = next.target.clone();
    }
}
/// An object, with the Zstandard bytes of its frame when the same read
/// authenticated a compressed frame.
type ObjectRead = (Arc<CanonicalObject>, Option<Arc<Vec<u8>>>);
fn read_object(
    file: &File,
    first: u64,
    end: u64,
    cache: &CacheLock,
    identity: u64,
    io: &PhysicalCounters,
    r: ObjectRef,
) -> Result<Arc<CanonicalObject>> {
    read_object_keeping(file, first, end, cache, identity, io, r, false).map(|read| read.0)
}
/// The object, and with `keep` the Zstandard bytes of its frame when this
/// call read and authenticated a compressed frame. A cache hit has no frame.
#[allow(clippy::too_many_arguments)]
fn read_object_keeping(
    file: &File,
    first: u64,
    end: u64,
    cache: &CacheLock,
    identity: u64,
    io: &PhysicalCounters,
    r: ObjectRef,
    keep: bool,
) -> Result<ObjectRead> {
    wire::validate_address(r.address, first, end)?;
    let length = r.address.length as usize;
    let recycled = match cache.get_or(identity, r, |cache| cache.take_read_buffer(length)) {
        Ok(object) => return Ok((object, None)),
        Err(recycled) => recycled,
    };
    let mut frame = recycled.unwrap_or_default();
    frame.resize(length, 0);
    // Small metadata frames are densely interleaved. Fetch their neighboring
    // immutable bytes once instead of issuing one cold positional I/O per node.
    // The window shares the decoded budget and never crosses this reader's
    // admitted extent. Every extracted frame still authenticates independently.
    // Recent publications cluster their directory and map paths at the tail.
    // Read those metadata pages in bounded 8/16 KiB windows to avoid a serial
    // cold I/O for every node. Older sparse points retain the 1 KiB policy.
    // Aligned windows can be reused while an appender advances its end.
    // A normal append can exceed 128 KiB before rereading the prior directory.
    // Keep both publications in the coalesced band while staging that append.
    let recent_metadata = length <= 8192 && end - r.address.offset <= 256 * 1024;
    let window_size = if !recent_metadata {
        1024
    } else if length <= 4096 {
        8 * 1024
    } else {
        16 * 1024
    };
    let mask = window_size - 1;
    let window_start = (r.address.offset & !mask).max(first);
    let window_end = (r.address.offset + length as u64)
        .checked_add(mask)
        .map(|end| end & !mask)
        .unwrap_or(end)
        .min(end);
    let window_length = (window_end - window_start) as usize;
    // A larger cached window may also contain a later request for a larger
    // frame. Cached bytes still confer no authority before frame validation.
    // Each step of a read that needs the cache takes the exclusive lock once.
    let (use_window, resident) = {
        let mut governing = cache.lock().unwrap();
        let use_window =
            (recent_metadata || length <= 1024) && governing.can_read_window(window_length);
        let hit = governing.read_window(identity, r.address.offset, &mut frame);
        (use_window, hit.then(|| governing.take_decoder()))
    };
    let mut decoder = match resident {
        Some(decoder) => decoder,
        None if use_window => {
            let mut bytes = vec![0; window_length];
            counted_read_at(file, &mut bytes, window_start, io, ReadClass::Object)?;
            let at = (r.address.offset - window_start) as usize;
            frame.copy_from_slice(&bytes[at..at + length]);
            let mut governing = cache.lock().unwrap();
            governing.insert_window(identity, window_start, bytes);
            governing.take_decoder()
        }
        None => {
            counted_read_at(file, &mut frame, r.address.offset, io, ReadClass::Object)?;
            cache.lock().unwrap().take_decoder()
        }
    };
    // The decoder checks these bytes; they are used only after it succeeds.
    let compressed = (keep && frame.get(4) == Some(&1))
        .then(|| {
            let stored = u32::from_le_bytes(frame.get(8..12)?.try_into().ok()?) as usize;
            frame
                .get(wire::FRAME..wire::FRAME.checked_add(stored)?)
                .map(|bytes| Arc::new(bytes.to_vec()))
        })
        .flatten();
    let decoded = decoder.decode_owned(r, frame, first, end);
    let mut cache = cache.lock().unwrap();
    cache.return_decoder(decoder);
    let object = Arc::new(decoded?);
    cache.verify(identity, r, (object.kind, object.version));
    cache.insert_shared(identity, r, &object);
    Ok((object, compressed))
}
struct FileSource<'a> {
    file: &'a File,
    io: &'a PhysicalCounters,
}
impl ReadAt for FileSource<'_> {
    fn len(&self) -> Result<u64> {
        Ok(self.file.metadata()?.len())
    }
    fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<()> {
        counted_read_at(self.file, bytes, offset, self.io, ReadClass::Bootstrap)
    }
}
fn admit_file(file: &File, io: &PhysicalCounters) -> Result<Reader> {
    // Bounded retries keep concurrent two-slot sampling from diagnosing a torn
    // pair as stable corruption. Writable admission is already fenced.
    let mut last = None;
    for _ in 0..4 {
        match Reader::open_at(&FileSource { file, io }) {
            Ok(reader) => return Ok(reader),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap())
}
fn read_trailer(
    file: &File,
    preamble: &wire::Preamble,
    offset: u64,
    io: &PhysicalCounters,
) -> Result<wire::Trailer> {
    let mut bytes = [0; 160];
    counted_read_at(file, &mut bytes, offset, io, ReadClass::Metadata)?;
    wire::Trailer::decode(&bytes, preamble, offset, file.metadata()?.len())
}
fn slot_offset(generation: u64) -> u64 {
    4096 + (generation % 2) * 4096
}
fn durable(file: &File) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        rustix::fs::fcntl_fullfsync(file).map_err(std::io::Error::from)?;
    }
    #[cfg(not(target_os = "macos"))]
    file.sync_all()?;
    Ok(())
}
fn sync_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let directory = File::open(path.parent().unwrap_or(Path::new(".")))?;
        directory.sync_all()?;
        #[cfg(target_os = "macos")]
        rustix::fs::fcntl_fullfsync(&directory).map_err(std::io::Error::from)?;
    }
    #[cfg(not(unix))]
    return Err(Error::Unsupported(
        "namespace durability unavailable".into(),
    ));
    Ok(())
}
fn verify_file_path(file: &File, path: &Path) -> Result<()> {
    // Check the namespace on every operation. On Unix, same-file identity is
    // exactly (device, inode), so fstat/stat avoid duplicating the retained
    // descriptor and opening/closing the pathname for each object rewrite.
    // Metadata follows symlinks, just as the previous pathname open did.
    #[cfg(unix)]
    let same = {
        use std::os::unix::fs::MetadataExt;
        let retained = file.metadata()?;
        let named = std::fs::metadata(path)?;
        (retained.dev(), retained.ino()) == (named.dev(), named.ino())
    };
    #[cfg(not(unix))]
    let same =
        same_file::Handle::from_file(file.try_clone()?)? == same_file::Handle::from_path(path)?;
    if !same {
        return Err(corrupt(
            "stale publication: destination names a different incarnation",
        ));
    }
    Ok(())
}
fn read_at(file: &File, buffer: &mut [u8], offset: u64) -> Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::read_exact_at(file, buffer, offset)?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut n = 0;
        while n < buffer.len() {
            let count = file.seek_read(&mut buffer[n..], offset + n as u64)?;
            if count == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
            }
            n += count;
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let mut f = file.try_clone()?;
        f.seek(SeekFrom::Start(offset))?;
        f.read_exact(buffer)?;
    }
    Ok(())
}
fn write_at(file: &mut File, buffer: &[u8], offset: u64) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.write_all_at(buffer, offset)?;
    }
    #[cfg(not(unix))]
    {
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(buffer)?;
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationFault {
    ChunksBarrier,
    SlotWrite { bytes: usize },
    SlotSync,
}
fn injected_failure() -> Error {
    std::io::Error::other("injected publication IO failure").into()
}

fn validate_closure_tracked(
    store: &impl ObjectStore,
    root: Option<ObjectRef>,
    cancelled: &impl Fn() -> bool,
    aggregate: Option<temporary::Budget>,
) -> Result<(ValidationReport, TemporaryIoStatistics)> {
    let budget = aggregate.map_or_else(
        || temporary::Budget::new(temporary::MAX_DISK),
        |aggregate| temporary::Budget::child(temporary::MAX_DISK, aggregate),
    );
    let mut seen =
        temporary::GraphTable::with_budget(temporary::GraphTable::RESIDENT_ENTRIES, budget.clone());
    let mut stack = DiskStack::with_budget(256, budget.clone())?;
    if let Some(root) = root {
        stack.push(root, false)?;
    }
    let mut report = ValidationReport::default();
    while let Some((reference, _)) = stack.pop()? {
        if cancelled() {
            return Err(std::io::Error::from(std::io::ErrorKind::Interrupted).into());
        }
        let key = spill::encode_ref(reference);
        if seen.get(&key)?.is_some() {
            continue;
        }
        seen.insert_cancellable(&key, &[], cancelled)?;
        let object = store.get_verified_shared(reference)?;
        validate_core_edges(&object, |child| {
            if cancelled() {
                return Err(std::io::Error::from(std::io::ErrorKind::Interrupted).into());
            }
            store.get_verified_shared(child)
        })?;
        report.objects += 1;
        if report.objects > 1_000_000_000 {
            return Err(Error::Limit("validation frame visits"));
        }
        report.decoded_bytes = report
            .decoded_bytes
            .checked_add(object.canonical_len() as u64)
            .ok_or(Error::Limit("validation decoded bytes"))?;
        for child in &object.children {
            if child
                .address
                .offset
                .checked_add(u64::from(child.address.length))
                .is_none_or(|end| end > reference.address.offset)
            {
                return Err(corrupt("closure child locator is not backward"));
            }
            stack.push(*child, false)?;
        }
    }
    Ok((report, budget.statistics()))
}
struct ValidationCacheGuard {
    cache: Arc<CacheLock>,
    old: usize,
}
impl ValidationCacheGuard {
    fn new(cache: Arc<CacheLock>, limits: &resources::Limits) -> Result<Self> {
        if limits.max_memory_bytes < 48 * 1024 * 1024 {
            return Err(Error::Limit("native validation memory"));
        }
        let old = cache.lock().unwrap().budget;
        cache.lock().unwrap().set_budget(0);
        Ok(Self { cache, old })
    }
}
impl Drop for ValidationCacheGuard {
    fn drop(&mut self) {
        self.cache.lock().unwrap().set_budget(self.old);
    }
}
fn validate_physical_closure(
    file: &File,
    reader: &Reader,
    io: &PhysicalCounters,
    store: &impl ObjectStore,
    limits: &resources::Limits,
) -> Result<ValidationReport> {
    let started = Instant::now();
    let budget = temporary::Budget::new(limits.max_temp_bytes);
    let mut inventory =
        temporary::GraphTable::with_budget(temporary::GraphTable::RESIDENT_ENTRIES, budget.clone());
    let mut offset = reader.first_record_offset();
    let end = reader.committed_end();
    let mut records = 0u64;
    let mut source_bytes = 0u64;
    let charge = |used: &mut u64, amount: u64| -> Result<()> {
        *used = used
            .checked_add(amount)
            .ok_or(Error::Limit("validation source bytes"))?;
        if *used > limits.max_source_bytes {
            return Err(Error::Limit("validation source bytes"));
        }
        Ok(())
    };
    while offset < end {
        records += 1;
        if records > limits.max_frames {
            return Err(Error::Limit("physical records"));
        }
        if started.elapsed() > limits.max_elapsed {
            return Err(Error::Limit("validation elapsed work"));
        }
        let mut header = [0; 56];
        charge(&mut source_bytes, 56)?;
        counted_read_at(file, &mut header, offset, io, ReadClass::Metadata)?;
        let span = if &header[..8] == b"SAC1END\0" {
            charge(&mut source_bytes, 160)?;
            let trailer = read_trailer(file, &reader.header, offset, io)?;
            if trailer.committed_end != offset + 160 {
                return Err(corrupt("physical trailer extent"));
            }
            160
        } else {
            let span = wire::frame_span(&header)? as u64;
            if offset.checked_add(span).is_none_or(|n| n > end) {
                return Err(corrupt("frame crosses selected extent"));
            }
            let decoded = u32::from_le_bytes(header[12..16].try_into().unwrap());
            let mut value = (span as u32).to_le_bytes().to_vec();
            value.extend(decoded.to_le_bytes());
            inventory.insert_cancellable(&offset.to_le_bytes(), &value, &|| false)?;
            let children = u16::from_le_bytes(header[6..8].try_into().unwrap()) as u64;
            let stored = u32::from_le_bytes(header[8..12].try_into().unwrap()) as u64;
            let used = 56 + stored + 12 * children;
            let pad = span - used;
            if pad > 0 {
                let mut bytes = [0; 7];
                charge(&mut source_bytes, pad)?;
                counted_read_at(
                    file,
                    &mut bytes[..pad as usize],
                    offset + used,
                    io,
                    ReadClass::Metadata,
                )?;
                if bytes[..pad as usize].iter().any(|b| *b != 0) {
                    return Err(corrupt("physical frame padding"));
                }
            }
            span
        };
        offset = offset
            .checked_add(span)
            .ok_or(Error::Limit("physical extent"))?;
        if offset > end {
            return Err(corrupt("record crosses selected extent"));
        }
    }
    if offset != end {
        return Err(corrupt("physical selected end"));
    }
    let mut seen =
        temporary::GraphTable::with_budget(temporary::GraphTable::RESIDENT_ENTRIES, budget.clone());
    let mut stack = DiskStack::with_budget(256, budget)?;
    if let Some(p) = reader.publication {
        stack.push(p.root, false)?;
    }
    let mut report = ValidationReport::default();
    let mut edges = 0u64;
    while let Some((r, expanded)) = stack.pop()? {
        if expanded {
            continue;
        }
        if started.elapsed() > limits.max_elapsed {
            return Err(Error::Limit("validation elapsed work"));
        }
        let key = spill::encode_ref(r);
        if seen.get(&key)?.is_some() {
            continue;
        }
        let record = inventory
            .get(&r.address.offset.to_le_bytes())?
            .ok_or_else(|| corrupt("reachable locator is not a top-level frame"))?;
        if record[..4] != r.address.length.to_le_bytes() {
            return Err(corrupt("reachable locator span"));
        }
        records = records
            .checked_add(1)
            .ok_or(Error::Limit("validation frame visits"))?;
        if records > limits.max_frames {
            return Err(Error::Limit("validation frame visits"));
        }
        charge(&mut source_bytes, r.address.length as u64)?;
        let decoded = u32::from_le_bytes(record[4..8].try_into().unwrap()) as u64;
        let next = report
            .decoded_bytes
            .checked_add(decoded)
            .ok_or(Error::Limit("validation decoded bytes"))?;
        if next > limits.max_decoded_bytes {
            return Err(Error::Limit("validation decoded bytes"));
        }
        seen.insert_cancellable(&key, &[], &|| false)?;
        let object = store.get_verified_shared(r)?;
        report.decoded_bytes = next;
        validate_core_edges(&object, |child| {
            if started.elapsed() > limits.max_elapsed {
                return Err(Error::Limit("validation elapsed work"));
            }
            records = records
                .checked_add(1)
                .ok_or(Error::Limit("validation frame visits"))?;
            if records > limits.max_frames {
                return Err(Error::Limit("validation frame visits"));
            }
            charge(&mut source_bytes, u64::from(child.address.length))?;
            let fetched = store.get_verified_shared(child)?;
            report.decoded_bytes = report
                .decoded_bytes
                .checked_add(fetched.canonical_len() as u64)
                .ok_or(Error::Limit("validation decoded bytes"))?;
            if report.decoded_bytes > limits.max_decoded_bytes {
                return Err(Error::Limit("validation decoded bytes"));
            }
            Ok(fetched)
        })?;
        report.objects += 1;
        for child in object.children.iter().rev() {
            edges = edges
                .checked_add(1)
                .ok_or(Error::Limit("validation graph edges"))?;
            if edges > limits.max_edges {
                return Err(Error::Limit("validation graph edges"));
            }
            stack.push(*child, false)?;
        }
    }
    Ok(report)
}

#[derive(Clone, Debug)]
pub struct CompactionBudget {
    pub max_catch_up_bytes: u64,
    pub max_pause: Duration,
    pub max_elapsed: Duration,
    pub max_temporary_bytes: u64,
    pub max_garbage_bytes: u64,
    pub preserve_recovery_input: bool,
}
impl Default for CompactionBudget {
    fn default() -> Self {
        Self {
            max_catch_up_bytes: 16 * 1024 * 1024,
            max_pause: Duration::from_millis(100),
            max_elapsed: Duration::from_secs(120),
            max_temporary_bytes: 64 * 1024 * 1024 * 1024,
            max_garbage_bytes: u64::MAX,
            preserve_recovery_input: false,
        }
    }
}
// The shared cancellation callback is boolean for copier/temporary APIs. Keep
// the observed cause so only their cooperative Interrupted error is reclassified;
// an unrelated OS Interrupted remains an I/O error even after a deadline elapsed.
struct CompactionFinishCancellation<'a> {
    caller: &'a dyn Fn() -> bool,
    pause_started: Instant,
    started: Instant,
    max_pause: Duration,
    max_elapsed: Duration,
    deadline_observed: std::cell::Cell<bool>,
}
impl CompactionFinishCancellation<'_> {
    fn cancelled(&self) -> bool {
        if (self.caller)() {
            return true;
        }
        let expired = self.pause_started.elapsed() > self.max_pause
            || self.started.elapsed() > self.max_elapsed;
        if expired {
            self.deadline_observed.set(true);
        }
        expired
    }
    fn interruption(&self) -> Error {
        if self.deadline_observed.get() {
            Error::Limit("compaction pause or elapsed work")
        } else {
            std::io::Error::from(std::io::ErrorKind::Interrupted).into()
        }
    }
    fn classify(&self, error: Error) -> Error {
        if self.deadline_observed.get()
            && matches!(&error, Error::Io(io) if io.kind() == std::io::ErrorKind::Interrupted)
        {
            self.interruption()
        } else {
            error
        }
    }
}
#[derive(Clone, Default, Debug)]
pub struct CompactionStatistics {
    pub copied_bytes: u64,
    pub catch_up_bytes: u64,
    pub residual_garbage_bytes: u64,
    pub pause_ns: u64,
    pub elapsed_ns: u64,
    pub copier_temporary: TemporaryIoStatistics,
    pub validation_temporary: TemporaryIoStatistics,
    pub retention_temporary: TemporaryIoStatistics,
    pub target_index_temporary: TemporaryIoStatistics,
    pub layout_temporary: TemporaryIoStatistics,
    pub peak_aggregate_temporary_bytes: u64,
    pub catch_up_index_write_bytes: u64,
    pub catch_up_slot_write_bytes: u64,
    pub catch_up_total_write_bytes: u64,
}
#[derive(Clone, Default, Debug)]
pub struct CompactionCleanupStatistics {
    pub retained_inode_bytes: u64,
    pub recovery_path: Option<PathBuf>,
    pub error: Option<String>,
}
struct PendingCompactionCleanup {
    path: PathBuf,
    bytes: u64,
    task: Option<std::thread::JoinHandle<Result<()>>>,
    error: Option<String>,
}
impl Drop for PendingCompactionCleanup {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}
type CompactionProjector<'a> = dyn FnMut(
        &NativeReader,
        &mut NativeStore,
        &mut ClosureCopy,
        Option<ObjectRef>,
        &dyn Fn() -> bool,
    ) -> Result<ObjectRef>
    + 'a;

pub struct Compaction {
    source: NativeReader,
    source_path: PathBuf,
    recovery_backup: Option<PathBuf>,
    keep_recovery_backup: bool,
    target: NativeStore,
    copied: ClosureCopy,
    prepared: bool,
    temporary: PathBuf,
    active: Arc<std::sync::atomic::AtomicBool>,
    aggregate_temporary: temporary::Budget,
    layout_budget: temporary::Budget,
    plan_reservation: temporary::Reservation,
    bundle_reservation: temporary::Reservation,
    plan: File,
    plan_groups: u64,
    bundle_ranges: File,
    bundle_count: u64,
    ranges: CompactionRanges,
    retained: temporary::GraphTable,
    base_root: Option<ObjectRef>,
    source_base_root: Option<ObjectRef>,
    projected: bool,
    garbage: u64,
    budget: CompactionBudget,
    statistics: CompactionStatistics,
    started: Instant,
}
impl Drop for Compaction {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.temporary);
        if !self.keep_recovery_backup
            && let Some(backup) = &self.recovery_backup
        {
            let _ = std::fs::remove_file(backup);
            let _ = sync_parent(backup);
        }
        self.active
            .store(false, std::sync::atomic::Ordering::Release);
    }
}
impl NativeStore {
    pub fn begin_compaction(&self) -> Result<Compaction> {
        self.check_writable()?;
        self.verify_current_path()?;
        if self.compaction_cleanup_statistics().retained_inode_bytes != 0 {
            return Err(Error::Busy);
        }
        if self
            .compaction_active
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return Err(Error::Unsupported("compaction already active".into()));
        }
        let result = (|| {
            let source = self.pin()?;
            let mut incarnation = [0; 16];
            File::open("/dev/urandom")?.read_exact(&mut incarnation)?;
            // A candidate left by a killed process can carry a recycled
            // process ID and the same counter value. It is never ours.
            let mut attempts = 0;
            let (temporary, mut target) = loop {
                let temporary = self.path.with_extension(format!(
                    "sac1-compact-{}-{}",
                    std::process::id(),
                    next_file_identity()
                ));
                match Self::create_policy(&temporary, wire::Preamble::live(incarnation)?) {
                    Ok(target) => break (temporary, target),
                    Err(Error::Io(error))
                        if error.kind() == std::io::ErrorKind::AlreadyExists && attempts < 4096 =>
                    {
                        attempts += 1;
                    }
                    Err(error) => return Err(error),
                }
            };
            target.cache = self.cache.clone();
            target.io = self.io.clone();
            target.compaction_target = true;
            let budget = CompactionBudget::default();
            let aggregate = temporary::Budget::new(budget.max_temporary_bytes);
            target.temporary_extent = Some(aggregate.reserve(target.end)?);
            target.recent.0.budget.attach_aggregate(aggregate.clone())?;
            let copied = ClosureCopy::new()?;
            copied.attach_aggregate_budget(aggregate.clone())?;
            let retained = temporary::GraphTable::with_budget(
                temporary::GraphTable::RESIDENT_ENTRIES,
                temporary::Budget::child(temporary::MAX_DISK, aggregate.clone()),
            );
            let layout_budget = temporary::Budget::child(temporary::MAX_DISK, aggregate.clone());
            Ok(Compaction {
                source,
                source_path: self.path.clone(),
                recovery_backup: None,
                keep_recovery_backup: false,
                target,
                copied,
                prepared: false,
                temporary,
                active: self.compaction_active.clone(),
                plan_reservation: layout_budget.reserve(0)?,
                bundle_reservation: layout_budget.reserve(0)?,
                aggregate_temporary: aggregate,
                layout_budget,
                plan: tempfile::tempfile()?,
                plan_groups: 0,
                bundle_ranges: tempfile::tempfile()?,
                bundle_count: 0,
                ranges: CompactionRanges::default(),
                retained,
                base_root: None,
                source_base_root: None,
                projected: false,
                garbage: 0,
                budget,
                statistics: CompactionStatistics::default(),
                started: Instant::now(),
            })
        })();
        if result.is_err() {
            self.compaction_active
                .store(false, std::sync::atomic::Ordering::Release);
        }
        result
    }
    pub fn finish_compaction(&mut self, job: Compaction) -> Result<()> {
        self.finish_compaction_pinned_cancellable(job, &|| false)
            .map(drop)
    }
    pub fn finish_compaction_pinned(&mut self, job: Compaction) -> Result<NativeReader> {
        self.finish_compaction_pinned_cancellable(job, &|| false)
    }
    pub fn finish_compaction_pinned_cancellable(
        &mut self,
        job: Compaction,
        cancelled: &impl Fn() -> bool,
    ) -> Result<NativeReader> {
        self.finish_compaction_with_projector(job, None, cancelled)
    }
    /// Finish a projected candidate prepared with
    /// [`Compaction::copy_projected_cancellable`]. The projector receives the
    /// latest admitted source pin and the previously published private candidate.
    /// It is skipped when the source Commit has not changed. Its writes, scratch,
    /// cancellation and strict graph checks share the ordinary cutover budgets.
    pub fn finish_compaction_projected_pinned_cancellable(
        &mut self,
        job: Compaction,
        projector: &mut impl FnMut(
            &NativeReader,
            &mut NativeStore,
            &mut ClosureCopy,
            Option<ObjectRef>,
            &dyn Fn() -> bool,
        ) -> Result<ObjectRef>,
        cancelled: &impl Fn() -> bool,
    ) -> Result<NativeReader> {
        self.finish_compaction_with_projector(job, Some(projector), cancelled)
    }
    fn finish_compaction_with_projector(
        &mut self,
        mut job: Compaction,
        projector: Option<&mut CompactionProjector<'_>>,
        cancelled: &impl Fn() -> bool,
    ) -> Result<NativeReader> {
        let started = Instant::now();
        let before = job.target.end;
        let index = job.target.recent.0.budget.clone();
        let copied = job.copied.temporary_budget();
        let retained = job.retained.budget.clone();
        let layout = job.layout_budget.clone();
        let index_before = index.statistics().write_bytes;
        let copied_before = copied.statistics().write_bytes;
        let retained_before = retained.statistics().write_bytes;
        let slot_before = job.target.publication_statistics().slot_write_bytes;
        let result = self.finish_compaction_inner(&mut job, projector, cancelled);
        if result.is_err() {
            job.statistics.catch_up_bytes = job.target.end.saturating_sub(before);
            job.statistics.copier_temporary = copied.statistics();
            job.statistics.target_index_temporary = index.statistics();
            job.statistics.retention_temporary = retained.statistics();
            job.statistics.layout_temporary = layout.statistics();
            job.statistics.peak_aggregate_temporary_bytes =
                job.aggregate_temporary.statistics().peak_reserved_bytes;
            job.statistics.catch_up_index_write_bytes =
                index.statistics().write_bytes - index_before + copied.statistics().write_bytes
                    - copied_before
                    + retained.statistics().write_bytes
                    - retained_before;
            job.statistics.catch_up_slot_write_bytes =
                job.target.publication_statistics().slot_write_bytes - slot_before;
            job.statistics.catch_up_total_write_bytes = job.statistics.catch_up_bytes
                + job.statistics.catch_up_index_write_bytes
                + job.statistics.catch_up_slot_write_bytes;
            job.statistics.pause_ns = started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            job.statistics.elapsed_ns =
                job.started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        }
        self.last_compaction_attempt_statistics = Some(job.statistics.clone());
        result
    }
    fn finish_compaction_inner(
        &mut self,
        job: &mut Compaction,
        projector: Option<&mut CompactionProjector<'_>>,
        cancelled: &impl Fn() -> bool,
    ) -> Result<NativeReader> {
        self.check_writable()?;
        self.verify_current_path()?;
        if !job.prepared {
            return Err(corrupt("compaction must be prepared"));
        }
        if job.projected != projector.is_some() {
            return Err(corrupt("compaction projection mode mismatch"));
        }
        if job.source.file_identity != self.file_identity {
            return Err(corrupt("compaction source identity changed"));
        }
        let start = Instant::now();
        let stop = CompactionFinishCancellation {
            caller: cancelled,
            pause_started: start,
            started: job.started,
            max_pause: job.budget.max_pause,
            max_elapsed: job.budget.max_elapsed,
            deadline_observed: std::cell::Cell::new(false),
        };
        let cancelled = || stop.cancelled();
        if cancelled() {
            return Err(stop.interruption());
        }
        let current = self
            .root()
            .ok_or_else(|| corrupt("compaction current root"))?;
        let before = job.target.end;
        let index_writes_before = job.target.temporary_statistics().write_bytes;
        let copier_writes_before = job.copied.temporary_statistics().write_bytes;
        let retention_writes_before = job.retained.budget.statistics().write_bytes;
        let slot_writes_before = job.target.publication_statistics().slot_write_bytes;
        job.target.set_file_byte_limit(
            before
                .checked_add(job.budget.max_catch_up_bytes)
                .ok_or(Error::Limit("compaction catch-up extent"))?
                .min(job.budget.max_temporary_bytes),
        )?;
        let copied = if let Some(projector) = projector {
            if job.source_base_root == Some(current.root) {
                job.base_root
                    .ok_or_else(|| corrupt("projected candidate root"))?
            } else {
                let latest = self.pin()?;
                let root = projector(
                    &latest,
                    &mut job.target,
                    &mut job.copied,
                    job.base_root,
                    &cancelled,
                )
                .map_err(|error| stop.classify(error))?;
                job.validate_projected_root(root, &cancelled)
                    .map_err(|error| stop.classify(error))?;
                root
            }
        } else {
            job.copied
                .copy_root_cancellable(self, &mut job.target, current.root, &cancelled)
                .map_err(|error| stop.classify(error))?
        };
        let mut catch_up = job.target.end - before;
        if catch_up > job.budget.max_catch_up_bytes
            || job.target.end > job.budget.max_temporary_bytes
        {
            return Err(Error::Limit("compaction catch-up bytes"));
        }
        // Adding the new root before releasing the old one preserves common
        // DAG reference counts, so unchanged subtrees never need a cutover scan.
        job.adjust_retained(copied, true, &cancelled)
            .map_err(|error| stop.classify(error))?;
        if let Some(base) = job.base_root {
            job.adjust_retained(base, false, &cancelled)
                .map_err(|error| stop.classify(error))?;
        }
        let allowance = job
            .budget
            .max_garbage_bytes
            .min(job.statistics.copied_bytes / 20);
        if job.garbage > allowance {
            return Err(Error::Limit("compaction live garbage allowance"));
        }
        if cancelled() {
            return Err(stop.interruption());
        }
        if !job.projected {
            let control_roots = self
                .control_roots
                .iter()
                .map(|root| {
                    job.copied
                        .copied
                        .get(root.hash)?
                        .ok_or_else(|| corrupt("compaction control root not retained"))
                })
                .collect::<Result<Vec<_>>>()?;
            job.target.set_control_roots(&control_roots)?;
        }
        job.target.publish_commit(copied)?;
        catch_up = job.target.end - before;
        job.statistics.copier_temporary = job.copied.temporary_statistics();
        job.statistics.retention_temporary = job.retained.budget.statistics();
        job.statistics.target_index_temporary = job.target.temporary_statistics();
        job.statistics.layout_temporary = job.layout_budget.statistics();
        job.statistics.peak_aggregate_temporary_bytes =
            job.aggregate_temporary.statistics().peak_reserved_bytes;
        job.statistics.catch_up_index_write_bytes =
            job.statistics.target_index_temporary.write_bytes - index_writes_before
                + job.statistics.copier_temporary.write_bytes
                - copier_writes_before
                + job.statistics.retention_temporary.write_bytes
                - retention_writes_before;
        job.statistics.catch_up_slot_write_bytes =
            job.target.publication_statistics().slot_write_bytes - slot_writes_before;
        job.statistics.catch_up_total_write_bytes = catch_up
            + job.statistics.catch_up_index_write_bytes
            + job.statistics.catch_up_slot_write_bytes;
        if job.statistics.catch_up_total_write_bytes > job.budget.max_catch_up_bytes {
            return Err(Error::Limit("compaction catch-up physical writes"));
        }
        // A storage barrier may complete after the cooperative pause budget.
        // The candidate is still private, so retire it before visible replacement.
        if cancelled() {
            return Err(stop.interruption());
        }
        job.target.cache = self.cache.clone();
        let pinned = job.target.pin()?;
        let remap = Arc::new(ForwardRemap {
            copied: Mutex::new(std::mem::replace(&mut job.copied, ClosureCopy::new()?)),
            target_identity: job.target.file_identity,
            target: job.target.generation.clone(),
            _charge: MetadataReservation::new(
                self.cache.clone(),
                std::mem::size_of::<ForwardRemap>() + std::mem::size_of::<FileGeneration>() + 64,
            )?,
        });
        // Keep a durable name for the old recovery input across uncertain rename
        // outcomes. The inode lock and destination fence remain owned throughout.
        let backup = job
            .recovery_backup
            .clone()
            .ok_or_else(|| corrupt("compaction recovery input not prepared"))?;
        verify_file_path(&job.source.file, &backup)?;
        let retained_inode_bytes = self.file_len();
        if cancelled() {
            return Err(stop.interruption());
        }
        // From the rename attempt onward an error may leave either namespace
        // installed. Retain the durable recovery input in every such outcome.
        job.keep_recovery_backup = true;
        self.poisoned = true;
        std::fs::rename(&job.target.path, &self.path)?;
        sync_parent(&self.path)?;
        verify_file_path(job.target.file.get_mut().unwrap(), &self.path)?;
        let fence = self.fence.take();
        job.target.fence = fence;
        job.target.path = self.path.clone();
        job.target.cache = self.cache.clone();
        job.target.compaction_active = self.compaction_active.clone();
        *self.generation.next.lock().unwrap() = Some(remap);
        std::mem::swap(self, &mut job.target);
        self.poisoned = false;
        self.compaction_target = false;
        self.temporary_extent = None;
        self.recent.0.budget.detach_aggregate();
        self.max_file_bytes = job.target.max_file_bytes;
        if job.budget.preserve_recovery_input {
            self.recovery_preserved = Some(backup.clone());
        } else {
            let path = backup.clone();
            // The replacement is durably installed. Namespace garbage
            // collection owns exactly this unique old-inode recovery link.
            let spawned = std::thread::Builder::new()
                .name("sac1-cleanup".into())
                .spawn(move || {
                    std::fs::remove_file(&path)?;
                    sync_parent(&path)
                });
            let (task, error) = match spawned {
                Ok(task) => (Some(task), None),
                Err(error) => (None, Some(error.to_string())),
            };
            *self.compaction_cleanup.lock().unwrap() = Some(PendingCompactionCleanup {
                path: backup,
                bytes: retained_inode_bytes,
                task,
                error,
            });
            job.recovery_backup = None;
        }
        job.statistics.catch_up_bytes = catch_up;
        job.statistics.residual_garbage_bytes = job.garbage;
        job.statistics.pause_ns = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        job.statistics.elapsed_ns = job.started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        self.last_compaction_statistics = Some(job.statistics.clone());
        Ok(pinned)
    }
    pub fn compact(&mut self) -> Result<()> {
        let mut job = self.begin_compaction()?;
        job.copy()?;
        self.finish_compaction(job)
    }
}
impl Compaction {
    pub fn set_budget(&mut self, budget: CompactionBudget) -> Result<()> {
        if self.prepared {
            return Err(corrupt("compaction already prepared"));
        }
        self.aggregate_temporary
            .set_limit(budget.max_temporary_bytes)?;
        self.target
            .set_file_byte_limit(budget.max_temporary_bytes)?;
        self.budget = budget;
        Ok(())
    }
    pub fn statistics(&self) -> &CompactionStatistics {
        &self.statistics
    }
    pub fn aggregate_temporary_bytes(&self) -> u64 {
        self.aggregate_temporary.used()
    }
    pub fn candidate_file_bytes(&self) -> Result<u64> {
        Ok(self.target.file.lock().unwrap().metadata()?.len())
    }
    pub fn set_layout(&mut self, layout: CompactionLayout) -> Result<()> {
        self.set_layout_iterator(layout.front, layout.bundles.into_iter().map(Ok))
    }
    pub fn set_layout_iterator(
        &mut self,
        front: Vec<ObjectHash>,
        bundles: impl IntoIterator<Item = Result<Vec<ObjectHash>>>,
    ) -> Result<()> {
        if self.prepared {
            return Err(corrupt("compaction already prepared"));
        }
        let mut plan = tempfile::tempfile()?;
        let mut reservation = self.layout_budget.reserve(0)?;
        let mut groups = 0u64;
        for group in std::iter::once(Ok(front)).chain(bundles) {
            let group = group?;
            let span = (group.len() as u64)
                .checked_mul(32)
                .and_then(|n| n.checked_add(8))
                .ok_or(Error::Limit("compaction plan bytes"))?;
            reservation.grow_to(
                plan.stream_position()?
                    .checked_add(span)
                    .ok_or(Error::Limit("compaction plan bytes"))?,
            )?;
            plan.write_all(&(group.len() as u64).to_le_bytes())?;
            for hash in group {
                plan.write_all(&hash.0)?;
            }
            self.layout_budget.wrote(span);
            groups = groups
                .checked_add(1)
                .ok_or(Error::Limit("compaction groups"))?;
            if plan.stream_position()? > self.budget.max_temporary_bytes {
                return Err(Error::Limit("compaction plan bytes"));
            }
        }
        self.plan = plan;
        self.plan_reservation = reservation;
        self.plan_groups = groups;
        Ok(())
    }
    pub fn layout_front_ranges(&self) -> &[ReadRequest] {
        &self.ranges.front
    }
    pub fn layout_bundle_ranges(&self) -> impl Iterator<Item = Result<ReadRequest>> + '_ {
        (0..self.bundle_count).map(|i| {
            let mut row = [0; 12];
            read_at(&self.bundle_ranges, &mut row, i * 12)?;
            self.layout_budget.read(12);
            Ok(ReadRequest {
                offset: u64::from_le_bytes(row[..8].try_into().unwrap()),
                length: u32::from_le_bytes(row[8..].try_into().unwrap()),
            })
        })
    }
    pub fn layout_ranges(&self) -> Result<CompactionRanges> {
        if self.bundle_count > 4096 {
            return Err(Error::Limit("collected layout ranges"));
        }
        Ok(CompactionRanges {
            front: self.ranges.front.clone(),
            bundles: self.layout_bundle_ranges().collect::<Result<Vec<_>>>()?,
        })
    }
    pub fn copy(&mut self) -> Result<()> {
        self.copy_cancellable(|| false)
    }
    pub fn copy_cancellable(&mut self, cancelled: impl Fn() -> bool) -> Result<()> {
        let outcome = self.copy_inner_cancellable(cancelled);
        self.statistics.copier_temporary = self.copied.temporary_statistics();
        self.statistics.retention_temporary = self.retained.budget.statistics();
        self.statistics.target_index_temporary = self.target.temporary_statistics();
        self.statistics.layout_temporary = self.layout_budget.statistics();
        self.statistics.peak_aggregate_temporary_bytes =
            self.aggregate_temporary.statistics().peak_reserved_bytes;
        outcome
    }
    /// Prepare an application-projected candidate without copying the source
    /// Commit's entire closure. The callback selects immutable component closures
    /// through the supplied bounded copier and authors a fresh Commit in target.
    /// `previous` is None initially and Some(candidate Commit) during catch-up.
    /// It must configure target control roots and poll cancellation during work.
    /// No old locality plan is applied: it may name deliberately pruned objects.
    /// Errors leave the source publication unchanged; this job should be dropped.
    pub fn copy_projected_cancellable(
        &mut self,
        projector: &mut impl FnMut(
            &NativeReader,
            &mut NativeStore,
            &mut ClosureCopy,
            Option<ObjectRef>,
            &dyn Fn() -> bool,
        ) -> Result<ObjectRef>,
        cancelled: impl Fn() -> bool,
    ) -> Result<()> {
        if self.prepared {
            return if self.projected {
                Ok(())
            } else {
                Err(corrupt("compaction projection mode mismatch"))
            };
        }
        self.projected = true;
        let outcome = self.copy_inner_with_projector(Some(projector), cancelled);
        self.statistics.copier_temporary = self.copied.temporary_statistics();
        self.statistics.retention_temporary = self.retained.budget.statistics();
        self.statistics.target_index_temporary = self.target.temporary_statistics();
        self.statistics.layout_temporary = self.layout_budget.statistics();
        self.statistics.peak_aggregate_temporary_bytes =
            self.aggregate_temporary.statistics().peak_reserved_bytes;
        outcome
    }
    /// Rebase an ordinary prepared candidate from a newer immutable source pin
    /// without holding the writer's cutover fence. The source must name the same
    /// admitted file incarnation and may not move backward. Copying and private
    /// publication use the preparation elapsed/temporary/garbage quotas; the
    /// final `finish_compaction` still enforces its catch-up and pause limits.
    /// A concurrent consumer should copy, refresh from its latest pin off-lock,
    /// then finish under its writer fence. Discard this job after any error.
    pub fn refresh_cancellable(
        &mut self,
        source: &NativeReader,
        cancelled: impl Fn() -> bool,
    ) -> Result<()> {
        let outcome = self.refresh_inner(source, None, &cancelled);
        self.statistics.copier_temporary = self.copied.temporary_statistics();
        self.statistics.retention_temporary = self.retained.budget.statistics();
        self.statistics.target_index_temporary = self.target.temporary_statistics();
        self.statistics.layout_temporary = self.layout_budget.statistics();
        self.statistics.peak_aggregate_temporary_bytes =
            self.aggregate_temporary.statistics().peak_reserved_bytes;
        self.statistics.elapsed_ns = self.started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        outcome
    }
    /// Rebase a prepared projected candidate to a newer immutable source pin
    /// before taking the writer's cutover fence. This preparation work uses the
    /// existing elapsed, aggregate temporary and garbage quotas, not the final
    /// catch-up byte/pause allowance. The final fence still handles only its
    /// bounded last delta. Errors leave the source unchanged; discard this job.
    pub fn refresh_projected_cancellable(
        &mut self,
        source: &NativeReader,
        projector: &mut impl FnMut(
            &NativeReader,
            &mut NativeStore,
            &mut ClosureCopy,
            Option<ObjectRef>,
            &dyn Fn() -> bool,
        ) -> Result<ObjectRef>,
        cancelled: impl Fn() -> bool,
    ) -> Result<()> {
        let outcome = self.refresh_inner(source, Some(projector), &cancelled);
        self.statistics.copier_temporary = self.copied.temporary_statistics();
        self.statistics.retention_temporary = self.retained.budget.statistics();
        self.statistics.target_index_temporary = self.target.temporary_statistics();
        self.statistics.layout_temporary = self.layout_budget.statistics();
        self.statistics.peak_aggregate_temporary_bytes =
            self.aggregate_temporary.statistics().peak_reserved_bytes;
        self.statistics.elapsed_ns = self.started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        outcome
    }
    fn refresh_inner(
        &mut self,
        source: &NativeReader,
        projector: Option<&mut CompactionProjector<'_>>,
        cancelled: &impl Fn() -> bool,
    ) -> Result<()> {
        if !self.prepared || self.projected != projector.is_some() {
            return Err(corrupt(
                "compaction refresh preparation or projection mode mismatch",
            ));
        }
        if source.file_identity != self.source.file_identity
            || source.reader.committed_end() < self.source.reader.committed_end()
        {
            return Err(corrupt(
                "compaction refresh source identity or extent changed",
            ));
        }
        verify_file_path(&source.file, &self.source_path)?;
        let start = self.started;
        let elapsed = self.budget.max_elapsed;
        let cancelled = || cancelled() || start.elapsed() > elapsed;
        if cancelled() {
            return Err(Error::Limit("compaction elapsed work"));
        }
        let publication = source
            .root()
            .ok_or_else(|| corrupt("empty compaction refresh source"))?;
        if self.source_base_root == Some(publication.root) {
            return Ok(());
        }
        let next_source = NativeReader::from_pinned(
            source.file.try_clone()?,
            source.reader.clone(),
            source.cache.clone(),
            source.file_identity,
            source.generation.clone(),
            source.io.clone(),
        )?;
        self.target
            .set_file_byte_limit(self.budget.max_temporary_bytes)?;
        let root = if let Some(projector) = projector {
            let root = projector(
                source,
                &mut self.target,
                &mut self.copied,
                self.base_root,
                &cancelled,
            )?;
            self.validate_projected_root(root, &cancelled)?;
            root
        } else {
            self.copied.copy_root_cancellable(
                source,
                &mut self.target,
                publication.root,
                &cancelled,
            )?
        };
        // Add before releasing the prior root: shared DAG components are not
        // rescanned and every now-obsolete physical byte remains charged.
        self.adjust_retained(root, true, &cancelled)?;
        if let Some(previous) = self.base_root {
            self.adjust_retained(previous, false, &cancelled)?;
        }
        let prepared_bytes = self.target.end - self.target.reader.first_record_offset();
        if self.garbage > self.budget.max_garbage_bytes.min(prepared_bytes / 20) {
            return Err(Error::Limit("compaction live garbage allowance"));
        }
        if cancelled() {
            return Err(Error::Limit("compaction elapsed work"));
        }
        verify_file_path(&source.file, &self.source_path)?;
        self.target.publish_commit(root)?;
        if cancelled() {
            return Err(Error::Limit("compaction elapsed work"));
        }
        self.source = next_source;
        self.source_base_root = Some(publication.root);
        self.base_root = Some(root);
        self.statistics.copied_bytes = self.target.end - self.target.reader.first_record_offset();
        self.statistics.residual_garbage_bytes = self.garbage;
        Ok(())
    }
    fn copy_inner_cancellable(&mut self, cancelled: impl Fn() -> bool) -> Result<()> {
        if self.projected {
            return Err(corrupt("compaction projection mode mismatch"));
        }
        self.copy_inner_with_projector(None, cancelled)
    }
    fn copy_inner_with_projector(
        &mut self,
        projector: Option<&mut CompactionProjector<'_>>,
        cancelled: impl Fn() -> bool,
    ) -> Result<()> {
        if self.prepared {
            return Ok(());
        }
        let start = self.started;
        let elapsed = self.budget.max_elapsed;
        let cancelled = || cancelled() || start.elapsed() > elapsed;
        let Some(publication) = self.source.root() else {
            return Err(corrupt("empty compaction source"));
        };
        // Build the optional locality plan's source lookup without an in-memory
        // object census. All physical occurrences are checked by ClosureCopy.
        if self.plan_groups > 0 && projector.is_none() {
            let mut sources = DiskRefs(temporary::GraphTable::with_budget(
                temporary::GraphTable::RESIDENT_ENTRIES,
                self.layout_budget.clone(),
            ));
            let mut seen = temporary::GraphTable::with_budget(
                temporary::GraphTable::RESIDENT_ENTRIES,
                self.layout_budget.clone(),
            );
            let mut stack = DiskStack::with_budget(256, self.layout_budget.clone())?;
            stack.push(publication.root, false)?;
            while let Some((r, _)) = stack.pop()? {
                if cancelled() {
                    return Err(Error::Limit("compaction elapsed work"));
                }
                if seen.get(&spill::encode_ref(r))?.is_some() {
                    continue;
                }
                seen.insert_cancellable(&spill::encode_ref(r), &[], &cancelled)?;
                let object = self.source.get_shared(r)?;
                self.copied.mark_validated(r, &cancelled)?;
                sources.insert_cancellable(r, &cancelled)?;
                for child in &object.children {
                    stack.push(*child, false)?;
                }
            }
            self.plan.seek(SeekFrom::Start(0))?;
            for group in 0..self.plan_groups {
                let mut count = [0; 8];
                self.plan.read_exact(&mut count)?;
                self.layout_budget.read(8);
                let count = u64::from_le_bytes(count);
                let first = self.target.end;
                for _ in 0..count {
                    let mut hash = [0; 32];
                    self.plan.read_exact(&mut hash)?;
                    self.layout_budget.read(32);
                    let source = sources
                        .get(ObjectHash(hash))?
                        .ok_or_else(|| corrupt("layout names unreachable object"))?;
                    self.copied.copy_root_cancellable(
                        &self.source,
                        &mut self.target,
                        source,
                        &cancelled,
                    )?;
                    if self.target.end > self.budget.max_temporary_bytes {
                        return Err(Error::Limit("compaction bytes"));
                    }
                }
                let range = ReadRequest {
                    offset: first,
                    length: u32::try_from(self.target.end - first)
                        .map_err(|_| Error::Limit("layout group bytes"))?,
                };
                if group == 0 {
                    self.ranges.front.push(range);
                } else {
                    let mut row = range.offset.to_le_bytes().to_vec();
                    row.extend(range.length.to_le_bytes());
                    self.bundle_reservation.grow_to(
                        (self.bundle_count + 1)
                            .checked_mul(12)
                            .ok_or(Error::Limit("compaction layout ranges"))?,
                    )?;
                    self.bundle_ranges.write_all(&row)?;
                    self.layout_budget.wrote(row.len() as u64);
                    self.bundle_count += 1;
                }
            }
        }
        let root = if let Some(projector) = projector {
            let root = projector(
                &self.source,
                &mut self.target,
                &mut self.copied,
                None,
                &cancelled,
            )?;
            self.validate_projected_root(root, &cancelled)?;
            root
        } else {
            let root = self.copied.copy_root_cancellable(
                &self.source,
                &mut self.target,
                publication.root,
                &cancelled,
            )?;
            let (_, temporary) = validate_closure_tracked(
                &self.target,
                Some(root),
                &cancelled,
                Some(self.aggregate_temporary.clone()),
            )?;
            self.statistics.validation_temporary = temporary;
            root
        };
        self.source_base_root = Some(publication.root);
        self.base_root = Some(root);
        self.adjust_retained(root, true, &cancelled)?;
        // Install and synchronize the private candidate before obtaining the
        // foreground cutover interval. Catch-up still publishes the new head
        // with the ordinary two durability barriers while the writer is held.
        self.target.publish_commit(root)?;
        if cancelled() {
            return Err(Error::Limit("compaction elapsed work"));
        }
        verify_file_path(&self.source.file, &self.source_path)?;
        // A preserved recovery input from an earlier interrupted writer keeps
        // its name. The process-local counter restarts in every process, so
        // an existing name means "taken", never "ours": choose another one.
        let mut attempts = 0;
        let backup = loop {
            let candidate = self
                .source_path
                .with_extension(format!("sac1-recovery-{}", next_file_identity()));
            match std::fs::hard_link(&self.source_path, &candidate) {
                Ok(()) => break candidate,
                Err(error)
                    if error.kind() == std::io::ErrorKind::AlreadyExists && attempts < 4096 =>
                {
                    attempts += 1;
                }
                Err(error) => return Err(error.into()),
            }
        };
        self.recovery_backup = Some(backup.clone());
        verify_file_path(&self.source.file, &backup)?;
        sync_parent(&backup)?;
        self.statistics.copied_bytes = self.target.end - self.target.reader.first_record_offset();
        self.statistics.copier_temporary = self.copied.temporary_statistics();
        self.statistics.retention_temporary = self.retained.budget.statistics();
        self.statistics.target_index_temporary = self.target.temporary_statistics();
        self.prepared = true;
        Ok(())
    }
    // Physical validation keys (44 bytes) are disjoint from canonical retention
    // counts (32 bytes). Immutable previously checked target occurrences stop the
    // catch-up traversal; newly authored parents and every new locator are checked.
    fn validate_projected_root(
        &mut self,
        root: ObjectRef,
        cancelled: &impl Fn() -> bool,
    ) -> Result<()> {
        if self.target.get_verified_shared(root)?.kind != 1 {
            return Err(corrupt("projected compaction must return Commit"));
        }
        let mut stack = DiskStack::with_budget(256, self.retained.budget.clone())?;
        stack.push(root, false)?;
        while let Some((reference, expanded)) = stack.pop()? {
            if cancelled() {
                return Err(Error::Limit("compaction pause or elapsed work"));
            }
            let key = spill::encode_ref(reference);
            if self.retained.get(&key)?.is_some() {
                continue;
            }
            if expanded {
                self.retained.insert_cancellable(&key, &[], cancelled)?;
                continue;
            }
            let object = self.target.get_verified_shared(reference)?;
            validate_core_edges(&object, |child| {
                if cancelled() {
                    return Err(Error::Limit("compaction pause or elapsed work"));
                }
                self.target.get_verified_shared(child)
            })?;
            stack.push(reference, true)?;
            for child in object.children.iter().rev() {
                if child
                    .address
                    .offset
                    .checked_add(u64::from(child.address.length))
                    .is_none_or(|end| end > reference.address.offset)
                {
                    return Err(corrupt("closure child locator is not backward"));
                }
                stack.push(*child, false)?;
            }
        }
        Ok(())
    }
    fn adjust_retained(
        &mut self,
        root: ObjectRef,
        add: bool,
        cancelled: &impl Fn() -> bool,
    ) -> Result<()> {
        let mut stack = DiskStack::with_budget(256, self.retained.budget.clone())?;
        stack.push(root, false)?;
        while let Some((r, _)) = stack.pop()? {
            if cancelled() {
                return Err(Error::Limit("compaction pause or elapsed work"));
            }
            let previous = self.retained.get(&r.hash.0)?;
            let count = previous
                .as_ref()
                .map_or(0, |v| u64::from_le_bytes(v[..8].try_into().unwrap()));
            let next = if add {
                count.checked_add(1)
            } else {
                count.checked_sub(1)
            }
            .ok_or_else(|| corrupt("compaction reference count"))?;
            self.retained
                .insert_cancellable(&r.hash.0, &next.to_le_bytes(), cancelled)?;
            if add && count > 0 || !add && next > 0 {
                continue;
            }
            let reference = if self.projected {
                r
            } else {
                self.copied
                    .copied
                    .get(r.hash)?
                    .ok_or_else(|| corrupt("compaction copied reference"))?
            };
            if add && previous.is_some() {
                self.garbage = self
                    .garbage
                    .checked_sub(reference.address.length as u64)
                    .ok_or_else(|| corrupt("compaction garbage count"))?;
            } else if !add {
                self.garbage = self
                    .garbage
                    .checked_add(reference.address.length as u64)
                    .ok_or(Error::Limit("compaction garbage bytes"))?;
            }
            if self.copied.has_no_children(r.hash)? {
                continue;
            }
            let object = self.target.get_shared(reference)?;
            for child in &object.children {
                stack.push(*child, false)?;
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests;
