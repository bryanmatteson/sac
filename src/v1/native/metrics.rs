/// Physical driver IO; unlike Reader::statistics these count executed reads.
/// One database handle, all its pins, and replacement compactions share totals.
/// Reopening an independent handle starts a new scope. Failed calls count as
/// operations and only bytes actually returned contribute to byte totals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PhysicalReadStatistics {
    pub read_operations: u64,
    pub read_bytes: u64,
    pub bootstrap_bytes: u64,
    pub metadata_bytes: u64,
    pub object_bytes: u64,
    /// Subset of totals issued by automatic maintenance, excluding demand reads.
    pub maintenance_read_operations: u64,
    pub maintenance_read_bytes: u64,
}
/// Actual attempted barriers, including failed OS calls. Injected failures before
/// a call do not count as IO. Totals include replacement compaction publications;
/// the compaction fields identify that subset. Shared readers do not publish.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublicationStatistics {
    pub attempts: u64,
    pub completed: u64,
    pub slot_writes: u64,
    pub slot_write_bytes: u64,
    pub appended_bytes: u64,
    pub compaction_attempts: u64,
    pub compaction_completed: u64,
    pub compaction_chunk_barrier_total_ns: u64,
    pub compaction_slot_sync_total_ns: u64,
    pub chunk_barriers: u64,
    pub chunk_barrier_last_ns: u64,
    pub chunk_barrier_total_ns: u64,
    pub chunk_barrier_max_ns: u64,
    pub slot_syncs: u64,
    pub slot_sync_last_ns: u64,
    pub slot_sync_total_ns: u64,
    pub slot_sync_max_ns: u64,
}
thread_local! { static MAINTENANCE_READ_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) }; }
fn maintenance_read_active() -> bool {
    MAINTENANCE_READ_DEPTH.with(|depth| depth.get() != 0)
}
/// Attribute physical reads on this worker to the maintenance subset while
/// preserving the actual total counters. This carries no read/write authority.
pub fn with_maintenance_read_accounting<T>(body: impl FnOnce() -> T) -> T {
    struct Restore(u32);
    impl Drop for Restore {
        fn drop(&mut self) {
            MAINTENANCE_READ_DEPTH.with(|depth| depth.set(self.0));
        }
    }
    let old = MAINTENANCE_READ_DEPTH.with(|depth| {
        let old = depth.get();
        depth.set(old.saturating_add(1));
        old
    });
    let _restore = Restore(old);
    body()
}

#[derive(Default)]
struct PhysicalCounters {
    publications: Mutex<PublicationStatistics>,
    operations: std::sync::atomic::AtomicU64,
    maintenance_operations: std::sync::atomic::AtomicU64,
    maintenance_bytes: std::sync::atomic::AtomicU64,
    bytes: std::sync::atomic::AtomicU64,
    bootstrap: std::sync::atomic::AtomicU64,
    metadata: std::sync::atomic::AtomicU64,
    object: std::sync::atomic::AtomicU64,
}
#[derive(Clone, Copy)]
enum ReadClass {
    Bootstrap,
    Metadata,
    Object,
}
impl PhysicalCounters {
    fn snapshot(&self) -> PhysicalReadStatistics {
        use std::sync::atomic::Ordering::Relaxed;
        PhysicalReadStatistics {
            read_operations: self.operations.load(Relaxed),
            read_bytes: self.bytes.load(Relaxed),
            bootstrap_bytes: self.bootstrap.load(Relaxed),
            metadata_bytes: self.metadata.load(Relaxed),
            object_bytes: self.object.load(Relaxed),
            maintenance_read_operations: self.maintenance_operations.load(Relaxed),
            maintenance_read_bytes: self.maintenance_bytes.load(Relaxed),
        }
    }
    fn bytes(&self, n: usize, class: ReadClass) {
        use std::sync::atomic::Ordering::Relaxed;
        self.bytes.fetch_add(n as u64, Relaxed);
        if maintenance_read_active() {
            self.maintenance_bytes.fetch_add(n as u64, Relaxed);
        }
        match class {
            ReadClass::Bootstrap => &self.bootstrap,
            ReadClass::Metadata => &self.metadata,
            ReadClass::Object => &self.object,
        }
        .fetch_add(n as u64, Relaxed);
    }
}
fn counted_read_at(
    file: &File,
    buffer: &mut [u8],
    offset: u64,
    io: &PhysicalCounters,
    class: ReadClass,
) -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;
    #[cfg(not(any(unix, windows)))]
    let mut fallback = {
        let mut f = file.try_clone()?;
        f.seek(SeekFrom::Start(offset))?;
        f
    };
    let mut done = 0;
    while done < buffer.len() {
        io.operations.fetch_add(1, Relaxed);
        if maintenance_read_active() {
            io.maintenance_operations.fetch_add(1, Relaxed);
        }
        #[cfg(unix)]
        let result = {
            use std::os::unix::fs::FileExt;
            file.read_at(&mut buffer[done..], offset + done as u64)
        };
        #[cfg(windows)]
        let result = {
            use std::os::windows::fs::FileExt;
            file.seek_read(&mut buffer[done..], offset + done as u64)
        };
        #[cfg(not(any(unix, windows)))]
        let result = fallback.read(&mut buffer[done..]);
        match result {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into()),
            Ok(n) => {
                io.bytes(n, class);
                done += n
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
