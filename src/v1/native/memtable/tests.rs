use super::*;
use crate::v1::native::PublicationFault;

fn options() -> MemtableOptions {
    MemtableOptions {
        flush_interval: Duration::from_secs(3600),
        ..Default::default()
    }
}
fn create() -> (tempfile::TempDir, MemtableStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = MemtableStore::create(dir.path().join("db.sac"), [9; 16], options()).unwrap();
    (dir, store)
}

#[test]
fn publication_failures_recover_acknowledged_batches_and_tombstones() {
    for fault in [
        PublicationFault::ChunksBarrier,
        PublicationFault::SlotWrite { bytes: 1 },
        PublicationFault::SlotWrite { bytes: 87 },
        PublicationFault::SlotWrite { bytes: 4095 },
        PublicationFault::SlotSync,
    ] {
        let (dir, store) = create();
        store.put(b"deleted", b"old").unwrap();
        store.flush().unwrap();
        store
            .write_batch(&[
                Mutation::Put {
                    key: b"new",
                    value: b"acknowledged",
                },
                Mutation::Delete { key: b"deleted" },
            ])
            .unwrap();
        store
            .shared
            .checkpoint
            .lock()
            .unwrap()
            .store
            .inject_publication_fault_once(fault);
        assert!(store.flush().is_err(), "{fault:?}");
        assert!(matches!(store.put(b"later", b"no"), Err(Error::Poisoned)));
        assert!(store.statistics().unwrap().failure.is_some());
        drop(store);
        let store = MemtableStore::open(dir.path().join("db.sac"), options()).unwrap();
        assert_eq!(
            store.get(b"new").unwrap().as_deref(),
            Some(&b"acknowledged"[..]),
            "{fault:?}"
        );
        assert_eq!(store.get(b"deleted").unwrap(), None, "{fault:?}");
        assert_eq!(store.statistics().unwrap().checkpoint_sequence, 2);
        store.close().unwrap();
    }
}

#[test]
fn publication_before_wal_retirement_does_not_reapply_old_batches() {
    let (dir, store) = create();
    store.put(b"key", b"one").unwrap();
    store.put(b"key", b"two").unwrap();
    store.delete(b"absent").unwrap();
    // Simulate a crash after durable publication and before WAL replacement.
    store.state().unwrap().fault = Some(Fault::Published);
    assert!(store.flush().is_err());
    assert!(store.statistics().unwrap().wal_bytes > HEADER);
    drop(store);
    let store = MemtableStore::open(dir.path().join("db.sac"), options()).unwrap();
    assert_eq!(store.get(b"key").unwrap().as_deref(), Some(&b"two"[..]));
    assert_eq!(store.statistics().unwrap().recovered_batches, 0);
    assert_eq!(store.statistics().unwrap().checkpoint_sequence, 3);
    assert_eq!(store.put(b"key", b"three").unwrap(), 4);
}

#[test]
fn corrupt_complete_records_and_forged_lengths_are_not_truncated() {
    for position in [0, 8, 24, 32, 64, 72, 80, 96, 110, 130] {
        let (dir, store) = create();
        store.put(b"first", b"survives").unwrap();
        store
            .write_batch(&[
                Mutation::Put {
                    key: b"alpha",
                    value: &[2; 100],
                },
                Mutation::Put {
                    key: b"beta",
                    value: &[3; 100],
                },
            ])
            .unwrap();
        drop(store);
        let path = dir.path().join("db.sac.wal");
        let mut bytes = std::fs::read(&path).unwrap();
        // Damage the second record so recovery must inspect the whole log
        // before applying an otherwise valid first batch.
        let second = HEADER as usize + RECORD_OVERHEAD as usize + 13 + 5 + 8;
        bytes[second + position] ^= 0x80;
        std::fs::write(&path, &bytes).unwrap();
        let before = std::fs::read(dir.path().join("db.sac")).unwrap();
        assert!(matches!(
            MemtableStore::open(dir.path().join("db.sac"), options()),
            Err(Error::Corrupt(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        // Writable native admission may stabilize its slots; the snapshot
        // identity must still select the original empty checkpoint.
        let admitted = crate::v1::Reader::open_at(&before).unwrap();
        let after = crate::v1::NativeReader::open(dir.path().join("db.sac")).unwrap();
        assert_eq!(
            admitted.snapshot().unwrap().hash,
            after.reader().snapshot().unwrap().hash
        );
    }
}

#[test]
fn incomplete_final_batch_is_atomic_at_each_representative_boundary() {
    let (source, store) = create();
    store.put(b"kept", b"durable WAL").unwrap();
    let first_end = store.statistics().unwrap().wal_bytes as usize;
    store
        .write_batch(&[
            Mutation::Put {
                key: b"a",
                value: b"one",
            },
            Mutation::Put {
                key: b"b",
                value: b"two",
            },
        ])
        .unwrap();
    drop(store);
    let wal = std::fs::read(source.path().join("db.sac.wal")).unwrap();
    let record_len = wal.len() - first_end;
    for cut in [
        0,
        1,
        7,
        31,
        32,
        63,
        64,
        65,
        80,
        record_len - 33,
        record_len - 1,
        record_len,
    ] {
        let target = tempfile::tempdir().unwrap();
        let path = target.path().join("db.sac");
        std::fs::copy(source.path().join("db.sac"), &path).unwrap();
        std::fs::write(target.path().join("db.sac.wal"), &wal[..first_end + cut]).unwrap();
        let store = MemtableStore::open(path, options()).unwrap();
        assert_eq!(
            store.get(b"kept").unwrap().as_deref(),
            Some(&b"durable WAL"[..])
        );
        let complete = cut == record_len;
        assert_eq!(store.get(b"a").unwrap().is_some(), complete, "cut {cut}");
        assert_eq!(store.get(b"b").unwrap().is_some(), complete, "cut {cut}");
        assert_eq!(
            store.statistics().unwrap().discarded_tail_bytes as usize,
            if complete { 0 } else { cut }
        );
    }
}

#[test]
fn lowered_recovery_memory_limit_preserves_the_log() {
    let (dir, store) = create();
    store.put(b"large", &[1; 4096]).unwrap();
    drop(store);
    let wal = std::fs::read(dir.path().join("db.sac.wal")).unwrap();
    let small = MemtableOptions {
        max_memory_bytes: 1024,
        ..options()
    };
    assert!(matches!(
        MemtableStore::open(dir.path().join("db.sac"), small),
        Err(Error::Limit(_))
    ));
    assert_eq!(std::fs::read(dir.path().join("db.sac.wal")).unwrap(), wal);
    let store = MemtableStore::open(dir.path().join("db.sac"), options()).unwrap();
    assert_eq!(store.get(b"large").unwrap().unwrap(), vec![1; 4096]);
}

#[test]
fn recovery_checkpoints_under_a_smaller_total_overlay_budget() {
    let (dir, store) = create();
    for i in 0..20u8 {
        store.put(&[i], &[i; 100]).unwrap();
    }
    drop(store);
    let small = MemtableOptions {
        max_memory_bytes: 800,
        ..options()
    };
    let store = MemtableStore::open(dir.path().join("db.sac"), small).unwrap();
    assert_eq!(store.statistics().unwrap().recovered_batches, 20);
    assert_eq!(store.statistics().unwrap().checkpoint_sequence, 20);
    assert!(store.statistics().unwrap().checkpoints >= 10);
    for i in 0..20u8 {
        assert_eq!(store.get(&[i]).unwrap().unwrap(), vec![i; 100]);
    }
}

#[test]
fn wal_replacement_or_truncation_poison_writes_without_acknowledgement() {
    for truncate in [false, true] {
        let (dir, store) = create();
        store.put(b"kept", b"yes").unwrap();
        let path = dir.path().join("db.sac.wal");
        if truncate {
            OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(HEADER)
                .unwrap();
        } else {
            std::fs::rename(&path, dir.path().join("original.wal")).unwrap();
            std::fs::write(&path, b"replacement").unwrap();
        }
        assert!(store.put(b"not-acknowledged", b"no").is_err());
        assert!(matches!(store.flush(), Err(Error::Poisoned)));
    }
}

#[test]
fn sequence_gaps_and_foreign_or_missing_wals_fail_closed() {
    let (a, store) = create();
    store.put(b"one", b"1").unwrap();
    store.put(b"two", b"2").unwrap();
    drop(store);
    let path = a.path().join("db.sac.wal");
    let wal = std::fs::read(&path).unwrap();
    let end_first = HEADER as usize + RECORD_OVERHEAD as usize + 13 + 3 + 1;
    let mut gap = wal[..HEADER as usize].to_vec();
    gap.extend_from_slice(&wal[end_first..]);
    std::fs::write(&path, gap).unwrap();
    assert!(matches!(
        MemtableStore::open(a.path().join("db.sac"), options()),
        Err(Error::Corrupt(_))
    ));
    let other = tempfile::tempdir().unwrap();
    let store = MemtableStore::create(other.path().join("db.sac"), [8; 16], options()).unwrap();
    drop(store);
    std::fs::copy(other.path().join("db.sac.wal"), &path).unwrap();
    assert!(matches!(
        MemtableStore::open(a.path().join("db.sac"), options()),
        Err(Error::Corrupt(_))
    ));
    std::fs::remove_file(&path).unwrap();
    assert!(matches!(
        MemtableStore::open(a.path().join("db.sac"), options()),
        Err(Error::Io(_))
    ));
}

#[test]
fn wal_failures_preserve_previous_acknowledgements_and_atomic_batches() {
    for fault in [Fault::WalHeader, Fault::WalSync, Fault::WalSynced] {
        let (dir, store) = create();
        store.put(b"acknowledged", b"kept").unwrap();
        store.state().unwrap().fault = Some(fault);
        assert!(
            store
                .write_batch(&[
                    Mutation::Put {
                        key: b"a",
                        value: b"maybe"
                    },
                    Mutation::Put {
                        key: b"b",
                        value: b"maybe"
                    },
                ])
                .is_err()
        );
        assert!(matches!(
            store.put(b"after-error", b"no"),
            Err(Error::Poisoned)
        ));
        drop(store);
        let store = MemtableStore::open(dir.path().join("db.sac"), options()).unwrap();
        assert_eq!(
            store.get(b"acknowledged").unwrap().as_deref(),
            Some(&b"kept"[..])
        );
        let second_present = fault != Fault::WalHeader;
        assert_eq!(store.get(b"a").unwrap().is_some(), second_present);
        assert_eq!(store.get(b"b").unwrap().is_some(), second_present);
    }
}

#[test]
fn wal_retirement_failures_and_interrupted_replay_are_idempotent() {
    for fault in [Fault::Published, Fault::WalRenamed] {
        let (dir, store) = create();
        store.put(b"key", b"latest").unwrap();
        store.state().unwrap().fault = Some(fault);
        assert!(store.flush().is_err());
        drop(store);
        let store = MemtableStore::open(dir.path().join("db.sac"), options()).unwrap();
        assert_eq!(store.get(b"key").unwrap().as_deref(), Some(&b"latest"[..]));
        assert_eq!(store.statistics().unwrap().checkpoint_sequence, 1);
    }
    let (dir, store) = create();
    store.put(b"key", b"first").unwrap();
    let mut pause = Pause::at(&store, Stage::Published);
    store.state().unwrap().fault = Some(Fault::Published);
    store.request_flush().unwrap();
    pause.wait();
    // A published immutable prefix and an acknowledged active suffix must
    // survive a crash before retiring the old segment.
    store.put(b"key", b"second").unwrap();
    store.put(b"other", b"third").unwrap();
    pause.release();
    assert!(store.flush().is_err());
    drop(store);
    let store = MemtableStore::open(dir.path().join("db.sac"), options()).unwrap();
    assert_eq!(store.statistics().unwrap().recovered_batches, 2);
    assert_eq!(store.get(b"key").unwrap().as_deref(), Some(&b"second"[..]));
    assert_eq!(store.get(b"other").unwrap().as_deref(), Some(&b"third"[..]));
}

#[test]
fn checkpoint_batches_inline_puts_without_intermediate_directory_versions() {
    let dir = tempfile::tempdir().unwrap();
    let store = MemtableStore::create(
        dir.path().join("db.sac"),
        [1; 16],
        MemtableOptions {
            compression_level: 0,
            ..options()
        },
    )
    .unwrap();
    let start = store.shared.checkpoint.lock().unwrap().store.file_len();
    let keys: Vec<_> = (0..100u16).map(u16::to_be_bytes).collect();
    let mutations: Vec<_> = keys
        .iter()
        .map(|key| Mutation::Put {
            key,
            value: b"small value",
        })
        .collect();
    store.write_batch(&mutations).unwrap();
    assert_eq!(
        store.shared.checkpoint.lock().unwrap().store.file_len(),
        start,
        "WAL acceptance must defer SAC object construction"
    );
    for _ in 0..3 {
        store.put(&keys[0], b"latest").unwrap();
    }
    assert_eq!(store.statistics().unwrap().pending_entries, 100);
    store.flush().unwrap();
    let appended = store.shared.checkpoint.lock().unwrap().store.file_len() - start;
    assert!(
        appended < 16 * 1024,
        "one small directory page plus publication controls, got {appended} bytes"
    );
    assert_eq!(
        store.get(&keys[0]).unwrap().as_deref(),
        Some(&b"latest"[..])
    );
    store.state().unwrap().base.validate().unwrap();
}

/// A one-shot deterministic worker pause, automatically released on unwind.
/// Tests exercise real I/O while the worker is stopped outside all API locks.
struct Pause {
    entered: std::sync::mpsc::Receiver<()>,
    release: Option<std::sync::mpsc::Sender<()>>,
}
impl Pause {
    fn at(store: &MemtableStore, point: Stage) -> Self {
        let (entered, receiver) = std::sync::mpsc::channel();
        let (release, resume) = std::sync::mpsc::channel();
        let resume = Mutex::new(Some(resume));
        *store.shared.hook.lock().unwrap() = Some(Box::new(move |stage| {
            if stage == point
                && let Some(resume) = resume.lock().unwrap().take()
            {
                entered.send(()).unwrap();
                let _ = resume.recv();
            }
        }));
        Self {
            entered: receiver,
            release: Some(release),
        }
    }
    fn wait(&self) {
        self.entered.recv_timeout(Duration::from_secs(10)).unwrap();
    }
    fn release(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}
impl Drop for Pause {
    fn drop(&mut self) {
        self.release();
    }
}

#[test]
fn immutable_flush_keeps_base_overlay_reads_and_wal_writes_running() {
    let (dir, store) = create();
    store
        .write_batch(&[
            Mutation::Put {
                key: b"base",
                value: b"unchanged",
            },
            Mutation::Put {
                key: b"deleted",
                value: b"base",
            },
        ])
        .unwrap();
    store.flush().unwrap();
    let store = Arc::new(store);
    let mut pause = Pause::at(&store, Stage::Frozen);
    store
        .write_batch(&[
            Mutation::Put {
                key: b"key",
                value: b"immutable",
            },
            Mutation::Put {
                key: b"gone",
                value: b"immutable",
            },
            Mutation::Delete { key: b"deleted" },
        ])
        .unwrap();
    let target = store.request_flush().unwrap();
    pause.wait();
    // These operations would deadlock against the old global checkpoint lock.
    let (sent, received) = std::sync::mpsc::channel();
    let caller = store.clone();
    let operations = thread::spawn(move || {
        assert_eq!(
            caller.get(b"base").unwrap().as_deref(),
            Some(&b"unchanged"[..])
        );
        assert_eq!(
            caller.get(b"key").unwrap().as_deref(),
            Some(&b"immutable"[..])
        );
        assert_eq!(caller.get(b"deleted").unwrap(), None);
        let seq = caller
            .write_batch(&[
                Mutation::Put {
                    key: b"key",
                    value: b"active",
                },
                Mutation::Delete { key: b"gone" },
                Mutation::Put {
                    key: b"deleted",
                    value: b"resurrected",
                },
            ])
            .unwrap();
        assert_eq!(caller.get(b"key").unwrap().as_deref(), Some(&b"active"[..]));
        assert_eq!(caller.get(b"gone").unwrap(), None);
        assert_eq!(
            caller.get(b"deleted").unwrap().as_deref(),
            Some(&b"resurrected"[..])
        );
        let stats = caller.statistics().unwrap();
        assert!(
            stats.flush_in_progress
                && stats.immutable_memory_bytes > 0
                && stats.active_memory_bytes > 0
        );
        assert_eq!(
            stats.pending_memory_bytes,
            stats.immutable_memory_bytes + stats.active_memory_bytes
        );
        assert!(stats.checkpoint_sequence < target && seq > target);
        sent.send(seq).unwrap();
    });
    let outcome = received.recv_timeout(Duration::from_secs(10));
    pause.release();
    let sequence = outcome.expect("reads and writes stalled behind immutable flush");
    operations.join().unwrap();
    assert!(store.flush().unwrap() >= sequence);
    drop(store);
    let store = MemtableStore::open(dir.path().join("db.sac"), options()).unwrap();
    assert_eq!(store.get(b"key").unwrap().as_deref(), Some(&b"active"[..]));
    assert_eq!(store.get(b"gone").unwrap(), None);
    assert_eq!(store.statistics().unwrap().live_entries, 3);
}

#[test]
fn combined_memory_and_wal_budgets_backpressure_without_blocking_reads() {
    for wal_pressure in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let opts = MemtableOptions {
            max_memory_bytes: 4096,
            max_wal_bytes: if wal_pressure { 300 } else { 4096 },
            ..options()
        };
        let store = Arc::new(
            MemtableStore::create(dir.path().join("db.sac"), [7; 16], opts.clone()).unwrap(),
        );
        let mut pause = Pause::at(&store, Stage::Frozen);
        let value = vec![3; if wal_pressure { 16 } else { 256 }];
        store.put(b"frozen", &value).unwrap();
        store.request_flush().unwrap();
        pause.wait();
        let caller = store.clone();
        let (sent, received) = std::sync::mpsc::channel();
        let operation = thread::spawn(move || {
            let keys: Vec<_> = (0..if wal_pressure { 1 } else { 5 })
                .map(|i| vec![i])
                .collect();
            let batch: Vec<_> = keys
                .iter()
                .map(|key| Mutation::Put { key, value: &value })
                .collect();
            let result = caller.write_batch(&batch);
            sent.send(result).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        while store.statistics().unwrap().backpressure_waits == 0 {
            if Instant::now() >= deadline {
                pause.release();
                panic!("writer did not apply bounded backpressure");
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(received.try_recv().is_err());
        assert!(store.get(b"frozen").unwrap().is_some());
        let stats = store.statistics().unwrap();
        assert!(
            stats.pending_memory_bytes <= opts.max_memory_bytes
                && stats.wal_bytes <= opts.max_wal_bytes
        );
        pause.release();
        received
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        operation.join().unwrap();
        store.flush().unwrap();
        let stats = store.statistics().unwrap();
        assert_eq!(stats.pending_memory_bytes, 0);
        assert_eq!(stats.wal_bytes, HEADER);
    }
}

#[test]
fn secondary_wal_corruption_is_validated_before_any_recovery_checkpoint() {
    let (dir, store) = create();
    let mut pause = Pause::at(&store, Stage::Frozen);
    store.put(b"frozen", b"value").unwrap();
    store.request_flush().unwrap();
    pause.wait();
    store.put(b"active", b"durable").unwrap();
    // Keep both segments by failing immediately after publication.
    store.state().unwrap().fault = Some(Fault::Published);
    pause.release();
    assert!(store.flush().is_err());
    drop(store);
    let path = dir.path().join("db.sac");
    let next = dir.path().join("db.sac.wal.next");
    let mut bytes = std::fs::read(&next).unwrap();
    bytes[HEADER as usize + 70] ^= 1;
    std::fs::write(&next, &bytes).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        MemtableStore::open(&path, options()),
        Err(Error::Corrupt(_))
    ));
    assert_eq!(std::fs::read(&next).unwrap(), bytes);
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn immutable_crash_child() {
    let Some(path) = std::env::var_os("SAC_IMMUTABLE_CRASH_PATH") else {
        return;
    };
    let stage = match std::env::var("SAC_IMMUTABLE_CRASH_STAGE").unwrap().as_str() {
        "prepared" => Stage::Prepared,
        "frozen" => Stage::Frozen,
        "published" => Stage::Published,
        "renamed" => Stage::Renamed,
        _ => panic!(),
    };
    let store = Arc::new(MemtableStore::create(path, [4; 16], options()).unwrap());
    store
        .write_batch(&[
            Mutation::Put {
                key: b"seed",
                value: b"old",
            },
            Mutation::Put {
                key: b"victim",
                value: b"old",
            },
        ])
        .unwrap();
    store.flush().unwrap();
    let weak = Arc::downgrade(&store);
    *store.shared.hook.lock().unwrap() = Some(Box::new(move |point| {
        if point == stage {
            weak.upgrade()
                .unwrap()
                .write_batch(&[
                    Mutation::Put {
                        key: b"active",
                        value: b"acknowledged",
                    },
                    Mutation::Delete { key: b"victim" },
                ])
                .unwrap();
            std::process::exit(73);
        }
    }));
    store
        .write_batch(&[
            Mutation::Put {
                key: b"immutable",
                value: b"acknowledged",
            },
            Mutation::Delete { key: b"seed" },
        ])
        .unwrap();
    store.request_flush().unwrap();
    thread::sleep(Duration::from_secs(15));
    std::process::exit(74);
}

#[test]
fn active_and_immutable_acknowledgements_survive_crashes_at_each_handoff() {
    for stage in ["prepared", "frozen", "published", "renamed"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sac");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "v1::native::memtable::tests::immutable_crash_child",
                "--nocapture",
            ])
            .env("SAC_IMMUTABLE_CRASH_PATH", &path)
            .env("SAC_IMMUTABLE_CRASH_STAGE", stage)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(73), "{stage}");
        let store = MemtableStore::open(&path, options()).unwrap();
        for key in [b"immutable".as_slice(), b"active"] {
            assert_eq!(
                store.get(key).unwrap().as_deref(),
                Some(&b"acknowledged"[..]),
                "{stage}"
            );
        }
        for key in [b"seed".as_slice(), b"victim"] {
            assert_eq!(store.get(key).unwrap(), None, "{stage}");
        }
        assert_eq!(store.statistics().unwrap().live_entries, 2);
        store.close().unwrap();
        let store = MemtableStore::open(&path, options()).unwrap();
        assert_eq!(store.statistics().unwrap().recovered_batches, 0);
        store.close().unwrap();
        NativeReader::open(path).unwrap().validate().unwrap();
    }
}

#[test]
fn failed_publication_wakes_budget_waiters_and_preserves_active_acknowledgements() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sac");
    let opts = MemtableOptions {
        max_memory_bytes: 4096,
        ..options()
    };
    let store = Arc::new(MemtableStore::create(&path, [6; 16], opts).unwrap());
    let mut pause = Pause::at(&store, Stage::Frozen);
    store.put(b"frozen", &[1; 1500]).unwrap();
    store.request_flush().unwrap();
    pause.wait();
    store.put(b"active", &[2; 128]).unwrap();
    store
        .shared
        .checkpoint
        .lock()
        .unwrap()
        .store
        .inject_publication_fault_once(PublicationFault::ChunksBarrier);
    let caller = store.clone();
    let (sent, received) = std::sync::mpsc::channel();
    let writer = thread::spawn(move || {
        sent.send(caller.write_batch(&[
            Mutation::Put {
                key: b"a",
                value: &[3; 256],
            },
            Mutation::Put {
                key: b"b",
                value: &[4; 256],
            },
        ]))
        .unwrap();
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while store.statistics().unwrap().backpressure_waits == 0 {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(1));
    }
    pause.release();
    assert!(matches!(
        received.recv_timeout(Duration::from_secs(10)).unwrap(),
        Err(Error::Poisoned)
    ));
    writer.join().unwrap();
    assert!(matches!(store.flush(), Err(Error::Poisoned)));
    drop(store);
    let store = MemtableStore::open(&path, options()).unwrap();
    assert_eq!(store.get(b"frozen").unwrap(), Some(vec![1; 1500]));
    assert_eq!(store.get(b"active").unwrap(), Some(vec![2; 128]));
    assert_eq!(store.get(b"a").unwrap(), None);
    assert_eq!(store.statistics().unwrap().recovered_batches, 2);
}

#[test]
fn worker_panic_poison_notifies_flush_waiters_and_recovery_keeps_the_wal() {
    let (dir, store) = create();
    *store.shared.hook.lock().unwrap() = Some(Box::new(|point| {
        if point == Stage::Frozen {
            panic!("injected worker panic");
        }
    }));
    store.put(b"key", b"durable").unwrap();
    assert!(matches!(store.flush(), Err(Error::Poisoned)));
    drop(store);
    let store = MemtableStore::open(dir.path().join("db.sac"), options()).unwrap();
    assert_eq!(store.get(b"key").unwrap().as_deref(), Some(&b"durable"[..]));
}

#[test]
fn secondary_incomplete_batch_is_atomic_and_a_torn_predecessor_is_rejected() {
    let (source, store) = create();
    let mut pause = Pause::at(&store, Stage::Published);
    store.put(b"frozen", b"durable").unwrap();
    store.request_flush().unwrap();
    pause.wait();
    store
        .write_batch(&[
            Mutation::Put {
                key: b"a",
                value: b"one",
            },
            Mutation::Put {
                key: b"b",
                value: b"two",
            },
        ])
        .unwrap();
    store.state().unwrap().fault = Some(Fault::Published);
    pause.release();
    assert!(store.flush().is_err());
    drop(store);
    let primary = std::fs::read(source.path().join("db.sac.wal")).unwrap();
    let secondary = std::fs::read(source.path().join("db.sac.wal.next")).unwrap();
    let record_len = secondary.len() - HEADER as usize;
    for cut in [0, 1, 63, 64, record_len - 33, record_len - 1, record_len] {
        let target = tempfile::tempdir().unwrap();
        let path = target.path().join("db.sac");
        std::fs::copy(source.path().join("db.sac"), &path).unwrap();
        std::fs::write(target.path().join("db.sac.wal"), &primary).unwrap();
        std::fs::write(
            target.path().join("db.sac.wal.next"),
            &secondary[..HEADER as usize + cut],
        )
        .unwrap();
        let store = MemtableStore::open(&path, options()).unwrap();
        assert_eq!(
            store.get(b"frozen").unwrap().as_deref(),
            Some(&b"durable"[..])
        );
        assert_eq!(store.get(b"a").unwrap().is_some(), cut == record_len);
        assert_eq!(store.get(b"b").unwrap().is_some(), cut == record_len);
    }
    std::fs::write(
        source.path().join("db.sac.wal"),
        &primary[..primary.len() - 1],
    )
    .unwrap();
    assert!(matches!(
        MemtableStore::open(source.path().join("db.sac"), options()),
        Err(Error::Corrupt(_))
    ));
}

#[test]
fn legacy_profile_and_wal_are_recovered_and_upgraded_before_new_acceptance() {
    let (dir, store) = create();
    {
        let mut checkpoint = store.shared.checkpoint.lock().unwrap();
        let directory = checkpoint.directory;
        let id = checkpoint.id;
        let root = checkpoint
            .store
            .put(
                8,
                1,
                &cbor::encode(&cbor::Value::Array(vec![
                    cbor::Value::Text(LEGACY_PROFILE.into()),
                    cbor::Value::Text("root".into()),
                    cbor::Value::Uint(1),
                    cbor::Value::Bytes(cbor::encode(&cbor::Value::Array(vec![
                        cbor::Value::Bytes(id.to_vec()),
                        cbor::Value::Uint(0),
                    ]))),
                ])),
                &[directory],
            )
            .unwrap();
        let snapshot = resources::snapshot(
            &mut checkpoint.store,
            directory,
            vec![Profile {
                id: LEGACY_PROFILE.into(),
                version: 1,
                root,
            }],
            Vec::new(),
        )
        .unwrap();
        checkpoint.store.publish(snapshot).unwrap();
    }
    store.put(b"legacy", b"acknowledged").unwrap();
    drop(store);
    let store = MemtableStore::open(dir.path().join("db.sac"), options()).unwrap();
    assert_eq!(
        store.get(b"legacy").unwrap().as_deref(),
        Some(&b"acknowledged"[..])
    );
    let checkpoint = store.shared.checkpoint.lock().unwrap();
    let snapshot = checkpoint.store.reader().snapshot().unwrap();
    assert!(
        !admit_checkpoint(&checkpoint.store, snapshot, &options())
            .unwrap()
            .5
    );
    drop(checkpoint);
    store.put(b"new", b"acknowledged").unwrap();
    store.close().unwrap();
}

#[test]
fn hot_set_above_half_capacity_coalesces_until_explicit_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let opts = MemtableOptions {
        max_memory_bytes: 1024 * 1024,
        ..options()
    };
    let store = MemtableStore::create(dir.path().join("db.sac"), [6; 16], opts.clone()).unwrap();
    let keys: Vec<_> = (0..1024u64).map(u64::to_le_bytes).collect();
    for round in 0..3u8 {
        let value = [round; 128];
        for keys in keys.chunks(64) {
            let batch: Vec<_> = keys
                .iter()
                .map(|key| Mutation::Put { key, value: &value })
                .collect();
            store.write_batch(&batch).unwrap();
            let stats = store.statistics().unwrap();
            assert!(stats.pending_memory_bytes <= opts.max_memory_bytes);
            assert_eq!(stats.checkpoints, 0);
        }
    }
    let stats = store.statistics().unwrap();
    assert!(stats.active_memory_bytes > opts.max_memory_bytes / 2);
    assert_eq!(stats.pending_entries, keys.len());
    assert_eq!(stats.backpressure_waits, 0);
    store.flush().unwrap();
    assert_eq!(store.statistics().unwrap().checkpoints, 1);
    drop(store);
    let store = MemtableStore::open(dir.path().join("db.sac"), opts).unwrap();
    for key in &keys {
        assert_eq!(
            store.get(key).unwrap().as_deref(),
            Some([2; 128].as_slice())
        );
    }
}

#[test]
fn prepared_successor_allows_primary_writes_and_recovers_without_a_handoff() {
    let (dir, store) = create();
    let mut pause = Pause::at(&store, Stage::Prepared);
    store.put(b"key", b"first").unwrap();
    pause.wait();
    let next = dir.path().join("db.sac.wal.next");
    assert_eq!(std::fs::read(&next).unwrap(), wal_header([9; 16], 0));
    assert!(!store.statistics().unwrap().flush_in_progress);
    store
        .write_batch(&[
            Mutation::Delete { key: b"key" },
            Mutation::Put {
                key: b"later",
                value: b"acknowledged",
            },
        ])
        .unwrap();
    assert_eq!(store.get(b"key").unwrap(), None);
    assert_eq!(
        store.get(b"later").unwrap().as_deref(),
        Some(b"acknowledged".as_slice())
    );
    pause.release();
    drop(store);
    assert_eq!(std::fs::metadata(next).unwrap().len(), HEADER);
    let store = MemtableStore::open(dir.path().join("db.sac"), options()).unwrap();
    assert_eq!(store.get(b"key").unwrap(), None);
    assert_eq!(
        store.get(b"later").unwrap().as_deref(),
        Some(b"acknowledged".as_slice())
    );
    assert_eq!(store.statistics().unwrap().recovered_batches, 2);
}

#[test]
fn admission_wait_does_not_schedule_an_unnecessary_active_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let opts = MemtableOptions {
        max_memory_bytes: 4096,
        ..options()
    };
    let store = Arc::new(MemtableStore::create(dir.path().join("db.sac"), [5; 16], opts).unwrap());
    store.put(b"frozen", &[1; 256]).unwrap();
    let mut pause = Pause::at(&store, Stage::Frozen);
    let target = store.request_flush().unwrap();
    pause.wait();
    store.put(b"active", &[2; 256]).unwrap();
    let caller = store.clone();
    let (sent, received) = std::sync::mpsc::channel();
    let operation = thread::spawn(move || sent.send(caller.put(b"blocked", &[3; 2048])).unwrap());
    let deadline = Instant::now() + Duration::from_secs(10);
    while store.statistics().unwrap().backpressure_waits == 0 {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(1));
    }
    assert!(received.try_recv().is_err());
    assert_eq!(store.state().unwrap().requested, target);
    assert_eq!(store.get(b"active").unwrap(), Some(vec![2; 256]));
    pause.release();
    received
        .recv_timeout(Duration::from_secs(10))
        .unwrap()
        .unwrap();
    operation.join().unwrap();
    let stats = store.statistics().unwrap();
    assert_eq!(stats.checkpoints, 1);
    assert_eq!(stats.checkpoint_sequence, target);
    assert_eq!(stats.pending_entries, 2);
    assert!(stats.pending_memory_bytes <= 4096);
    store.flush().unwrap();
    assert_eq!(store.statistics().unwrap().checkpoints, 2);
    assert_eq!(store.get(b"blocked").unwrap(), Some(vec![3; 2048]));
}

#[test]
fn io_statistics_distinguish_acknowledgement_and_checkpoint_barriers() {
    let (_dir, store) = create();
    let before = store.statistics().unwrap();
    store
        .write_batch(&[
            Mutation::Put {
                key: b"key",
                value: &[1; 1024],
            },
            Mutation::Put {
                key: b"key",
                value: &[2; 1024],
            },
        ])
        .unwrap();
    let acknowledged = store.statistics().unwrap();
    assert_eq!(acknowledged.io.wal_batches, 1);
    assert!(acknowledged.io.wal_sync_total_ns > 0);
    assert!(acknowledged.io.wal_sync_max_ns <= acknowledged.io.wal_sync_total_ns);
    assert_eq!(
        acknowledged.io.native_publication.completed,
        before.io.native_publication.completed
    );
    store.flush().unwrap();
    let checkpointed = store.statistics().unwrap();
    assert_eq!(checkpointed.io.wal_batches, 1);
    assert_eq!(
        checkpointed.io.native_publication.completed,
        before.io.native_publication.completed + 1
    );
    assert!(
        checkpointed.io.native_publication.chunk_barriers
            > before.io.native_publication.chunk_barriers
    );
    assert!(
        checkpointed.io.native_publication.slot_syncs > before.io.native_publication.slot_syncs
    );
    assert!(checkpointed.io.checkpoint_materialize_total_ns > 0);
    assert!(checkpointed.io.checkpoint_publish_total_ns > 0);
    assert!(checkpointed.io.checkpoint_retire_total_ns > 0);
    assert_eq!(checkpointed.pending_memory_bytes, 0);
    assert_eq!(store.get(b"key").unwrap(), Some(vec![2; 1024]));
}
