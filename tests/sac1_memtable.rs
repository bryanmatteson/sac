#![cfg(feature = "native")]
use sac::{Error, MemtableOptions, MemtableStore, Mutation, NativeReader};
use std::time::{Duration, Instant};

fn options() -> MemtableOptions {
    MemtableOptions {
        flush_interval: Duration::from_secs(3600),
        ..Default::default()
    }
}

#[test]
fn overlay_reads_deletes_atomic_batches_and_native_checkpoint_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sac");
    let store = MemtableStore::create(&path, [1; 16], options()).unwrap();
    assert_eq!(store.get(b"missing").unwrap(), None);
    assert_eq!(store.put(b"", b"").unwrap(), 1);
    store.put(&[0, 255, b'/'], b"binary key").unwrap();
    store.put(b"large", &[0x5a; 100_000]).unwrap();
    store.put(b"key", b"base").unwrap();
    assert_eq!(store.statistics().unwrap().checkpoint_sequence, 0);
    // Pending data is visible through the overlay before native publication.
    let reader = NativeReader::open(&path).unwrap();
    let archive = sac::resources::ArchiveReader::open(
        &reader,
        reader.reader().snapshot().unwrap(),
        Default::default(),
    )
    .unwrap();
    assert!(archive.list().unwrap().is_empty());
    store.flush().unwrap();
    assert_eq!(store.get(b"large").unwrap().unwrap(), vec![0x5a; 100_000]);
    store
        .write_batch(&[
            Mutation::Put {
                key: b"key",
                value: b"intermediate",
            },
            Mutation::Delete { key: b"key" },
            Mutation::Put {
                key: b"key",
                value: b"latest",
            },
            Mutation::Delete { key: b"large" },
            Mutation::Delete { key: b"missing" },
        ])
        .unwrap();
    assert_eq!(store.get(b"key").unwrap().as_deref(), Some(&b"latest"[..]));
    assert_eq!(store.get(b"large").unwrap(), None);
    assert_eq!(store.get(b"").unwrap(), Some(Vec::new()));
    assert_eq!(
        store.get(&[0, 255, b'/']).unwrap().as_deref(),
        Some(&b"binary key"[..])
    );
    store.close().unwrap();
    let store = MemtableStore::open(&path, options()).unwrap();
    assert_eq!(store.get(b"key").unwrap().as_deref(), Some(&b"latest"[..]));
    assert_eq!(store.get(b"large").unwrap(), None);
    assert_eq!(store.statistics().unwrap().live_entries, 3);
    store.close().unwrap();
    let reader = NativeReader::open(&path).unwrap();
    reader.validate().unwrap();
    let archive = sac::resources::ArchiveReader::open(
        &reader,
        reader.reader().snapshot().unwrap(),
        Default::default(),
    )
    .unwrap();
    archive.verify_commit(reader.root().unwrap().root).unwrap();
    assert_eq!(
        archive.read_range(&[b"k6b6579".to_vec()], 0, 6).unwrap(),
        b"latest"
    );
}

#[test]
fn memory_and_wal_pressure_checkpoint_without_exceeding_bounds() {
    for wal_pressure in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let opts = MemtableOptions {
            max_memory_bytes: if wal_pressure { 4096 } else { 900 },
            max_wal_bytes: if wal_pressure { 400 } else { 4096 },
            ..options()
        };
        let store =
            MemtableStore::create(dir.path().join("db.sac"), [1; 16], opts.clone()).unwrap();
        for i in 0..10u8 {
            let key = if wal_pressure { 0 } else { i };
            store.put(&[key], &[i; 16]).unwrap();
            let stats = store.statistics().unwrap();
            assert!(stats.pending_memory_bytes <= opts.max_memory_bytes);
            assert!(stats.wal_bytes <= opts.max_wal_bytes);
        }
        assert!(store.statistics().unwrap().checkpoints > 0);
        store.close().unwrap();
    }
}

#[test]
fn idle_timer_flushes_and_reports_checkpoint_errors() {
    let dir = tempfile::tempdir().unwrap();
    let store = MemtableStore::create(
        dir.path().join("db.sac"),
        [1; 16],
        MemtableOptions {
            flush_interval: Duration::from_millis(20),
            ..options()
        },
    )
    .unwrap();
    store.put(b"key", b"value").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while store.statistics().unwrap().checkpoint_sequence < 1 {
        assert!(Instant::now() < deadline, "timer did not checkpoint");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(store.statistics().unwrap().pending_entries, 0);
    // Simulate a namespace failure while the next checkpoint is pending.
    store.put(b"next", b"value").unwrap();
    std::fs::rename(dir.path().join("db.sac"), dir.path().join("moved.sac")).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while store.statistics().unwrap().failure.is_none() {
        assert!(
            Instant::now() < deadline,
            "worker did not report the failure"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(matches!(
        store.put(b"later", b"value"),
        Err(Error::Poisoned)
    ));
}

#[test]
fn oversize_input_and_collection_limits_reject_before_wal_ack() {
    let dir = tempfile::tempdir().unwrap();
    let mut opts = options();
    opts.max_memory_bytes = 2048;
    opts.max_value_bytes = 1024;
    opts.limits.max_entries = 2;
    let store = MemtableStore::create(dir.path().join("db.sac"), [1; 16], opts).unwrap();
    store.put(b"one", b"a").unwrap();
    store.put(b"two", b"b").unwrap();
    let before = store.statistics().unwrap().sequence;
    for (key, value) in [
        (b"three".as_slice(), b"c".as_slice()),
        (b"large", &[0; 1025]),
        (&[0; 2048], b"v"),
    ] {
        assert!(matches!(store.put(key, value), Err(Error::Limit(_))));
        assert_eq!(store.statistics().unwrap().sequence, before);
    }
    store
        .write_batch(&[
            Mutation::Delete { key: b"one" },
            Mutation::Put {
                key: b"three",
                value: b"c",
            },
        ])
        .unwrap();
    store.close().unwrap();
}

#[test]
fn abrupt_exit_child() {
    let Some(path) = std::env::var_os("SAC_MEMTABLE_CRASH_PATH") else {
        return;
    };
    let store = MemtableStore::create(path, [1; 16], options()).unwrap();
    store.put(b"deleted", b"old").unwrap();
    store.flush().unwrap();
    let keys: Vec<_> = (0..65u64).map(u64::to_be_bytes).collect();
    let value = [0x5a; 1024];
    let mut mutations = vec![
        Mutation::Put {
            key: b"durable",
            value: b"acknowledged before process exit",
        },
        Mutation::Delete { key: b"deleted" },
    ];
    mutations.extend(keys.iter().map(|key| Mutation::Put { key, value: &value }));
    // More than one gather group, mixed with a tombstone, must still recover as
    // one atomic record after a real process exit with no destructors.
    store.write_batch(&mutations).unwrap();
    // Exit without destructors, matching a process crash after acknowledgement.
    std::process::exit(71);
}

#[test]
fn acknowledged_wal_survives_abrupt_process_exit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sac");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "abrupt_exit_child", "--nocapture"])
        .env("SAC_MEMTABLE_CRASH_PATH", &path)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(71));
    let store = MemtableStore::open(&path, options()).unwrap();
    assert_eq!(
        store.get(b"durable").unwrap().as_deref(),
        Some(&b"acknowledged before process exit"[..])
    );
    assert_eq!(store.get(b"deleted").unwrap(), None);
    for key in (0..65u64).map(u64::to_be_bytes) {
        assert_eq!(store.get(&key).unwrap(), Some(vec![0x5a; 1024]));
    }
    assert_eq!(store.statistics().unwrap().recovered_batches, 1);
    store.close().unwrap();
    let store = MemtableStore::open(path, options()).unwrap();
    assert_eq!(store.statistics().unwrap().recovered_batches, 0);
}

#[test]
fn concurrent_callers_are_serialized_and_exclusive_writer_lock_is_retained() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sac");
    let store = std::sync::Arc::new(MemtableStore::create(&path, [1; 16], options()).unwrap());
    assert!(matches!(
        MemtableStore::open(&path, options()),
        Err(Error::Busy)
    ));
    std::thread::scope(|scope| {
        for thread in 0..4u8 {
            let store = &store;
            scope.spawn(move || {
                for i in 0..10u8 {
                    store.put(&[thread, i], &[i; 32]).unwrap();
                    assert_eq!(store.get(&[thread, i]).unwrap().unwrap(), vec![i; 32]);
                }
            });
        }
    });
    store.flush().unwrap();
    drop(store);
    let store = MemtableStore::open(path, options()).unwrap();
    assert_eq!(store.statistics().unwrap().live_entries, 40);
}

#[test]
fn batch_checkpoints_split_pages_delete_to_empty_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sac");
    let store = MemtableStore::create(&path, [1; 16], options()).unwrap();
    let keys: Vec<_> = (0..600u16).map(u16::to_be_bytes).collect();
    let values: Vec<_> = (0..600u16).map(|i| vec![(i % 251) as u8; 1000]).collect();
    let puts: Vec<_> = keys
        .iter()
        .zip(&values)
        .map(|(key, value)| Mutation::Put { key, value })
        .collect();
    store.write_batch(&puts).unwrap();
    store.flush().unwrap();
    for i in [0, 63, 191, 255, 511, 599] {
        assert_eq!(store.get(&keys[i]).unwrap().as_ref(), Some(&values[i]));
    }
    store.close().unwrap();
    let store = MemtableStore::open(&path, options()).unwrap();
    let deletes: Vec<_> = keys.iter().map(|key| Mutation::Delete { key }).collect();
    store.write_batch(&deletes).unwrap();
    store.flush().unwrap();
    assert_eq!(store.statistics().unwrap().live_entries, 0);
    assert_eq!(store.get(&keys[599]).unwrap(), None);
    let maximum_key = [0xff; 2047];
    store.put(&maximum_key, b"maximum key").unwrap();
    store.close().unwrap();
    let store = MemtableStore::open(&path, options()).unwrap();
    assert_eq!(store.statistics().unwrap().live_entries, 1);
    assert_eq!(
        store.get(&maximum_key).unwrap().as_deref(),
        Some(&b"maximum key"[..])
    );
    store.close().unwrap();
    NativeReader::open(path).unwrap().validate().unwrap();
}

#[test]
fn foreground_writes_and_base_reads_overlap_repeated_background_checkpoints() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("concurrent.sac");
    let opts = MemtableOptions {
        max_memory_bytes: 64 * 1024,
        max_wal_bytes: 4096,
        flush_interval: Duration::from_millis(5),
        ..options()
    };
    let store = Arc::new(MemtableStore::create(&path, [5; 16], opts.clone()).unwrap());
    store.put(b"sentinel", b"unchanged").unwrap();
    store.flush().unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let observed = Arc::new(AtomicUsize::new(0));
    let reader = {
        let store = store.clone();
        let done = done.clone();
        let observed = observed.clone();
        std::thread::spawn(move || {
            let mut reads = 0;
            while !done.load(Ordering::Acquire) {
                assert_eq!(
                    store.get(b"sentinel").unwrap().as_deref(),
                    Some(&b"unchanged"[..])
                );
                let stats = store.statistics().unwrap();
                assert!(stats.pending_memory_bytes <= opts.max_memory_bytes);
                assert_eq!(
                    stats.pending_memory_bytes,
                    stats.active_memory_bytes + stats.immutable_memory_bytes
                );
                assert!(stats.wal_bytes <= opts.max_wal_bytes);
                if stats.flush_in_progress {
                    observed.fetch_add(1, Ordering::Relaxed);
                }
                reads += 1;
                if reads % 16 == 0 {
                    store.request_flush().unwrap();
                }
                std::thread::sleep(Duration::from_micros(500));
            }
        })
    };
    let writers: Vec<_> = (0..4u8)
        .map(|thread| {
            let store = store.clone();
            std::thread::spawn(move || {
                for ordinal in 0..48u8 {
                    store
                        .put(&[thread, ordinal % 13], &[thread, ordinal])
                        .unwrap();
                }
            })
        })
        .collect();
    let results: Vec<_> = writers.into_iter().map(|writer| writer.join()).collect();
    done.store(true, Ordering::Release);
    reader.join().unwrap();
    for result in results {
        result.unwrap();
    }
    assert!(
        observed.load(Ordering::Relaxed) > 0,
        "no base reads completed during checkpoints"
    );
    store.flush().unwrap();
    drop(store);
    let store = MemtableStore::open(&path, options()).unwrap();
    for thread in 0..4u8 {
        for key in 0..13u8 {
            let last = (47 - key) / 13 * 13 + key;
            assert_eq!(store.get(&[thread, key]).unwrap(), Some(vec![thread, last]));
        }
    }
    assert_eq!(store.statistics().unwrap().live_entries, 53);
    store.close().unwrap();
    NativeReader::open(path).unwrap().validate().unwrap();
}
