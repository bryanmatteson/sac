use super::*;
use crate::v1::resources::{ArchiveBuilder, ArchiveReader, Limits, path_from_str};
fn data(byte: u8, length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    blake3::Hasher::new()
        .update(&[byte])
        .finalize_xof()
        .fill(&mut bytes);
    bytes
}
fn publish(store: &mut NativeStore, byte: u8) {
    let mut b = ArchiveBuilder::new(store);
    b.add_file(&path_from_str("data").unwrap(), &data(byte, 512 << 10))
        .unwrap();
    let s = b.finish().unwrap();
    store.publish(s).unwrap();
}
fn fixture(path: &Path) -> NativeStore {
    let mut store = NativeStore::create_live(path, [24; 16]).unwrap();
    publish(&mut store, 1);
    publish(&mut store, 2);
    publish(&mut store, 3);
    store
}
fn verify(store: &NativeStore, hash: ObjectHash) {
    verify_data(store, hash, 3);
}
fn verify_data(store: &NativeStore, hash: ObjectHash, byte: u8) {
    assert_eq!(store.root().unwrap().root.hash, hash);
    store.validate().unwrap();
    let r =
        ArchiveReader::open(store, store.reader().snapshot().unwrap(), Limits::default()).unwrap();
    assert_eq!(
        r.read_range(&path_from_str("data").unwrap(), 0, 512 << 10)
            .unwrap(),
        data(byte, 512 << 10)
    );
}
#[test]
fn slide_preserves_inode_and_identity_and_rejects_pins() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("live");
    let mut store = fixture(&path);
    let before = std::fs::metadata(&path).unwrap();
    let hash = store.root().unwrap().root.hash;
    let pin = NativeReader::open_file(File::open(&path).unwrap()).unwrap();
    assert!(matches!(
        store.compact_in_place(Default::default()),
        Err(Error::Busy)
    ));
    drop(pin);
    let stats = store.compact_in_place(Default::default()).unwrap();
    assert!(stats.file_bytes_after < stats.file_bytes_before);
    assert!(stats.dead_frames > 0);
    assert_eq!(std::fs::metadata(&path).unwrap().ino(), before.ino());
    verify(&store, hash);
    drop(store);
    let store = NativeStore::open(&path, true).unwrap();
    verify(&store, hash);
}
#[test]
fn sweep_preserves_old_pin_and_reuses_exact_spans() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("live");
    let mut store = NativeStore::create_live(&path, [1; 16]).unwrap();
    publish(&mut store, 0);
    let pin = store.pin().unwrap();
    publish(&mut store, 1);
    publish(&mut store, 2);
    publish(&mut store, 3);

    let first = store.reclaim_online(Default::default()).unwrap();
    assert!(first.punched_bytes > 0);
    assert!(first.allocated_bytes_after < first.allocated_bytes_before);
    pin.validate().unwrap();
    let r = ArchiveReader::open(&pin, pin.reader().snapshot().unwrap(), Limits::default()).unwrap();
    assert_eq!(
        r.read_range(&path_from_str("data").unwrap(), 0, 512 << 10)
            .unwrap(),
        data(0, 512 << 10)
    );
    // The resource builder used 256 KiB byte chunks. Use the same span to
    // exercise actual same-file reuse rather than another append.
    let length = store.file_len();
    let new = store.put(7, 1, &data(91, 256 << 10), &[]).unwrap();
    assert!(new.address.offset < length);
    assert_eq!(length, store.file_len());
    assert!(matches!(
        store.reclaim_online(Default::default()),
        Err(Error::Busy)
    ));
    let mut b = ArchiveBuilder::new(&mut store);
    b.add_file(&path_from_str("data").unwrap(), &data(4, 512 << 10))
        .unwrap();
    let snapshot = b.finish().unwrap();
    store.publish(snapshot).unwrap();
    let old = store.root().unwrap().root.hash;
    verify_data(&store, old, 4);
    pin.validate().unwrap();
    drop(pin);
    let second = store.reclaim_online(Default::default()).unwrap();
    assert!(second.dead_frames > first.dead_frames);
    verify_data(&store, old, 4);
}
#[test]
fn quotas_fail_without_a_transaction_or_source_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("live");
    let mut store = fixture(&path);
    let original = std::fs::read(&path).unwrap();
    for case in 0..5 {
        let mut o = ReclamationOptions::default();
        match case {
            0 => o.limits.max_memory_bytes = 1,
            1 => o.limits.max_source_bytes = 1,
            2 => o.limits.max_frames = 1,
            3 => o.limits.max_temp_bytes = 1,
            _ => o.limits.max_edges = 0,
        }
        assert!(store.compact_in_place(o).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(!leases::pending(
            &leases::domain(store.file.get_mut().unwrap()).unwrap()
        ));
    }
}
#[test]
fn crash_child() {
    let Some(path) = std::env::var_os("SAC_TEST_MAINTENANCE_FILE") else {
        return;
    };
    let mut store = NativeStore::open(PathBuf::from(path), true).unwrap();
    if std::env::var("SAC_TEST_MAINTENANCE_FAULT").unwrap() == "punch" {
        store.reclaim_online(Default::default()).unwrap();
    } else if std::env::var("SAC_TEST_MAINTENANCE_FAULT")
        .unwrap()
        .starts_with("reuse-")
    {
        store.reclaim_online(Default::default()).unwrap();
        store.put(7, 1, &data(91, 256 << 10), &[]).unwrap();
    } else {
        store
            .compact_in_place(ReclamationOptions {
                journal_batch_bytes: 4096,
                ..Default::default()
            })
            .unwrap();
    }
    panic!("fault was not reached");
}
#[test]
fn killed_processes_recover_before_admission() {
    for point in [
        "punch",
        "plan",
        "progress-initial",
        "manifest",
        "redo",
        "partial-data",
        "data-sync",
        "progress",
        "partial-preamble",
        "preamble",
        "partial-slot",
        "slot",
        "truncate",
        "commit",
        "reuse-redo",
        "reuse-partial",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("live");
        let store = fixture(&path);
        let hash = store.root().unwrap().root.hash;
        let ino = std::fs::metadata(&path).unwrap().ino();
        drop(store);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "v1::native::maintenance::tests::crash_child",
                "--nocapture",
            ])
            .env("SAC_TEST_MAINTENANCE_FILE", &path)
            .env("SAC_TEST_MAINTENANCE_FAULT", point)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(86), "{point}");
        if !matches!(point, "commit" | "plan" | "progress-initial" | "punch") {
            assert!(
                matches!(NativeReader::open(&path), Err(Error::RecoveryRequired)),
                "{point}"
            );
        }
        let store = NativeStore::open(&path, true).unwrap();
        verify(&store, hash);
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), ino, "{point}");
    }
}
fn crash(path: &Path, point: &str) {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "v1::native::maintenance::tests::crash_child",
            "--nocapture",
        ])
        .env("SAC_TEST_MAINTENANCE_FILE", path)
        .env("SAC_TEST_MAINTENANCE_FAULT", point)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(86), "{point}");
}
/// Replace the contents of the same inode, as copying a backup over a path does.
fn restore(path: &Path, bytes: &[u8]) {
    let ino = std::fs::metadata(path).unwrap().ino();
    std::fs::write(path, bytes).unwrap();
    assert_eq!(std::fs::metadata(path).unwrap().ino(), ino);
}
fn journal(path: &Path) -> PathBuf {
    leases::domain(&File::open(path).unwrap()).unwrap()
}
#[test]
fn journal_of_an_interrupted_slide_never_changes_a_restored_file_it_does_not_describe() {
    // The first three points leave a file the journal still describes once the
    // backup is back: nothing durable depends on moved frames, so the slide
    // completes. At the later points the journal records moved frames that
    // the restored file does not have. It is stale and must be dropped.
    for (point, stale) in [
        ("manifest", false),
        ("redo", false),
        ("partial-data", false),
        ("progress", true),
        ("preamble", true),
        ("slot", true),
        ("truncate", true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("live");
        let store = fixture(&path);
        let hash = store.root().unwrap().root.hash;
        drop(store);
        let backup = std::fs::read(&path).unwrap();
        crash(&path, point);
        restore(&path, &backup);
        let store = NativeStore::open(&path, true).unwrap();
        verify(&store, hash);
        drop(store);
        assert!(!leases::pending(&journal(&path)), "{point}");
        if stale {
            assert_eq!(std::fs::read(&path).unwrap(), backup, "{point}");
        }
        let store = NativeStore::open(&path, true).unwrap();
        verify(&store, hash);
    }
}
#[test]
fn journal_is_dropped_when_an_older_version_of_the_file_is_restored() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("live");
    let mut store = NativeStore::create_live(&path, [24; 16]).unwrap();
    publish(&mut store, 1);
    publish(&mut store, 2);
    let older = store.root().unwrap().root.hash;
    let backup = std::fs::read(&path).unwrap();
    publish(&mut store, 3);
    drop(store);
    for point in ["manifest", "progress", "truncate"] {
        crash(&path, point);
        restore(&path, &backup);
        let store = NativeStore::open(&path, true).unwrap();
        verify_data(&store, older, 2);
        drop(store);
        assert!(!leases::pending(&journal(&path)), "{point}");
        assert_eq!(std::fs::read(&path).unwrap(), backup, "{point}");
        let mut store = NativeStore::open(&path, true).unwrap();
        publish(&mut store, 3);
    }
}
#[test]
fn damaged_slide_output_fails_closed_and_resumes_after_repair() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("live");
    let store = fixture(&path);
    let hash = store.root().unwrap().root.hash;
    drop(store);
    // Every frame has moved and the old layout is gone.
    crash(&path, "preamble");
    let good = std::fs::read(&path).unwrap();
    let mut damaged = good.clone();
    damaged[BOOTSTRAP_SIZE + 4096] ^= 1;
    restore(&path, &damaged);
    assert!(matches!(
        NativeStore::open(&path, true),
        Err(Error::Corrupt(message)) if message.contains("journal does not match")
    ));
    assert_eq!(std::fs::read(&path).unwrap(), damaged);
    assert!(leases::pending(&journal(&path)));
    restore(&path, &good);
    let store = NativeStore::open(&path, true).unwrap();
    verify(&store, hash);
}
#[test]
fn reuse_record_for_another_version_of_the_file_is_dropped_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("live");
    let mut store = NativeStore::create_live(&path, [24; 16]).unwrap();
    publish(&mut store, 1);
    publish(&mut store, 2);
    let older = store.root().unwrap().root.hash;
    let backup = std::fs::read(&path).unwrap();
    publish(&mut store, 3);
    drop(store);
    crash(&path, "reuse-redo");
    assert!(journal(&path).join("reuse").exists());
    restore(&path, &backup);
    let store = NativeStore::open(&path, true).unwrap();
    verify_data(&store, older, 2);
    drop(store);
    assert!(!leases::pending(&journal(&path)));
    assert_eq!(std::fs::read(&path).unwrap(), backup);
}
#[test]
fn pin_child() {
    let Some(path) = std::env::var_os("SAC_TEST_PIN_FILE") else {
        return;
    };
    let pin = NativeReader::open_file(File::open(path).unwrap()).unwrap();
    println!("reader-ready");
    std::io::stdout().flush().unwrap();
    let mut byte = [0];
    std::io::stdin().read_exact(&mut byte).unwrap();
    pin.validate().unwrap();
}
#[test]
fn hardlink_reader_in_another_process_blocks_sliding_and_survives_sweep() {
    use std::io::BufRead;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("live");
    let alias = dir.path().join("alias");
    let mut store = fixture(&path);
    std::fs::hard_link(&path, &alias).unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "v1::native::maintenance::tests::pin_child",
            "--nocapture",
        ])
        .env("SAC_TEST_PIN_FILE", &alias)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
    loop {
        let mut line = String::new();
        assert_ne!(output.read_line(&mut line).unwrap(), 0);
        if line.contains("reader-ready") {
            break;
        }
    }
    assert!(matches!(
        store.compact_in_place(Default::default()),
        Err(Error::Busy)
    ));
    publish(&mut store, 4);
    publish(&mut store, 5);
    store.reclaim_online(Default::default()).unwrap();
    child.stdin.take().unwrap().write_all(&[0]).unwrap();
    assert!(child.wait().unwrap().success());
    store.compact_in_place(Default::default()).unwrap();
}
#[test]
fn an_interior_frame_cannot_become_reclamation_authority() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("live");
    let mut store = fixture(&path);
    let object = CanonicalObject {
        kind: 7,
        version: 1,
        bytes: vec![3; 24],
        children: vec![],
    };
    let frame = wire::encode_frame(&object, 0).unwrap();
    let wrapper = store.put(7, 1, &frame, &[]).unwrap();
    let mut r = wrapper;
    r.hash = object.hash();
    r.address.offset += 64;
    r.address.length = frame.len() as u32;
    let mut root = store.reader.publication.unwrap();
    root.root = r;
    store.reader.publication = Some(root);
    // Call the traversal directly because the fabricated reference is not a
    // published commit; it still must be rejected before any destructive step.
    assert!(
        mark(
            &FrozenFile::capture(&store).unwrap(),
            &[r],
            &Default::default(),
            temporary::Budget::new(1 << 20)
        )
        .is_err()
    );
}
#[test]
fn damaged_redo_fails_closed_and_can_resume_after_record_repair() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("live");
    let store = fixture(&path);
    let hash = store.root().unwrap().root.hash;
    let journal = leases::domain(&store.file.lock().unwrap()).unwrap();
    drop(store);
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "v1::native::maintenance::tests::crash_child",
            "--nocapture",
        ])
        .env("SAC_TEST_MAINTENANCE_FILE", &path)
        .env("SAC_TEST_MAINTENANCE_FAULT", "partial-data")
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(86));
    let redo = std::fs::read(journal.join("redo")).unwrap();
    let mut bad = redo.clone();
    bad[20] ^= 1;
    std::fs::write(journal.join("redo"), bad).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(NativeStore::open(&path, true).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    std::fs::write(journal.join("redo"), redo).unwrap();
    let store = NativeStore::open(&path, true).unwrap();
    verify(&store, hash);
}

#[test]
fn sweep_and_reuse_retire_deferred_rewrite_capabilities() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("live");
    let mut store = fixture(&path);
    let parent = store.root().unwrap().root;
    let object = store.get(parent).unwrap();
    let before = store.rewrite_source(parent).unwrap().unwrap();
    store.reclaim_online(Default::default()).unwrap();
    assert!(
        store
            .rewrite(
                &before,
                object.kind,
                object.version,
                &object.bytes,
                &object.children
            )
            .is_err()
    );
    let after = store.rewrite_source(parent).unwrap().unwrap();
    store.put(7, 1, &data(91, 256 << 10), &[]).unwrap();
    assert!(
        store
            .rewrite(
                &after,
                object.kind,
                object.version,
                &object.bytes,
                &object.children
            )
            .is_err()
    );
}
#[test]
fn persistent_resource_updates_work_after_reclamation_and_reuse() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("live");
    let mut store = fixture(&path);
    let directory = store
        .get(store.reader().snapshot().unwrap())
        .unwrap()
        .children[0];
    store.reclaim_online(Default::default()).unwrap();
    let mut builder = ArchiveBuilder::from_directory(&mut store, directory, Limits::default());
    builder
        .set_file(
            &path_from_str("data").unwrap(),
            &data(5, 512 << 10),
            cbor::Value::Map(vec![]),
        )
        .unwrap();
    let snapshot = builder.finish().unwrap();
    store.publish(snapshot).unwrap();
    let hash = store.root().unwrap().root.hash;
    verify_data(&store, hash, 5);
}
#[test]
fn sealed_child_without_home() {
    let Some(path) = std::env::var_os("SAC_TEST_SEALED_FILE") else {
        return;
    };
    let store = NativeStore::open(&path, false).unwrap();
    store.validate().unwrap();
    let reader = NativeReader::open(&path).unwrap();
    reader.validate().unwrap();
}
#[test]
fn sealed_readers_do_not_require_live_reader_registry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sealed");
    let mut store = NativeStore::create_sealed(&path, Header::new([1; 16], [2; 16])).unwrap();
    assert!(matches!(
        store.compact_in_place(Default::default()),
        Err(Error::Unsupported(_))
    ));
    assert!(matches!(
        store.reclaim_online(Default::default()),
        Err(Error::Unsupported(_))
    ));
    publish(&mut store, 3);
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        store.compact_in_place(Default::default()),
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied
    ));
    assert!(matches!(
        store.reclaim_online(Default::default()),
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    drop(store);
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "v1::native::maintenance::tests::sealed_child_without_home",
            "--nocapture",
        ])
        .env("SAC_TEST_SEALED_FILE", &path)
        .env_remove("HOME")
        .status()
        .unwrap();
    assert!(status.success());
}
#[test]
fn background_job_keeps_writer_and_new_reader_generations_online() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("live");
    let mut store = fixture(&path);
    let old = store.pin().unwrap();
    let mut job = store.begin_reclamation(Default::default()).unwrap();
    assert!(store.begin_compaction().is_err());
    assert!(matches!(
        store.compact_in_place(Default::default()),
        Err(Error::Busy)
    ));
    // Exercise a publication before marking and another after the immutable
    // prefix was marked but before punching. Neither writer call waits for GC.
    publish(&mut store, 4);
    let (marked_tx, marked_rx) = std::sync::mpsc::channel();
    let (continue_tx, continue_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let disk = temporary::Budget::new(job.options.limits.max_temp_bytes);
        let live = mark(&job.source, &job.roots, &job.options, disk.clone()).unwrap();
        marked_tx.send(()).unwrap();
        continue_rx.recv().unwrap();
        job.sweep(live, disk).unwrap();
        job
    });
    marked_rx.recv().unwrap();
    publish(&mut store, 5);
    let current = store.pin().unwrap();
    continue_tx.send(()).unwrap();
    let job = worker.join().unwrap();
    let stats = store.finish_reclamation(job).unwrap();
    assert!(stats.punched_bytes > 0);
    old.validate().unwrap();
    current.validate().unwrap();
    verify_data(&store, store.root().unwrap().root.hash, 5);
    // The captured-root pin stays usable even after a later reuse publication.
    publish(&mut store, 6);
    old.validate().unwrap();
    current.validate().unwrap();
    let archive = ArchiveReader::open(
        &current,
        current.reader().snapshot().unwrap(),
        Limits::default(),
    )
    .unwrap();
    assert_eq!(
        archive
            .read_range(&path_from_str("data").unwrap(), 0, 512 << 10)
            .unwrap(),
        data(5, 512 << 10)
    );
}
#[test]
fn abandoning_a_background_job_releases_only_its_physical_owner() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("live");
    let mut store = fixture(&path);
    let job = store.begin_reclamation(Default::default()).unwrap();
    publish(&mut store, 4);
    drop(job);
    store.reclaim_online(Default::default()).unwrap();
    store.compact_in_place(Default::default()).unwrap();
    verify_data(&store, store.root().unwrap().root.hash, 4);
}
#[test]
fn repeated_compaction_is_a_byte_preserving_noop() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("live");
    let mut store = fixture(&path);
    store.compact_in_place(Default::default()).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let root = store.root().unwrap();
    let stats = store.compact_in_place(Default::default()).unwrap();
    assert_eq!(stats.moved_bytes, 0);
    assert_eq!(stats.journal_peak_bytes, 0);
    assert_eq!(store.root().unwrap(), root);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}
#[test]
fn generation_overflow_is_rejected_before_committing_a_journal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("live");
    let mut store = fixture(&path);
    let mut at = store.reader.first_record_offset();
    let mut trailers = Vec::new();
    while at < store.end {
        let (span, h) = record(store.file.get_mut().unwrap(), at, store.end).unwrap();
        if h.is_none() {
            trailers.push(at);
        }
        at += span;
    }
    for (i, offset) in trailers.iter().rev().take(2).rev().enumerate() {
        let mut trailer = read_trailer(
            store.file.get_mut().unwrap(),
            &store.reader.header,
            *offset,
            &store.io,
        )
        .unwrap();
        trailer.generation = u64::MAX - 2 + i as u64;
        let slot = wire::Slot {
            preamble_digest: store.reader.header.digest(),
            generation: trailer.generation,
            trailer_offset: *offset,
            trailer_digest: trailer.digest(),
        };
        write_at(store.file.get_mut().unwrap(), &trailer.encode(), *offset).unwrap();
        write_at(
            store.file.get_mut().unwrap(),
            &slot.encode(),
            slot_offset(trailer.generation),
        )
        .unwrap();
    }
    durable(store.file.get_mut().unwrap()).unwrap();
    drop(store);
    let mut store = NativeStore::open(&path, true).unwrap();
    assert_eq!(store.root().unwrap().generation, u64::MAX - 1);
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        store.compact_in_place(Default::default()),
        Err(Error::Limit("maintenance generation"))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(!leases::pending(
        &leases::domain(store.file.get_mut().unwrap()).unwrap()
    ));
}
