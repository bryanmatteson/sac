#![cfg(feature = "native")]
use sac::v1::resources::{ArchiveBuilder, ArchiveReader, Limits, path_from_str};
use sac::v1::{Header, NativeStore, ObjectStore};

fn publish(store: &mut NativeStore, text: &[u8]) {
    let mut builder = match store.reader().snapshot() {
        Some(snapshot) => {
            let directory = store.get(snapshot).unwrap().children[0];
            ArchiveBuilder::from_directory(store, directory, Limits::default())
        }
        None => {
            let mut builder = ArchiveBuilder::new(store);
            let mut bytes = vec![0; 128 * 1024];
            blake3::Hasher::new().finalize_xof().fill(&mut bytes);
            builder
                .add_file(&path_from_str("retained").unwrap(), &bytes)
                .unwrap();
            builder
        }
    };
    builder
        .set_file(
            &path_from_str("value").unwrap(),
            text,
            sac::v1::cbor::Value::Map(vec![]),
        )
        .unwrap();
    let snapshot = builder.finish().unwrap();
    store.publish(snapshot).unwrap();
}
fn names(directory: &std::path::Path) -> Vec<String> {
    std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}
fn wait_cleanup(store: &NativeStore) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let statistics = store.compaction_cleanup_statistics();
        assert!(statistics.error.is_none(), "{statistics:?}");
        if statistics.retained_inode_bytes == 0 {
            return;
        }
        assert!(std::time::Instant::now() < deadline, "{statistics:?}");
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}
#[test]
fn prepare_durably_installs_candidate_without_advancing_source() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("live.sac");
    let mut store = NativeStore::create(&path, Header::new([1; 16], [2; 16])).unwrap();
    publish(&mut store, b"old");
    let old = store.pin().unwrap();
    let original = store.root().unwrap();
    let before = store.publication_statistics();
    let mut job = store.begin_compaction().unwrap();
    job.copy().unwrap();
    let prepared = store.publication_statistics();
    assert_eq!(store.root().unwrap(), original);
    assert_eq!(
        prepared.compaction_completed - before.compaction_completed,
        1
    );
    assert_eq!(prepared.chunk_barriers - before.chunk_barriers, 1);
    assert_eq!(prepared.slot_syncs - before.slot_syncs, 1);
    assert!(
        names(directory.path())
            .iter()
            .any(|name| name.starts_with("live.sac1-recovery-"))
    );
    publish(&mut store, b"acknowledged intervening update");
    let acknowledged = store.root().unwrap().root.hash;
    store.finish_compaction(job).unwrap();
    assert_eq!(store.root().unwrap().root.hash, acknowledged);
    wait_cleanup(&store);
    assert!(
        !names(directory.path())
            .iter()
            .any(|name| name.starts_with("live.sac1-recovery-"))
    );
    let new = ArchiveReader::open(
        &store,
        store.reader().snapshot().unwrap(),
        Limits::default(),
    )
    .unwrap();
    assert_eq!(
        new.read_range(
            &path_from_str("value").unwrap(),
            0,
            b"acknowledged intervening update".len()
        )
        .unwrap(),
        b"acknowledged intervening update"
    );
    let old =
        ArchiveReader::open(&old, old.reader().snapshot().unwrap(), Limits::default()).unwrap();
    assert_eq!(
        old.read_range(&path_from_str("value").unwrap(), 0, 3)
            .unwrap(),
        b"old"
    );
    new.verify().unwrap();
}
#[test]
fn abandoned_and_cancelled_prepared_candidates_remove_owned_links_only() {
    for cancel in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("live.sac");
        let mut store = NativeStore::create(&path, Header::new([3; 16], [4; 16])).unwrap();
        publish(&mut store, b"kept");
        let mut job = store.begin_compaction().unwrap();
        job.copy().unwrap();
        if cancel {
            assert!(
                store
                    .finish_compaction_pinned_cancellable(job, &|| true)
                    .is_err()
            );
        } else {
            drop(job);
        }
        assert!(
            !names(directory.path())
                .iter()
                .any(|name| name.starts_with("live.sac1-recovery-"))
        );
        publish(&mut store, b"still writable");
        assert!(path.is_file());
        assert!(store.begin_compaction().is_ok());
    }
}

#[test]
fn aggregate_disk_quota_includes_copier_tables_and_keeps_source_writable() {
    use sac::v1::native::CompactionBudget;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("live.sac");
    let mut store = NativeStore::create(&path, Header::new([5; 16], [6; 16])).unwrap();
    let mut bytes = vec![0; 4 << 20];
    blake3::Hasher::new().finalize_xof().fill(&mut bytes);
    let snapshot = {
        let mut b = ArchiveBuilder::new(&mut store);
        b.set_chunk_size(1024).unwrap();
        b.add_file(&path_from_str("manychunks").unwrap(), &bytes)
            .unwrap();
        b.finish().unwrap()
    };
    store.publish(snapshot).unwrap();
    let selected = store.root().unwrap();
    let limit = store.file_len() + 128 * 1024;
    let mut job = store.begin_compaction().unwrap();
    job.set_budget(CompactionBudget {
        max_temporary_bytes: limit,
        ..CompactionBudget::default()
    })
    .unwrap();
    assert!(matches!(job.copy(), Err(sac::v1::Error::Limit(_))));
    assert!(job.aggregate_temporary_bytes() <= limit);
    assert!(job.statistics().peak_aggregate_temporary_bytes <= limit);
    assert!(job.statistics().copier_temporary.peak_reserved_bytes > 0);
    assert!(job.candidate_file_bytes().unwrap() < limit);
    drop(job);
    assert_eq!(store.root().unwrap(), selected);
    publish(&mut store, b"usable after quota rejection");
    let mut job = store.begin_compaction().unwrap();
    job.copy().unwrap();
    assert!(job.statistics().peak_aggregate_temporary_bytes > limit);
    store.finish_compaction(job).unwrap();
    wait_cleanup(&store);
    ArchiveReader::open(
        &store,
        store.reader().snapshot().unwrap(),
        Limits::default(),
    )
    .unwrap()
    .verify()
    .unwrap();
}

#[test]
fn aggregate_layout_quota_counts_old_and_replacement_spools() {
    use sac::v1::native::CompactionBudget;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("live.sac");
    let mut store = NativeStore::create(&path, Header::new([7; 16], [8; 16])).unwrap();
    publish(&mut store, b"kept");
    let mut job = store.begin_compaction().unwrap();
    let initial = job.candidate_file_bytes().unwrap();
    job.set_budget(CompactionBudget {
        max_temporary_bytes: initial + 79,
        ..CompactionBudget::default()
    })
    .unwrap();
    let root = store.root().unwrap().root.hash;
    job.set_layout_iterator(vec![root], std::iter::empty())
        .unwrap();
    assert_eq!(job.aggregate_temporary_bytes(), initial + 40);
    assert!(matches!(
        job.set_layout_iterator(vec![root], std::iter::empty()),
        Err(sac::v1::Error::Limit(_))
    ));
    assert_eq!(job.aggregate_temporary_bytes(), initial + 40);
    assert_eq!(job.candidate_file_bytes().unwrap(), initial);
    drop(job);
    publish(&mut store, b"writable after layout rejection");
}

#[test]
fn ordinary_refresh_prepares_large_delta_outside_the_final_fence() {
    use sac::v1::native::CompactionBudget;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("refresh.sac");
    let mut store = NativeStore::create(&path, Header::new([11; 16], [12; 16])).unwrap();
    publish(&mut store, b"before");
    let old = store.pin().unwrap();
    let original = store.root().unwrap();
    let mut job = store.begin_compaction().unwrap();
    job.set_budget(CompactionBudget {
        max_catch_up_bytes: 1024,
        max_pause: std::time::Duration::from_secs(2), // functional byte-fence test
        ..CompactionBudget::default()
    })
    .unwrap();
    job.copy().unwrap();
    let before = store.file_len();
    let mut bytes = vec![0; 24 << 20];
    blake3::Hasher::new()
        .update(b"ordinary-refresh-distinct")
        .finalize_xof()
        .fill(&mut bytes);
    let snapshot = {
        let root = store.reader().snapshot().unwrap();
        let directory = store.get(root).unwrap().children[0];
        let mut b = ArchiveBuilder::from_directory(&mut store, directory, Limits::default());
        b.add_file(&path_from_str("new-large-resource").unwrap(), &bytes)
            .unwrap();
        b.finish().unwrap()
    };
    store.publish(snapshot).unwrap();
    assert!(store.file_len() - before > 16 << 20);
    let acknowledged = store.root().unwrap();
    let latest = store.pin().unwrap();
    job.refresh_cancellable(&latest, || false).unwrap();
    assert_eq!(
        store.root().unwrap(),
        acknowledged,
        "private refresh published source"
    );
    assert!(job.statistics().copied_bytes > 24 << 20);
    let extent = job.candidate_file_bytes().unwrap();
    job.refresh_cancellable(&latest, || false).unwrap();
    assert_eq!(
        job.candidate_file_bytes().unwrap(),
        extent,
        "unchanged refresh appended"
    );
    assert!(job.refresh_cancellable(&old, || false).is_err());
    // Stale-pin rejection precedes any mutation, so this candidate remains intact.
    store.finish_compaction(job).unwrap();
    assert_eq!(store.root().unwrap().root.hash, acknowledged.root.hash);
    assert!(
        store
            .last_compaction_statistics()
            .unwrap()
            .catch_up_total_write_bytes
            <= 1024
    );
    store.validate().unwrap();
    let reader = ArchiveReader::open(
        &store,
        store.reader().snapshot().unwrap(),
        Limits::default(),
    )
    .unwrap();
    assert_eq!(
        reader
            .read_range(
                &path_from_str("new-large-resource").unwrap(),
                0,
                bytes.len()
            )
            .unwrap(),
        bytes
    );
    assert_eq!(old.root().unwrap(), original);
    let old_archive =
        ArchiveReader::open(&old, old.reader().snapshot().unwrap(), Limits::default()).unwrap();
    assert_eq!(
        old_archive
            .read_range(&path_from_str("value").unwrap(), 0, 6)
            .unwrap(),
        b"before"
    );
}

#[test]
fn ordinary_refresh_rejects_wrong_source_cancellation_and_projection_mode() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = NativeStore::create(
        directory.path().join("source.sac"),
        Header::new([13; 16], [14; 16]),
    )
    .unwrap();
    publish(&mut store, b"source");
    let mut other = NativeStore::create(
        directory.path().join("other.sac"),
        Header::new([15; 16], [16; 16]),
    )
    .unwrap();
    publish(&mut other, b"other");
    let selected = store.root().unwrap();
    let mut job = store.begin_compaction().unwrap();
    assert!(
        job.refresh_cancellable(&store.pin().unwrap(), || false)
            .is_err()
    );
    job.copy().unwrap();
    assert!(
        job.refresh_cancellable(&other.pin().unwrap(), || false)
            .is_err()
    );
    assert!(
        job.refresh_cancellable(&store.pin().unwrap(), || true)
            .is_err()
    );
    let mut projector =
        |_: &sac::v1::NativeReader,
         _: &mut NativeStore,
         _: &mut sac::v1::ClosureCopy,
         _: Option<sac::v1::ObjectRef>,
         _: &dyn Fn() -> bool|
         -> sac::v1::Result<sac::v1::ObjectRef> { panic!("mismatched callback invoked") };
    assert!(
        job.refresh_projected_cancellable(&store.pin().unwrap(), &mut projector, || false)
            .is_err()
    );
    drop(job);
    assert_eq!(store.root().unwrap(), selected);
    publish(&mut store, b"still writable");
    store.validate().unwrap();
}
