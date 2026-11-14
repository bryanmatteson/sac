#![cfg(feature = "native")]
use sac::v1::resources::{ArchiveBuilder, ArchiveReader, Limits, path_from_str};
use sac::v1::{Error, Header, NativeStore};

fn staged(path: &std::path::Path) -> (NativeStore, sac::v1::ObjectRef, Vec<u8>) {
    let mut store = NativeStore::create_sealed(path, Header::new([1; 16], [2; 16])).unwrap();
    let mut bytes = vec![0; 4 << 20];
    blake3::Hasher::new().finalize_xof().fill(&mut bytes);
    let snapshot = {
        let mut builder = ArchiveBuilder::new(&mut store);
        builder.set_chunk_size(1024).unwrap();
        builder
            .add_file(&path_from_str("payload").unwrap(), &bytes)
            .unwrap();
        builder.finish().unwrap()
    };
    (store, snapshot, bytes)
}

#[test]
fn sealed_total_quota_counts_both_extents_and_copy_workspace() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("limited.sac");
    let (mut limited, snapshot, _) = staged(&path);
    let two_extents = limited.file_len() * 2;
    limited
        .set_total_temporary_disk_budget(two_extents)
        .unwrap();
    assert!(matches!(limited.publish(snapshot), Err(Error::Limit(_))));
    let stats = limited.total_temporary_statistics();
    assert!(stats.peak_reserved_bytes <= two_extents);
    assert!(stats.peak_reserved_bytes > limited.file_len());
    assert!(
        !path.exists(),
        "quota rejection must not publish a destination"
    );
    drop(limited);

    let path = directory.path().join("adequate.sac");
    let (mut adequate, snapshot, expected) = staged(&path);
    adequate
        .set_total_temporary_disk_budget(two_extents + (8 << 20))
        .unwrap();
    adequate.publish(snapshot).unwrap();
    let stats = adequate.total_temporary_statistics();
    assert!(
        stats.peak_reserved_bytes > two_extents,
        "actual sealing scratch exceeds a two-file-only allowance: {stats:?}"
    );
    assert_eq!(
        stats.reserved_bytes, 0,
        "installed output is no longer temporary"
    );
    let archive = ArchiveReader::open(
        &adequate,
        adequate.reader().snapshot().unwrap(),
        Limits::default(),
    )
    .unwrap();
    assert_eq!(
        archive
            .read_range(&path_from_str("payload").unwrap(), 0, expected.len())
            .unwrap(),
        expected
    );
    archive
        .verify_commit(adequate.root().unwrap().root)
        .unwrap();
}

#[test]
fn sealed_repack_preserves_the_callers_disposable_index_limit() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("index-limited.sac");
    let (mut store, snapshot, _) = staged(&path);
    store.discard_disposable_caches();
    store.set_append_index_memory_budget(0).unwrap();
    store.set_temporary_disk_budget(0).unwrap();
    store.set_total_temporary_disk_budget(64 << 20).unwrap();
    assert!(matches!(store.publish(snapshot), Err(Error::Limit(_))));
    assert_eq!(store.temporary_bytes().unwrap(), 0);
    assert!(!path.exists());
}

#[test]
fn unpublished_total_quota_reserves_before_append_and_releases_on_publication() {
    use sac::v1::ObjectStore;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("live.sac");
    let mut store = NativeStore::create_live(&path, [3; 16]).unwrap();
    let initial = store.file_len();
    store
        .set_total_temporary_disk_budget(initial + 100)
        .unwrap();
    let mut bytes = [0; 1024];
    blake3::Hasher::new().finalize_xof().fill(&mut bytes);
    assert!(matches!(store.put(7, 1, &bytes, &[]), Err(Error::Limit(_))));
    assert_eq!(store.file_len(), initial);
    assert_eq!(store.total_temporary_statistics().reserved_bytes, initial);
    store.set_total_temporary_disk_budget(64 << 10).unwrap();
    let snapshot = {
        let mut builder = ArchiveBuilder::new(&mut store);
        builder
            .add_file(&path_from_str("small").unwrap(), b"durable")
            .unwrap();
        builder.finish().unwrap()
    };
    store.publish(snapshot).unwrap();
    assert_eq!(store.total_temporary_statistics().reserved_bytes, 0);
    assert!(path.is_file());
}
