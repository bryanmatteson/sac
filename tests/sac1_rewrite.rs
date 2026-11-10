#![cfg(feature = "native")]
use sac::v1::{ClosureCopy, NativeStore, ObjectRef, ObjectStore, resources::ArchiveBuilder};
#[cfg(unix)]
use std::os::unix::fs::FileExt;

fn store() -> (tempfile::TempDir, NativeStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = NativeStore::create_live(dir.path().join("db.sac"), [9; 16]).unwrap();
    (dir, store)
}
fn commit(store: &mut NativeStore) {
    let snapshot = ArchiveBuilder::new(store).finish().unwrap();
    store.publish(snapshot).unwrap();
}
fn parent(store: &mut NativeStore, children: &[ObjectRef]) -> ObjectRef {
    store.put(4096, 1, b"original", children).unwrap()
}
fn wrong_locator(reference: ObjectRef, location: ObjectRef) -> ObjectRef {
    ObjectRef {
        address: location.address,
        ..reference
    }
}

#[test]
fn rewrite_carries_exact_edges_after_cache_loss_without_marking_children_verified() {
    let (_dir, mut store) = store();
    let children: Vec<_> = (0u8..64)
        .map(|n| store.put(7, 1, &[n; 256], &[]).unwrap())
        .collect();
    let prior = parent(&mut store, &children);
    commit(&mut store);
    store.discard_disposable_caches();
    let before = store.physical_statistics();
    let source = store.rewrite_source(prior).unwrap().unwrap();
    let prepared = store.physical_statistics();
    let length = store.file_len();
    assert_eq!(
        store
            .rewrite(&source, 4096, 1, b"original", &children)
            .unwrap(),
        prior
    );
    assert_eq!(
        store.file_len(),
        length,
        "exact unchanged rewrite must reuse its committed occurrence without the ID index"
    );
    assert_eq!(
        prepared.read_operations - before.read_operations,
        1,
        "authenticate the prior parent exactly once"
    );
    let rewritten = store
        .rewrite(&source, 4096, 1, b"rewritten", &children)
        .unwrap();
    assert_eq!(
        store.physical_statistics().read_operations,
        prepared.read_operations,
        "unchanged child payloads remain deferred"
    );
    assert_eq!(store.get(rewritten).unwrap().children, children);
    let before_strict = store.physical_statistics();
    store
        .put(4096, 1, b"strict remains strict", &children)
        .unwrap();
    let child_reads = store.physical_statistics().read_operations - before_strict.read_operations;
    assert!(
        child_reads > 0 && child_reads <= 64,
        "strict child admission may coalesce physical reads: {child_reads}"
    );
    // The native owning unit test checks the verified-child markers directly;
    // physical read counts also include the shared small-frame windows.
    let mut target = sac::v1::MemoryStore::sealed();
    ClosureCopy::new()
        .unwrap()
        .copy_root(&store, &mut target, rewritten)
        .unwrap();
}

#[test]
fn rewrite_rejects_wrong_source_and_authenticates_relocated_same_id() {
    let (_dir, mut store) = store();
    let a = store.put(7, 1, b"AAAA", &[]).unwrap();
    let b = store.put(7, 1, b"BBBB", &[]).unwrap();
    let prior = parent(&mut store, &[a]);
    assert!(
        store.rewrite_source(prior).unwrap().is_none(),
        "staged parents have no inherited committed authority"
    );
    commit(&mut store);
    store.discard_disposable_caches();
    let source = store.rewrite_source(prior).unwrap().unwrap();
    let bad = wrong_locator(a, b);
    let length = store.file_len();
    assert!(
        store
            .rewrite(&source, 4096, 1, b"changed locator", &[bad])
            .is_err()
    );
    assert_eq!(store.file_len(), length, "reject before append");
    let (_other_dir, mut other) = self::store();
    commit(&mut other);
    assert!(
        other
            .rewrite(&source, 4096, 1, b"wrong file", &[a])
            .is_err()
    );
    let changed = store
        .rewrite(&source, 4096, 1, b"new valid child", &[b])
        .unwrap();
    assert_eq!(store.get(changed).unwrap().children, vec![b]);
    store.compact().unwrap();
    assert!(
        store
            .rewrite(&source, 4096, 1, b"replaced incarnation", &[a])
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn inherited_poisoned_locator_stays_deferred_and_fails_dereference_and_full_copy() {
    let (dir, mut store) = store();
    let a = store.put(7, 1, b"AAAA", &[]).unwrap();
    let b = store.put(7, 1, b"BBBB", &[]).unwrap();
    let prior = parent(&mut store, &[a]);
    commit(&mut store);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.path().join("db.sac"))
        .unwrap();
    let mut header = [0; 56];
    file.read_exact_at(&mut header, prior.address.offset)
        .unwrap();
    let stored = u32::from_le_bytes(header[8..12].try_into().unwrap()) as u64;
    // External child hints are not canonical-hash committed. Preserve the
    // expected ID but poison its locator with another valid earlier frame.
    let at = prior.address.offset + 56 + stored;
    file.write_all_at(&b.address.offset.to_le_bytes(), at)
        .unwrap();
    file.write_all_at(&b.address.length.to_le_bytes(), at + 8)
        .unwrap();
    store.discard_disposable_caches();
    let source = store.rewrite_source(prior).unwrap().unwrap();
    let bad = wrong_locator(a, b);
    let rewritten = store
        .rewrite(&source, 4096, 1, b"deferred corruption", &[bad])
        .unwrap();
    assert_eq!(store.get(rewritten).unwrap().children, vec![bad]);
    assert!(
        store.get(bad).is_err(),
        "rewrite does not repair or certify inherited hints"
    );
    assert!(
        store.put(4096, 1, b"strict child check", &[bad]).is_err(),
        "no authenticated-child marker was created"
    );
    let mut target = sac::v1::MemoryStore::sealed();
    assert!(
        ClosureCopy::new()
            .unwrap()
            .copy_root(&store, &mut target, rewritten)
            .is_err(),
        "full closure traversal rejects the deferred corruption"
    );
}

#[test]
fn native_directory_rewrite_survives_splits_and_strict_verification() {
    use sac::v1::{
        cbor::Value as V,
        resources::{ArchiveReader, ExtentAccumulator, Limits, path_from_str},
    };
    let (_dir, mut store) = store();
    let base = {
        let mut builder = ArchiveBuilder::new(&mut store);
        builder.set_page_limit(1024).unwrap();
        for n in 0..100 {
            builder
                .set_file(
                    &path_from_str(&format!("dir/{n:04}")).unwrap(),
                    b"before",
                    V::Map(vec![]),
                )
                .unwrap();
        }
        builder.finish().unwrap()
    };
    store.publish(base).unwrap();
    let root = store
        .get(store.reader().snapshot().unwrap())
        .unwrap()
        .children[0];
    store.discard_disposable_caches();
    let mut extent = ExtentAccumulator::new();
    extent.push_data(&mut store, b"after!").unwrap();
    let extent = extent.finish(&mut store).unwrap().unwrap();
    let edits: Vec<_> = (90..160)
        .map(|n| {
            (
                path_from_str(&format!("dir/{n:04}")).unwrap(),
                6,
                extent,
                V::Map(vec![]),
            )
        })
        .collect();
    let next = {
        let mut builder = ArchiveBuilder::from_directory(&mut store, root, Limits::default());
        builder.set_page_limit(1024).unwrap();
        builder.set_extent_files_batch(&edits).unwrap();
        builder.finish().unwrap()
    };
    store.publish(next).unwrap();
    let reader = ArchiveReader::open(
        &store,
        store.reader().snapshot().unwrap(),
        Limits::default(),
    )
    .unwrap();
    reader.verify().unwrap();
    for n in 0..160 {
        let actual = reader
            .read_file_bounded(&path_from_str(&format!("dir/{n:04}")).unwrap(), 6)
            .unwrap()
            .unwrap()
            .1;
        assert_eq!(actual, if n < 90 { b"before" } else { b"after!" });
    }
}
