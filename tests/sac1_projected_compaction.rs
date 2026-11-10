#![cfg(feature = "native")]
use sac::v1::resources::{ArchiveBuilder, ArchiveReader, Limits, path_from_str};
use sac::v1::{
    ClosureCopy, CompactionBudget, Error, NativeReader, NativeStore, ObjectRef, ObjectStore,
    Result,
    cbor::{self, Value as V},
};
use std::{cell::Cell, time::Duration};

fn bytes(size: usize, seed: &[u8]) -> Vec<u8> {
    let mut data = vec![0; size];
    blake3::Hasher::new()
        .update(seed)
        .finalize_xof()
        .fill(&mut data);
    data
}
fn commit(store: &mut NativeStore, snapshot: ObjectRef) -> Result<ObjectRef> {
    store.put(
        1,
        1,
        &cbor::encode(&V::Array(vec![V::Uint(0), V::Null, V::Null])),
        &[snapshot],
    )
}
fn publish(store: &mut NativeStore, value: &[u8]) {
    let mut builder = ArchiveBuilder::new(store);
    builder
        .add_file(&path_from_str("keep").unwrap(), &bytes(128 * 1024, b"keep"))
        .unwrap();
    builder
        .add_file(
            &path_from_str("discard").unwrap(),
            &bytes(512 * 1024, b"discard"),
        )
        .unwrap();
    builder
        .add_file(&path_from_str("value").unwrap(), value)
        .unwrap();
    let snapshot = builder.finish().unwrap();
    store.publish(snapshot).unwrap();
}
fn project(
    source: &NativeReader,
    target: &mut NativeStore,
    copier: &mut ClosureCopy,
    previous: Option<ObjectRef>,
    cancelled: &dyn Fn() -> bool,
) -> Result<ObjectRef> {
    let snapshot = source.reader().snapshot().unwrap();
    let directory = source.get(snapshot)?.children[0];
    // Exercise the shared copier for a selected immutable source component,
    // without copying its parent directory or any discarded sibling.
    let object = source.get(directory)?;
    let V::Array(rows) = cbor::decode(&object.bytes)? else {
        panic!()
    };
    let mut keep_extent = None;
    for row in rows {
        let V::Array(row) = row else { panic!() };
        if row[0] == V::Bytes(b"keep".to_vec()) {
            let V::Array(storage) = &row[3] else { panic!() };
            let V::Uint(index) = storage[2] else { panic!() };
            keep_extent = Some(object.children[index as usize]);
        }
    }
    let extent =
        copier.copy_root_cancellable(source, target, keep_extent.unwrap(), &|| cancelled())?;
    let input = ArchiveReader::open(source, snapshot, Limits::default())?;
    let value = input
        .read_file_bounded(&path_from_str("value")?, 100)?
        .unwrap()
        .1;
    let mut builder = if let Some(previous) = previous {
        let previous_snapshot = target.get(previous)?.children[0];
        let previous_directory = target.get(previous_snapshot)?.children[0];
        ArchiveBuilder::from_directory(target, previous_directory, Limits::default())
    } else {
        ArchiveBuilder::new(target)
    };
    builder.set_extent_file(&path_from_str("keep")?, 128 * 1024, extent, V::Map(vec![]))?;
    builder.set_file(&path_from_str("value")?, &value, V::Map(vec![]))?;
    let snapshot = builder.finish()?;
    target.set_control_roots(&[])?;
    commit(target, snapshot)
}
fn generous(job: &mut sac::v1::Compaction) {
    job.set_budget(CompactionBudget {
        max_pause: Duration::from_secs(2),
        ..Default::default()
    })
    .unwrap();
}
fn value(store: &impl ObjectStore, snapshot: ObjectRef, path: &str, length: usize) -> Vec<u8> {
    ArchiveReader::open(store, snapshot, Limits::default())
        .unwrap()
        .read_file_bounded(&path_from_str(path).unwrap(), length)
        .unwrap()
        .unwrap()
        .1
}
#[test]
fn projected_compaction_prunes_public_rows_preserves_pins_and_skips_unchanged_source() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = NativeStore::create_live(dir.path().join("db.sac"), [1; 16]).unwrap();
    publish(&mut store, b"initial");
    let old = store.pin().unwrap();
    let old_size = store.file_len();
    let old_root = store.root().unwrap();
    let calls = Cell::new(0);
    let mut projector = |source: &NativeReader,
                         target: &mut NativeStore,
                         copier: &mut ClosureCopy,
                         previous: Option<ObjectRef>,
                         cancelled: &dyn Fn() -> bool| {
        calls.set(calls.get() + 1);
        assert!(previous.is_none());
        project(source, target, copier, previous, cancelled)
    };
    let mut job = store.begin_compaction().unwrap();
    generous(&mut job);
    job.copy_projected_cancellable(&mut projector, || false)
        .unwrap();
    assert_eq!(store.root().unwrap(), old_root);
    let new_pin = store
        .finish_compaction_projected_pinned_cancellable(job, &mut projector, &|| false)
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert!(store.file_len() < old_size / 2);
    store.validate().unwrap();
    let snapshot = new_pin.reader().snapshot().unwrap();
    assert_eq!(value(&new_pin, snapshot, "value", 100), b"initial");
    assert!(
        ArchiveReader::open(&new_pin, snapshot, Limits::default())
            .unwrap()
            .read_file_bounded(&path_from_str("discard").unwrap(), 1_000_000)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        value(
            &old,
            old.reader().snapshot().unwrap(),
            "discard",
            512 * 1024
        ),
        bytes(512 * 1024, b"discard")
    );
}
#[test]
fn projected_catch_up_uses_latest_pin_and_previous_candidate() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = NativeStore::create_live(dir.path().join("db.sac"), [2; 16]).unwrap();
    publish(&mut store, b"initial");
    let calls = Cell::new(0);
    let mut projector = |source: &NativeReader,
                         target: &mut NativeStore,
                         copier: &mut ClosureCopy,
                         previous: Option<ObjectRef>,
                         cancelled: &dyn Fn() -> bool| {
        assert_eq!(previous.is_some(), calls.get() != 0);
        calls.set(calls.get() + 1);
        project(source, target, copier, previous, cancelled)
    };
    let mut job = store.begin_compaction().unwrap();
    generous(&mut job);
    job.copy_projected_cancellable(&mut projector, || false)
        .unwrap();
    publish(&mut store, b"acknowledged during prepare");
    store
        .finish_compaction_projected_pinned_cancellable(job, &mut projector, &|| false)
        .unwrap();
    assert_eq!(calls.get(), 2);
    store.validate().unwrap();
    assert_eq!(
        value(&store, store.reader().snapshot().unwrap(), "value", 100),
        b"acknowledged during prepare"
    );
}
#[test]
fn projected_errors_and_mode_mismatch_do_not_replace_source() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = NativeStore::create_live(dir.path().join("db.sac"), [3; 16]).unwrap();
    publish(&mut store, b"initial");
    let original = store.root().unwrap();
    let mut job = store.begin_compaction().unwrap();
    generous(&mut job);
    let mut bad = |_: &NativeReader,
                   target: &mut NativeStore,
                   _: &mut ClosureCopy,
                   _: Option<ObjectRef>,
                   _: &dyn Fn() -> bool| target.put(7, 1, b"not a Commit", &[]);
    assert!(job.copy_projected_cancellable(&mut bad, || false).is_err());
    drop(job);
    assert_eq!(store.root().unwrap(), original);
    let mut job = store.begin_compaction().unwrap();
    generous(&mut job);
    job.copy_projected_cancellable(&mut project, || false)
        .unwrap();
    assert!(store.finish_compaction(job).is_err());
    assert_eq!(store.root().unwrap(), original);
    let mut job = store.begin_compaction().unwrap();
    generous(&mut job);
    job.copy_projected_cancellable(&mut project, || false)
        .unwrap();
    publish(&mut store, b"new current");
    let latest = store.root().unwrap();
    let mut reject = |_: &NativeReader,
                      _: &mut NativeStore,
                      _: &mut ClosureCopy,
                      _: Option<ObjectRef>,
                      _: &dyn Fn() -> bool| Err(Error::Busy);
    assert!(matches!(
        store.finish_compaction_projected_pinned_cancellable(job, &mut reject, &|| false),
        Err(Error::Busy)
    ));
    assert_eq!(store.root().unwrap(), latest);
    store.validate().unwrap();
}

#[test]
fn selected_root_delta_preserves_shared_dags_and_bounds_destructive_removal() {
    let dir = tempfile::tempdir().unwrap();
    let mut target = NativeStore::create_live(dir.path().join("target.sac"), [4; 16]).unwrap();
    let common = target.put(7, 1, b"common", &[]).unwrap();
    let left = target.put(4096, 1, b"left", &[common]).unwrap();
    let right = target.put(4096, 1, b"right", &[common]).unwrap();
    let mut copy = ClosureCopy::new().unwrap();
    assert!(
        copy.update_retained_roots(&target, &[left, right], &|| false)
            .unwrap()
            .is_empty()
    );
    assert!(
        copy.update_retained_roots(&target, &[right, left], &|| false)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        copy.update_retained_roots(&target, &[right], &|| false)
            .unwrap(),
        vec![left]
    );
    assert_eq!(
        copy.update_retained_roots(&target, &[], &|| false).unwrap(),
        vec![right, common]
    );
    assert!(
        copy.update_retained_roots(&target, &[common; 9], &|| false)
            .is_err()
    );
    let mut chain = common;
    for index in 0u32..513 {
        chain = target.put(4096, 1, &index.to_le_bytes(), &[chain]).unwrap();
    }
    let mut copy = ClosureCopy::new().unwrap();
    copy.update_retained_roots(&target, &[chain], &|| false)
        .unwrap();
    assert!(matches!(
        copy.update_retained_roots(&target, &[], &|| false),
        Err(Error::Limit("selected component removals"))
    ));
    let mut copy = ClosureCopy::new_with_disk_budget(0).unwrap();
    assert!(
        copy.update_retained_roots(&target, &[chain], &|| false)
            .is_err()
    );
}

#[test]
fn projected_validation_rejects_bad_core_edges_and_cancelled_or_over_quota_candidates() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = NativeStore::create_live(dir.path().join("db.sac"), [5; 16]).unwrap();
    publish(&mut store, b"initial");
    let original = store.root().unwrap();
    let mut invalid = |_: &NativeReader,
                       target: &mut NativeStore,
                       _: &mut ClosureCopy,
                       _: Option<ObjectRef>,
                       _: &dyn Fn() -> bool| {
        let wrong_directory = target.put(7, 1, b"bytes are not a directory", &[])?;
        let snapshot = target.put(
            2,
            1,
            &cbor::encode(&V::Array(vec![
                V::Uint(0),
                V::Array(vec![]),
                V::Array(vec![]),
            ])),
            &[wrong_directory],
        )?;
        commit(target, snapshot)
    };
    let mut job = store.begin_compaction().unwrap();
    generous(&mut job);
    assert!(
        job.copy_projected_cancellable(&mut invalid, || false)
            .is_err()
    );
    drop(job);
    assert_eq!(store.root().unwrap(), original);
    let stop = Cell::new(false);
    let mut cancel_after_authored =
        |source: &NativeReader,
         target: &mut NativeStore,
         copier: &mut ClosureCopy,
         previous: Option<ObjectRef>,
         cancelled: &dyn Fn() -> bool| {
            let root = project(source, target, copier, previous, cancelled)?;
            stop.set(true);
            Ok(root)
        };
    let mut job = store.begin_compaction().unwrap();
    generous(&mut job);
    assert!(
        job.copy_projected_cancellable(&mut cancel_after_authored, || stop.get())
            .is_err()
    );
    drop(job);
    assert_eq!(store.root().unwrap(), original);
    let mut job = store.begin_compaction().unwrap();
    let initial = job.candidate_file_bytes().unwrap();
    job.set_budget(CompactionBudget {
        max_temporary_bytes: initial,
        ..Default::default()
    })
    .unwrap();
    assert!(
        job.copy_projected_cancellable(&mut project, || false)
            .is_err()
    );
    drop(job);
    assert_eq!(store.root().unwrap(), original);
    // A projected callback's private control roots survive both preparation and
    // cutover; an unrelated source control root is never copied into candidate.
    let old_control = store.put(7, 1, b"old-only control", &[]).unwrap();
    store.set_control_roots(&[old_control]).unwrap();
    let mut with_control = |source: &NativeReader,
                            target: &mut NativeStore,
                            copier: &mut ClosureCopy,
                            previous: Option<ObjectRef>,
                            cancelled: &dyn Fn() -> bool| {
        let root = project(source, target, copier, previous, cancelled)?;
        let control = target.put(7, 1, b"new candidate control", &[])?;
        target.set_control_roots(&[control])?;
        Ok(root)
    };
    let mut job = store.begin_compaction().unwrap();
    generous(&mut job);
    job.set_layout(sac::v1::CompactionLayout {
        front: vec![old_control.hash],
        bundles: vec![],
    })
    .unwrap();
    job.copy_projected_cancellable(&mut with_control, || false)
        .unwrap();
    store
        .finish_compaction_projected_pinned_cancellable(job, &mut with_control, &|| false)
        .unwrap();
    store.validate().unwrap();
}

#[test]
fn projected_refresh_prepares_large_delta_before_small_final_fence() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = NativeStore::create_live(dir.path().join("db.sac"), [8; 16]).unwrap();
    let snapshot = {
        let mut builder = ArchiveBuilder::new(&mut store);
        builder
            .add_file(&path_from_str("base").unwrap(), &bytes(2 << 20, b"base"))
            .unwrap();
        builder.finish().unwrap()
    };
    store.publish(snapshot).unwrap();
    let old = store.pin().unwrap();
    let calls = Cell::new(0);
    let mut projector = |source: &NativeReader,
                         target: &mut NativeStore,
                         copier: &mut ClosureCopy,
                         _: Option<ObjectRef>,
                         cancelled: &dyn Fn() -> bool| {
        calls.set(calls.get() + 1);
        target.set_control_roots(&[])?;
        copier.copy_root_cancellable(source, target, source.root().unwrap().root, &|| cancelled())
    };
    let mut job = store.begin_compaction().unwrap();
    job.set_budget(CompactionBudget {
        max_catch_up_bytes: 1024,
        max_pause: Duration::from_secs(2),
        ..Default::default()
    })
    .unwrap();
    job.copy_projected_cancellable(&mut projector, || false)
        .unwrap();
    let before = store.file_len();
    let directory = store
        .get(store.reader().snapshot().unwrap())
        .unwrap()
        .children[0];
    let snapshot = {
        let mut builder = ArchiveBuilder::from_directory(&mut store, directory, Limits::default());
        builder
            .add_file(
                &path_from_str("delta").unwrap(),
                &bytes(24 << 20, b"large-delta"),
            )
            .unwrap();
        builder.finish().unwrap()
    };
    store.publish(snapshot).unwrap();
    assert!(store.file_len() - before > 16 << 20);
    let latest = store.pin().unwrap();
    job.refresh_projected_cancellable(&latest, &mut projector, || false)
        .unwrap();
    assert!(job.statistics().copied_bytes > 24 << 20);
    assert_eq!(calls.get(), 2);
    job.refresh_projected_cancellable(&latest, &mut projector, || false)
        .unwrap();
    assert_eq!(
        calls.get(),
        2,
        "unchanged latest pin must not project twice"
    );
    assert!(
        job.refresh_projected_cancellable(&old, &mut projector, || false)
            .is_err(),
        "older source pin must not roll the prepared root back"
    );
    store
        .finish_compaction_projected_pinned_cancellable(job, &mut projector, &|| false)
        .unwrap();
    assert_eq!(
        calls.get(),
        2,
        "unchanged source needs no callback under the final fence"
    );
    assert!(store.last_compaction_statistics().unwrap().catch_up_bytes <= 1024);
    store.validate().unwrap();
    assert_eq!(
        value(
            &store,
            store.reader().snapshot().unwrap(),
            "delta",
            24 << 20
        ),
        bytes(24 << 20, b"large-delta")
    );
    assert!(
        ArchiveReader::open(&old, old.reader().snapshot().unwrap(), Limits::default())
            .unwrap()
            .read_file_bounded(&path_from_str("delta").unwrap(), 24 << 20)
            .unwrap()
            .is_none()
    );
}

#[test]
fn projected_refresh_rejects_wrong_source_and_cancellation_without_source_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = NativeStore::create_live(dir.path().join("db.sac"), [9; 16]).unwrap();
    publish(&mut store, b"initial");
    let mut job = store.begin_compaction().unwrap();
    generous(&mut job);
    job.copy_projected_cancellable(&mut project, || false)
        .unwrap();
    let mut other = NativeStore::create_live(dir.path().join("other.sac"), [9; 16]).unwrap();
    publish(&mut other, b"other");
    assert!(
        job.refresh_projected_cancellable(&other.pin().unwrap(), &mut project, || false)
            .is_err()
    );
    publish(&mut store, b"new current");
    let current = store.root();
    assert!(
        job.refresh_projected_cancellable(&store.pin().unwrap(), &mut project, || true)
            .is_err()
    );
    assert_eq!(store.root(), current);
    store.validate().unwrap();
}
