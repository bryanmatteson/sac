#![cfg(feature = "native")]
use sac::v1::resources::{ArchiveBuilder, ArchiveReader, Limits, path_from_str};
use sac::v1::{CanonicalObject, MemoryStore, ObjectRef, ObjectStore, Result};

#[derive(Default)]
struct Counts {
    leaf: u64,
    branch: u64,
}
struct Counted {
    inner: MemoryStore,
    counts: Counts,
    reads: std::cell::Cell<u64>,
}
impl ObjectStore for Counted {
    fn get(&self, r: ObjectRef) -> Result<CanonicalObject> {
        self.reads.set(self.reads.get() + 1);
        self.inner.get(r)
    }
    fn put(
        &mut self,
        kind: u16,
        version: u16,
        bytes: &[u8],
        children: &[ObjectRef],
    ) -> Result<ObjectRef> {
        if kind == 3 {
            self.counts.leaf += 1;
        }
        if kind == 4 {
            self.counts.branch += 1;
        }
        self.inner.put(kind, version, bytes, children)
    }
}
fn build(reverse: bool) -> (Counted, ObjectRef) {
    let mut store = Counted {
        inner: MemoryStore::sealed(),
        counts: Counts::default(),
        reads: std::cell::Cell::new(0),
    };
    let limits = Limits {
        max_memory_bytes: 2 << 20,
        max_temp_bytes: 16 << 20,
        ..Default::default()
    };
    let mut builder = ArchiveBuilder::bulk(&mut store, limits).unwrap();
    let mut keys: Vec<_> = (0..1536).collect();
    if reverse {
        keys.reverse();
    }
    for i in keys {
        let path = path_from_str(&format!("d{}/{i:06}", i % 4)).unwrap();
        let bytes = vec![(i % 251) as u8; 1000];
        builder.add_file(&path, &bytes).unwrap();
    }
    let (root, statistics) = builder.finish_with_statistics().unwrap();
    assert!(statistics.temporary_peak_bytes > 1_536_000);
    assert!(statistics.temporary_peak_bytes <= 16 << 20);
    assert!(statistics.temporary_read_bytes >= 1_536_000);
    assert!(statistics.temporary_write_bytes >= statistics.temporary_read_bytes);
    (store, root)
}
#[test]
fn external_bulk_sort_is_deterministic_and_writes_pages_once() {
    let (store, root) = build(true);
    let (other, other_root) = build(false);
    assert_eq!(root.hash, other_root.hash);
    assert!(store.counts.leaf < 40, "{}", store.counts.leaf);
    assert!(store.counts.branch < 12, "{}", store.counts.branch);
    let reader = ArchiveReader::open(&store, root, Limits::default()).unwrap();
    assert_eq!(reader.list().unwrap().len(), 1540);
    let before = store.reads.get();
    reader.verify().unwrap();
    assert!(
        store.reads.get() - before < 128,
        "full verification rerouted every file: {} object reads",
        store.reads.get() - before
    );
    for i in [0, 767, 1535] {
        let path = path_from_str(&format!("d{}/{i:06}", i % 4)).unwrap();
        assert_eq!(
            reader.read_range(&path, 0, 1000).unwrap(),
            vec![(i % 251) as u8; 1000]
        );
    }
    assert_eq!(store.counts.leaf, other.counts.leaf);
}

#[test]
fn profile_roots_match_declared_namespace_type_and_version() {
    use sac::v1::cbor::{Value as V, encode};
    use sac::v1::resources::{Profile, snapshot};
    for (namespace, kind, version, valid) in [
        ("example.profile", "root", 1, true),
        ("wrong.profile", "root", 1, false),
        ("example.profile", "other", 1, false),
        ("example.profile", "root", 2, false),
    ] {
        let mut store = MemoryStore::sealed();
        let directory = store.put(3, 1, &[0x80], &[]).unwrap();
        let body = V::Array(vec![
            V::Text(namespace.into()),
            V::Text(kind.into()),
            V::Uint(version),
            V::Bytes(Vec::new()),
        ]);
        let root = store.put(8, 1, &encode(&body), &[]).unwrap();
        let root = snapshot(
            &mut store,
            directory,
            vec![Profile {
                id: "example.profile".into(),
                version: 1,
                root,
            }],
            Vec::new(),
        )
        .unwrap();
        let result = ArchiveReader::open(&store, root, Limits::default())
            .unwrap()
            .verify();
        assert_eq!(result.is_ok(), valid, "{namespace}/{kind}/{version}");
        if let Ok(report) = result {
            assert!(report.core_checked);
            assert!(!report.profile_checked);
        }
    }
}

#[test]
fn commit_verification_includes_optional_children_and_snapshot_binding() {
    use sac::v1::cbor::{Value as V, encode};
    let mut store = MemoryStore::sealed();
    let mut builder = ArchiveBuilder::new(&mut store);
    builder
        .add_file(&path_from_str("a").unwrap(), b"retained")
        .unwrap();
    let snapshot = builder.finish().unwrap();
    let bytes = store.put(7, 1, b"wrong optional child", &[]).unwrap();
    let invalid = store
        .put(
            1,
            1,
            &encode(&V::Array(vec![V::Uint(0), V::Uint(1), V::Null])),
            &[snapshot, bytes],
        )
        .unwrap();
    let valid = store
        .put(
            1,
            1,
            &encode(&V::Array(vec![V::Uint(0), V::Null, V::Null])),
            &[snapshot],
        )
        .unwrap();
    let reader = ArchiveReader::open(&store, snapshot, Limits::default()).unwrap();
    reader.verify().unwrap();
    assert!(reader.verify_commit(invalid).is_err());
    reader.verify_commit(valid).unwrap();
    assert!(reader.verify_commit(bytes).is_err());
    let mut destination = MemoryStore::sealed();
    let mut copier = sac::v1::native::ClosureCopy::new().unwrap();
    assert!(copier.copy_root(&store, &mut destination, invalid).is_err());
    copier.copy_root(&store, &mut destination, valid).unwrap();
}

#[test]
fn closure_copy_reads_large_byte_leaves_once_and_reuses_completed_occurrences() {
    let mut source = Counted {
        inner: MemoryStore::sealed(),
        counts: Counts::default(),
        reads: std::cell::Cell::new(0),
    };
    let children = (0u64..128)
        .map(|ordinal| {
            let mut bytes = vec![0x5a; 32 * 1024];
            bytes[..8].copy_from_slice(&ordinal.to_le_bytes());
            source.put(7, 1, &bytes, &[]).unwrap()
        })
        .collect::<Vec<_>>();
    let root = source
        .put(65000, 1, b"opaque strong edges", &children)
        .unwrap();
    source.reads.set(0);
    let mut target = Counted {
        inner: MemoryStore::sealed(),
        counts: Counts::default(),
        reads: std::cell::Cell::new(0),
    };
    let mut copier = sac::v1::native::ClosureCopy::new().unwrap();
    let copied = copier.copy_root(&source, &mut target, root).unwrap();
    assert_eq!(copied.hash, root.hash);
    assert_eq!(source.reads.get(), 128 + 2);
    for (ordinal, child) in target.get(copied).unwrap().children.iter().enumerate() {
        let bytes = target.get(*child).unwrap().bytes;
        assert_eq!(bytes.len(), 32 * 1024);
        assert_eq!(
            u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            ordinal as u64
        );
    }
    source.reads.set(0);
    assert_eq!(
        copier.copy_root(&source, &mut target, root).unwrap(),
        copied
    );
    assert_eq!(source.reads.get(), 0);

    target.reads.set(0);
    assert!(
        copier
            .update_retained_roots(&target, &[copied], &|| false)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        target.reads.get(),
        1,
        "only the parent has outgoing retention edges"
    );
    target.reads.set(0);
    assert!(
        copier
            .update_retained_roots(&target, &[copied], &|| false)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        target.reads.get(),
        0,
        "unchanged retained roots need no payload reads"
    );

    // A cancellation after copying some children must discard pending ancestor
    // frames before another selected root uses the same bounded copier.
    let mut cancelled_target = MemoryStore::sealed();
    let mut cancelled_copy = sac::v1::native::ClosureCopy::new().unwrap();
    assert!(
        cancelled_copy
            .copy_root_cancellable(&source, &mut cancelled_target, root, &|| source.reads.get()
                >= 8,)
            .is_err()
    );
    source.reads.set(0);
    let last = *children.last().unwrap();
    let copied_last = cancelled_copy
        .copy_root(&source, &mut cancelled_target, last)
        .unwrap();
    assert_eq!(copied_last.hash, last.hash);
    assert_eq!(
        source.reads.get(),
        1,
        "cancelled ancestors must not resume during another root copy"
    );
}
#[test]
fn bulk_namespace_conflicts_fail_before_publication() {
    for conflict in ["a", "a/child"] {
        let mut store = MemoryStore::sealed();
        let mut builder = ArchiveBuilder::bulk(&mut store, Limits::default()).unwrap();
        builder
            .add_file(&path_from_str("a").unwrap(), b"first")
            .unwrap();
        builder
            .add_file(&path_from_str(conflict).unwrap(), b"second")
            .unwrap();
        assert!(builder.finish().is_err());
        assert!(store.root().is_none());
    }
    let mut store = MemoryStore::sealed();
    let mut builder = ArchiveBuilder::bulk(&mut store, Limits::default()).unwrap();
    builder.add_directory(&path_from_str("a").unwrap()).unwrap();
    builder
        .add_file(&path_from_str("a/child").unwrap(), b"content")
        .unwrap();
    let root = builder.finish().unwrap();
    assert_eq!(
        ArchiveReader::open(&store, root, Limits::default())
            .unwrap()
            .list()
            .unwrap()
            .len(),
        2
    );
}
#[test]
fn bulk_temporary_and_frontier_limits_are_real() {
    let mut store = MemoryStore::sealed();
    let limits = Limits {
        max_temp_bytes: 0,
        ..Default::default()
    };
    let mut builder = ArchiveBuilder::bulk(&mut store, limits).unwrap();
    builder
        .add_file(&path_from_str("a").unwrap(), b"content")
        .unwrap();
    assert!(matches!(builder.finish(), Err(sac::v1::Error::Limit(_))));
    assert!(store.root().is_none());
}
#[test]
fn bulk_prefix_probe_preserves_fixed_chunk_geometry() {
    let data: Vec<_> = (0..70000).map(|i| (i % 251) as u8).collect();
    let mut store = MemoryStore::sealed();
    let mut builder = ArchiveBuilder::bulk(&mut store, Limits::default()).unwrap();
    builder.set_chunk_size(16384).unwrap();
    builder
        .add_reader(&path_from_str("a").unwrap(), std::io::Cursor::new(&data))
        .unwrap();
    let root = builder.finish().unwrap();
    let reader = ArchiveReader::open(&store, root, Limits::default()).unwrap();
    assert_eq!(
        reader
            .read_range(&path_from_str("a").unwrap(), 16380, 64)
            .unwrap(),
        data[16380..16444]
    );
    reader.verify().unwrap();
}

#[test]
fn generic_inline_boundaries_and_profile_page_target_round_trip() {
    for bulk in [false, true] {
        let mut store = MemoryStore::sealed();
        let mut builder = if bulk {
            ArchiveBuilder::bulk(&mut store, Limits::default()).unwrap()
        } else {
            ArchiveBuilder::new(&mut store)
        };
        for size in [8192, 8193, 16384, 16385, 32768, 49152, 49153, 65536] {
            builder
                .add_file(
                    &path_from_str(&format!("file{size}")).unwrap(),
                    &vec![0x71; size],
                )
                .unwrap();
        }
        let root = builder.finish().unwrap();
        let reader = ArchiveReader::open(&store, root, Limits::default()).unwrap();
        reader.verify().unwrap();
        for size in [8192, 8193, 16384, 16385, 32768, 49152, 49153, 65536] {
            assert_eq!(
                reader
                    .read_range(&path_from_str(&format!("file{size}")).unwrap(), 0, size)
                    .unwrap(),
                vec![0x71; size]
            );
        }
    }
    let mut store = MemoryStore::sealed();
    let mut builder = ArchiveBuilder::new(&mut store);
    builder.set_page_limit(16 * 1024).unwrap();
    for ordinal in 0..64 {
        builder
            .add_file(
                &path_from_str(&format!("f{ordinal:03}")).unwrap(),
                &vec![ordinal as u8; 8193],
            )
            .unwrap();
    }
    let root = builder.finish().unwrap();
    let mut stack = vec![root];
    while let Some(reference) = stack.pop() {
        let object = store.get(reference).unwrap();
        if matches!(object.kind, 3 | 4) {
            assert!(object.canonical_len() <= 16 * 1024);
        }
        stack.extend(object.children);
    }
    ArchiveReader::open(&store, root, Limits::default())
        .unwrap()
        .verify()
        .unwrap();
}

#[test]
fn metadata_prevents_inline_placement_and_uses_bounded_extents() {
    use sac::v1::cbor::{MapEntry, Value, encode};
    let mut store = MemoryStore::sealed();
    let mut payload = vec![0; 8192];
    blake3::Hasher::new().finalize_xof().fill(&mut payload);
    let mut metadata_payload = vec![0; 12 * 1024];
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sac1-metadata-outside-inline-v1");
    hasher.finalize_xof().fill(&mut metadata_payload);
    let key = Value::Text("example.large".into());
    let metadata = Value::Map(vec![MapEntry {
        key_bytes: encode(&key),
        key,
        value: Value::Bytes(metadata_payload),
    }]);
    let snapshot = {
        let mut builder = ArchiveBuilder::new(&mut store);
        builder.set_page_limit(16 * 1024).unwrap();
        builder
            .add_file_with_metadata(&path_from_str("added").unwrap(), &payload, metadata.clone())
            .unwrap();
        builder
            .set_file(
                &path_from_str("edited").unwrap(),
                &payload,
                metadata.clone(),
            )
            .unwrap();
        builder.finish().unwrap()
    };
    let directory = store.get(snapshot).unwrap().children[0];
    let mut stack = vec![directory];
    let mut extent_entries = 0;
    while let Some(reference) = stack.pop() {
        let object = store.get(reference).unwrap();
        if matches!(object.kind, 3 | 4) {
            assert!(object.canonical_len() <= 16 * 1024);
            if object.kind == 3 {
                let Value::Array(entries) = sac::v1::cbor::decode(&object.bytes).unwrap() else {
                    panic!()
                };
                for row in entries {
                    let Value::Array(fields) = row else { panic!() };
                    let Value::Array(file) = &fields[3] else {
                        panic!()
                    };
                    assert_eq!(
                        file[1],
                        Value::Uint(1),
                        "metadata must force extent placement"
                    );
                    extent_entries += 1;
                }
            }
            stack.extend(object.children);
        }
    }
    assert_eq!(extent_entries, 2);
    store.publish(snapshot).unwrap();
    let reader = store.reader().unwrap();
    let archive =
        ArchiveReader::open(&store, reader.snapshot().unwrap(), Limits::default()).unwrap();
    archive
        .verify_commit(reader.publication.unwrap().root)
        .unwrap();
    for name in ["added", "edited"] {
        let (entry, actual) = archive
            .read_file_bounded(&path_from_str(name).unwrap(), payload.len())
            .unwrap()
            .unwrap();
        assert_eq!(entry.metadata, metadata);
        assert_eq!(actual, payload);
    }
    if let Some(directory) = std::env::var_os("SAC1_METADATA_FIXTURE_DIR") {
        let directory = std::path::Path::new(&directory);
        std::fs::create_dir_all(directory).unwrap();
        std::fs::write(directory.join("metadata.sac"), store.as_bytes()).unwrap();
        std::fs::write(directory.join("metadata.expected.bin"), &payload).unwrap();
        std::fs::write(directory.join("metadata-fixture.json"), serde_json::to_vec_pretty(&serde_json::json!({"case":"metadata-outside-inline","writer_page_bytes":16384,"inline_payload_cap_bytes":8192,"files":2,"payload_bytes_per_file":payload.len(),"fixed_metadata_cbor_bytes_per_file":encode(&metadata).len(),"metadata_cbor_hex":hex::encode(encode(&metadata)),"storage":"extents","packed_bytes":store.as_bytes().len(),"snapshot":reader.snapshot().unwrap().hash.to_string()})).unwrap()).unwrap();
    }
}
