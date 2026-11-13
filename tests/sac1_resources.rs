use sac::v1::resources::{
    ArchiveBuilder, ArchiveReader, Limits, Lookup, SparseSegment, path_from_str,
};
use sac::v1::{MemoryStore, ObjectStore, PositionalStore};

fn path(name: &str) -> Vec<Vec<u8>> {
    path_from_str(name).unwrap()
}
fn packed(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut store = MemoryStore::sealed();
    store.set_compression_level(0);
    let mut builder = ArchiveBuilder::new(&mut store);
    for (name, bytes) in files {
        builder.add_file(&path(name), bytes).unwrap();
    }
    let snapshot = builder.finish().unwrap();
    store.publish(snapshot).unwrap();
    store.as_bytes().to_vec()
}

#[test]
fn tiny_sealed_archive_and_verified_absence() {
    let payload = b"a tiny twenty bytes!";
    let bytes = packed(&[("hello.txt", payload)]);
    assert!(bytes.len() - payload.len() <= 768, "{}", bytes.len());
    let store = PositionalStore::open(bytes).unwrap();
    let reader = ArchiveReader::open(
        &store,
        store.reader().snapshot().unwrap(),
        Limits::default(),
    )
    .unwrap();
    assert_eq!(
        reader
            .read_range(&path("hello.txt"), 0, payload.len())
            .unwrap(),
        payload
    );
    assert!(matches!(
        reader.lookup(&path("missing")).unwrap(),
        Lookup::NoMatchUnverified
    ));
    let token = reader.validate_directory(&[]).unwrap();
    assert!(matches!(
        reader.lookup_validated(&token, b"missing").unwrap(),
        Lookup::NotFound
    ));
    let report = reader.verify().unwrap();
    assert_eq!(report.files, 1);
    assert!(report.core_checked);
    assert!(!report.physical_checked);
}

#[test]
fn sealed_export_does_not_reload_childless_objects_for_postorder() {
    struct Counted<'a> {
        source: PositionalStore<&'a [u8]>,
        payload_reads: std::cell::Cell<usize>,
    }
    impl ObjectStore for Counted<'_> {
        fn get(&self, reference: sac::ObjectRef) -> sac::Result<sac::CanonicalObject> {
            let object = self.source.get(reference)?;
            if object.kind == 7 {
                self.payload_reads.set(self.payload_reads.get() + 1);
            }
            Ok(object)
        }
        fn put(
            &mut self,
            _: u16,
            _: u16,
            _: &[u8],
            _: &[sac::ObjectRef],
        ) -> sac::Result<sac::ObjectRef> {
            unreachable!("read-only source");
        }
    }
    let payload = vec![5; 128 << 10];
    let bytes = packed(&[("one-chunk", &payload)]);
    let source = Counted {
        source: PositionalStore::open(bytes.as_slice()).unwrap(),
        payload_reads: std::cell::Cell::new(0),
    };
    let snapshot = source.source.reader().snapshot().unwrap();
    let exported = sac::pack_snapshot(&source, snapshot, Vec::new()).unwrap();
    // One read checks the extent edge. A second authenticated read supplies
    // the bytes to the destination without a third read in postorder.
    assert_eq!(source.payload_reads.get(), 2);
    let store = PositionalStore::open(exported).unwrap();
    let root = store.reader().snapshot().unwrap();
    assert_eq!(root.hash, snapshot.hash);
    let archive = ArchiveReader::open(&store, root, Limits::default()).unwrap();
    assert_eq!(
        archive
            .read_range(&path("one-chunk"), 0, payload.len())
            .unwrap(),
        payload
    );
}

#[cfg(feature = "native")]
#[test]
fn combined_export_enforces_namespace_and_graph_frame_budget() {
    let data = vec![11; 384 << 10];
    let bytes = packed(&[("chunked", &data)]);
    let source = PositionalStore::open(bytes.as_slice()).unwrap();
    let publication = source.reader().publication.unwrap();
    let snapshot = source.reader().snapshot().unwrap();
    let mut rejected_by_verification_only = false;
    let mut accepted = false;
    for max_frames in 8..40 {
        let limits = Limits {
            max_frames,
            ..Limits::default()
        };
        let reader = ArchiveReader::open(&source, snapshot, limits.clone()).unwrap();
        let copy =
            sac::pack_commit_with_limits(&source, publication.root, Vec::new(), limits.clone());
        let combined =
            reader.pack_verified_commit(publication.root, Vec::new(), limits.max_temp_bytes);
        match (reader.verify(), copy, combined) {
            (Ok(_), Ok(expected), Ok(actual)) => {
                assert_eq!(expected, actual);
                accepted = true;
            }
            (
                Err(sac::Error::Limit("frame visits")),
                Ok(_),
                Err(sac::Error::Limit("frame visits")),
            ) => {
                rejected_by_verification_only = true;
            }
            (_, Err(sac::Error::Limit("frame visits")), Err(sac::Error::Limit("frame visits"))) => {
            }
            result => panic!("inconsistent frame budget at {max_frames}: {result:?}"),
        }
    }
    assert!(rejected_by_verification_only);
    assert!(accepted);
}

#[cfg(feature = "native")]
#[test]
fn combined_export_checks_extent_geometry_and_deferred_byte_roles() {
    use sac::cbor::{Value::*, encode};

    for (file_length, extent_length, leaf_kind, expected_error) in [
        (5, 4, 7, "extent root length mismatch"),
        (5, 5, 7, "extent byte length"),
        (4, 4, 10, "core child role kind or schema"),
    ] {
        let mut source = MemoryStore::sealed();
        let leaf = source.put(leaf_kind, 1, b"data", &[]).unwrap();
        let extent = source
            .put(
                5,
                1,
                &encode(&Array(vec![Array(vec![Uint(extent_length), Uint(0)])])),
                &[leaf],
            )
            .unwrap();
        let directory = source
            .put(
                3,
                1,
                &encode(&Array(vec![Array(vec![
                    Bytes(b"file".to_vec()),
                    Uint(0),
                    Map(vec![]),
                    Array(vec![Uint(file_length), Uint(1), Uint(0)]),
                ])])),
                &[extent],
            )
            .unwrap();
        let snapshot =
            sac::v1::resources::snapshot(&mut source, directory, vec![], vec![]).unwrap();
        let commit = source
            .put(
                1,
                1,
                &encode(&Array(vec![Uint(0), Null, Null])),
                &[snapshot],
            )
            .unwrap();
        let limits = Limits::default();
        let reader = ArchiveReader::open(&source, snapshot, limits.clone()).unwrap();
        let mut output = Vec::new();
        assert!(matches!(
            reader.pack_verified_commit(commit, &mut output, limits.max_temp_bytes),
            Err(sac::Error::Corrupt(message)) if message == expected_error
        ));
        assert!(PositionalStore::open(output).is_err());
    }
}

#[test]
fn split_pages_nested_raw_names_cross_chunk_and_sparse_ranges() {
    let mut store = MemoryStore::sealed();
    let mut builder = ArchiveBuilder::new(&mut store);
    builder.set_chunk_size(16384).unwrap();
    for i in 0..24 {
        builder
            .add_file(&path(&format!("dir/{i:04}.bin")), &vec![i as u8; 8192])
            .unwrap();
    }
    let raw = vec![b"dir".to_vec(), vec![0xff, 0xfe]];
    builder.add_file(&raw, b"raw byte name").unwrap();
    let data: Vec<u8> = (0..70000)
        .map(|i| ((i * 31 + i / 256) % 251) as u8)
        .collect();
    builder.add_file(&path("chunked"), &data).unwrap();
    builder
        .add_sparse(
            &path("sparse"),
            vec![
                SparseSegment::Data(b"prefix".to_vec()),
                SparseSegment::Hole(1 << 20),
                SparseSegment::Data(b"tail".to_vec()),
            ],
        )
        .unwrap();
    let root = builder.finish().unwrap();
    store.publish(root).unwrap();
    let opened = PositionalStore::open(store.as_bytes().to_vec()).unwrap();
    let reader = ArchiveReader::open(
        &opened,
        opened.reader().snapshot().unwrap(),
        Limits::default(),
    )
    .unwrap();
    assert_eq!(
        reader.read_range(&path("chunked"), 16380, 64).unwrap(),
        data[16380..16444]
    );
    assert_eq!(
        reader.read_range(&path("sparse"), 4, 8).unwrap(),
        [b'i', b'x', 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(reader.read_range(&raw, 0, 13).unwrap(), b"raw byte name");
    let mut count = 0;
    reader
        .visit_entries(&mut |_| {
            count += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(count, 28);
    assert!(reader.verify().unwrap().core_checked);
}

#[test]
fn persistent_edit_keeps_unchanged_payload_identity() {
    let mut store = MemoryStore::sealed();
    let (root, directory) = {
        let mut builder = ArchiveBuilder::new(&mut store);
        builder.add_file(&path("a"), &vec![11; 10000]).unwrap();
        builder.add_file(&path("b"), b"old").unwrap();
        let directory = builder.directory_root().unwrap();
        (builder.finish().unwrap(), directory)
    };
    let old = ArchiveReader::open(&store, root, Limits::default())
        .unwrap()
        .read_range(&path("a"), 0, 10000)
        .unwrap();
    let mut editor = ArchiveBuilder::from_directory(&mut store, directory, Limits::default());
    editor
        .set_file(&path("b"), b"new", sac::cbor::Value::Map(Vec::new()))
        .unwrap();
    let next = editor.finish().unwrap();
    let reader = ArchiveReader::open(&store, next, Limits::default()).unwrap();
    assert_eq!(reader.read_range(&path("a"), 0, 10000).unwrap(), old);
    assert_eq!(reader.read_range(&path("b"), 0, 3).unwrap(), b"new");
}

#[test]
fn persistent_deletion_collapses_branches_and_preserves_siblings() {
    let mut store = MemoryStore::sealed();
    let mut builder = ArchiveBuilder::new(&mut store);
    for i in 0..24 {
        builder
            .add_file(&path(&format!("d/{i:04}")), &vec![i as u8; 8192])
            .unwrap();
    }
    for i in 0..23 {
        builder.remove_file(&path(&format!("d/{i:04}"))).unwrap();
    }
    let snapshot = builder.finish().unwrap();
    let reader = ArchiveReader::open(&store, snapshot, Limits::default()).unwrap();
    assert_eq!(
        reader.read_range(&path("d/0023"), 0, 8192).unwrap(),
        vec![23; 8192]
    );
    assert_eq!(reader.list().unwrap().len(), 2);
    reader.verify().unwrap();
}

#[test]
fn sparse_logical_limits_and_shared_directory_expansion_are_charged() {
    let mut store = MemoryStore::sealed();
    let limits = Limits {
        max_file_bytes: 100,
        ..Default::default()
    };
    let mut builder = ArchiveBuilder::with_limits(&mut store, limits);
    assert!(
        builder
            .add_sparse(&path("bomb"), vec![SparseSegment::Hole(101)])
            .is_err()
    );
    let mut child = store.put(3, 1, &[0x80], &[]).unwrap();
    for _ in 0..10 {
        use sac::cbor::Value as V;
        let row = |name: &[u8]| {
            V::Array(vec![
                V::Bytes(name.to_vec()),
                V::Uint(1),
                V::Map(Vec::new()),
                V::Uint(0),
            ])
        };
        let body = sac::cbor::encode(&V::Array(vec![row(b"a"), row(b"b")]));
        child = store.put(3, 1, &body, &[child]).unwrap();
    }
    let root = sac::v1::resources::snapshot(&mut store, child, Vec::new(), Vec::new()).unwrap();
    let limits = Limits {
        max_entries: 100,
        ..Default::default()
    };
    let reader = ArchiveReader::open(&store, root, limits).unwrap();
    assert!(reader.visit_entries(&mut |_| Ok(())).is_err());
}

#[test]
fn malformed_off_path_index_cannot_prove_absence() {
    use sac::cbor::{Value as V, encode};
    let mut store = MemoryStore::sealed();
    let entry = |name: &[u8]| {
        V::Array(vec![
            V::Bytes(name.to_vec()),
            V::Uint(0),
            V::Map(Vec::new()),
            V::Array(vec![V::Uint(0), V::Uint(0), V::Bytes(Vec::new())]),
        ])
    };
    let hidden = store
        .put(3, 1, &encode(&V::Array(vec![entry(b"z")])), &[])
        .unwrap();
    let normal = store
        .put(
            3,
            1,
            &encode(&V::Array(vec![entry(b"b"), entry(b"c")])),
            &[],
        )
        .unwrap();
    let branch = V::Array(vec![
        V::Uint(1),
        V::Array(vec![
            V::Array(vec![V::Bytes(b"a".to_vec()), V::Uint(0)]),
            V::Array(vec![V::Bytes(b"c".to_vec()), V::Uint(1)]),
        ]),
    ]);
    let directory = store
        .put(4, 1, &encode(&branch), &[hidden, normal])
        .unwrap();
    let snapshot =
        sac::v1::resources::snapshot(&mut store, directory, Vec::new(), Vec::new()).unwrap();
    let reader = ArchiveReader::open(&store, snapshot, Limits::default()).unwrap();
    assert!(matches!(
        reader.lookup(&path("z")).unwrap(),
        Lookup::NoMatchUnverified
    ));
    assert!(reader.validate_directory(&[]).is_err());
    assert!(reader.verify().is_err());
}

#[cfg(all(feature = "native", unix))]
#[test]
fn extraction_maps_unsafe_names_preserves_report_and_never_clobbers() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = packed(&[
        ("hello.txt", b"hello"),
        ("A", b"upper"),
        ("a", b"lower"),
        ("report.cbor", b"archive file"),
    ]);
    let store = PositionalStore::open(bytes).unwrap();
    let reader = ArchiveReader::open(
        &store,
        store.reader().snapshot().unwrap(),
        Limits::default(),
    )
    .unwrap();
    let destination = dir.path().join("output");
    let report = reader.extract(&destination).unwrap();
    assert_eq!(report.files, 4);
    assert_eq!(
        std::fs::read(destination.join("content/hello.txt")).unwrap(),
        b"hello"
    );
    assert_eq!(
        std::fs::read(destination.join("content/report.cbor")).unwrap(),
        b"archive file"
    );
    assert!(destination.join("report.cbor").is_file());
    assert!(reader.extract(&destination).is_err());
    assert_eq!(
        std::fs::read(destination.join("content/a")).unwrap(),
        b"lower"
    );
}

#[cfg(all(feature = "native", unix))]
#[test]
fn tree_extraction_restores_names_or_refuses_what_the_host_cannot_hold() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = packed(&[
        ("Read Me.TXT", b"mixed case and a space"),
        ("nested/Deep File", b"nested"),
        ("report.cbor", b"archive file"),
    ]);
    let store = PositionalStore::open(bytes).unwrap();
    let reader = ArchiveReader::open(
        &store,
        store.reader().snapshot().unwrap(),
        Limits::default(),
    )
    .unwrap();
    let destination = dir.path().join("tree");
    let report = reader.extract_tree(&destination).unwrap();
    assert_eq!((report.files, report.mapped_entries), (3, 0));
    assert_eq!(
        std::fs::read(destination.join("Read Me.TXT")).unwrap(),
        b"mixed case and a space"
    );
    assert_eq!(
        std::fs::read(destination.join("nested/Deep File")).unwrap(),
        b"nested"
    );
    assert_eq!(
        std::fs::read(destination.join("report.cbor")).unwrap(),
        b"archive file"
    );
    assert!(reader.extract_tree(&destination).is_err());
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(leftovers, ["tree"]);

    // Two names that differ only by case are one name on some filesystems.
    // The tree is then refused whole; it is never silently merged or renamed.
    let bytes = packed(&[("A", b"upper"), ("a", b"lower")]);
    let store = PositionalStore::open(bytes).unwrap();
    let reader = ArchiveReader::open(
        &store,
        store.reader().snapshot().unwrap(),
        Limits::default(),
    )
    .unwrap();
    let destination = dir.path().join("case");
    match reader.extract_tree(&destination) {
        Ok(_) => {
            assert_eq!(std::fs::read(destination.join("A")).unwrap(), b"upper");
            assert_eq!(std::fs::read(destination.join("a")).unwrap(), b"lower");
        }
        Err(error) => {
            assert!(matches!(error, sac::v1::Error::Unsupported(_)), "{error}");
            assert!(!destination.exists());
        }
    }
}

#[cfg(all(feature = "native", unix))]
#[test]
fn extraction_checks_expanded_entry_limits_before_touching_the_filesystem() {
    use sac::v1::cbor::{Value, encode};
    // Each level names the level below twice, so 20 small pages expand to
    // more than a million entries.
    let mut store = MemoryStore::sealed();
    let file = Value::Array(vec![
        Value::Bytes(b"f".to_vec()),
        Value::Uint(0),
        Value::Map(vec![]),
        Value::Array(vec![
            Value::Uint(1),
            Value::Uint(0),
            Value::Bytes(b"x".to_vec()),
        ]),
    ]);
    let mut directory = store
        .put(3, 1, &encode(&Value::Array(vec![file])), &[])
        .unwrap();
    for _ in 0..20 {
        let child = |name: &[u8]| {
            Value::Array(vec![
                Value::Bytes(name.to_vec()),
                Value::Uint(1),
                Value::Map(vec![]),
                Value::Uint(0),
            ])
        };
        directory = store
            .put(
                3,
                1,
                &encode(&Value::Array(vec![child(b"a"), child(b"b")])),
                &[directory],
            )
            .unwrap();
    }
    let snapshot = sac::v1::resources::snapshot(&mut store, directory, vec![], vec![]).unwrap();
    store.publish(snapshot).unwrap();
    let store = PositionalStore::open(store.as_bytes().to_vec()).unwrap();
    let reader = ArchiveReader::open(
        &store,
        store.reader().snapshot().unwrap(),
        Limits {
            max_entries: 10_000,
            ..Limits::default()
        },
    )
    .unwrap();
    // The destination's parent does not exist. Reaching the filesystem first
    // would report that instead of the exhausted entry limit.
    let dir = tempfile::tempdir().unwrap();
    for destination in [
        dir.path().join("missing/contained"),
        dir.path().join("missing/tree"),
    ] {
        let contained = destination.ends_with("contained");
        let error = if contained {
            reader.extract(&destination)
        } else {
            reader.extract_tree(&destination)
        }
        .unwrap_err();
        assert!(matches!(error, sac::v1::Error::Limit(_)), "{error}");
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[cfg(feature = "native")]
#[test]
fn salvage_rebuilds_damaged_locators_and_requires_root_authority() {
    use sac::v1::{ObjectHash, ReadAt};
    let mut bytes = packed(&[("a", &vec![37; 65536]), ("b", b"small")]);
    let original = PositionalStore::open(bytes.clone()).unwrap();
    let expected = original.reader().snapshot().unwrap().hash;
    let directory = ArchiveReader::open(
        &original,
        original.reader().snapshot().unwrap(),
        Limits::default(),
    )
    .unwrap()
    .directory_root();
    let at = directory.address.offset as usize;
    let stored = u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap()) as usize;
    // Locator hints are outside canonical identity; overwrite the first one.
    bytes[at + 56 + stored..at + 56 + stored + 12].fill(0xff);
    assert!(
        PositionalStore::open(bytes.clone())
            .and_then(|store| ArchiveReader::open(
                &store,
                store.reader().snapshot().unwrap(),
                Limits::default()
            )?
            .verify())
            .is_err()
    );
    let mut recovered = MemoryStore::sealed();
    let report =
        sac::v1::resources::salvage(&bytes, None, &mut recovered, Limits::default()).unwrap();
    assert_eq!(report.snapshot_id, expected);
    assert!(!report.attachments_preserved);
    assert_eq!(
        ArchiveReader::open(&recovered, report.snapshot, Limits::default())
            .unwrap()
            .read_range(&path("a"), 19990, 10)
            .unwrap(),
        vec![37; 10]
    );
    // Removing publication authority never promotes an encountered orphan.
    let length = ReadAt::len(&bytes).unwrap();
    bytes.truncate(length as usize - 160);
    assert!(
        sac::v1::resources::salvage(&bytes, None, &mut MemoryStore::sealed(), Limits::default())
            .is_err()
    );
    let selected = sac::v1::resources::salvage(
        &bytes,
        Some(expected),
        &mut MemoryStore::sealed(),
        Limits::default(),
    )
    .unwrap();
    assert_eq!(selected.snapshot_id, expected);
    assert!(
        sac::v1::resources::salvage(
            &bytes,
            Some(ObjectHash([0; 32])),
            &mut MemoryStore::sealed(),
            Limits::default()
        )
        .is_err()
    );
}

#[cfg(feature = "native")]
#[test]
fn salvage_limits_fail_before_oversized_work() {
    let bytes = packed(&[("a", b"payload")]);
    let store = PositionalStore::open(bytes.clone()).unwrap();
    let expected = store.reader().snapshot().unwrap().hash;
    let limits = Limits {
        max_decoded_bytes: 0,
        ..Default::default()
    };
    assert!(matches!(
        sac::v1::resources::salvage(&bytes, Some(expected), &mut MemoryStore::sealed(), limits),
        Err(sac::v1::Error::Limit(_))
    ));
    let limits = Limits {
        max_temp_bytes: 0,
        ..Default::default()
    };
    assert!(matches!(
        sac::v1::resources::salvage(&bytes, Some(expected), &mut MemoryStore::sealed(), limits),
        Err(sac::v1::Error::Limit(_))
    ));
}

#[cfg(feature = "native")]
#[test]
fn salvage_spills_long_profile_history_without_namespace_depth_limit() {
    use sac::cbor::{Value as V, encode};
    use sac::v1::resources::{Profile, snapshot};
    let mut source = MemoryStore::sealed();
    let mut previous = None;
    for n in 0..1001u64 {
        let body = encode(&V::Array(vec![
            V::Text("test.history".into()),
            V::Text("node".into()),
            V::Uint(1),
            V::Bytes(encode(&V::Uint(n))),
        ]));
        let children = previous.into_iter().collect::<Vec<_>>();
        previous = Some(source.put(8, 1, &body, &children).unwrap());
    }
    let body = encode(&V::Array(vec![
        V::Text("test.history".into()),
        V::Text("root".into()),
        V::Uint(1),
        V::Bytes(encode(&V::Uint(0))),
    ]));
    let profile = source.put(8, 1, &body, &[previous.unwrap()]).unwrap();
    let directory = source.put(3, 1, &[0x80], &[]).unwrap();
    let root = snapshot(
        &mut source,
        directory,
        vec![Profile {
            id: "test.history".into(),
            version: 1,
            root: profile,
        }],
        vec![],
    )
    .unwrap();
    source.publish(root).unwrap();
    let limits = Limits {
        max_depth: 4,
        ..Default::default()
    };
    let mut destination = MemoryStore::sealed();
    let recovered = sac::v1::resources::salvage(
        &source.as_bytes().to_vec(),
        None,
        &mut destination,
        limits.clone(),
    )
    .unwrap();
    assert_eq!(recovered.snapshot.hash, root.hash);
    let reader = ArchiveReader::open(&destination, recovered.snapshot, limits).unwrap();
    assert!(reader.verify().unwrap().core_checked);
}
