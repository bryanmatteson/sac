#![cfg(feature = "native")]

use sac::resources::{ArchiveBuilder, ArchiveReader, Limits, copy_snapshot, path_from_str};
use sac::{CanonicalObject, MemoryStore, NativeStore, ObjectStore};

#[test]
fn duplicate_appends_use_exact_provenance_after_cache_eviction_and_spill() {
    for index_budget in [0, 8 * 1024 * 1024] {
        let dir = tempfile::tempdir().unwrap();
        let mut store = NativeStore::create_live(dir.path().join("live.sac"), [1; 16]).unwrap();
        store.set_append_index_memory_budget(index_budget).unwrap();
        store.set_decoded_cache_budget(0);
        let body = vec![42; 16 * 1024];
        let child = store.put(7, 1, &body, &[]).unwrap();
        let end = store.file_len();
        let before = store.physical_statistics();
        for _ in 0..8 {
            assert_eq!(store.put(7, 1, &body, &[]).unwrap(), child);
        }
        assert_eq!(store.file_len(), end);
        assert_eq!(store.physical_statistics(), before);
        assert_eq!(store.get(child).unwrap().bytes, body);
    }
}

#[test]
fn repeated_edges_authenticate_once_per_put_without_a_decoded_cache() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = NativeStore::create_live(dir.path().join("live.sac"), [2; 16]).unwrap();
    let root = ArchiveBuilder::new(&mut store).finish().unwrap();
    store.publish(root).unwrap();
    let first = store.put(7, 1, &[42; 16 * 1024], &[]).unwrap();
    let second = store.put(7, 1, b"other child", &[]).unwrap();
    // Drain pending appends, then exercise inherited authentication with no
    // append provenance, decoded objects or type-cache allowance.
    drop(store.pin().unwrap());
    store.discard_disposable_caches();
    store.set_decoded_cache_budget(0);
    let children = [first, second, first, second, first, first, second];
    let before = store.physical_statistics().read_operations;
    let parent = store.put(4096, 1, b"map", &children).unwrap();
    assert_eq!(store.physical_statistics().read_operations - before, 2);
    assert_eq!(store.get(parent).unwrap().children, children);

    let mut forged = [first; 3];
    forged[0].hash.0[0] ^= 1;
    forged[1].address.length += 8;
    forged[2].address = second.address;
    for bad in forged {
        let end = store.file_len();
        assert!(
            store
                .put(4096, 1, b"invalid", &[first, first, bad, first])
                .is_err()
        );
        assert_eq!(store.file_len(), end);
    }
}

#[test]
fn compression_changes_cover_prepared_frames_and_preserve_live_edit_and_seal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("live.sac");
    let mut store = NativeStore::create_live(&path, [3; 16]).unwrap();
    store.set_encode_threads(2);
    let mut previous_directory = None;
    let mut hashes = Vec::new();
    for (round, level) in [0, -3, 1].into_iter().enumerate() {
        // Prepare at another level to exercise the put_prepared fallback.
        store.set_compression_level(if level == 0 { 1 } else { 0 });
        let bodies = [
            vec![(round * 2) as u8; 8192],
            vec![(round * 2 + 1) as u8; 8192],
        ];
        let prepared = store
            .prepare(7, 1, &[&bodies[0], &bodies[1]])
            .unwrap()
            .unwrap();
        store.set_compression_level(level);
        for (body, prepared) in bodies.iter().zip(prepared) {
            let saved = store.put_prepared(prepared).unwrap();
            let object = CanonicalObject {
                kind: 7,
                version: 1,
                bytes: body.clone(),
                children: vec![],
            };
            assert_eq!(saved.hash, object.hash());
            assert_eq!(
                saved.address.length as usize,
                sac::v1::wire::encode_frame(&object, level).unwrap().len()
            );
            assert_eq!(store.get(saved).unwrap(), object);
        }
        let mut builder = match previous_directory {
            Some(directory) => {
                ArchiveBuilder::from_directory(&mut store, directory, Limits::default())
            }
            None => ArchiveBuilder::new(&mut store),
        };
        for index in 0..96u64 {
            builder
                .set_file(
                    &path_from_str(&format!("records/{index:04}")).unwrap(),
                    &(index + ((round as u64) << 32)).to_le_bytes(),
                    sac::cbor::Value::Map(Vec::new()),
                )
                .unwrap();
        }
        builder
            .set_file(
                &path_from_str("payload").unwrap(),
                &[7; 16384],
                sac::cbor::Value::Map(Vec::new()),
            )
            .unwrap();
        let root = builder.finish().unwrap();
        hashes.push(root.hash);
        let (publication, pin) = store.publish_pinned(root).unwrap();
        assert_eq!(publication.generation, hashes.len() as u64);
        let archive = ArchiveReader::open(&pin, root, Limits::default()).unwrap();
        archive.verify().unwrap();
        previous_directory = Some(archive.directory_root());
        assert_eq!(
            archive
                .read_file_bounded(&path_from_str("records/0042").unwrap(), 8)
                .unwrap()
                .unwrap()
                .1,
            (42u64 + ((round as u64) << 32)).to_le_bytes()
        );
        let mut sealed = MemoryStore::sealed();
        let copied = copy_snapshot(&pin, &mut sealed, root, Limits::default()).unwrap();
        assert_eq!(copied.hash, root.hash);
        sealed.publish(copied).unwrap();
        ArchiveReader::open(&sealed, copied, Limits::default())
            .unwrap()
            .verify()
            .unwrap();
    }
    let expected = hashes.last().copied().unwrap();
    drop(store);
    let reopened = NativeStore::open(&path, false).unwrap();
    reopened.validate().unwrap();
    assert_eq!(reopened.reader().snapshot().unwrap().hash, expected);
}

#[test]
fn append_compression_setting_survives_replacement_compaction() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = NativeStore::create_live(dir.path().join("live.sac"), [4; 16]).unwrap();
    let root = ArchiveBuilder::new(&mut store).finish().unwrap();
    store.publish(root).unwrap();
    let mut compaction = store.begin_compaction().unwrap();
    compaction.copy().unwrap();
    // A live caller can change policy after a candidate has been prepared.
    store.set_compression_level(0);
    store.finish_compaction(compaction).unwrap();
    let object = CanonicalObject {
        kind: 7,
        version: 1,
        bytes: vec![17; 8192],
        children: vec![],
    };
    let saved = store.put(7, 1, &object.bytes, &[]).unwrap();
    assert_eq!(
        saved.address.length as usize,
        sac::v1::wire::encode_frame(&object, 0).unwrap().len()
    );
    assert_eq!(store.get(saved).unwrap(), object);
}

#[test]
fn large_directory_edits_preserve_identity_authentication_pins_and_durability() {
    for level in [0, 1] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("map.sac");
        let mut store = NativeStore::create_live(&path, [5; 16]).unwrap();
        store.set_compression_level(level);
        let mut builder = ArchiveBuilder::new(&mut store);
        for index in 0..128 {
            builder
                .add_file(
                    &path_from_str(&format!("file-{index:04}")).unwrap(),
                    &[71; 512],
                )
                .unwrap();
        }
        // Include a real child edge as well as the large inline page, so
        // authenticated role checks remain exercised with the hash cache hot.
        builder
            .add_file(&path_from_str("payload").unwrap(), &[42; 65536])
            .unwrap();
        let first = builder.finish().unwrap();
        let (_, old_pin) = store.publish_pinned(first).unwrap();
        let old = ArchiveReader::open(&old_pin, first, Limits::default()).unwrap();
        let mut directory = old.directory_root();
        let mut expected = vec![vec![71; 512]; 128];
        for ordinal in 0..160u64 {
            let index = (ordinal as usize * 37) % 128;
            // Cross subtree boundaries and grow/shrink the encoded rows.
            let length = [8, 512, 1536, 0][ordinal as usize % 4];
            expected[index] = vec![ordinal as u8; length];
            let mut builder =
                ArchiveBuilder::from_directory(&mut store, directory, Limits::default());
            builder
                .set_file(
                    &path_from_str(&format!("file-{index:04}")).unwrap(),
                    &expected[index],
                    sac::cbor::Value::Map(Vec::new()),
                )
                .unwrap();
            directory = builder.finish_directory().unwrap();
            let object = store.get(directory).unwrap();
            assert_eq!(directory.hash, object.hash());
            assert!(object.bytes.len() > 4096);
            if !object.children.is_empty() {
                let mut forged = object.children.clone();
                forged[0].hash.0[0] ^= 1;
                let end = store.file_len();
                assert!(
                    store
                        .put(object.kind, object.version, &object.bytes, &forged)
                        .is_err()
                );
                assert_eq!(store.file_len(), end);
            }
        }
        let root = ArchiveBuilder::from_directory(&mut store, directory, Limits::default())
            .finish()
            .unwrap();
        let before = store.publication_statistics();
        store.publish(root).unwrap();
        let after = store.publication_statistics();
        assert_eq!(after.chunk_barriers - before.chunk_barriers, 1);
        assert_eq!(after.slot_syncs - before.slot_syncs, 1);
        assert_eq!(
            old.read_file_bounded(&path_from_str("file-0063").unwrap(), 512)
                .unwrap()
                .unwrap()
                .1,
            [71; 512]
        );
        drop(store);
        let reopened = NativeStore::open(&path, false).unwrap();
        reopened.validate().unwrap();
        assert_eq!(reopened.reader().snapshot().unwrap().hash, root.hash);
        let pin = reopened.pin().unwrap();
        let archive = ArchiveReader::open(&pin, root, Limits::default()).unwrap();
        archive.verify().unwrap();
        for (index, expected) in expected.iter().enumerate() {
            assert_eq!(
                &archive
                    .read_file_bounded(&path_from_str(&format!("file-{index:04}")).unwrap(), 1536)
                    .unwrap()
                    .unwrap()
                    .1,
                expected
            );
        }
        assert_eq!(
            archive
                .read_file_bounded(&path_from_str("payload").unwrap(), 65536)
                .unwrap()
                .unwrap()
                .1,
            [42; 65536]
        );
        let mut sealed = MemoryStore::sealed();
        assert_eq!(
            copy_snapshot(&pin, &mut sealed, root, Limits::default())
                .unwrap()
                .hash,
            root.hash
        );
    }
}

#[test]
fn many_key_edits_bound_leaf_rows_and_keep_publication_failure_semantics() {
    use sac::v1::native::PublicationFault;
    for (case, fault) in [
        None,
        Some(PublicationFault::ChunksBarrier),
        Some(PublicationFault::SlotWrite { bytes: 40 }),
        Some(PublicationFault::SlotSync),
    ]
    .into_iter()
    .enumerate()
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("map.sac");
        let mut store = NativeStore::create_live(&path, [6; 16]).unwrap();
        // Dense bulk/older pages remain legal. Persistent edits split them
        // without reducing the legal inline or metadata size of a row.
        let mut builder = ArchiveBuilder::bulk(&mut store, Limits::default()).unwrap();
        for key in 0..1024 {
            builder
                .add_file(&path_from_str(&format!("key-{key:04}")).unwrap(), &[7; 64])
                .unwrap();
        }
        let first = builder.finish().unwrap();
        let (_, old_pin) = store.publish_pinned(first).unwrap();
        let old = ArchiveReader::open(&old_pin, first, Limits::default()).unwrap();
        let mut directory = old.directory_root();
        assert_eq!(store.get(directory).unwrap().kind, 3);
        if case % 2 == 1 {
            store.set_append_index_memory_budget(0).unwrap();
            store.set_decoded_cache_budget(0);
        }
        let mut expected = std::collections::BTreeMap::new();
        for ordinal in 0..48 {
            let key = (ordinal * 197) % 1024;
            let path = path_from_str(&format!("key-{key:04}")).unwrap();
            let bytes = vec![ordinal as u8; [0, 8, 64, 512, 48 * 1024, 65536][ordinal % 6]];
            let mut builder =
                ArchiveBuilder::from_directory(&mut store, directory, Limits::default());
            builder
                .set_file(&path, &bytes, sac::cbor::Value::Map(Vec::new()))
                .unwrap();
            directory = builder.finish_directory().unwrap();
            expected.insert(path, bytes);
        }
        fn check_pages(store: &NativeStore, reference: sac::ObjectRef) {
            let object = store.get(reference).unwrap();
            assert_eq!(object.hash(), reference.hash);
            if object.kind == 3 {
                assert!(
                    sac::v1::cbor_view::view(&object.bytes)
                        .unwrap()
                        .array()
                        .unwrap()
                        .len()
                        <= 192
                );
            } else {
                assert_eq!(object.kind, 4);
                for child in &object.children {
                    check_pages(store, *child);
                }
            }
        }
        check_pages(&store, directory);
        let branch = store.get(directory).unwrap();
        assert_eq!(branch.kind, 4);
        let mut forged = branch.children.clone();
        forged[0].hash.0[31] ^= 1;
        let end = store.file_len();
        assert!(store.put(4, 1, &branch.bytes, &forged).is_err());
        assert_eq!(store.file_len(), end);
        let next = ArchiveBuilder::from_directory(&mut store, directory, Limits::default())
            .finish()
            .unwrap();
        if let Some(fault) = fault {
            store.inject_publication_fault_once(fault);
            assert!(store.publish(next).is_err());
            assert!(matches!(store.publish(next), Err(sac::Error::Poisoned)));
        } else {
            let before = store.publication_statistics();
            store.publish(next).unwrap();
            let after = store.publication_statistics();
            assert_eq!(after.chunk_barriers - before.chunk_barriers, 1);
            assert_eq!(after.slot_syncs - before.slot_syncs, 1);
        }
        assert_eq!(
            old.read_file_bounded(&path_from_str("key-0000").unwrap(), 64)
                .unwrap()
                .unwrap()
                .1,
            [7; 64]
        );
        drop(store);
        let reopened = NativeStore::open(&path, false).unwrap();
        reopened.validate().unwrap();
        let visible = reopened.reader().snapshot().unwrap();
        let expect_new = fault.is_none() || fault == Some(PublicationFault::SlotSync);
        assert_eq!(
            visible.hash,
            if expect_new { next.hash } else { first.hash }
        );
        let pin = reopened.pin().unwrap();
        let archive = ArchiveReader::open(&pin, visible, Limits::default()).unwrap();
        archive.verify().unwrap();
        if expect_new {
            for key in 0..1024 {
                let path = path_from_str(&format!("key-{key:04}")).unwrap();
                let bytes = expected.get(&path).cloned().unwrap_or_else(|| vec![7; 64]);
                assert_eq!(
                    archive.read_file_bounded(&path, 65536).unwrap().unwrap().1,
                    bytes
                );
            }
        }
    }
}
