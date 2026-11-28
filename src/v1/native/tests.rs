use super::*;
fn store() -> (tempfile::TempDir, NativeStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = NativeStore::create_live(dir.path().join("db.sac"), [2; 16]).unwrap();
    (dir, store)
}
fn snapshot(store: &mut impl ObjectStore, text: &[u8]) -> ObjectRef {
    let bytes = store.put(7, 1, text, &[]).unwrap();
    let extent = store
        .put(
            5,
            1,
            &cbor::encode(&cbor::Value::Array(vec![cbor::Value::Array(vec![
                cbor::Value::Uint(text.len() as u64),
                cbor::Value::Uint(0),
            ])])),
            &[bytes],
        )
        .unwrap();
    let row = cbor::Value::Array(vec![
        cbor::Value::Bytes(b"file".to_vec()),
        cbor::Value::Uint(0),
        cbor::Value::Map(Vec::new()),
        cbor::Value::Array(vec![
            cbor::Value::Uint(text.len() as u64),
            cbor::Value::Uint(1),
            cbor::Value::Uint(0),
        ]),
    ]);
    let directory = store
        .put(
            3,
            1,
            &cbor::encode(&cbor::Value::Array(vec![row])),
            &[extent],
        )
        .unwrap();
    store
        .put(
            2,
            1,
            &cbor::encode(&cbor::Value::Array(vec![
                cbor::Value::Uint(0),
                cbor::Value::Array(Vec::new()),
                cbor::Value::Array(Vec::new()),
            ])),
            &[directory],
        )
        .unwrap()
}
#[test]
fn save_has_two_barriers_and_durable_noop_has_none() {
    let (_dir, mut store) = store();
    let s = snapshot(&mut store, b"first");
    let p = store.publish(s).unwrap();
    let before = store.publication_statistics();
    assert_eq!(before.chunk_barriers, 1);
    assert_eq!(before.slot_syncs, 1);
    assert_eq!(store.publish(s).unwrap(), p);
    assert_eq!(store.publication_statistics(), before);
    store.validate().unwrap();
}

#[cfg(windows)]
#[test]
fn windows_publication_fences_case_and_hard_link_aliases_without_blocking_readers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sac");
    let alternate_case = dir.path().join("DB.SAC");
    let hard_link = dir.path().join("alias.sac");
    let mut writer = NativeStore::create_live(&path, [2; 16]).unwrap();
    assert!(!path.exists());
    assert!(matches!(
        NativeStore::create_live(&alternate_case, [3; 16]),
        Err(Error::Busy)
    ));

    let snapshot = snapshot(&mut writer, b"first publication");
    let publication = writer.publish(snapshot).unwrap();
    std::fs::hard_link(&path, &hard_link).unwrap();
    assert!(matches!(
        NativeStore::open(&hard_link, true),
        Err(Error::Busy)
    ));
    let pin = NativeReader::open(&hard_link).unwrap();
    assert_eq!(pin.root(), Some(publication));
    assert_eq!(pin.get(snapshot).unwrap(), writer.get(snapshot).unwrap());

    drop(writer);
    let mut writer = NativeStore::open(&hard_link, true).unwrap();
    assert_eq!(writer.publish(snapshot).unwrap(), publication);
}

#[test]
fn verified_cold_capture_leaf_is_reused_after_detaching_its_source() {
    let (dir, mut writer) = store();
    let bytes = vec![0x7a; 64 * 1024];
    let leaf = writer.put(7, 1, &bytes, &[]).unwrap();
    let root = snapshot(&mut writer, &bytes);
    writer.publish(root).unwrap();
    drop(writer);

    let mut writer = NativeStore::open(dir.path().join("db.sac"), true).unwrap();
    let pin = writer.pin().unwrap();
    let detached = pin.verified_object(leaf).unwrap();
    drop(pin);
    let before = writer.file_len();
    assert_eq!(writer.put_verified(&detached, &[]).unwrap(), leaf);
    assert_eq!(writer.file_len(), before);
    writer.set_encode_threads(2);
    let other = vec![0x7b; bytes.len()];
    let mut batch = writer.prepare(7, 1, &[&bytes, &other]).unwrap().unwrap();
    assert_eq!(writer.put_prepared(batch.remove(0)).unwrap(), leaf);
    assert_eq!(writer.file_len(), before);
    writer.discard_disposable_caches();
    let reappended = writer.put_verified(&detached, &[]).unwrap();
    assert_ne!(reappended.address, leaf.address);
    assert_eq!(reappended.hash, leaf.hash);
}

#[test]
fn prepared_duplicates_reuse_the_destination_or_encode_on_an_index_miss() {
    let (_source_dir, mut source) = store();
    let (_destination_dir, mut destination) = store();
    source.set_encode_threads(2);
    let bytes = vec![b'a'; 128 << 10];
    let other = vec![b'b'; 128 << 10];
    let original = source.put(7, 1, &bytes, &[]).unwrap();
    let prepared = source.prepare(7, 1, &[&bytes, &other]).unwrap().unwrap();
    assert!(prepared[0].frame.is_none());
    assert!(prepared[1].frame.is_some());
    let mut prepared = prepared.into_iter();
    let duplicate = prepared.next().unwrap();
    assert_eq!(duplicate.body(), bytes);
    assert_eq!(source.put_prepared(duplicate).unwrap(), original);

    let duplicate = source
        .prepare(7, 1, &[&bytes, &other])
        .unwrap()
        .unwrap()
        .remove(0);
    let transferred = destination.put_prepared(duplicate).unwrap();
    assert_eq!(transferred.hash, original.hash);
    assert_eq!(destination.get(transferred).unwrap().bytes, bytes);
}
#[test]
fn closure_copy_reports_only_completed_subtrees_in_the_destination() {
    let (_dir, mut source) = store();
    let child = source.put(7, 1, b"observed child", &[]).unwrap();
    let root = source.put(65000, 1, b"parent", &[child]).unwrap();
    let mut destination = MemoryStore::sealed();
    destination.put(7, 1, b"distinct placement", &[]).unwrap();
    let mut copy = ClosureCopy::new().unwrap();
    let mut completed = Vec::new();
    let result = copy
        .copy_root_observing(
            &source,
            &mut destination,
            root,
            |_, _| Ok(None),
            |store, found| {
                store.validate_reference(found).unwrap();
                completed.push(found);
            },
            &|| false,
        )
        .unwrap();
    assert_eq!(
        completed,
        vec![destination.get(result).unwrap().children[0], result]
    );
    assert_eq!(completed[0].hash, child.hash);
    let mut reported = false;
    let bad = ObjectRef {
        address: ChunkAddress {
            offset: u64::MAX,
            length: 64,
        },
        ..root
    };
    assert!(
        copy.copy_root_observing(
            &source,
            &mut destination,
            bad,
            |_, _| Ok(None),
            |_, _| reported = true,
            &|| false
        )
        .is_err()
    );
    assert!(!reported);
}
#[cfg(feature = "compression")]
#[test]
fn retained_compressed_frames_authenticate_detached_child_ids() {
    let (_dir, mut source) = store();
    source.set_compression_level(3);
    let child = source.put(7, 1, b"child", &[]).unwrap();
    let body = vec![0x55; 128 * 1024];
    let parent = source.put(65002, 1, &body, &[child]).unwrap();
    let verified = source.verified_object(parent).unwrap();
    let detached = ObjectRef {
        hash: child.hash,
        address: ChunkAddress::default(),
    };
    let mut encoder = wire::FrameEncoder::default();
    let frame = encoder.encode_verified(&verified, &[detached]).unwrap();
    assert!(frame.len() < body.len() / 8);
    let restored = wire::decode_detached_frame(parent.hash, frame).unwrap();
    assert_eq!(restored.children, [detached]);
    assert_eq!(restored.bytes, body);
    assert!(wire::decode_detached_frame(child.hash, frame).is_err());
    assert!(encoder.encode_verified(&verified, &[]).is_err());
    let physical = encoder.encode_verified(&verified, &[child]).unwrap();
    assert!(wire::decode_detached_frame(parent.hash, physical).is_err());
    let mut memory = MemoryStore::sealed();
    let raw = memory.put(7, 1, b"raw canonical bytes", &[]).unwrap();
    let frame = encoder
        .encode_verified(&memory.verified_object(raw).unwrap(), &[])
        .unwrap();
    assert_eq!(
        wire::decode_detached_frame(raw.hash, frame).unwrap(),
        memory.get(raw).unwrap()
    );
}

#[test]
fn verified_copy_preserves_identity_and_checks_relocated_physical_children() {
    let mut source = MemoryStore::sealed();
    let child = source.put(7, 1, b"authenticated scalar", &[]).unwrap();
    let parent = source.put(65002, 1, b"parent", &[child]).unwrap();
    let verified = source.verified_object(parent).unwrap();
    let (_dir, mut destination) = store();
    let rewritten_child = destination
        .put_verified(&source.verified_object(child).unwrap(), &[])
        .unwrap();
    let copied = destination
        .put_verified(&verified, &[rewritten_child])
        .unwrap();
    assert_eq!(copied.hash, parent.hash);
    assert_eq!(
        destination.get(copied).unwrap().children,
        vec![rewritten_child]
    );
    let changed = destination.put(7, 1, b"different identity", &[]).unwrap();
    assert!(destination.put_verified(&verified, &[changed]).is_err());
    assert!(destination.put_verified(&verified, &[]).is_err());
    let invalid = ObjectRef {
        address: ChunkAddress {
            offset: u64::MAX - 100,
            length: 80,
        },
        ..rewritten_child
    };
    assert!(
        destination.put_verified(&verified, &[invalid]).is_err(),
        "an equal hash does not authenticate a relocated occurrence"
    );
    let mut portable = MemoryStore::sealed();
    let portable_child = portable
        .put_verified(&source.verified_object(child).unwrap(), &[])
        .unwrap();
    assert_eq!(
        portable
            .put_verified(&verified, &[portable_child])
            .unwrap()
            .hash,
        parent.hash
    );
}
#[test]
fn borrowed_visits_reuse_bounded_scratch_allow_nested_reads_and_reject_bad_occurrences() {
    for level in [0, 1] {
        let (_dir, mut source) = store();
        source.set_compression_level(level);
        let bytes = vec![b'x'; 128 << 10];
        let child = source.put(7, 1, &bytes, &[]).unwrap();
        let parent = source.put(65002, 1, b"parent", &[child]).unwrap();
        let root = snapshot(&mut source, b"published bounds");
        source.publish(root).unwrap();
        let reader = source.pin().unwrap();
        reader.clear_decoded_cache();
        reader.set_decoded_cache_budget(8 << 20);
        for _ in 0..8 {
            reader
                .visit_verified(parent, &mut |object| {
                    assert_eq!(object.bytes, b"parent");
                    assert_eq!(object.children, [child]);
                    reader.visit_verified(child, &mut |object| {
                        assert_eq!(object.bytes, bytes);
                        assert!(object.children.is_empty());
                        Ok(())
                    })
                })
                .unwrap();
            assert!(reader.cache_usage().decoded_bytes <= 8 << 20);
        }
        assert_eq!(
            reader
                .cache
                .lock()
                .unwrap()
                .borrowed
                .iter()
                .flatten()
                .count(),
            2
        );
        assert!(matches!(
            reader.visit_verified(child, &mut |_| Err(Error::Missing)),
            Err(Error::Missing)
        ));
        // A cached payload and idle scratch confer no authority on another
        // expected identity or a locator outside the pin's readable extent.
        reader.get_shared(child).unwrap();
        let mut changed = child;
        changed.hash.0[0] ^= 1;
        assert!(
            reader
                .visit_verified(changed, &mut |_| panic!("unauthenticated visit"))
                .is_err()
        );
        changed = child;
        changed.address.offset = reader.reader.trailer_offset();
        assert!(
            reader
                .visit_verified(changed, &mut |_| panic!("out-of-bounds visit"))
                .is_err()
        );
        reader.set_decoded_cache_budget(0);
        assert_eq!(reader.cache_usage().decoded_bytes, 0);
        assert!(
            reader
                .cache
                .lock()
                .unwrap()
                .borrowed
                .iter()
                .all(Option::is_none)
        );
        reader
            .visit_verified(child, &mut |object| {
                assert_eq!(object.bytes, bytes);
                Ok(())
            })
            .unwrap();
        assert_eq!(reader.cache_usage().decoded_bytes, 0);
    }
}

#[test]
fn borrowed_verified_copy_checks_identity_sequence_and_destination_occurrences() {
    let mut source = MemoryStore::sealed();
    let child = source.put(7, 1, b"child", &[]).unwrap();
    let parent = source.put(65002, 1, b"parent", &[child]).unwrap();
    let verified = source.verified_object(parent).unwrap();
    let (_dir, mut destination) = store();
    let copied_child = destination.put(7, 1, b"child", &[]).unwrap();
    let copied = destination
        .put_verified_view(&verified.view(), &[copied_child])
        .unwrap();
    assert_eq!(copied.hash, parent.hash);
    assert_eq!(destination.get(copied).unwrap().children, [copied_child]);
    let other = destination.put(7, 1, b"other", &[]).unwrap();
    assert!(
        destination
            .put_verified_view(&verified.view(), &[other])
            .is_err()
    );
    assert!(
        destination
            .put_verified_view(&verified.view(), &[])
            .is_err()
    );
    let invalid = ObjectRef {
        address: ChunkAddress {
            offset: u64::MAX - 100,
            length: 80,
        },
        ..copied_child
    };
    assert!(
        destination
            .put_verified_view(&verified.view(), &[invalid])
            .is_err()
    );
    let mut sealed = SealedWriter::new(Vec::new()).unwrap();
    let sealed_child = sealed.put(7, 1, b"child", &[]).unwrap();
    assert!(
        sealed
            .put_verified_view(&verified.view(), &[other])
            .is_err()
    );
    assert!(
        sealed
            .put_verified_view(&verified.view(), &[invalid])
            .is_err()
    );
    assert_eq!(
        sealed
            .put_verified_view(&verified.view(), &[sealed_child])
            .unwrap()
            .hash,
        parent.hash
    );
}
#[test]
fn public_direct_roles_still_validate_untrusted_child_shapes() {
    let child = ObjectRef::default();
    let parent = CanonicalObject {
        kind: 5,
        version: 1,
        bytes: cbor::encode(&cbor::Value::Array(vec![cbor::Value::Array(vec![
            cbor::Value::Uint(3),
            cbor::Value::Uint(0),
        ])])),
        children: vec![child],
    };
    let invalid = Arc::new(CanonicalObject {
        kind: 7,
        version: 1,
        bytes: b"abc".to_vec(),
        children: vec![child],
    });
    assert!(
        matches!(validate_core_edges(&parent, |_| Ok(invalid.clone())),
        Err(Error::Corrupt(message)) if message == "byte object children")
    );
    let mut invalid_parent = parent;
    invalid_parent.bytes.push(0);
    assert!(validate_core_edges(&invalid_parent, |_| panic!("invalid parent fetch")).is_err());
}
#[test]
fn packed_appends_preserve_bytes_across_frame_boundaries_and_failed_flushes() {
    let file = Mutex::new(tempfile::tempfile().unwrap());
    let pending = Mutex::new(AppendBuffer::default());
    let mut expected = Vec::new();
    for (ordinal, length) in [
        1,
        APPEND_BUFFER_BYTES - 3,
        13,
        APPEND_BUFFER_BYTES * 3 + 17,
        11,
    ]
    .into_iter()
    .enumerate()
    {
        let bytes = vec![ordinal as u8; length];
        append_frame(&file, &pending, expected.len() as u64, &bytes).unwrap();
        expected.extend_from_slice(&bytes);
        let stored = file.lock().unwrap().metadata().unwrap().len() as usize;
        assert_eq!(stored % APPEND_BUFFER_BYTES, 0);
        let pending = pending.lock().unwrap();
        assert!(pending.bytes.len() < APPEND_BUFFER_BYTES);
        assert_eq!(pending.bytes.capacity(), APPEND_BUFFER_BYTES);
        assert_eq!(pending.bytes, expected[stored..]);
        let mut actual = vec![0; stored];
        read_at(&file.lock().unwrap(), &mut actual, 0).unwrap();
        assert_eq!(actual, expected[..stored]);
    }
    let before = file.lock().unwrap().metadata().unwrap().len();
    assert!(append_frame(&file, &pending, expected.len() as u64 + 8, b"gap").is_err());
    assert_eq!(file.lock().unwrap().metadata().unwrap().len(), before);
    flush_append(&file, &pending).unwrap();
    assert!(pending.lock().unwrap().bytes.is_empty());
    let mut actual = vec![0; expected.len()];
    read_at(&file.lock().unwrap(), &mut actual, 0).unwrap();
    assert_eq!(actual, expected);
    #[cfg(target_os = "macos")]
    {
        assert!(matches!(
            append_at(
                &mut file.lock().unwrap(),
                b"overflow",
                u64::MAX,
                &mut AppendExtent::default(),
            ),
            Err(Error::Limit("append extent"))
        ));
        assert_eq!(
            file.lock().unwrap().metadata().unwrap().len(),
            expected.len() as u64
        );
    }

    let path = tempfile::NamedTempFile::new().unwrap();
    let readonly = Mutex::new(File::open(path.path()).unwrap());
    let pending = Mutex::new(AppendBuffer::default());
    append_frame(&readonly, &pending, 0, b"prefix").unwrap();
    assert!(append_frame(&readonly, &pending, 6, &vec![1; APPEND_BUFFER_BYTES]).is_err());
    assert!(pending.lock().unwrap().failed);
    assert!(matches!(
        append_frame(&readonly, &pending, 6, b"later"),
        Err(Error::Poisoned)
    ));
}

#[test]
#[cfg(target_os = "macos")]
fn sparse_append_extent_tracks_exact_writes_without_changing_bytes() {
    let mut file = tempfile::tempfile().unwrap();
    let mut buffer = AppendBuffer::default();
    let bytes = vec![71; APPEND_BUFFER_BYTES];
    append_at(&mut file, &bytes, 0, &mut buffer.extent).unwrap();
    assert_eq!(file.metadata().unwrap().len(), bytes.len() as u64);
    assert_eq!(buffer.extent.end, bytes.len() as u64);
    append_at(&mut file, b"tail", bytes.len() as u64, &mut buffer.extent).unwrap();
    assert_eq!(file.metadata().unwrap().len(), bytes.len() as u64 + 4);
    // Slot overwrites do not shorten an extent that contains appended bytes.
    write_at(&mut file, b"slot", 0).unwrap();
    let end = bytes.len() as u64 + 4;
    assert_eq!(file.metadata().unwrap().len(), end);
    assert_eq!(buffer.extent.end, end);
    let mut actual = vec![0; end as usize];
    read_at(&file, &mut actual, 0).unwrap();
    assert_eq!(&actual[..4], b"slot");
    assert!(actual[4..bytes.len()].iter().all(|&byte| byte == 71));
    assert_eq!(&actual[bytes.len()..], b"tail");
}

#[test]
#[cfg(target_os = "macos")]
fn published_writer_extends_only_persisted_bytes_and_obeys_lowered_limits() {
    let (_dir, mut store) = store();
    let root = snapshot(&mut store, b"initial");
    store.publish(root).unwrap();
    store.compression_level = 0;
    let before = store.file_len();
    let maximum = before + APPEND_BUFFER_BYTES as u64 * 2 + 7;
    store.set_file_byte_limit(maximum).unwrap();
    store
        .put(42000, 1, &vec![71; APPEND_BUFFER_BYTES], &[])
        .unwrap();
    assert_eq!(
        store.file.lock().unwrap().metadata().unwrap().len(),
        before + APPEND_BUFFER_BYTES as u64
    );
    // An old publication remains readable while its writer has a pending tail.
    store.pin().unwrap().validate().unwrap();
    let publication = store.root();
    store.publish(root).unwrap();
    assert_eq!(store.root(), publication);
    assert_eq!(
        store.file.lock().unwrap().metadata().unwrap().len(),
        store.file_len()
    );
    store.set_file_byte_limit(u64::MAX).unwrap();
    let before = store.file_len();
    let maximum = before + APPEND_BUFFER_BYTES as u64 * 2 + 7;
    store.set_file_byte_limit(maximum).unwrap();
    store
        .put(42000, 1, &vec![72; APPEND_BUFFER_BYTES], &[])
        .unwrap();
    assert_eq!(
        store.file.lock().unwrap().metadata().unwrap().len(),
        before + APPEND_BUFFER_BYTES as u64
    );
    let logical = store.file_len();
    assert!(logical < maximum);
    store.set_file_byte_limit(logical).unwrap();
    // Draining a pending short tail must also obey the lowered limit.
    store.pin().unwrap().validate().unwrap();
    assert_eq!(
        store.file.lock().unwrap().metadata().unwrap().len(),
        logical
    );
    assert!(matches!(
        store.put(42000, 1, b"over limit", &[]),
        Err(Error::Limit(_))
    ));
    assert_eq!(store.file_len(), logical);
    store.set_file_byte_limit(u64::MAX).unwrap();
    let next = snapshot(&mut store, b"next");
    store.publish(next).unwrap();
    assert_eq!(
        store.file.lock().unwrap().metadata().unwrap().len(),
        store.file_len()
    );
    store.validate().unwrap();
}

#[test]
fn opaque_appends_keep_exact_types_and_admit_payloads_only_on_read() {
    let (_dir, mut store) = store();
    let bytes = b"small opaque payload";
    let child = store.put(7, 1, b"small byte leaf", &[]).unwrap();
    let opaque = store.put(65000, 9, bytes, &[child]).unwrap();
    let key = (
        store.file_identity,
        opaque.hash,
        opaque.address.offset,
        opaque.address.length,
    );
    {
        let cache = store.cache.lock().unwrap();
        assert!(!cache.objects.slots.contains_key(&key));
        assert!(cache.verified.slots.contains_key(&key));
    }
    assert_eq!(store.cached_object_type(opaque).unwrap(), Some((65000, 9)));
    assert!(!store.append_buffer.lock().unwrap().bytes.is_empty());
    let mut other = opaque;
    other.address.length -= 8;
    assert_eq!(store.cached_object_type(other).unwrap(), None);
    let parent = store.put(65001, 1, b"parent", &[opaque]).unwrap();
    assert!(!store.append_buffer.lock().unwrap().bytes.is_empty());
    let before = store.physical_statistics();
    let object = store.get_verified_shared(opaque).unwrap();
    assert_eq!(object.kind, 65000);
    assert_eq!(object.version, 9);
    assert_eq!(object.bytes, bytes);
    assert_eq!(object.children, [child]);
    assert!(store.physical_statistics().read_bytes > before.read_bytes);
    let before = store.physical_statistics();
    assert!(Arc::ptr_eq(
        &object,
        &store.get_verified_shared(opaque).unwrap()
    ));
    assert_eq!(store.physical_statistics().read_bytes, before.read_bytes);
    assert_eq!(store.get(parent).unwrap().children, [opaque]);
    // Small byte leaves also defer payload residency until explicitly read.
    assert!(store.cache.get(store.file_identity, child).is_none());
}

#[test]
fn extent_and_byte_leaf_payloads_are_deferred_without_losing_exact_authentication() {
    let (_dir, mut store) = store();
    for bytes in [b"leaf".as_slice(), &[7; 2048], &[9; 8192]] {
        let leaf = store.put(7, 1, bytes, &[]).unwrap();
        let body = cbor::encode(&cbor::Value::Array(vec![cbor::Value::Array(vec![
            cbor::Value::Uint(bytes.len() as u64),
            cbor::Value::Uint(0),
        ])]));
        let extent = store.put(5, 1, &body, &[leaf]).unwrap();
        for (reference, kind) in [(leaf, 7), (extent, 5)] {
            assert!(store.cache.get(store.file_identity, reference).is_none());
            assert_eq!(
                store.cached_object_type(reference).unwrap(),
                Some((kind, 1))
            );
            let mut wrong = reference;
            wrong.address.length += 8;
            assert!(store.put(65000, 1, b"bad locator", &[wrong]).is_err());
        }
        let before = store.physical_statistics();
        store.put(65000, 1, b"parent", &[extent]).unwrap();
        assert_eq!(store.physical_statistics(), before);
        let pin = store.get_verified_shared(extent).unwrap();
        assert_eq!(pin.bytes, body);
        assert_eq!(pin.children, [leaf]);
        let before = store.physical_statistics();
        assert!(Arc::ptr_eq(
            &pin,
            &store.get_verified_shared(extent).unwrap()
        ));
        assert_eq!(store.physical_statistics(), before);
        store.discard_disposable_caches();
        assert_eq!(pin.bytes, body);
        assert_eq!(store.get(leaf).unwrap().bytes, bytes);
    }
}

#[test]
fn unretained_puts_preserve_frames_and_strict_authentication() {
    let (_ordinary_dir, mut ordinary) = store();
    let (_final_dir, mut final_pages) = store();
    let expected = ordinary.put(3, 1, &[0x80], &[]).unwrap();
    let actual = final_pages.put_unretained(3, 1, &[0x80], &[]).unwrap();
    assert_eq!(actual, expected);
    let key = (
        final_pages.file_identity,
        actual.hash,
        actual.address.offset,
        actual.address.length,
    );
    {
        let cache = final_pages.cache.lock().unwrap();
        assert!(!cache.objects.slots.contains_key(&key));
        assert!(cache.verified.slots.contains_key(&key));
    }
    let before = final_pages.physical_statistics();
    assert_eq!(final_pages.object_type(actual).unwrap(), (3, 1));
    final_pages
        .put_unretained(42000, 1, b"parent", &[actual])
        .unwrap();
    assert_eq!(
        final_pages.physical_statistics().read_bytes,
        before.read_bytes
    );
    ordinary.pin().unwrap();
    let old = final_pages.pin().unwrap();
    // New stores still own private staging files until their first publication.
    let frame = |store: &NativeStore| {
        let mut bytes = vec![0; actual.address.length as usize];
        counted_read_at(
            &store.file.lock().unwrap(),
            &mut bytes,
            actual.address.offset,
            &store.io,
            ReadClass::Object,
        )
        .unwrap();
        bytes
    };
    assert_eq!(frame(&ordinary), frame(&final_pages));
    let end = final_pages.end;
    assert!(final_pages.put_unretained(3, 1, &[0xf6], &[]).is_err());
    let mut wrong = actual;
    wrong.hash.0[0] ^= 1;
    assert!(
        final_pages
            .put_unretained(42000, 1, b"wrong", &[wrong])
            .is_err()
    );
    assert_eq!(final_pages.end, end);
    assert!(old.get(actual).is_err());
    assert_eq!(final_pages.get(actual).unwrap().bytes, [0x80]);
    assert_eq!(final_pages.put(3, 1, &[0x80], &[]).unwrap(), actual);
    let root = resources::snapshot(&mut final_pages, actual, vec![], vec![]).unwrap();
    final_pages.publish(root).unwrap();
    let published = final_pages.pin().unwrap();
    drop(final_pages);
    assert_eq!(published.get(actual).unwrap().bytes, [0x80]);
}

#[test]
fn child_authentication_batches_hits_but_releases_the_cache_on_misses() {
    let (_dir, mut store) = store();
    let first = store.put(65000, 1, b"first", &[]).unwrap();
    let second = store.put(65000, 1, b"second", &[]).unwrap();
    let root = snapshot(&mut store, b"published parent");
    store.publish(root).unwrap();
    store.discard_disposable_caches();
    assert_eq!(store.object_type(first).unwrap(), (65000, 1));
    // A cached inherited child, a cold inherited child and another cached hit
    // exercise guard reuse on either side of the physical authentication read.
    let before = store.physical_statistics();
    let children = [first, second, first];
    let parent = store.put(65001, 1, b"parent", &children).unwrap();
    assert!(store.physical_statistics().read_bytes > before.read_bytes);
    assert_eq!(store.get(parent).unwrap().children, children);
    let mut wrong = second;
    wrong.hash.0[0] ^= 1;
    let end = store.end;
    assert!(
        store
            .put(65001, 1, b"invalid parent", &[first, wrong])
            .is_err()
    );
    assert_eq!(store.end, end);
    // A failed batch must also release its guard for subsequent operations.
    assert_eq!(store.get(parent).unwrap().children, children);
}

#[test]
fn small_frame_appends_coalesce_and_cache_misses_drain_before_reading() {
    let (dir, mut store) = store();
    let first = store.put(7, 1, b"buffered immutable bytes", &[]).unwrap();
    assert!(store.file.lock().unwrap().metadata().unwrap().len() < store.end);
    assert!(!store.append_buffer.lock().unwrap().bytes.is_empty());
    assert_eq!(store.get(first).unwrap().bytes, b"buffered immutable bytes");
    assert!(store.append_buffer.lock().unwrap().bytes.is_empty());
    // The first read admits the deferred leaf. Subsequent hits need no
    // flush even when another frame is waiting in the append buffer.
    let second = store.put(7, 1, b"another buffered leaf", &[]).unwrap();
    assert_eq!(store.get(first).unwrap().bytes, b"buffered immutable bytes");
    assert!(!store.append_buffer.lock().unwrap().bytes.is_empty());
    store.set_decoded_cache_budget(0);
    assert_eq!(store.get(second).unwrap().bytes, b"another buffered leaf");
    assert!(store.append_buffer.lock().unwrap().bytes.is_empty());
    let root = snapshot(&mut store, b"durable buffered snapshot");
    store.publish(root).unwrap();
    drop(store);
    let reader = NativeReader::open(dir.path().join("db.sac")).unwrap();
    assert_eq!(reader.reader().snapshot(), Some(root));
    reader.validate().unwrap();
}
#[test]
fn reader_identity_distinguishes_a_file_copy_from_a_second_descriptor() {
    let (directory, mut store) = store();
    let root = snapshot(&mut store, b"original");
    store.publish(root).unwrap();
    let original = store.pin().unwrap();
    let path = directory.path().join("db.sac");
    let hard_link = directory.path().join("alias.sac");
    let copy = directory.path().join("copy.sac");
    std::fs::hard_link(&path, &hard_link).unwrap();
    std::fs::copy(&path, &copy).unwrap();
    assert!(original.shares_backing_file(&store.pin().unwrap()).unwrap());
    assert!(
        original
            .shares_backing_file(&NativeReader::open(&hard_link).unwrap())
            .unwrap()
    );
    assert!(
        !original
            .shares_backing_file(&NativeReader::open(&copy).unwrap())
            .unwrap()
    );
}

#[test]
fn complete_cache_visible_slot_is_stabilized_on_writable_reopen() {
    let (dir, mut store) = store();
    let s = snapshot(&mut store, b"first");
    store.publish(s).unwrap();
    let next = snapshot(&mut store, b"second");
    store.inject_publication_fault_once(PublicationFault::SlotSync);
    assert!(store.publish(next).is_err());
    assert!(matches!(store.publish(next), Err(Error::Poisoned)));
    drop(store);
    let mut reopened = NativeStore::open(dir.path().join("db.sac"), true).unwrap();
    assert_eq!(reopened.reader().snapshot().unwrap().hash, next.hash);
    let before = reopened.publication_statistics();
    assert_eq!(before.chunk_barriers, 1);
    assert_eq!(before.slot_syncs, 1);
    assert_eq!(before.slot_writes, 0);
    assert_eq!(before.appended_bytes, 0);
    reopened.publish(next).unwrap();
    assert_eq!(reopened.publication_statistics(), before);
}
#[test]
fn torn_slots_preserve_source_and_require_explicit_recovery() {
    for prefix in [1, 7, 8, 39, 40, 87, 88, 4063, 4064, 4095] {
        let (dir, mut store) = store();
        let first = snapshot(&mut store, b"old");
        store.publish(first).unwrap();
        let next = snapshot(&mut store, b"new");
        store.inject_publication_fault_once(PublicationFault::SlotWrite { bytes: prefix });
        assert!(store.publish(next).is_err());
        drop(store);
        let file = dir.path().join("db.sac");
        let before = std::fs::read(&file).unwrap();
        let reader = NativeReader::open(&file).unwrap();
        assert_eq!(reader.reader().snapshot().unwrap().hash, first.hash);
        let error = NativeStore::open(&file, true).err();
        assert!(
            matches!(error, Some(Error::RecoveryRequired)),
            "torn slot prefix {prefix}: {error:?}"
        );
        assert_eq!(std::fs::read(&file).unwrap(), before);
    }
}
#[test]
fn clean_writer_close_releases_only_its_unpublished_append_extent() {
    let (dir, mut store) = store();
    let selected = snapshot(&mut store, b"selected");
    store.publish(selected).unwrap();
    let end = store.reader().committed_end();
    let incarnation = store.reader().header.incarnation;
    let path = dir.path().join("db.sac");
    let _orphan = snapshot(&mut store, b"unfinished");
    let pin = store.pin().unwrap();
    assert!(std::fs::metadata(&path).unwrap().len() > end);
    drop(store);
    assert_eq!(std::fs::metadata(&path).unwrap().len(), end);
    let reopened = NativeStore::open(&path, true).unwrap();
    assert!(reopened.preserved_recovery_input().is_none());
    assert_eq!(reopened.reader().header.incarnation, incarnation);
    assert_eq!(pin.reader().snapshot().unwrap().hash, selected.hash);
}

#[test]
fn append_barrier_failure_does_not_promote_orphan_or_delete_suffix() {
    let (dir, mut store) = store();
    let s = snapshot(&mut store, b"old");
    store.publish(s).unwrap();
    let next = snapshot(&mut store, b"new");
    store.inject_publication_fault_once(PublicationFault::ChunksBarrier);
    assert!(store.publish(next).is_err());
    drop(store);
    let file = dir.path().join("db.sac");
    let length = std::fs::metadata(&file).unwrap().len();
    let reader = NativeReader::open(&file).unwrap();
    assert_eq!(reader.reader().snapshot().unwrap().hash, s.hash);
    let recovered = NativeStore::open(&file, true).unwrap();
    assert_eq!(recovered.reader().snapshot().unwrap().hash, s.hash);
    assert_eq!(
        std::fs::metadata(recovered.preserved_recovery_input().unwrap())
            .unwrap()
            .len(),
        length
    );
    assert_ne!(recovered.reader().header.incarnation, [2; 16]);
}
#[test]
fn destination_fence_survives_replacement_and_old_pins_survive_compaction() {
    let (dir, mut store) = store();
    let s = snapshot(&mut store, b"retained old bytes");
    store.publish(s).unwrap();
    let old = store.pin().unwrap();
    assert!(matches!(
        NativeStore::open(dir.path().join("db.sac"), true),
        Err(Error::Busy)
    ));
    store.compact().unwrap();
    assert_ne!(
        old.reader().header.incarnation,
        store.reader().header.incarnation
    );
    assert_eq!(
        old.reader().snapshot().unwrap().hash,
        store.reader().snapshot().unwrap().hash
    );
    old.validate().unwrap();
    store.validate().unwrap();
    assert!(matches!(
        NativeStore::open(dir.path().join("db.sac"), true),
        Err(Error::Busy)
    ));
}
#[cfg(unix)]
#[test]
fn replaced_ancestor_directory_is_rejected_at_publication() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir(&home).unwrap();
    let path = home.join("db.sac");
    let mut store = NativeStore::create_live(&path, [2; 16]).unwrap();
    let first = snapshot(&mut store, b"old");
    store.publish(first).unwrap();
    std::fs::rename(&home, dir.path().join("moved")).unwrap();
    std::fs::create_dir(&home).unwrap();
    std::fs::write(&path, b"replacement").unwrap();
    // The check before a write looks in the directory that the writer
    // opened, where its file still has its name. The write is not durable
    // authority; the publication examines the complete path.
    let next = snapshot(&mut store, b"new");
    assert!(store.verify_current_path().is_err());
    assert!(store.publish(next).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
}
#[test]
fn stale_descriptor_is_rejected_before_append() {
    let (dir, mut store) = store();
    let s = snapshot(&mut store, b"old");
    store.publish(s).unwrap();
    let path = dir.path().join("db.sac");
    std::fs::rename(&path, dir.path().join("old")).unwrap();
    std::fs::write(&path, b"replacement").unwrap();
    assert!(store.put(7, 1, b"must not append", &[]).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
}

#[test]
fn staging_checks_once_and_a_replaced_destination_cannot_receive_the_commit() {
    let (dir, mut store) = store();
    let first = snapshot(&mut store, b"old");
    store.publish(first).unwrap();
    let old = store.pin().unwrap();
    let next = snapshot(&mut store, b"staged batch");
    let path = dir.path().join("db.sac");
    std::fs::rename(&path, dir.path().join("retired.sac")).unwrap();
    std::fs::write(&path, b"replacement").unwrap();
    // Staged immutable appends confer no durable authority and no longer
    // repeat a path lookup for each object in the batch.
    store.put(7, 1, b"another staged object", &[]).unwrap();
    assert!(store.publish(next).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
    assert_eq!(old.reader().snapshot().unwrap().hash, first.hash);
    old.validate().unwrap();
}

#[test]
fn staging_cannot_publish_after_its_destination_is_removed_or_appears() {
    let (dir, mut store) = store();
    let first = snapshot(&mut store, b"old");
    store.publish(first).unwrap();
    let next = snapshot(&mut store, b"uncommitted");
    std::fs::remove_file(dir.path().join("db.sac")).unwrap();
    store.put(7, 1, b"private bytes", &[]).unwrap();
    assert!(store.publish(next).is_err());

    let (dir, mut store) = self::store();
    let first = snapshot(&mut store, b"private creation");
    let path = dir.path().join("db.sac");
    std::fs::write(&path, b"another creator").unwrap();
    store.put(7, 1, b"more private bytes", &[]).unwrap();
    assert!(store.publish(first).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"another creator");
}
#[cfg(unix)]
#[test]
fn path_identity_follows_aliases_and_rejects_replaced_targets() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("original");
    let hard = dir.path().join("hard");
    let symbolic = dir.path().join("symbolic");
    std::fs::write(&original, b"same bytes").unwrap();
    let retained = File::open(&original).unwrap();
    std::fs::hard_link(&original, &hard).unwrap();
    std::os::unix::fs::symlink("original", &symbolic).unwrap();
    for path in [&original, &hard, &symbolic] {
        verify_file_path(&retained, path).unwrap();
    }

    // Equal contents do not confer the retained file's identity. The hard link
    // still names the admitted inode after the original name is replaced.
    std::fs::rename(&original, dir.path().join("retired")).unwrap();
    std::fs::write(&original, b"same bytes").unwrap();
    verify_file_path(&retained, &hard).unwrap();
    assert!(verify_file_path(&retained, &original).is_err());
    assert!(verify_file_path(&retained, &symbolic).is_err());
    std::fs::remove_file(&original).unwrap();
    assert!(verify_file_path(&retained, &symbolic).is_err());
}
#[test]
fn sealed_pack_drops_intermediate_objects_and_admits_exact_eof() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sealed.sac");
    let mut store = NativeStore::create_sealed(&path, Header::new([1; 16], [2; 16])).unwrap();
    store.put(7, 1, &vec![3; 1_000_000], &[]).unwrap();
    let s = snapshot(&mut store, b"selected");
    let directory = store.get(s).unwrap().children[0];
    store.set_control_roots(&[directory]).unwrap();
    store.publish(s).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let mut at = 128;
    let mut unique = BTreeSet::new();
    while at < bytes.len() - 160 {
        let span = wire::frame_span(&bytes[at..at + 56]).unwrap();
        assert!(
            unique.insert(bytes[at + 16..at + 48].to_vec()),
            "sealed pack duplicated a canonical object"
        );
        at += span;
    }
    assert_eq!(at, bytes.len() - 160);
    assert!(std::fs::metadata(&path).unwrap().len() < 4096);
    drop(store);
    let reader = NativeReader::open(&path).unwrap();
    assert_eq!(reader.reader().header.policy, wire::LocatorPolicy::Sealed);
    reader.validate().unwrap();
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(&[0]).unwrap();
    assert!(NativeReader::open(&path).is_err());
}
#[test]
fn missing_disposable_index_cold_save_is_bounded() {
    let (dir, mut store) = store();
    let s = snapshot(&mut store, b"old");
    store.publish(s).unwrap();
    drop(store);
    let mut reopened = NativeStore::open(dir.path().join("db.sac"), true).unwrap();
    let before = reopened.physical_statistics();
    let s = snapshot(&mut reopened, b"next");
    reopened.publish(s).unwrap();
    let after = reopened.physical_statistics();
    assert!(after.read_bytes - before.read_bytes < 1024 * 1024);
    assert!(after.read_operations - before.read_operations < 64);
}
#[test]
fn prior_small_frames_stay_coalesced_while_staging_a_large_append() {
    let (_dir, mut store) = store();
    let mut references = Vec::new();
    for n in 0..128u64 {
        references.push(store.put(7, 1, &n.to_le_bytes(), &[]).unwrap());
    }
    // Incompressible bytes put the preceding metadata outside the old 128 KiB
    // tail band, as happens while a writer stages its next publication.
    let padding = (0..160 * 1024u64)
        .map(|n| blake3::hash(&n.to_le_bytes()).as_bytes()[0])
        .collect::<Vec<_>>();
    store.put(7, 1, &padding, &[]).unwrap();
    assert!(store.end - references[0].address.offset > 128 * 1024);
    store.discard_disposable_caches();
    let before = store.physical_statistics();
    for (n, reference) in references.into_iter().enumerate() {
        assert_eq!(
            store.get(reference).unwrap().bytes,
            (n as u64).to_le_bytes()
        );
    }
    let after = store.physical_statistics();
    assert!(after.read_operations - before.read_operations <= 4);
    assert!(after.read_bytes - before.read_bytes <= 64 * 1024);
}
#[test]
fn every_slot_prefix_can_only_admit_complete_old_or_new_binding() {
    let preamble = wire::Preamble::live([8; 16]).unwrap();
    let old = wire::Slot {
        preamble_digest: preamble.digest(),
        generation: 1,
        trailer_offset: 16384,
        trailer_digest: ObjectHash([10; 32]),
    };
    let new = wire::Slot {
        preamble_digest: preamble.digest(),
        generation: 3,
        trailer_offset: 32768,
        trailer_digest: ObjectHash([11; 32]),
    };
    let old_bytes = old.encode();
    let new_bytes = new.encode();
    for prefix in 0..=4096 {
        let mut bytes = old_bytes;
        bytes[..prefix].copy_from_slice(&new_bytes[..prefix]);
        match wire::Slot::decode(&bytes, &preamble, 1) {
            Ok(Some(slot)) => assert!(slot == old || slot == new),
            Err(Error::Corrupt(_)) => {}
            other => panic!("prefix {prefix}: {other:?}"),
        }
    }
}
#[test]
fn temporary_quota_is_reserved_before_spill_or_destination_mutation() {
    let budget = temporary::Budget::new(0);
    let mut map = temporary::GraphTable::with_budget(0, budget.clone());
    assert!(matches!(
        map.insert_cancellable(b"key", b"value", &|| false),
        Err(Error::Limit(_))
    ));
    assert_eq!(budget.used(), 0);
    assert!(map.get(b"key").unwrap().is_none());
    let mut source = MemoryStore::new(Header::new([1; 16], [2; 16]));
    let root = source.put(7, 1, b"payload", &[]).unwrap();
    let mut target = MemoryStore::sealed();
    let before = target.as_bytes().len();
    let mut copy = ClosureCopy::new_with_disk_budget(0).unwrap();
    assert!(matches!(
        copy.copy_root(&source, &mut target, root),
        Err(Error::Limit(_))
    ));
    assert_eq!(target.as_bytes().len(), before);
    assert_eq!(copy.disk_bytes().unwrap(), 0);
}
#[test]
fn validation_window_coalesces_reads_and_charges_read_ahead_within_source_limit() {
    let mut file = tempfile::tempfile().unwrap();
    let bytes: Vec<_> = (0..3 * ValidationWindow::BYTES).map(|i| i as u8).collect();
    file.write_all(&bytes).unwrap();
    let io = PhysicalCounters::default();
    let mut window = ValidationWindow::default();
    let mut charged = 56;
    let end = bytes.len() as u64;
    let mut header = [0; 56];
    window
        .read(&file, &io, 0, end, &mut header, &mut charged, end)
        .unwrap();
    assert_eq!(header, bytes[..56]);
    assert_eq!(charged, ValidationWindow::BYTES as u64);
    let after = io.snapshot();
    for offset in [56, 128, 4096, ValidationWindow::BYTES - 56] {
        charged += 56;
        window
            .read(
                &file,
                &io,
                offset as u64,
                end,
                &mut header,
                &mut charged,
                end,
            )
            .unwrap();
        assert_eq!(header, bytes[offset..offset + 56]);
    }
    assert_eq!(io.snapshot().read_operations, after.read_operations);

    // Near the quota the window reads only the charged request and remaining
    // allowance, instead of issuing an uncharged full speculative read.
    charged = end - 17;
    let offset = end - 100;
    let before = io.snapshot();
    window
        .read(&file, &io, offset, end, &mut header, &mut charged, end)
        .unwrap();
    assert_eq!(charged, end);
    assert_eq!(
        io.snapshot().metadata_bytes - before.metadata_bytes,
        56 + 17
    );
    assert_eq!(header, bytes[offset as usize..offset as usize + 56]);
    assert!(window.bytes.len() <= ValidationWindow::BYTES);
}

#[test]
fn strict_physical_validation_enforces_operation_limits() {
    let (_dir, mut store) = store();
    let root = snapshot(&mut store, b"bounded");
    store.publish(root).unwrap();
    let pin = store.pin().unwrap();
    let mut limits = resources::Limits {
        max_frames: 1,
        ..Default::default()
    };
    assert!(matches!(
        pin.validate_with_limits(&limits),
        Err(Error::Limit(_))
    ));
    limits = resources::Limits::default();
    limits.max_source_bytes = 1;
    assert!(matches!(
        pin.validate_with_limits(&limits),
        Err(Error::Limit(_))
    ));
    limits = resources::Limits::default();
    limits.max_decoded_bytes = 1;
    assert!(matches!(
        pin.validate_with_limits(&limits),
        Err(Error::Limit(_))
    ));
}

#[test]
fn physical_validation_authenticates_each_occurrence_once_and_keeps_logical_charges() {
    let dir = tempfile::tempdir().unwrap();
    for embedded in [false, true] {
        let payload = CanonicalObject {
            kind: 7,
            version: 1,
            bytes: vec![42; 4096],
            children: Vec::new(),
        };
        let mut writer = SealedWriter::new(Vec::new()).unwrap();
        writer.set_compression_level(0);
        let chunk = if embedded {
            let bytes = wire::encode_frame(&payload, 0).unwrap();
            let outer = writer.put(7, 1, &bytes, &[]).unwrap();
            ObjectRef {
                hash: payload.hash(),
                address: ChunkAddress {
                    offset: outer.address.offset + wire::FRAME as u64 + 8,
                    length: bytes.len() as u32,
                },
            }
        } else {
            writer.put(7, 1, &payload.bytes, &[]).unwrap()
        };
        use cbor::Value::{Array, Bytes, Map, Uint};
        let extent = writer
            .put(
                5,
                1,
                &cbor::encode(&Array(vec![Array(vec![
                    Uint(payload.bytes.len() as u64),
                    Uint(0),
                ])])),
                &[chunk],
            )
            .unwrap();
        let directory = writer
            .put(
                3,
                1,
                &cbor::encode(&Array(vec![Array(vec![
                    Bytes(b"file".to_vec()),
                    Uint(0),
                    Map(vec![]),
                    Array(vec![Uint(payload.bytes.len() as u64), Uint(1), Uint(0)]),
                ])])),
                &[extent],
            )
            .unwrap();
        let snapshot = resources::snapshot(&mut writer, directory, vec![], vec![]).unwrap();
        let path = dir.path().join(format!("sealed-{embedded}.sac"));
        std::fs::write(&path, writer.finish(snapshot).unwrap()).unwrap();
        let reader = NativeReader::open(&path).unwrap();
        if embedded {
            assert!(matches!(
                reader.validate(),
                Err(Error::Corrupt(message)) if message == "reachable locator is not a top-level frame"
            ));
            continue;
        }
        let commit = reader.root().unwrap().root;
        let mut decoded = reader.get(commit).unwrap().canonical_len() as u64;
        for reference in [snapshot, directory, extent, chunk] {
            decoded += 2 * reader.get(reference).unwrap().canonical_len() as u64;
        }
        let before = reader.physical_statistics().object_bytes;
        let report = reader.validate().unwrap();
        let physical_bytes = reader.physical_statistics().object_bytes - before;
        assert_eq!(
            report,
            ValidationReport {
                objects: 5,
                decoded_bytes: decoded,
            }
        );
        assert_eq!(
            physical_bytes,
            u64::from(commit.address.length)
                + [snapshot, directory, extent]
                    .into_iter()
                    .map(|reference| u64::from(reference.address.length))
                    .sum::<u64>()
                + u64::from(chunk.address.length)
        );
        let limits = resources::Limits {
            max_decoded_bytes: decoded - 1,
            ..Default::default()
        };
        assert!(matches!(
            reader.validate_with_limits(&limits),
            Err(Error::Limit("validation decoded bytes"))
        ));
    }
}

#[test]
fn physical_validation_checks_every_incoming_role_on_shared_occurrences() {
    use cbor::Value::{Array, Bytes, Map, Uint};
    for duplicate_index in [false, true] {
        let mut writer = SealedWriter::new(Vec::new()).unwrap();
        let bytes = writer.put(7, 1, b"abc", &[]).unwrap();
        let rows = |lengths: &[u64]| {
            cbor::encode(&Array(
                lengths
                    .iter()
                    .map(|length| Array(vec![Uint(*length), Uint(0)]))
                    .collect(),
            ))
        };
        let first = writer.put(5, 1, &rows(&[3]), &[bytes]).unwrap();
        let second = writer
            .put(
                5,
                1,
                &rows(if duplicate_index { &[3, 4] } else { &[4] }),
                &[bytes],
            )
            .unwrap();
        let directory = writer
            .put(
                3,
                1,
                &cbor::encode(&Array(vec![
                    Array(vec![
                        Bytes(b"a".to_vec()),
                        Uint(0),
                        Map(vec![]),
                        Array(vec![Uint(3), Uint(1), Uint(0)]),
                    ]),
                    Array(vec![
                        Bytes(b"b".to_vec()),
                        Uint(0),
                        Map(vec![]),
                        Array(vec![
                            Uint(if duplicate_index { 7 } else { 4 }),
                            Uint(1),
                            Uint(1),
                        ]),
                    ]),
                ])),
                &[first, second],
            )
            .unwrap();
        let snapshot = resources::snapshot(&mut writer, directory, vec![], vec![]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("roles.sac");
        std::fs::write(&path, writer.finish(snapshot).unwrap()).unwrap();
        assert!(matches!(NativeReader::open(path).unwrap().validate(),
            Err(Error::Corrupt(message)) if message == "extent byte length"));
    }
}

#[test]
fn physical_validation_checks_deferred_branch_heights() {
    use cbor::Value::{Array, Bytes, Uint};
    let mut writer = SealedWriter::new(Vec::new()).unwrap();
    let leaf = writer
        .put(3, 1, &cbor::encode(&Array(vec![])), &[])
        .unwrap();
    let branch = |height| {
        cbor::encode(&Array(vec![
            Uint(height),
            Array(vec![
                Array(vec![Bytes(b"a".to_vec()), Uint(0)]),
                Array(vec![Bytes(b"b".to_vec()), Uint(0)]),
            ]),
        ]))
    };
    let child = writer.put(4, 1, &branch(1), &[leaf]).unwrap();
    let root = writer.put(4, 1, &branch(3), &[child]).unwrap();
    let snapshot = resources::snapshot(&mut writer, root, vec![], vec![]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("height.sac");
    std::fs::write(&path, writer.finish(snapshot).unwrap()).unwrap();
    assert!(matches!(NativeReader::open(path).unwrap().validate(),
        Err(Error::Corrupt(message)) if message == "core branch child height"));
}

#[test]
fn publication_relocates_requested_control_roots_without_changing_ids() {
    let (_dir, mut store) = store();
    let first = snapshot(&mut store, b"old");
    store.publish(first).unwrap();
    let directory = store.get(first).unwrap().children[0];
    let mut noise = Vec::with_capacity(128 * 1024);
    for n in 0..4096u64 {
        noise.extend(blake3::hash(&n.to_le_bytes()).as_bytes());
    }
    store.put(7, 1, &noise, &[]).unwrap();
    let feature = cbor::Value::Array(vec![
        cbor::Value::Null,
        cbor::Value::Text("test.optional".into()),
        cbor::Value::Uint(1),
        cbor::Value::Bool(false),
    ]);
    let next = store
        .put(
            2,
            1,
            &cbor::encode(&cbor::Value::Array(vec![
                cbor::Value::Uint(0),
                cbor::Value::Array(vec![]),
                cbor::Value::Array(vec![feature]),
            ])),
            &[directory],
        )
        .unwrap();
    store.set_control_roots(&[directory]).unwrap();
    store.publish(next).unwrap();
    let selected = store
        .get(store.reader().snapshot().unwrap())
        .unwrap()
        .children[0];
    assert_eq!(selected.hash, directory.hash);
    assert!(selected.address.offset > directory.address.offset);
    assert!(selected.address.offset >= store.root().unwrap().committed_end - 65536);
    store.validate().unwrap();
}

#[test]
fn disposable_cache_loss_preserves_pins_and_does_not_scan_or_publish() {
    let (_directory, mut store) = store();
    let first = snapshot(&mut store, b"first");
    store.publish(first).unwrap();
    let pin = store.pin().unwrap();
    let first_object = pin.get(first).unwrap();
    assert!(store.appended_reference(first.hash).unwrap().is_some());
    let before_reads = store.physical_statistics();
    let before_writes = store.publication_statistics();
    let before_length = store.file_len();
    let budget = store.cache_usage().budget;
    store.discard_disposable_caches();
    assert_eq!(store.cache_usage().decoded_bytes, 0);
    assert_eq!(store.cache_usage().budget, budget);
    assert!(store.appended_reference(first.hash).unwrap().is_none());
    assert_eq!(store.physical_statistics(), before_reads);
    assert_eq!(store.publication_statistics(), before_writes);
    assert_eq!(store.file_len(), before_length);
    assert_eq!(pin.get(first).unwrap(), first_object);
    pin.clear_decoded_cache();
    assert_eq!(store.cache_usage().decoded_bytes, 0);
    let second = snapshot(&mut store, b"second");
    store.publish(second).unwrap();
    let after_reads = store.physical_statistics();
    assert!(after_reads.read_bytes - before_reads.read_bytes < 64 * 1024);
    let after_writes = store.publication_statistics();
    assert_eq!(
        after_writes.chunk_barriers - before_writes.chunk_barriers,
        1
    );
    assert_eq!(after_writes.slot_syncs - before_writes.slot_syncs, 1);
    assert_eq!(pin.get(first).unwrap(), first_object);
}

#[test]
fn append_ids_stay_resident_and_pressure_spills_without_changing_deduplication() {
    let (_directory, mut store) = store();
    let mut objects = Vec::new();
    for ordinal in 0..5000_u64 {
        objects.push(store.put(7, 1, &ordinal.to_le_bytes(), &[]).unwrap());
    }
    assert!(store.append_index_memory_bytes() <= DEFAULT_APPEND_INDEX_MEMORY_BYTES);
    assert_eq!(store.temporary_statistics().write_bytes, 0);
    assert_eq!(store.temporary_statistics().read_bytes, 0);
    store.set_append_index_memory_budget(0).unwrap();
    assert_eq!(store.append_index_memory_bytes(), 0);
    assert!(store.temporary_statistics().write_bytes > 0);
    let before = store.file_len();
    for (ordinal, expected) in objects.iter().enumerate() {
        assert_eq!(
            store
                .put(7, 1, &(ordinal as u64).to_le_bytes(), &[])
                .unwrap(),
            *expected
        );
    }
    assert_eq!(store.file_len(), before);
    store.discard_disposable_caches();
    assert_eq!(store.recent.0.resident_limit(), 0);
    store.put(7, 1, b"still under pressure", &[]).unwrap();
    assert_eq!(store.append_index_memory_bytes(), 0);
}

#[test]
fn closure_indexes_stay_resident_within_budget_and_survive_pressure() {
    let mut source = MemoryStore::sealed();
    let mut destination = MemoryStore::sealed();
    let mut copy = ClosureCopy::new().unwrap();
    let mut roots = Vec::new();
    for ordinal in 0..5000_u64 {
        let root = source.put(7, 1, &ordinal.to_le_bytes(), &[]).unwrap();
        let copied = copy.copy_root(&source, &mut destination, root).unwrap();
        assert_eq!(copied.hash, root.hash);
        roots.push((root, copied));
    }
    assert!(copy.index_memory_bytes() <= 16 * 1024 * 1024);
    assert_eq!(copy.temporary_statistics().write_bytes, 0);
    copy.set_index_memory_budget(0).unwrap();
    assert_eq!(copy.index_memory_bytes(), 0);
    assert!(copy.temporary_statistics().write_bytes > 0);
    let length = destination.as_bytes().len();
    for (root, copied) in roots {
        assert_eq!(
            copy.copy_root(&source, &mut destination, root).unwrap(),
            copied
        );
    }
    assert_eq!(destination.as_bytes().len(), length);
}

#[test]
fn failed_append_index_spill_preserves_the_resident_table() {
    let (_directory, mut store) = store();
    let reference = store.put(7, 1, b"retained", &[]).unwrap();
    store.set_temporary_disk_budget(0).unwrap();
    let limit = store.recent.0.resident_limit();
    assert!(matches!(
        store.set_append_index_memory_budget(0),
        Err(Error::Limit(_))
    ));
    assert_eq!(store.recent.0.resident_limit(), limit);
    assert_eq!(
        store.appended_reference(reference.hash).unwrap(),
        Some(reference)
    );
    assert_eq!(store.temporary_statistics().reserved_bytes, 0);
    assert_eq!(store.put(7, 1, b"retained", &[]).unwrap(), reference);
}

#[test]
fn data_appends_preserve_hot_metadata_and_admit_opaque_payloads_on_read() {
    let (_directory, mut store) = store();
    let root = snapshot(&mut store, b"hot structural metadata");
    store.publish(root).unwrap();
    store.set_decoded_cache_budget(64 * 1024);
    store.discard_disposable_caches();
    let hot = store.get_shared(root).unwrap();
    // Medium opaque payloads must not evict structural pages just because
    // they were written. Their exact append provenance is sufficient here.
    let mut body = vec![71; 3 * 1024];
    let children = [root; 96];
    let mut references = Vec::new();
    for ordinal in 0..32u64 {
        body[..8].copy_from_slice(&ordinal.to_le_bytes());
        references.push(store.put(4096, 1, &body, &[root]).unwrap());
        // A tiny body with a large child vector needs the same admission rule.
        references.push(store.put(4097, 1, &[ordinal as u8], &children).unwrap());
    }
    let before = store.physical_statistics();
    assert!(Arc::ptr_eq(&hot, &store.get_shared(root).unwrap()));
    for (index, &reference) in references.iter().enumerate() {
        assert_eq!(
            store.object_type(reference).unwrap(),
            (4096 + index as u16 % 2, 1)
        );
    }
    assert_eq!(store.physical_statistics(), before);
    let small = store.put(4096, 1, b"small opaque data", &[]).unwrap();
    assert_eq!(store.object_type(small).unwrap(), (4096, 1));
    assert_eq!(store.physical_statistics(), before);
    assert_eq!(store.get(small).unwrap().bytes, b"small opaque data");
    assert!(store.physical_statistics().read_bytes > before.read_bytes);

    let large = *references.last().unwrap();
    let object = store.get_shared(large).unwrap();
    assert_eq!(object.bytes, [31]);
    assert_eq!(object.children, children);
    assert!(store.physical_statistics().read_bytes > before.read_bytes);
    let read = store.physical_statistics();
    assert!(Arc::ptr_eq(&object, &store.get_shared(large).unwrap()));
    assert_eq!(store.physical_statistics(), read);
    let usage = store.cache_usage();
    assert!(usage.decoded_bytes + usage.pinned_metadata_bytes <= usage.budget);
}

#[test]
fn authenticated_types_survive_payload_eviction_but_keep_exact_pin_fences() {
    let (_directory, mut store) = store();
    let payload = store.put(7, 1, &vec![23; 128 * 1024], &[]).unwrap();
    let root = snapshot(&mut store, b"type cache old head");
    store.publish(root).unwrap();
    let old = store.pin().unwrap();
    store.set_decoded_cache_budget(64 * 1024);
    old.clear_decoded_cache();
    let unread = old.physical_statistics();
    assert_eq!(old.cached_object_type(payload).unwrap(), None);
    assert_eq!(old.physical_statistics(), unread);
    assert_eq!(old.object_type(payload).unwrap(), (7, 1));
    let before = old.physical_statistics();
    assert_eq!(old.cached_object_type(payload).unwrap(), Some((7, 1)));
    assert_eq!(old.object_type(payload).unwrap(), (7, 1));
    assert_eq!(old.physical_statistics(), before);
    // The decoded value cannot fit, so this hit retained only authentication
    // metadata. A different expected ID or locator must still be read/checked.
    let mut wrong = payload;
    wrong.hash.0[0] ^= 1;
    assert!(old.object_type(wrong).is_err());
    wrong = payload;
    wrong.address.offset += 1;
    assert!(old.object_type(wrong).is_err());
    let later = store.put(7, 1, b"later type", &[]).unwrap();
    let next = snapshot(&mut store, b"type cache new head");
    store.publish(next).unwrap();
    assert_eq!(store.object_type(later).unwrap(), (7, 1));
    assert!(old.object_type(later).is_err());
    assert!(old.cached_object_type(later).is_err());
    assert!(
        store.cache_usage().decoded_bytes + store.cache_usage().pinned_metadata_bytes <= 64 * 1024
    );
}

#[test]
fn small_frame_windows_coalesce_reads_but_keep_hash_and_old_pin_fences() {
    let (_directory, mut store) = store();
    let mut references = Vec::new();
    for i in 0..128u64 {
        let mut bytes = vec![0; 96];
        bytes[..8].copy_from_slice(&i.to_le_bytes());
        references.push(store.put(7, 1, &bytes, &[]).unwrap());
    }
    let root = snapshot(&mut store, b"metadata windows");
    store.publish(root).unwrap();
    let old = store.pin().unwrap();
    old.clear_decoded_cache();
    let before = old.physical_statistics();
    for (i, reference) in references.iter().enumerate() {
        let object = old.get(*reference).unwrap();
        assert_eq!(&object.bytes[..8], &(i as u64).to_le_bytes());
    }
    let after = old.physical_statistics();
    assert!(
        after.read_operations - before.read_operations < 32,
        "{before:?} -> {after:?}"
    );
    assert!(after.read_bytes - before.read_bytes < 64 * 1024);
    let usage = store.cache_usage();
    assert!(usage.decoded_bytes + usage.pinned_metadata_bytes <= usage.budget);
    let mut wrong = references[0];
    wrong.hash = references[1].hash;
    assert!(old.get(wrong).is_err());
    let later = store.put(7, 1, b"later immutable bytes", &[]).unwrap();
    let next = snapshot(&mut store, b"new head");
    store.publish(next).unwrap();
    let new = store.pin().unwrap();
    new.clear_decoded_cache();
    assert_eq!(new.get(later).unwrap().bytes, b"later immutable bytes");
    assert!(old.get(later).is_err());
    assert_eq!(old.get(references[0]).unwrap().bytes, vec![0; 96]);
}

#[test]
fn recent_metadata_windows_reuse_large_frames_with_bounded_reads() {
    let (_directory, mut store) = store();
    let references: Vec<_> = (0..12u64)
        .map(|i| {
            let mut bytes = vec![0; 4096];
            blake3::Hasher::new()
                .update(&i.to_le_bytes())
                .finalize_xof()
                .fill(&mut bytes);
            store.put(7, 1, &bytes, &[]).unwrap()
        })
        .collect();
    let root = snapshot(&mut store, b"recent directory pages");
    store.publish(root).unwrap();
    let reader = store.pin().unwrap();
    reader.clear_decoded_cache();
    let before = reader.physical_statistics();
    for reference in &references {
        assert_eq!(reader.get(*reference).unwrap().bytes.len(), 4096);
    }
    let after = reader.physical_statistics();
    assert!(after.read_operations - before.read_operations <= 5);
    assert!(after.read_bytes - before.read_bytes <= 128 * 1024);
    let mut wrong = references[1];
    wrong.hash = references[0].hash;
    assert!(reader.get(wrong).is_err());
    let usage = store.cache_usage();
    assert!(usage.decoded_bytes + usage.pinned_metadata_bytes <= usage.budget);
}

#[test]
fn rewrites_and_prefetch_do_not_admit_carried_child_frames() {
    let (_directory, mut store) = store();
    let children: Vec<_> = (0..64u8)
        .map(|i| store.put(7, 1, &[i; 256], &[]).unwrap())
        .collect();
    let parent = store.put(4096, 1, b"old", &children).unwrap();
    let root = snapshot(&mut store, b"carried frames");
    store.publish(root).unwrap();
    store.discard_disposable_caches();
    let source = store.rewrite_source(parent).unwrap().unwrap();
    store.rewrite(&source, 4096, 1, b"new", &children).unwrap();
    {
        let mut cache = store.cache.lock().unwrap();
        for child in &children {
            assert!(!cache.verified(store.file_identity, *child));
        }
    }
    store.put(4096, 1, b"strict", &children).unwrap();
    let mut cache = store.cache.lock().unwrap();
    for child in &children {
        assert!(cache.verified(store.file_identity, *child));
    }
}

#[test]
fn cancellation_after_private_publication_prevents_visible_replacement() {
    use resources::{ArchiveBuilder, Limits, path_from_str};
    fn edit(store: &mut NativeStore, value: &[u8]) -> ObjectRef {
        let mut builder = if let Some(snapshot) = store.reader().snapshot() {
            let directory = store.get(snapshot).unwrap().children[0];
            ArchiveBuilder::from_directory(store, directory, Limits::default())
        } else {
            let mut builder = ArchiveBuilder::new(store);
            let mut retained = vec![0; 128 << 10];
            blake3::Hasher::new().finalize_xof().fill(&mut retained);
            builder
                .add_file(&path_from_str("retained").unwrap(), &retained)
                .unwrap();
            builder
        };
        builder
            .set_file(
                &path_from_str("value").unwrap(),
                value,
                cbor::Value::Map(vec![]),
            )
            .unwrap();
        builder.finish().unwrap()
    }
    let (directory, mut store) = store();
    let first = edit(&mut store, b"old");
    store.publish(first).unwrap();
    let mut job = store.begin_compaction().unwrap();
    job.copy().unwrap();
    let next = edit(&mut store, b"acknowledged");
    let selected = store.publish(next).unwrap();
    let identity = store.file_identity;
    let counters = store.io.clone();
    let before = store.publication_statistics();
    let result = store.finish_compaction_pinned_cancellable(job, &|| {
        counters.publications.lock().unwrap().compaction_completed > before.compaction_completed
    });
    assert!(matches!(
        result,
        Err(Error::Io(ref error)) if error.kind() == std::io::ErrorKind::Interrupted
    ));
    assert_eq!(store.root().unwrap(), selected);
    assert_eq!(store.file_identity, identity);
    assert_eq!(
        NativeStore::open(directory.path().join("db.sac"), false)
            .unwrap()
            .root()
            .unwrap(),
        selected
    );
    let attempt = store.last_compaction_attempt_statistics().unwrap();
    assert!(attempt.catch_up_total_write_bytes > 0);
    assert!(attempt.peak_aggregate_temporary_bytes > 0);
    let after = store.publication_statistics();
    assert_eq!(after.compaction_completed - before.compaction_completed, 1);
    assert_eq!(after.chunk_barriers - before.chunk_barriers, 1);
    assert_eq!(after.slot_syncs - before.slot_syncs, 1);
    let next = edit(&mut store, b"still writable");
    store.publish(next).unwrap();
    assert!(store.begin_compaction().is_ok());
}

fn staged_rewrite_branch(store: &mut NativeStore) -> (ObjectRef, Vec<ObjectRef>) {
    let mut children = Vec::new();
    let mut fences = Vec::new();
    for n in 0..32u64 {
        let name = format!("file-{n:04}").into_bytes();
        let mut data = vec![0; 8192];
        let mut seed = blake3::Hasher::new();
        seed.update(&n.to_le_bytes());
        seed.finalize_xof().fill(&mut data);
        let row = cbor::Value::Array(vec![
            cbor::Value::Bytes(name.clone()),
            cbor::Value::Uint(0),
            cbor::Value::Map(Vec::new()),
            cbor::Value::Array(vec![
                cbor::Value::Uint(8192),
                cbor::Value::Uint(0),
                cbor::Value::Bytes(data),
            ]),
        ]);
        children.push(
            store
                .put(3, 1, &cbor::encode(&cbor::Value::Array(vec![row])), &[])
                .unwrap(),
        );
        fences.push(cbor::Value::Array(vec![
            cbor::Value::Bytes(name),
            cbor::Value::Uint(n),
        ]));
    }
    let body = cbor::encode(&cbor::Value::Array(vec![
        cbor::Value::Uint(1),
        cbor::Value::Array(fences),
    ]));
    let parent = store.put(4, 1, &body, &children).unwrap();
    (parent, children)
}

#[test]
fn staged_rewrite_carries_exact_edges_without_promoting_child_authentication() {
    let (_dir, mut store) = store();
    let initial = snapshot(&mut store, b"published base");
    store.publish(initial).unwrap();
    let old = store.pin().unwrap();
    let (parent, children) = staged_rewrite_branch(&mut store);
    assert!(
        old.get(parent).is_err(),
        "an old pin cannot acquire staged bytes"
    );
    store.cache.lock().unwrap().clear();
    let source = store.rewrite_source(parent).unwrap().unwrap();
    let before = store.physical_statistics();
    let result = store
        .rewrite(&source, 4, 1, &source.object.bytes, &children)
        .unwrap();
    let checked = store.physical_statistics().read_bytes - before.read_bytes;
    assert_eq!(result, parent);
    assert_eq!(
        checked,
        u64::from(parent.address.length),
        "one exact parent auth, no child body reads"
    );
    {
        let mut cache = store.cache.lock().unwrap();
        for child in &children {
            assert!(!cache.verified(store.file_identity, *child));
        }
    }
    let before = store.physical_statistics();
    assert_eq!(
        store.put(4, 1, &source.object.bytes, &children).unwrap(),
        parent
    );
    let strict = store.physical_statistics().read_bytes - before.read_bytes;
    assert_eq!(
        strict, 0,
        "the append index admits each child of an ordinary put"
    );
    {
        let mut cache = store.cache.lock().unwrap();
        for child in &children {
            assert!(!cache.verified(store.file_identity, *child));
        }
    }
    // A new physical edge never inherits the old edge's authentication.
    let mut wrong = children.clone();
    wrong[0].hash = children[1].hash;
    let end = store.end;
    assert!(
        store
            .rewrite(&source, 4, 1, &source.object.bytes, &wrong)
            .is_err()
    );
    let mut cycle = children;
    cycle[0].address.offset = store.end;
    assert!(
        store
            .rewrite(&source, 4, 1, &source.object.bytes, &cycle)
            .is_err()
    );
    assert_eq!(store.end, end);
    store.discard_disposable_caches();
    assert!(
        store.rewrite_source(parent).unwrap().is_none(),
        "lost provenance uses strict fallback"
    );
}

#[test]
fn byte_appends_preserve_decoded_pages_until_payloads_are_read() {
    let (_dir, mut store) = store();
    let page = snapshot(&mut store, b"decoded directory");
    store.publish(page).unwrap();
    store.set_decoded_cache_budget(64 * 1024);
    store.cache.lock().unwrap().clear();
    store.get_verified_shared(page).unwrap();

    let mut last = None;
    for index in 0..24u8 {
        last = Some(store.put(7, 1, &[index; 8192], &[]).unwrap());
    }
    let payload = last.unwrap();
    assert!(store.cache.get(store.file_identity, page).is_some());
    assert!(store.cache.get(store.file_identity, payload).is_none());
    assert_eq!(store.cached_object_type(payload).unwrap(), Some((7, 1)));

    let before = store.physical_statistics().read_operations;
    store.put(4096, 1, b"parent", &[payload]).unwrap();
    assert_eq!(store.physical_statistics().read_operations, before);
    assert_eq!(store.get(payload).unwrap().bytes, [23; 8192]);
    assert!(store.cache.get(store.file_identity, payload).is_some());
}

#[test]
fn borrowed_child_authentication_survives_spill_cache_pressure_and_publication() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let (dir, mut store) = store();
    // Exercise overflow deliberately; the default resident budget fits this
    // small database and must not spill merely because it has 2,048 IDs.
    store
        .set_append_index_memory_budget(512 + 256 * 2048)
        .unwrap();
    let references: Vec<_> = (9..25u8)
        .map(|i| store.put(7, 1, &[i; 16 * 1024], &[]).unwrap())
        .collect();
    let root = snapshot(&mut store, b"base with inherited child");
    let initial = store.publish(root).unwrap();
    let old = store.pin().unwrap();
    store.discard_disposable_caches();
    store.set_decoded_cache_budget(4 * 1024);

    let stop = AtomicBool::new(false);
    let started = std::sync::Barrier::new(5);
    let reads = std::thread::scope(|scope| {
        let readers: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    started.wait();
                    let archive =
                        resources::ArchiveReader::open(&old, root, resources::Limits::default())
                            .unwrap();
                    let entry = archive.open_file(&[b"file".to_vec()]).unwrap().unwrap();
                    let mut bytes = [0; 25];
                    let mut count = 0;
                    while count < 8 || (count < 4096 && !stop.load(Ordering::Acquire)) {
                        entry.read_into(0, &mut bytes).unwrap();
                        assert_eq!(&bytes, b"base with inherited child");
                        count += 1;
                    }
                    count
                })
            })
            .collect();
        started.wait();
        let result = (|| -> Result<()> {
            for i in 0..10_000u64 {
                let child = references[i as usize % references.len()];
                let put = store.put(4096, 1, &i.to_le_bytes(), &[child])?;
                if i % 1000 == 999 {
                    let head = snapshot(&mut store, &i.to_le_bytes());
                    store.publish(head)?;
                    let pin = store.pin()?;
                    assert_eq!(pin.get(put)?.children, [child]);
                    assert!(old.get(put).is_err());
                }
            }
            Ok(())
        })();
        stop.store(true, Ordering::Release);
        let reads: usize = readers
            .into_iter()
            .map(|reader| reader.join().unwrap())
            .sum();
        result.unwrap();
        reads
    });
    assert!(reads >= 32);
    let spilled = store.recent.0.disk_bytes().unwrap();
    assert!(spilled > 0);
    assert!(store.temporary_bytes().unwrap() >= spilled);
    assert_eq!(store.root().unwrap().generation, initial.generation + 10);
    let child = references[0];
    let mut wrong = child;
    wrong.hash.0[0] ^= 1;
    let end = store.end;
    assert!(store.put(4096, 1, b"wrong child", &[wrong]).is_err());
    assert_eq!(store.end, end);

    // Reopen with an empty append index and no decoded payload residency.
    drop(store);
    let mut reopened = NativeStore::open(dir.path().join("db.sac"), true).unwrap();
    reopened.set_decoded_cache_budget(0);
    let before = reopened.physical_statistics().read_operations;
    let put = reopened.put(4096, 1, b"reopened", &[child]).unwrap();
    assert_eq!(reopened.physical_statistics().read_operations, before + 1);
    assert_eq!(reopened.get(put).unwrap().children, [child]);
    NativeReader::open(dir.path().join("db.sac"))
        .unwrap()
        .validate()
        .unwrap();
}

#[test]
fn put_admits_appended_children_without_a_read_until_the_index_is_gone() {
    let (dir, mut store) = store();
    let base = snapshot(&mut store, b"base");
    store.publish(base).unwrap();
    let children: Vec<_> = (0..64u8)
        .map(|n| store.put(7, 1, &[n; 4096], &[]).unwrap())
        .collect();
    store.cache.lock().unwrap().clear();
    let before = store.physical_statistics();
    store.put(4096, 1, b"parent", &children).unwrap();
    assert_eq!(
        store.physical_statistics().read_operations,
        before.read_operations,
        "each child is a frame that this writer appended"
    );
    // Only the complete reference is in the index. The same hash at another
    // frame, a shorter frame and another hash at the same frame are read,
    // and the read rejects them.
    let end = store.end;
    let mut moved = children.clone();
    moved[0].address = children[1].address;
    assert!(store.put(4096, 1, b"moved", &moved).is_err());
    let mut shorter = children.clone();
    shorter[0].address.length -= 1;
    assert!(store.put(4096, 1, b"shorter", &shorter).is_err());
    let mut renamed = children.clone();
    renamed[0].hash = children[1].hash;
    assert!(store.put(4096, 1, b"renamed", &renamed).is_err());
    assert_eq!(store.end, end, "a rejected put appends nothing");
    assert!(
        store.physical_statistics().read_operations > before.read_operations,
        "a reference that the index does not have is read"
    );
    // Without the index, the writer reads each child and records it.
    store.discard_disposable_caches();
    let before = store.physical_statistics();
    store.put(4096, 1, b"after discard", &children).unwrap();
    assert!(store.physical_statistics().read_bytes > before.read_bytes);
    {
        let mut cache = store.cache.lock().unwrap();
        for child in &children {
            assert!(cache.verified(store.file_identity, *child));
        }
    }
    // A writer that opens the file did not append these frames.
    let next = snapshot(&mut store, b"next");
    store.publish(next).unwrap();
    drop(store);
    let mut reopened = NativeStore::open(dir.path().join("db.sac"), true).unwrap();
    let before = reopened.physical_statistics();
    reopened.put(4096, 1, b"reopened", &children).unwrap();
    assert!(reopened.physical_statistics().read_bytes > before.read_bytes);
}

#[test]
fn reference_authentication_survives_payload_eviction_but_checks_exact_pin_bounds() {
    let (_dir, mut store) = store();
    let base = snapshot(&mut store, b"base");
    store.publish(base).unwrap();
    let old = store.pin().unwrap();
    let payload = store
        .put(65000, 1, &vec![17; 2 * 1024 * 1024], &[])
        .unwrap();
    store.validate_reference(payload).unwrap();
    // Drop the decoded bytes while keeping the independently budgeted exact
    // physical authentication. No payload read is necessary for reuse.
    store.cache.lock().unwrap().remove(&(
        store.file_identity,
        payload.hash,
        payload.address.offset,
        payload.address.length,
    ));
    let before = store.physical_statistics();
    for _ in 0..32 {
        store.validate_reference(payload).unwrap();
    }
    // Deduplication consumes the exact authenticated occurrence too. A new
    // parent must not reload this large, already admitted child, and putting
    // the same payload must not reload the candidate just to return its ref.
    store.put(65001, 1, b"parent", &[payload]).unwrap();
    assert_eq!(
        store
            .put(65000, 1, &vec![17; 2 * 1024 * 1024], &[])
            .unwrap(),
        payload
    );
    assert_eq!(store.physical_statistics().read_bytes, before.read_bytes);
    assert!(old.validate_reference(payload).is_err());
    let mut wrong = payload;
    wrong.hash.0[0] ^= 1;
    assert!(store.validate_reference(wrong).is_err());
    wrong = payload;
    wrong.address.offset += 8;
    assert!(store.validate_reference(wrong).is_err());
    // Disposable authentication loss restores full frame admission.
    store.discard_disposable_caches();
    let before = store.physical_statistics();
    store.validate_reference(payload).unwrap();
    assert!(store.physical_statistics().read_bytes > before.read_bytes);
}

#[test]
fn staged_rewrite_rejects_changed_physical_layout_even_after_capability_issue() {
    let (_dir, mut store) = store();
    let (parent, children) = staged_rewrite_branch(&mut store);
    // Copy an identical leaf before another parent, then materialize a valid
    // alternate locator table under that parent's SAME canonical ID/full ref.
    let duplicate = store
        .append_object(store.get(children[0]).unwrap())
        .unwrap();
    let object = store.get(parent).unwrap();
    let second = store.put(4, 1, &object.bytes, &object.children).unwrap();
    assert_eq!(second, parent);
    // The earlier parent cannot point forward; append a fresh equivalent parent
    // explicitly so the alternate locator is valid and backward ordered.
    let later = store.append_object(object.clone()).unwrap();
    let source = store.rewrite_source(later).unwrap().unwrap();
    let mut changed = object;
    changed.children[0] = duplicate;
    assert_eq!(changed.hash(), later.hash);
    let frame = wire::encode_frame(&changed, store.compression_level).unwrap();
    assert_eq!(frame.len(), later.address.length as usize);
    flush_append(&store.file, &store.append_buffer).unwrap();
    write_at(store.file.get_mut().unwrap(), &frame, later.address.offset).unwrap();
    // Force a valuable waiver; with already verified children ordinary strict
    // admission is the cheaper, equally safe fallback and needs no parent read.
    store.cache.lock().unwrap().clear();
    let end = store.end;
    assert!(
        store
            .rewrite(&source, 4, 1, &source.object.bytes, &source.object.children)
            .is_err()
    );
    assert_eq!(store.end, end);
    store.cache.lock().unwrap().clear();
    assert!(
        store.rewrite_source(later).is_err(),
        "wire auth alone cannot mint changed-layout provenance"
    );
    let mut relocated = later;
    relocated.address.offset -= 8;
    assert!(store.rewrite_source(relocated).unwrap().is_none());
    let _ = source;
}

#[test]
fn staged_rewrite_is_bound_to_writer_extent_path_and_reopen_generation() {
    let (dir, mut first) = store();
    let base = snapshot(&mut first, b"durable base");
    first.publish(base).unwrap();
    let (parent, _) = staged_rewrite_branch(&mut first);
    let source = first.rewrite_source(parent).unwrap().unwrap();
    let (_other_dir, mut other) = store();
    let before = other.end;
    assert!(
        other
            .rewrite(&source, 4, 1, &source.object.bytes, &source.object.children)
            .is_err()
    );
    assert_eq!(other.end, before);
    // Simulate a rollback pin without changing disk bytes: captured extent may
    // not be reused below the source's admitted end.
    let end = first.end;
    first.end = first.reader.committed_end();
    assert!(
        first
            .rewrite(&source, 4, 1, &source.object.bytes, &source.object.children)
            .is_err()
    );
    first.end = end;
    drop(first);
    let mut reopened = NativeStore::open(dir.path().join("db.sac"), true).unwrap();
    let before = reopened.end;
    assert!(
        reopened
            .rewrite(&source, 4, 1, &source.object.bytes, &source.object.children)
            .is_err()
    );
    assert_eq!(reopened.end, before);
    let (new_parent, _) = staged_rewrite_branch(&mut reopened);
    let new_source = reopened.rewrite_source(new_parent).unwrap().unwrap();
    reopened.poisoned = true;
    assert!(matches!(
        reopened.rewrite(
            &new_source,
            4,
            1,
            &new_source.object.bytes,
            &new_source.object.children
        ),
        Err(Error::Poisoned)
    ));
    reopened.poisoned = false;
    let path = dir.path().join("db.sac");
    std::fs::rename(&path, dir.path().join("replaced.sac")).unwrap();
    std::fs::write(&path, b"foreign replacement").unwrap();
    let before = reopened.end;
    // An unchanged staged rewrite is still local to this descriptor. The
    // publication boundary rejects the replaced destination for the batch.
    assert_eq!(
        reopened
            .rewrite(
                &new_source,
                4,
                1,
                &new_source.object.bytes,
                &new_source.object.children
            )
            .unwrap(),
        new_parent
    );
    assert_eq!(reopened.end, before);
    let next = snapshot(&mut reopened, b"rejected batch");
    assert!(reopened.publish(next).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"foreign replacement");
}

#[test]
fn staged_rewrite_tiny_edges_and_verified_children_keep_the_strict_fast_path() {
    let (_dir, mut store) = store();
    let byte = store.put(7, 1, b"x", &[]).unwrap();
    let extent = store
        .put(
            5,
            1,
            &cbor::encode(&cbor::Value::Array(vec![cbor::Value::Array(vec![
                cbor::Value::Uint(1),
                cbor::Value::Uint(0),
            ])])),
            &[byte],
        )
        .unwrap();
    let rows = [b"a".as_slice(), b"b".as_slice()]
        .iter()
        .map(|name| {
            cbor::Value::Array(vec![
                cbor::Value::Bytes(name.to_vec()),
                cbor::Value::Uint(0),
                cbor::Value::Map(Vec::new()),
                cbor::Value::Array(vec![
                    cbor::Value::Uint(1),
                    cbor::Value::Uint(1),
                    cbor::Value::Uint(0),
                ]),
            ])
        })
        .collect();
    let tiny = store
        .put(3, 1, &cbor::encode(&cbor::Value::Array(rows)), &[extent])
        .unwrap();
    store.cache.lock().unwrap().clear();
    let before = store.physical_statistics();
    assert!(store.rewrite_source(tiny).unwrap().is_none());
    assert_eq!(
        store.physical_statistics().read_bytes,
        before.read_bytes,
        "cheap-child fallback must not reread the parent"
    );
    let (parent, children) = staged_rewrite_branch(&mut store);
    let source = store.rewrite_source(parent).unwrap().unwrap();
    let before = store.physical_statistics();
    assert_eq!(
        store
            .rewrite(&source, 4, 1, &source.object.bytes, &children)
            .unwrap(),
        parent
    );
    assert_eq!(
        store.physical_statistics().read_bytes,
        before.read_bytes,
        "verified children need no layout waiver or parent reread"
    );
    store.cache.lock().unwrap().clear();
    for child in &children {
        store.get(*child).unwrap();
        assert_eq!(
            store
                .cache
                .lock()
                .unwrap()
                .verified_type(store.file_identity, *child),
            Some((3, 1)),
            "a decoded child retains its authenticated type after payload eviction"
        );
    }
    store.get(parent).unwrap();
    let before = store.physical_statistics();
    assert_eq!(
        store
            .rewrite(&source, 4, 1, &source.object.bytes, &children)
            .unwrap(),
        parent
    );
    assert_eq!(
        store.physical_statistics().read_bytes,
        before.read_bytes,
        "prefetched decoded children also need no layout waiver or parent reread"
    );
}

#[test]
fn compaction_finish_classifies_only_observed_deadline_interruptions() {
    let caller = std::cell::Cell::new(false);
    let cancelled = || caller.get();
    let now = Instant::now();
    let stop = CompactionFinishCancellation {
        caller: &cancelled,
        pause_started: now - Duration::from_secs(1),
        started: now,
        max_pause: Duration::from_millis(100),
        max_elapsed: Duration::from_secs(120),
        deadline_observed: std::cell::Cell::new(false),
    };
    // An OS error is not a retryable deadline merely because wall time expired.
    assert!(matches!(
        stop.classify(std::io::Error::from(std::io::ErrorKind::Interrupted).into()),
        Error::Io(ref error) if error.kind() == std::io::ErrorKind::Interrupted
    ));
    caller.set(true);
    assert!(stop.cancelled());
    assert!(matches!(stop.interruption(), Error::Io(ref error)
        if error.kind() == std::io::ErrorKind::Interrupted));
    caller.set(false);
    assert!(stop.cancelled());
    assert!(matches!(
        stop.classify(std::io::Error::from(std::io::ErrorKind::Interrupted).into()),
        Error::Limit("compaction pause or elapsed work")
    ));
    assert!(matches!(
        stop.classify(std::io::Error::from(std::io::ErrorKind::Other).into()),
        Error::Io(ref error) if error.kind() == std::io::ErrorKind::Other
    ));
    assert!(matches!(
        stop.classify(Error::Limit("other budget")),
        Error::Limit("other budget")
    ));
    let elapsed = CompactionFinishCancellation {
        caller: &cancelled,
        pause_started: now,
        started: now - Duration::from_secs(2),
        max_pause: Duration::from_secs(120),
        max_elapsed: Duration::from_secs(1),
        deadline_observed: std::cell::Cell::new(false),
    };
    assert!(elapsed.cancelled());
    assert!(matches!(
        elapsed.interruption(),
        Error::Limit("compaction pause or elapsed work")
    ));
}

#[test]
fn compaction_finish_deadline_and_caller_cancel_preserve_selected_source() {
    for caller_cancel in [false, true] {
        let (_dir, mut store) = store();
        let root = snapshot(&mut store, b"selected source");
        let selected = store.publish(root).unwrap();
        let mut job = store.begin_compaction().unwrap();
        job.copy().unwrap();
        job.budget.max_pause = Duration::from_secs(1);
        job.started = Instant::now() - Duration::from_secs(2);
        job.budget.max_elapsed = Duration::from_secs(1);
        let identity = store.file_identity;
        let result = store.finish_compaction_pinned_cancellable(job, &|| caller_cancel);
        if caller_cancel {
            assert!(matches!(result, Err(Error::Io(ref error))
                if error.kind() == std::io::ErrorKind::Interrupted));
        } else {
            assert!(matches!(
                result,
                Err(Error::Limit("compaction pause or elapsed work"))
            ));
        }
        assert_eq!(store.root().unwrap(), selected);
        assert_eq!(store.file_identity, identity);
        let next = snapshot(&mut store, b"still writable");
        store.publish(next).unwrap();
        assert!(store.begin_compaction().is_ok());
    }
}

#[test]
fn inherited_cache_miss_keeps_pending_appends_coalesced() {
    let (dir, mut store) = store();
    let prior = store.put(7, 1, b"old immutable bytes", &[]).unwrap();
    let root = snapshot(&mut store, b"old selected resource");
    store.publish(root).unwrap();
    store.set_decoded_cache_budget(0);
    let written_end = store.file.lock().unwrap().metadata().unwrap().len();
    let next = store.put(7, 1, b"pending new bytes", &[]).unwrap();
    let buffered = store.append_buffer.lock().unwrap().bytes.len();
    assert!(buffered > 0);
    assert_eq!(store.get(prior).unwrap().bytes, b"old immutable bytes");
    assert_eq!(store.append_buffer.lock().unwrap().bytes.len(), buffered);
    assert_eq!(
        store.file.lock().unwrap().metadata().unwrap().len(),
        written_end
    );
    // A cache miss that actually requests the suffix drains it before decode.
    assert_eq!(store.get(next).unwrap().bytes, b"pending new bytes");
    assert!(store.append_buffer.lock().unwrap().bytes.is_empty());
    let root = snapshot(&mut store, b"new selected resource");
    store.publish(root).unwrap();
    drop(store);
    NativeReader::open(dir.path().join("db.sac"))
        .unwrap()
        .validate()
        .unwrap();
}

#[test]
fn appended_payload_copies_read_back_without_io() {
    let (_dir, mut store) = store();
    // Off by default: reading a payload append back is physical.
    let cold = store.put(65000, 1, b"cold payload", &[]).unwrap();
    let before = store.physical_statistics();
    assert_eq!(store.get(cold).unwrap().bytes, b"cold payload");
    assert!(store.physical_statistics().read_bytes > before.read_bytes);
    assert_eq!(store.writer_read_statistics().copies_kept, 0);

    store.set_appended_payload_budget(1 << 20);
    let leaf = store.put(7, 1, b"byte leaf", &[]).unwrap();
    let payload = store.put(65000, 2, b"warm payload", &[leaf]).unwrap();
    let before = store.physical_statistics();
    let reads = store.writer_read_statistics();
    let object = store.get_verified_shared(payload).unwrap();
    assert_eq!((object.kind, object.version), (65000, 2));
    assert_eq!(object.bytes, b"warm payload");
    assert_eq!(object.children, [leaf]);
    assert!(Arc::ptr_eq(
        &object,
        &store.get_verified_shared(payload).unwrap()
    ));
    assert_eq!(store.get(leaf).unwrap().bytes, b"byte leaf");
    assert_eq!(store.cached_object_type(payload).unwrap(), Some((65000, 2)));
    store.validate_reference(payload).unwrap();
    assert_eq!(store.physical_statistics(), before);
    let counted = store.writer_read_statistics();
    assert_eq!(counted.copy_hits - reads.copy_hits, 3);
    assert_eq!(counted.file_reads, reads.file_reads);
    assert_eq!(counted.copies_kept, 2);
    // Only the exact occurrence, and the shared cache holds no payload copy.
    let mut other = payload;
    other.address.length -= 8;
    assert_eq!(store.cached_object_type(other).unwrap(), None);
    assert!(store.cache.get(store.file_identity, payload).is_none());
    // A caller keeping frames is served by the copy. A small object's copy
    // has no compressed bytes, so a frame-keeping destination encodes it.
    let verified = store.verified_object(payload).unwrap();
    assert!(Arc::ptr_eq(&verified.object, &object));
    assert!(verified.compressed.is_none());
    assert_eq!(store.physical_statistics(), before);
    assert_eq!(
        store.writer_read_statistics().file_reads,
        counted.file_reads
    );
    // A large object's copy keeps the frame's compressed bytes, charged to
    // the budget; a native destination stores them again.
    let text = b"a large compressible payload ".repeat(200);
    let kept = store.writer_read_statistics().copy_bytes;
    let large_payload = store.put(65000, 6, &text, &[leaf]).unwrap();
    let before = store.physical_statistics();
    let verified = store.verified_object(large_payload).unwrap();
    assert_eq!(store.physical_statistics(), before);
    assert_eq!(verified.object().bytes, text);
    let compressed = verified.compressed.clone().unwrap();
    assert!(compressed.len() < text.len() / 4);
    assert_eq!(
        store.writer_read_statistics().copy_bytes - kept,
        (text.len() + std::mem::size_of::<ObjectRef>() + compressed.len() + DECODED_ENTRY_METADATA)
            as u64
    );
    // The destination compresses at another level, so equal bytes on reread
    // are the source's frame stored again rather than a fresh encoding. A
    // level-0 destination keeps every object raw and drops them.
    let other_dir = tempfile::tempdir().unwrap();
    let mut destination =
        NativeStore::create_live(other_dir.path().join("db.sac"), [3; 16]).unwrap();
    destination.set_compression_level(crate::BULK_COMPRESSION_LEVEL);
    let leaf_copy = destination
        .put_verified(&store.verified_object(leaf).unwrap(), &[])
        .unwrap();
    let copied = destination.put_verified(&verified, &[leaf_copy]).unwrap();
    destination.discard_disposable_caches();
    let reread = destination.verified_object(copied).unwrap();
    assert_eq!(reread.object().bytes, text);
    assert_eq!(reread.compressed, Some(compressed.clone()));
    // A closure copy of the writer's new objects reads none of them back.
    let mut portable = MemoryStore::sealed();
    let copied = ClosureCopy::new()
        .unwrap()
        .copy_root(&store, &mut portable, large_payload)
        .unwrap();
    assert_eq!(store.physical_statistics(), before);
    assert_eq!(portable.get(copied).unwrap().bytes, text);

    // Payloads over 64 KiB are read back from the file.
    let large = vec![5; 70 * 1024];
    let big = store.put(65000, 5, &large, &[]).unwrap();
    assert_eq!(store.writer_read_statistics().copies_skipped, 1);
    let before = store.physical_statistics();
    assert_eq!(store.get(big).unwrap().bytes, large);
    assert!(store.physical_statistics().read_bytes > before.read_bytes);

    // The budget evicts the oldest copies and refuses no append.
    store.set_appended_payload_budget(DECODED_ENTRY_METADATA + 64);
    let first = store.put(65000, 3, b"first", &[]).unwrap();
    let second = store.put(65000, 3, b"second", &[]).unwrap();
    assert!(store.writer_read_statistics().copies_evicted >= 2);
    let before = store.physical_statistics();
    assert_eq!(store.get(second).unwrap().bytes, b"second");
    assert_eq!(store.physical_statistics(), before);
    assert_eq!(store.get(first).unwrap().bytes, b"first");
    assert!(store.physical_statistics().read_bytes > before.read_bytes);

    // Copies outlive a publication; discarding disposable caches ends them.
    store.set_appended_payload_budget(1 << 20);
    let late = store.put(65000, 4, b"late", &[]).unwrap();
    let root = snapshot(&mut store, b"published");
    store.publish(root).unwrap();
    let before = store.physical_statistics();
    assert_eq!(store.get(late).unwrap().bytes, b"late");
    assert_eq!(store.physical_statistics(), before);
    store.discard_disposable_caches();
    assert_eq!(store.get(late).unwrap().bytes, b"late");
    assert!(store.physical_statistics().read_bytes > before.read_bytes);
    // The large copy kept the same compressed bytes as its frame in the file.
    let file = store.verified_object(large_payload).unwrap();
    assert_eq!(file.object().bytes, text);
    assert_eq!(file.compressed, Some(compressed));
    store.validate().unwrap();
}
