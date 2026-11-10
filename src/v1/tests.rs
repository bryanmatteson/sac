use super::*;
use cbor::Value;

#[test]
fn canonical_size_validation_matches_writer_boundaries() {
    let mut object = CanonicalObject {
        kind: 65000,
        version: 1,
        bytes: vec![0; MAX_CHUNK_SIZE - 8],
        children: vec![],
    };
    object.validate_size().unwrap();
    object.bytes.push(0);
    assert!(matches!(
        object.validate_size(),
        Err(Error::Limit("canonical object"))
    ));
    object.bytes.clear();
    object.children = vec![ObjectRef::default(); MAX_CHILDREN];
    object.validate_size().unwrap();
    object.children.push(ObjectRef::default());
    assert!(matches!(
        object.validate_size(),
        Err(Error::Limit("canonical object"))
    ));
    object.children.truncate(1);
    object.bytes = vec![0; MAX_CHUNK_SIZE - 8 - 32];
    object.validate_size().unwrap();
    object.bytes.push(0);
    assert!(matches!(
        object.validate_size(),
        Err(Error::Limit("canonical object"))
    ));
}

fn snapshot(store: &mut impl ObjectStore) -> ObjectRef {
    let directory = store.put(3, 1, &[0x80], &[]).unwrap();
    resources::snapshot(store, directory, vec![], vec![]).unwrap()
}

#[test]
fn canonical_identity_ignores_physical_locations() {
    let child = ObjectRef {
        hash: ObjectHash::digest(b"child"),
        address: ChunkAddress {
            offset: 128,
            length: 64,
        },
    };
    let mut object = CanonicalObject {
        kind: 42,
        version: 1,
        bytes: b"body".to_vec(),
        children: vec![child],
    };
    let hash = object.hash();
    object.children[0].address.offset = 4096;
    assert_eq!(hash, object.hash());
    assert_eq!(object.canonical_len(), 44);
    assert_ne!(hash, ObjectHash::digest(&object.canonical_bytes()));
}

#[test]
fn sealed_export_is_exact_reachable_closure_and_two_reads() {
    let mut source = MemoryStore::sealed();
    source.put(42, 1, b"unreachable", &[]).unwrap();
    let root = snapshot(&mut source);
    let publication = source.publish(root).unwrap();
    let reader = source.reader().unwrap();
    assert_eq!(reader.snapshot().unwrap().hash, root.hash);
    assert_eq!(publication.generation, 1);
    assert_eq!(source.validate().unwrap().objects, 3);
    // Empty directory, snapshot, commit, preamble and trailer; no duplicate controls.
    let expected = 128 + 72 + 112 + 112 + 160;
    assert_eq!(source.as_bytes().len(), expected);
    struct Count<'a> {
        bytes: &'a [u8],
        reads: std::cell::Cell<usize>,
    }
    impl ReadAt for Count<'_> {
        fn len(&self) -> Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<()> {
            self.reads.set(self.reads.get() + 1);
            self.bytes.read_exact_at(offset, bytes)
        }
    }
    let count = Count {
        bytes: source.as_bytes(),
        reads: std::cell::Cell::new(0),
    };
    Reader::open_at(&count).unwrap();
    assert_eq!(count.reads.get(), 2);
    let mut trailing = source.as_bytes().to_vec();
    trailing.push(0);
    assert!(Reader::open_at(&trailing).is_err());
}

#[test]
fn live_publications_pin_immutable_extents_and_ignore_tail() {
    let mut source = MemoryStore::new(Header::new([1; 16], [2; 16]));
    let root = snapshot(&mut source);
    let first = source.publish(root).unwrap();
    let pinned = source.reader().unwrap();
    let second = source.publish(root).unwrap();
    assert_eq!(second.generation, 2);
    source.bytes.extend_from_slice(b"incomplete append");
    assert_eq!(source.reader().unwrap().publication, Some(second));
    assert_eq!(pinned.publication, Some(first));
    assert_eq!(pinned.get_at(&source.bytes, first.root).unwrap().kind, 1);
    assert!(pinned.request(second.root).is_err());
}

#[test]
fn damaged_latest_slot_is_reported_and_older_publication_recovered() {
    let mut source = MemoryStore::new(Header::new([1; 16], [2; 16]));
    let root = snapshot(&mut source);
    let first = source.publish(root).unwrap();
    source.publish(root).unwrap();
    source.bytes[PAGE_SIZE + 100] ^= 1;
    let reader = source.reader().unwrap();
    assert_eq!(reader.publication, Some(first));
    assert_eq!(reader.recovery_diagnostics, vec!["damaged slot 0"]);
    // An authentic but contradictory slot must never be treated as a torn write.
    let header = source.header;
    let bad = Slot {
        preamble_digest: header.digest(),
        generation: 2,
        trailer_offset: first.committed_end - 160,
        trailer_digest: ObjectHash::default(),
    };
    source.bytes[PAGE_SIZE..2 * PAGE_SIZE].copy_from_slice(&bad.encode());
    assert!(source.reader().is_err());
}

#[test]
fn four_byte_magic_preserves_layout_and_requires_zero_reserved_bytes() {
    assert_eq!(wire::MAGIC, *b"SAC1");
    for preamble in [Preamble::sealed(), Preamble::live([3; 16]).unwrap()] {
        let bytes = preamble.encode();
        assert_eq!(bytes.len(), 128);
        assert_eq!(&bytes[..4], b"SAC1");
        assert_eq!(&bytes[4..8], &[0; 4]);
        assert_eq!(bytes[8], u8::from(preamble.policy == LocatorPolicy::Live));
        assert_eq!(Preamble::decode(&bytes).unwrap(), preamble);
        for offset in 4..8 {
            let mut corrupt = bytes;
            corrupt[offset] = 1;
            let digest = domain_hash(b"SAC1/preamble\0", &corrupt[..96]);
            corrupt[96..].copy_from_slice(&digest.0);
            assert!(
                matches!(Preamble::decode(&corrupt), Err(Error::Corrupt(reason)) if reason == "preamble reserved")
            );
        }
        let mut old_signature = bytes;
        old_signature[4..8].copy_from_slice(b"\r\n\x1a\n");
        let digest = domain_hash(b"SAC1/preamble\0", &old_signature[..96]);
        old_signature[96..].copy_from_slice(&digest.0);
        assert!(
            matches!(Preamble::decode(&old_signature), Err(Error::Corrupt(reason)) if reason == "preamble reserved")
        );
    }
    assert!(Preamble::decode(b"SAC1").is_err());
}

#[test]
fn slot_and_trailer_bind_policy_incarnation_generation_extent() {
    let preamble = Preamble::live([3; 16]).unwrap();
    assert!(Preamble::live([0; 16]).is_err());
    assert_eq!(Preamble::decode(&preamble.encode()).unwrap(), preamble);
    let slot = Slot {
        preamble_digest: preamble.digest(),
        generation: 1,
        trailer_offset: 13000,
        trailer_digest: ObjectHash::digest(b"trailer"),
    };
    assert_eq!(
        Slot::decode(&slot.encode(), &preamble, 1).unwrap(),
        Some(slot)
    );
    assert!(Slot::decode(&slot.encode(), &preamble, 0).is_err());
    assert!(Slot::decode(&slot.encode(), &Preamble::live([4; 16]).unwrap(), 1).is_err());
}

#[test]
fn frame_decoder_rejects_padding_header_hash_and_forward_edges() {
    let object = CanonicalObject {
        kind: 42,
        version: 1,
        bytes: vec![1],
        children: vec![],
    };
    let frame = encode_frame(&object, 0).unwrap();
    let reference = ObjectRef {
        hash: object.hash(),
        address: ChunkAddress {
            offset: 128,
            length: frame.len() as u32,
        },
    };
    assert_eq!(decode_frame(reference, &frame, 128, 1024).unwrap(), object);
    let mut bad = frame.clone();
    *bad.last_mut().unwrap() = 1;
    assert!(decode_frame(reference, &bad, 128, 1024).is_err());
    let mut bad = frame.clone();
    bad[8] ^= 1;
    assert!(decode_frame(reference, &bad, 128, 1024).is_err());
    let mut bad = reference;
    bad.hash.0[0] ^= 1;
    assert!(decode_frame(bad, &frame, 128, 1024).is_err());
    let parent = CanonicalObject {
        kind: 42,
        version: 1,
        bytes: vec![],
        children: vec![reference],
    };
    let bytes = encode_frame(&parent, 0).unwrap();
    let r = ObjectRef {
        hash: parent.hash(),
        address: ChunkAddress {
            offset: 128,
            length: bytes.len() as u32,
        },
    };
    assert!(decode_frame(r, &bytes, 128, 1024).is_err());
    assert!(
        validate_address(
            ChunkAddress {
                offset: u64::MAX - 7,
                length: 64
            },
            128,
            u64::MAX
        )
        .is_err()
    );
}

#[test]
fn strict_cbor_rejects_nonminimal_duplicates_unbounded_counts_and_depth() {
    for bytes in [
        &[0x18, 0x00][..],
        &[0xa2, 0x00, 0x01, 0x00, 0x02],
        &[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        &[0xf9, 0, 0],
        &[0x9f, 0xff],
        &[0xc0, 0],
        &[0, 0],
    ] {
        assert!(cbor::decode(bytes).is_err(), "{bytes:?}");
    }
    let mut depth = vec![0x81; 65];
    depth.push(0);
    assert!(cbor::decode(&depth).is_err());
    let mut depth = vec![0x81; 64];
    depth.push(0);
    assert!(cbor::decode(&depth).is_ok());
}

#[test]
fn intrinsic_schemas_reject_unused_children_and_out_of_range_indices() {
    let child = ObjectRef {
        hash: ObjectHash::default(),
        address: ChunkAddress {
            offset: 128,
            length: 64,
        },
    };
    let mut object = CanonicalObject {
        kind: 1,
        version: 1,
        bytes: cbor::encode(&Value::Array(vec![
            Value::Uint(1),
            Value::Null,
            Value::Null,
        ])),
        children: vec![child],
    };
    assert!(validate_core_object(&object).is_err());
    object.kind = 3;
    object.bytes = vec![0x80];
    assert!(validate_core_object(&object).is_err());
    object.kind = 7;
    assert!(validate_core_object(&object).is_err());
    object.kind = 42;
    assert!(validate_core_object(&object).is_ok());
}

#[test]
fn portable_commit_keeps_attestations_drops_local_and_retains_snapshot_identity() {
    let mut source = MemoryStore::new(Header::new([1; 16], [2; 16]));
    let root = snapshot(&mut source);
    let attest = source
        .put(
            9,
            1,
            &cbor::encode(&Value::Array(vec![Value::Bytes(vec![9; 64])])),
            &[],
        )
        .unwrap();
    let local = source
        .put(
            8,
            1,
            &cbor::encode(&Value::Array(vec![
                Value::Text("org.test.local".into()),
                Value::Text("authority".into()),
                Value::Uint(1),
                Value::Bytes(b"private-local".to_vec()),
            ])),
            &[],
        )
        .unwrap();
    let commit = resources::commit(&mut source, root, Some(attest), Some(local)).unwrap();
    let bytes = pack_commit(&source, commit, Vec::new()).unwrap();
    let store = PositionalStore::open(bytes).unwrap();
    assert_eq!(store.reader().snapshot().unwrap().hash, root.hash);
    let copied = store.get(store.reader().publication.unwrap().root).unwrap();
    let body = cbor::decode(&copied.bytes).unwrap();
    assert_eq!(schema::array(&body, 3).unwrap()[2], Value::Null);
    assert_eq!(copied.children.len(), 2);
    assert_eq!(copied.children[1].hash, attest.hash);
    assert_eq!(
        validate_closure(&store, store.reader().publication.map(|p| p.root))
            .unwrap()
            .objects,
        4
    );
}

#[test]
fn generation_overflow_fails_without_publishing_slot() {
    let mut source = MemoryStore::new(Header::new([1; 16], [2; 16]));
    let root = snapshot(&mut source);
    let publication = source.publish(root).unwrap();
    source.publication = Some(Publication {
        generation: u64::MAX,
        ..publication
    });
    assert!(matches!(
        source.publish(root),
        Err(Error::Limit("generation"))
    ));
    assert_eq!(source.reader().unwrap().publication, Some(publication));
}

#[cfg(feature = "compression")]
#[test]
fn compressed_frames_decode_without_native_decoder_and_control_stays_stored() {
    let object = CanonicalObject {
        kind: 7,
        version: 1,
        bytes: vec![7; 1024 * 1024],
        children: vec![],
    };
    let bytes = encode_frame(&object, 1).unwrap();
    assert_eq!(bytes[4], 1);
    let reference = ObjectRef {
        hash: object.hash(),
        address: ChunkAddress {
            offset: 128,
            length: bytes.len() as u32,
        },
    };
    assert_eq!(
        decode_frame(reference, &bytes, 128, 128 + bytes.len() as u64).unwrap(),
        object
    );
    let mut source = MemoryStore::sealed();
    let root = snapshot(&mut source);
    source.publish(root).unwrap();
    let reader = source.reader().unwrap();
    let root = reader.publication.unwrap().root;
    assert_eq!(source.bytes[root.address.offset as usize + 4], 0);
}

#[test]
fn export_cross_implementation_vectors() {
    let Ok(directory) = std::env::var("SAC1_VECTOR_DIR") else {
        return;
    };
    let directory = std::path::Path::new(&directory);
    std::fs::create_dir_all(directory).unwrap();
    let mut source = MemoryStore::new(Header::new([11; 16], [12; 16]));
    let mut builder = resources::ArchiveBuilder::new(&mut source);
    builder
        .add_file(&[b"hello.txt".to_vec()], b"hello SAC1\n")
        .unwrap();
    builder
        .add_file(
            &[b"nested".to_vec(), b"bulk.bin".to_vec()],
            &vec![42; 16384],
        )
        .unwrap();
    let root = builder.finish().unwrap();
    source.publish(root).unwrap();
    std::fs::write(directory.join("positive-live.sac"), source.as_bytes()).unwrap();
    let bytes = pack_snapshot(&source, root, Vec::new()).unwrap();
    std::fs::write(directory.join("positive-sealed.sac"), &bytes).unwrap();
    let mut damaged = bytes.clone();
    damaged[96] ^= 1;
    std::fs::write(directory.join("negative-preamble-checksum.sac"), damaged).unwrap();
    let mut damaged = bytes.clone();
    damaged.push(0);
    std::fs::write(directory.join("negative-trailing-sealed-byte.sac"), damaged).unwrap();
    let mut damaged = bytes;
    let n = damaged.len();
    damaged[n - 1] ^= 1;
    std::fs::write(directory.join("negative-trailer-checksum.sac"), damaged).unwrap();
}

#[test]
fn salvage_checks_content_while_treating_locators_as_untrusted_hints() {
    let child = ObjectRef {
        hash: ObjectHash::digest(b"intact child identity"),
        address: ChunkAddress {
            offset: 0,
            length: 0,
        },
    };
    let object = CanonicalObject {
        kind: 42,
        version: 1,
        bytes: vec![8],
        children: vec![child],
    };
    let frame = encode_frame(&object, 0).unwrap();
    let reference = ObjectRef {
        hash: object.hash(),
        address: ChunkAddress {
            offset: 128,
            length: frame.len() as u32,
        },
    };
    assert!(decode_frame(reference, &frame, 128, 1024).is_err());
    assert_eq!(
        wire::decode_frame_salvage(reference, &frame).unwrap(),
        object
    );
    let mut bad = frame;
    bad[wire::FRAME + 8] ^= 1;
    assert!(wire::decode_frame_salvage(reference, &bad).is_err());
}

#[test]
fn independent_python_codec1_vector_decodes_without_compression_feature() {
    // Emitted by tools/test_sac1_recover.py's independent Builder (zstandard3).
    let bytes=hex::decode("534f3100010100001800000008040000f5c9ca0b4f084ade2c7082a4c02e99ac5eec14c0eb90e77cf87197cae8879ca236f009c40000000028b52ffd60080375000028070001005a0200fc41090b1001").unwrap();
    let hash = ObjectHash(
        hex::decode("f5c9ca0b4f084ade2c7082a4c02e99ac5eec14c0eb90e77cf87197cae8879ca2")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let reference = ObjectRef {
        hash,
        address: ChunkAddress {
            offset: 128,
            length: bytes.len() as u32,
        },
    };
    let object = decode_frame(reference, &bytes, 128, 128 + bytes.len() as u64).unwrap();
    assert_eq!(object.kind, 7);
    assert_eq!(object.bytes, vec![b'Z'; 1024]);
    assert!(object.children.is_empty());
    assert_eq!(object.hash(), hash);

    // Keep framing, declared decoded size and expected ID otherwise valid:
    // rejection must come from the exact single-Zstandard-frame rule.
    for suffix in [
        vec![0],
        bytes[56..80].to_vec(),
        vec![0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0],
    ] {
        let mut payload = bytes[56..80].to_vec();
        payload.extend(suffix);
        let mut altered = bytes[..56].to_vec();
        altered[8..12].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        altered[48..52].fill(0);
        let mut crc = !0u32;
        for byte in &altered {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0x82f63b78 & 0u32.wrapping_sub(crc & 1));
            }
        }
        altered[48..52].copy_from_slice(&(!crc).to_le_bytes());
        altered.extend(payload);
        altered.resize((altered.len() + 7) & !7, 0);
        let reference = ObjectRef {
            address: ChunkAddress {
                length: altered.len() as u32,
                ..reference.address
            },
            ..reference
        };
        assert!(decode_frame(reference, &altered, 128, 128 + altered.len() as u64).is_err());
    }
}

#[test]
fn core_roles_reject_wrong_optional_children_and_profile_root_bindings() {
    let mut store = MemoryStore::new(Header::new([1; 16], [2; 16]));
    let snapshot = snapshot(&mut store);
    let bytes = store
        .put(7, 1, b"not a catalogue or local record", &[])
        .unwrap();
    for body in [
        vec![Value::Uint(0), Value::Uint(1), Value::Null],
        vec![Value::Uint(0), Value::Null, Value::Uint(1)],
    ] {
        let commit = store
            .put(1, 1, &cbor::encode(&Value::Array(body)), &[snapshot, bytes])
            .unwrap();
        assert!(validate_closure(&store, Some(commit)).is_err());
        assert!(store.publish_commit(commit).is_err());
        assert!(store.root().is_none());
    }
    let directory = store.put(3, 1, &[0x80], &[]).unwrap();
    for (namespace, kind, version) in [
        ("org.test.profile", "record", 1),
        ("org.test.profile", "root", 2),
        ("org.test.other", "root", 1),
    ] {
        let profile = store
            .put(
                8,
                1,
                &cbor::encode(&Value::Array(vec![
                    Value::Text(namespace.into()),
                    Value::Text(kind.into()),
                    Value::Uint(version),
                    Value::Bytes(vec![]),
                ])),
                &[],
            )
            .unwrap();
        let root = resources::snapshot(
            &mut store,
            directory,
            vec![resources::Profile {
                id: "org.test.profile".into(),
                version: 1,
                root: profile,
            }],
            vec![],
        )
        .unwrap();
        assert!(validate_closure(&store, Some(root)).is_err());
        assert!(store.publish(root).is_err());
    }
    let wrong_directory = resources::snapshot(&mut store, bytes, vec![], vec![]).unwrap();
    assert!(validate_closure(&store, Some(wrong_directory)).is_err());
    assert!(store.publish(wrong_directory).is_err());
}

#[test]
fn verified_shared_default_rejects_untrusted_store_identity() {
    struct Untrusted;
    impl ObjectStore for Untrusted {
        fn get(&self, _: ObjectRef) -> Result<CanonicalObject> {
            Ok(CanonicalObject {
                kind: 7,
                version: 1,
                bytes: vec![],
                children: vec![],
            })
        }
        fn put(&mut self, _: u16, _: u16, _: &[u8], _: &[ObjectRef]) -> Result<ObjectRef> {
            unreachable!()
        }
    }
    assert!(Untrusted.get_verified_shared(ObjectRef::default()).is_err());
}

#[test]
fn directory_geometry_accepts_48k_inline_and_128k_leaf_only() {
    fn entry(name: u8, length: usize) -> Value {
        Value::Array(vec![
            Value::Bytes(vec![name]),
            Value::Uint(0),
            Value::Map(vec![]),
            Value::Array(vec![
                Value::Uint(length as u64),
                Value::Uint(0),
                Value::Bytes(vec![7; length]),
            ]),
        ])
    }
    let object = CanonicalObject {
        kind: 3,
        version: 1,
        bytes: cbor::encode(&Value::Array(vec![
            entry(b'a', 48 * 1024),
            entry(b'b', 48 * 1024),
        ])),
        children: vec![],
    };
    let frame = encode_frame(&object, 0).unwrap();
    assert!(frame.len() > 64 * 1024 && frame.len() <= 144 * 1024);
    let reference = ObjectRef {
        hash: object.hash(),
        address: ChunkAddress {
            offset: 128,
            length: frame.len() as u32,
        },
    };
    assert_eq!(
        decode_frame(reference, &frame, 128, 128 + frame.len() as u64).unwrap(),
        object
    );
    let oversized_inline = CanonicalObject {
        bytes: cbor::encode(&Value::Array(vec![entry(b'a', 48 * 1024 + 1)])),
        ..object.clone()
    };
    assert!(encode_frame(&oversized_inline, 0).is_err());
    let oversized_leaf = CanonicalObject {
        bytes: cbor::encode(&Value::Array(vec![
            entry(b'a', 48 * 1024),
            entry(b'b', 48 * 1024),
            entry(b'c', 48 * 1024),
        ])),
        ..object
    };
    assert!(encode_frame(&oversized_leaf, 0).is_err());
}

#[cfg(feature = "native")]
#[test]
fn native_full_validation_checks_optional_commit_child_roles() {
    let mut source = MemoryStore::sealed();
    let snapshot = snapshot(&mut source);
    let bad = source.put(7, 1, b"not a kind9 catalogue", &[]).unwrap();
    let commit = resources::commit(&mut source, snapshot, Some(bad), None).unwrap();
    // Encode an adversarial structurally valid publication without the checked writer.
    let offset = source.bytes.len() as u64;
    let trailer = Trailer {
        preamble_digest: source.header.digest(),
        generation: 1,
        committed_end: offset + 160,
        commit,
    };
    source.bytes.extend(trailer.encode());
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bad.sac");
    std::fs::write(&path, &source.bytes).unwrap();
    let reader = NativeReader::open(&path).unwrap();
    assert!(reader.validate().is_err());
    let output = directory.path().join("checked.sac");
    let mut target = NativeStore::create_live(&output, [8; 16]).unwrap();
    assert!(copy_closure(&source, &mut target, commit).is_err());
    let copied_snapshot = copy_closure(&source, &mut target, snapshot).unwrap();
    let copied_bad = target.put(7, 1, b"not a kind9 catalogue", &[]).unwrap();
    let copied = resources::commit(&mut target, copied_snapshot, Some(copied_bad), None).unwrap();
    assert!(target.publish_commit(copied).is_err());
    assert!(target.root().is_none());
    assert_eq!(target.publication_statistics().completed, 0);
    assert!(!output.exists());
}

#[test]
fn owned_byte_frame_path_matches_common_decoder_and_rejects_corruption() {
    for length in [0, 1, 1024 * 1024] {
        let object = CanonicalObject {
            kind: 7,
            version: 1,
            bytes: vec![b'X'; length],
            children: vec![],
        };
        let frame = encode_frame(&object, 0).unwrap();
        let reference = ObjectRef {
            hash: object.hash(),
            address: ChunkAddress {
                offset: 128,
                length: frame.len() as u32,
            },
        };
        assert_eq!(
            wire::decode_frame_owned(reference, frame.clone(), 128, 128 + frame.len() as u64)
                .unwrap(),
            decode_frame(reference, &frame, 128, 128 + frame.len() as u64).unwrap()
        );
        let mut content = frame.clone();
        content[wire::FRAME] ^= 1;
        assert!(
            wire::decode_frame_owned(reference, content, 128, 128 + frame.len() as u64).is_err()
        );
        let mut header = frame.clone();
        header[8] ^= 1;
        assert!(
            wire::decode_frame_owned(reference, header, 128, 128 + frame.len() as u64).is_err()
        );
        if length == 1 {
            let mut padding = frame.clone();
            *padding.last_mut().unwrap() = 1;
            assert!(
                wire::decode_frame_owned(reference, padding, 128, 128 + frame.len() as u64)
                    .is_err()
            );
        }
    }
}

#[test]
fn sealed_memory_publication_rejects_local_without_implicit_repack() {
    let mut store = MemoryStore::sealed();
    let root = snapshot(&mut store);
    let body = cbor::encode(&Value::Array(vec![
        Value::Text("org.test.local".into()),
        Value::Text("authority".into()),
        Value::Uint(1),
        Value::Bytes(vec![]),
    ]));
    let local = store.put(8, 1, &body, &[]).unwrap();
    let commit = resources::commit(&mut store, root, None, Some(local)).unwrap();
    assert!(store.publish_commit(commit).is_err());
    assert!(store.root().is_none());
    let portable = pack_commit(&store, commit, Vec::new()).unwrap();
    assert_eq!(
        Reader::open_at(&portable).unwrap().snapshot().unwrap().hash,
        root.hash
    );
}

#[test]
fn deep_profile_ancestry_verifies_and_packs_without_recursive_stack_or_payloads() {
    let mut source = MemoryStore::new(Header::new([1; 16], [7; 16]));
    let namespace = "test.deep-history";
    let mut previous = None;
    for ordinal in 0..10_001u64 {
        let body = cbor::encode(&Value::Array(vec![
            Value::Text(namespace.into()),
            Value::Text(
                if ordinal == 10_000 {
                    "root"
                } else {
                    "revision"
                }
                .into(),
            ),
            Value::Uint(1),
            Value::Bytes(ordinal.to_le_bytes().to_vec()),
        ]));
        previous = Some(
            source
                .put(8, 1, &body, &previous.into_iter().collect::<Vec<_>>())
                .unwrap(),
        );
    }
    let directory = source.put(3, 1, &[0x80], &[]).unwrap();
    let snapshot = resources::snapshot(
        &mut source,
        directory,
        vec![resources::Profile {
            id: namespace.into(),
            version: 1,
            root: previous.unwrap(),
        }],
        vec![],
    )
    .unwrap();
    let limits = resources::Limits::default();
    let reader = resources::ArchiveReader::open(&source, snapshot, limits.clone()).unwrap();
    assert!(reader.verify().unwrap().core_checked);
    assert!(validate_closure(&source, Some(snapshot)).unwrap().objects >= 10_003);
    let mut copied = MemoryStore::sealed();
    assert_eq!(
        copy_closure(&source, &mut copied, snapshot).unwrap().hash,
        snapshot.hash
    );
    let bytes = pack_snapshot_with_limits(&source, snapshot, Vec::new(), limits.clone()).unwrap();
    assert!(bytes.len() < 3 * 1024 * 1024);
    let packed = PositionalStore::open(bytes).unwrap();
    let packed_snapshot = packed.reader().snapshot().unwrap();
    assert_eq!(packed_snapshot.hash, snapshot.hash);
    assert!(
        resources::ArchiveReader::open(&packed, packed_snapshot, limits.clone())
            .unwrap()
            .verify()
            .unwrap()
            .core_checked
    );
    let mut exhausted = limits.clone();
    exhausted.max_frames = 16;
    assert!(matches!(
        resources::ArchiveReader::open(&source, snapshot, exhausted.clone())
            .unwrap()
            .verify(),
        Err(Error::Limit(_))
    ));
    assert!(matches!(
        pack_snapshot_with_limits(&source, snapshot, Vec::new(), exhausted),
        Err(Error::Limit(_))
    ));
    let mut exhausted = limits;
    exhausted.max_memory_bytes = 256 * 1024;
    assert!(matches!(
        pack_snapshot_with_limits(&source, snapshot, Vec::new(), exhausted),
        Err(Error::Limit(_))
    ));
    #[cfg(feature = "native")]
    {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("deep.sac");
        std::fs::write(&path, packed.source).unwrap();
        let native = NativeReader::open(&path).unwrap();
        assert!(native.validate().unwrap().objects >= 10_003);
    }
}

#[cfg(feature = "native")]
#[test]
fn native_resource_graph_spills_verify_and_pack_below_resident_index_size() {
    // The previous resident walker rejected 8 MiB before doing any work and
    // grows with history length. The native operation now retains a fixed
    // prefix; both the frontier and completed/remapping tables must spill.
    let temporary = tempfile::tempdir().unwrap();
    let source_path = temporary.path().join("history.sac");
    let namespace = "test.spill-history";
    let mut source = MemoryStore::new(Header::new([3; 16], [9; 16]));
    source.set_compression_level(0);
    let mut previous = None;
    for ordinal in 0..20_001u64 {
        let body = cbor::encode(&Value::Array(vec![
            Value::Text(namespace.into()),
            Value::Text(
                if ordinal == 20_000 {
                    "root"
                } else {
                    "revision"
                }
                .into(),
            ),
            Value::Uint(1),
            Value::Bytes(ordinal.to_le_bytes().to_vec()),
        ]));
        previous = Some(
            source
                .put(8, 1, &body, &previous.into_iter().collect::<Vec<_>>())
                .unwrap(),
        );
    }
    let directory = source.put(3, 1, &[0x80], &[]).unwrap();
    let snapshot = resources::snapshot(
        &mut source,
        directory,
        vec![resources::Profile {
            id: namespace.into(),
            version: 1,
            root: previous.unwrap(),
        }],
        vec![],
    )
    .unwrap();
    source.publish(snapshot).unwrap();
    std::fs::write(&source_path, source.as_bytes()).unwrap();
    drop(source);

    let source = NativeReader::open(&source_path).unwrap();
    source.set_decoded_cache_budget(1 << 20);
    let limits = resources::Limits {
        max_memory_bytes: 8 << 20,
        max_temp_bytes: 32 << 20,
        max_depth: 4,
        ..resources::Limits::default()
    };
    assert!(
        resources::ArchiveReader::open(&source, snapshot, limits.clone())
            .unwrap()
            .verify()
            .unwrap()
            .core_checked
    );
    let output_path = temporary.path().join("packed.sac");
    let output = std::fs::File::create(&output_path).unwrap();
    pack_snapshot_with_limits(&source, snapshot, output, limits.clone()).unwrap();
    let packed = NativeReader::open(&output_path).unwrap();
    packed.set_decoded_cache_budget(1 << 20);
    let packed_snapshot = packed.reader().snapshot().unwrap();
    assert_eq!(packed_snapshot.hash, snapshot.hash);
    assert!(
        resources::ArchiveReader::open(&packed, packed_snapshot, limits.clone())
            .unwrap()
            .verify()
            .unwrap()
            .core_checked
    );

    let mut exhausted = limits.clone();
    exhausted.max_temp_bytes = 0;
    assert!(matches!(
        resources::ArchiveReader::open(&source, snapshot, exhausted.clone())
            .unwrap()
            .verify(),
        Err(Error::Limit("temporary disk bytes"))
    ));
    assert!(matches!(
        pack_snapshot_with_limits(&source, snapshot, std::io::sink(), exhausted),
        Err(Error::Limit("temporary disk bytes"))
    ));
    let mut exhausted = limits;
    exhausted.max_edges = 16;
    assert!(matches!(
        resources::ArchiveReader::open(&source, snapshot, exhausted.clone())
            .unwrap()
            .verify(),
        Err(Error::Limit(_))
    ));
    assert!(matches!(
        pack_snapshot_with_limits(&source, snapshot, std::io::sink(), exhausted),
        Err(Error::Limit(_))
    ));
}

#[test]
fn cyclic_untrusted_graph_fails_authentication_instead_of_spinning() {
    struct Cyclic;
    impl ObjectStore for Cyclic {
        fn get(&self, reference: ObjectRef) -> Result<CanonicalObject> {
            Ok(CanonicalObject {
                kind: 42,
                version: 1,
                bytes: vec![],
                children: vec![reference],
            })
        }
        fn put(&mut self, _: u16, _: u16, _: &[u8], _: &[ObjectRef]) -> Result<ObjectRef> {
            unreachable!()
        }
    }
    let root = ObjectRef {
        hash: ObjectHash([3; 32]),
        address: ChunkAddress {
            offset: 128,
            length: 128,
        },
    };
    assert!(matches!(
        validate_closure(&Cyclic, Some(root)),
        Err(Error::Corrupt(_))
    ));
    assert!(matches!(
        resources::copy_snapshot(
            &Cyclic,
            &mut MemoryStore::sealed(),
            root,
            resources::Limits::default()
        ),
        Err(Error::Corrupt(_))
    ));
}

#[test]
fn shared_diamond_graph_is_verified_and_copied_once_per_physical_occurrence() {
    struct Counted<'a> {
        source: &'a MemoryStore,
        reads: std::cell::Cell<usize>,
    }
    impl ObjectStore for Counted<'_> {
        fn get(&self, r: ObjectRef) -> Result<CanonicalObject> {
            self.source.get(r)
        }
        fn get_verified_shared(&self, r: ObjectRef) -> Result<Arc<CanonicalObject>> {
            self.reads.set(self.reads.get() + 1);
            self.source.get_verified_shared(r)
        }
        fn put(&mut self, _: u16, _: u16, _: &[u8], _: &[ObjectRef]) -> Result<ObjectRef> {
            unreachable!()
        }
    }
    let mut source = MemoryStore::sealed();
    let mut previous = source.put(7, 1, b"shared baseline", &[]).unwrap();
    for ordinal in 0..30 {
        let body = cbor::encode(&Value::Array(vec![
            Value::Text("test.diamond".into()),
            Value::Text(if ordinal == 29 { "root" } else { "revision" }.into()),
            Value::Uint(1),
            Value::Bytes(vec![ordinal]),
        ]));
        previous = source.put(8, 1, &body, &[previous, previous]).unwrap();
    }
    let directory = source.put(3, 1, &[0x80], &[]).unwrap();
    let snapshot = resources::snapshot(
        &mut source,
        directory,
        vec![resources::Profile {
            id: "test.diamond".into(),
            version: 1,
            root: previous,
        }],
        vec![],
    )
    .unwrap();
    let counted = Counted {
        source: &source,
        reads: std::cell::Cell::new(0),
    };
    let limits = resources::Limits {
        max_frames: 256,
        ..Default::default()
    };
    let reader = resources::ArchiveReader::open(&counted, snapshot, limits.clone()).unwrap();
    counted.reads.set(0);
    assert!(reader.verify().unwrap().core_checked);
    assert!(
        counted.reads.get() < 100,
        "{} graph reads",
        counted.reads.get()
    );
    counted.reads.set(0);
    pack_snapshot_with_limits(&counted, snapshot, Vec::new(), limits).unwrap();
    assert!(
        counted.reads.get() < 100,
        "{} pack reads",
        counted.reads.get()
    );
    counted.reads.set(0);
    copy_closure(&counted, &mut MemoryStore::sealed(), snapshot).unwrap();
    assert!(
        counted.reads.get() < 100,
        "{} generic-copy reads",
        counted.reads.get()
    );
}

#[test]
fn completed_graph_dedup_never_authorizes_a_distinct_corrupt_physical_copy() {
    let mut source = MemoryStore::sealed();
    let first = source.put(7, 1, b"same canonical object", &[]).unwrap();
    source.recent.clear();
    let second = source.put(7, 1, b"same canonical object", &[]).unwrap();
    assert_eq!(first.hash, second.hash);
    assert_ne!(first.address, second.address);
    let envelope = cbor::encode(&Value::Array(vec![
        Value::Text("test.duplicates".into()),
        Value::Text("root".into()),
        Value::Uint(1),
        Value::Bytes(vec![]),
    ]));
    let profile = source.put(8, 1, &envelope, &[first, second]).unwrap();
    let directory = source.put(3, 1, &[0x80], &[]).unwrap();
    let snapshot = resources::snapshot(
        &mut source,
        directory,
        vec![resources::Profile {
            id: "test.duplicates".into(),
            version: 1,
            root: profile,
        }],
        vec![],
    )
    .unwrap();
    source.bytes[second.address.offset as usize + wire::FRAME + 8] ^= 1;
    let reader =
        resources::ArchiveReader::open(&source, snapshot, resources::Limits::default()).unwrap();
    assert!(matches!(reader.verify(), Err(Error::Corrupt(_))));
    assert!(matches!(
        pack_snapshot(&source, snapshot, Vec::new()),
        Err(Error::Corrupt(_))
    ));
    assert!(matches!(
        copy_closure(&source, &mut MemoryStore::sealed(), snapshot),
        Err(Error::Corrupt(_))
    ));
}
