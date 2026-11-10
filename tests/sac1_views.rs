use sac::resources::{
    ArchiveBuilder, ArchiveReader, EntryKind, Limits, Profile, SparseSegment, copy_snapshot,
    path_from_str, snapshot,
};
use sac::v1::{
    cbor_view,
    wire::{FrameDecoder, FrameEncoder, encode_frame, frame_span},
};
use sac::{CanonicalObject, ChunkAddress, Error, MemoryStore, ObjectRef, ObjectStore, cbor};

fn path(s: &str) -> Vec<Vec<u8>> {
    path_from_str(s).unwrap()
}

#[test]
fn borrowed_cbor_agrees_with_owned_and_separates_operational_memory_limits() {
    for bytes in [
        vec![0x83, 0x01, 0x42, 0xff, 0x00, 0xf6],
        vec![0xa2, 0, 0xf4, 1, 0x61, b'a'],
    ] {
        let owned = cbor::decode(&bytes).unwrap();
        assert_eq!(cbor::encoded_len(&owned), bytes.len());
        assert_eq!(cbor_view::view(&bytes).unwrap().encoded(), bytes);
    }
    for invalid in [
        vec![0x18, 0],
        vec![0x9f, 0xff],
        vec![0x81],
        vec![0xa2, 1, 0, 0, 0],
        vec![0xa2, 0, 0, 0, 1],
        vec![0x61, 0xff],
        vec![0, 0],
        vec![0xc0, 0],
    ] {
        assert!(cbor::decode(&invalid).is_err());
        assert!(cbor_view::view(&invalid).is_err());
    }
    let mut deep = vec![0x81; 65];
    deep.push(0);
    assert!(matches!(cbor_view::view(&deep), Err(Error::Limit(_))));
    let count = 600_000u32;
    let mut large = vec![0x9a];
    large.extend_from_slice(&count.to_be_bytes());
    large.resize(large.len() + count as usize, 0xf6);
    assert_eq!(
        cbor_view::view(&large).unwrap().array().unwrap().len(),
        count as usize
    );
    assert!(matches!(cbor::decode(&large), Err(Error::Limit(_))));
}

#[test]
fn borrowed_routes_and_opened_ranges_preserve_content_and_bounds() {
    let mut store = MemoryStore::sealed();
    let data: Vec<_> = (0..70_000).map(|i| (i % 251) as u8).collect();
    let mut builder = ArchiveBuilder::new(&mut store);
    builder.set_chunk_size(16384).unwrap();
    for i in 0..32 {
        builder
            .add_file(&path(&format!("dir/{i:04}")), &vec![i as u8; 8192])
            .unwrap();
    }
    builder.add_file(&path("inline"), b"hello").unwrap();
    builder.add_file(&path("chunked"), &data).unwrap();
    builder
        .add_sparse(
            &path("sparse"),
            vec![
                SparseSegment::Data(b"ab".to_vec()),
                SparseSegment::Hole(70_000),
                SparseSegment::Data(b"cd".to_vec()),
            ],
        )
        .unwrap();
    let root = builder.finish().unwrap();
    let reader = ArchiveReader::open(&store, root, Limits::default()).unwrap();
    let view = reader.lookup_shared(&path("inline")).unwrap().unwrap();
    assert_eq!(view.name(), b"inline");
    assert_eq!(view.kind(), EntryKind::File);
    assert_eq!(view.file_length(), Some(5));
    assert_eq!(view.metadata().map().unwrap().count(), 0);
    assert!(view.link_target().is_none());
    assert!(reader.lookup_shared(&path("missing")).unwrap().is_none());
    assert_eq!(
        reader.lookup_shared(&path("dir")).unwrap().unwrap().kind(),
        EntryKind::Directory
    );
    assert!(reader.open_file(&path("dir")).is_err());
    for (name, offset, length) in [
        ("inline", 1, 3),
        ("chunked", 16380, 64),
        ("sparse", 1, 16),
        ("dir/0023", 17, 32),
    ] {
        let expected = reader.read_range(&path(name), offset, length).unwrap();
        let file = reader.open_file(&path(name)).unwrap().unwrap();
        let mut output = vec![0; length];
        for _ in 0..4 {
            file.read_into(offset, &mut output).unwrap();
            assert_eq!(output, expected);
        }
        reader
            .read_range_into(&path(name), offset, &mut output)
            .unwrap();
        assert_eq!(output, expected);
        file.read_into(file.len(), &mut []).unwrap();
        assert!(file.read_into(file.len(), &mut [0]).is_err());
        assert!(file.read_into(u64::MAX, &mut [0]).is_err());
    }
}

#[test]
fn reusable_frames_borrow_raw_input_and_authenticate_each_use() {
    let child = ObjectRef {
        hash: sac::ObjectHash::digest(b"child"),
        address: ChunkAddress {
            offset: 128,
            length: 64,
        },
    };
    let object = CanonicalObject {
        kind: 42000,
        version: 5,
        bytes: vec![71; 1 << 20],
        children: vec![child],
    };
    let mut encoder = FrameEncoder::default();
    let mut decoder = FrameDecoder::default();
    let levels: &[i32] = if cfg!(feature = "compression") {
        &[0, 1]
    } else {
        &[0]
    };
    for &level in levels {
        let expected = encode_frame(&object, level).unwrap();
        assert_eq!(encoder.encode(&object, level).unwrap(), expected);
        let capacity = encoder.buffer_capacity();
        let reference = ObjectRef {
            hash: object.hash(),
            address: ChunkAddress {
                offset: 4096,
                length: expected.len() as u32,
            },
        };
        for _ in 0..4 {
            let frame = encoder.encode(&object, level).unwrap();
            let view = decoder
                .decode(reference, frame, 128, 4096 + frame.len() as u64)
                .unwrap();
            assert_eq!(view.body, object.bytes);
            assert_eq!(view.child(0), Some(child));
            assert_eq!(view.child(1), None);
            assert_eq!(view.to_owned(), object);
            if level == 0 {
                assert_eq!(view.body.as_ptr(), frame[56 + 8 + 32..].as_ptr());
            }
        }
        assert_eq!(encoder.buffer_capacity(), capacity);
        let retained = decoder.retained_bytes();
        let mut bad = expected.clone();
        bad[56] ^= 1;
        assert!(
            decoder
                .decode(reference, &bad, 128, 4096 + bad.len() as u64)
                .is_err()
        );
        assert!(decoder.decode(reference, &expected, 128, 4096).is_err());
        let owned = decoder
            .decode_owned(
                reference,
                expected,
                128,
                4096 + reference.address.length as u64,
            )
            .unwrap();
        assert_eq!(owned, object);
        assert!(decoder.retained_bytes() <= retained);
    }
}

#[test]
fn repacking_preserves_opaque_strong_closure_and_does_not_follow_embedded_hashes() {
    let mut source = MemoryStore::with_preamble(sac::v1::wire::Preamble::live([7; 16]).unwrap());
    source.set_compression_level(0);
    let weak = source.put(7, 1, &vec![91; 8192], &[]).unwrap();
    let strong = source.put(7, 1, b"declared dependency", &[]).unwrap();
    let opaque = source.put(42000, 9, &weak.hash.0, &[strong]).unwrap();
    let profile = source
        .put(
            8,
            1,
            &cbor::encode(&cbor::Value::Array(vec![
                cbor::Value::Text("example.profile".into()),
                cbor::Value::Text("root".into()),
                cbor::Value::Uint(1),
                cbor::Value::Bytes(vec![]),
            ])),
            &[opaque],
        )
        .unwrap();
    let directory = source.put(3, 1, &[0x80], &[]).unwrap();
    let root = snapshot(
        &mut source,
        directory,
        vec![Profile {
            id: "example.profile".into(),
            version: 1,
            root: profile,
        }],
        vec![],
    )
    .unwrap();
    source.publish(root).unwrap();
    let mut destination = MemoryStore::sealed();
    let copied = copy_snapshot(&source, &mut destination, root, Limits::default()).unwrap();
    assert_eq!(copied.hash, root.hash);
    destination.publish(copied).unwrap();
    let copied = destination.reader().unwrap().snapshot().unwrap();
    let archive = ArchiveReader::open(&destination, copied, Limits::default()).unwrap();
    let report = archive.verify().unwrap();
    assert!(report.core_checked);
    assert!(!report.profile_checked);
    let mut hashes = vec![];
    let mut offset = 128;
    while destination.as_bytes().get(offset..offset + 4) == Some(b"SO1\0") {
        let frame = &destination.as_bytes()[offset..];
        let span = frame_span(&frame[..56]).unwrap();
        hashes.push(sac::ObjectHash(frame[16..48].try_into().unwrap()));
        offset += span;
    }
    assert!(hashes.contains(&opaque.hash) && hashes.contains(&strong.hash));
    assert!(!hashes.contains(&weak.hash));
    assert!(destination.as_bytes().len() < source.as_bytes().len());
}
