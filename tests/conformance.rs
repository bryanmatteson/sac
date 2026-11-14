use sac::{
    ObjectStore, PositionalStore, ReadAt,
    resources::{ArchiveReader, Limits, path_from_str},
};
use serde_json::Value;

#[test]
fn object_identity_agrees_with_canonical_stream_at_hash_boundaries() {
    for count in [0, 1, 31, 63, 127, 128, 255, 256, 511] {
        let boundary = 4096usize.checked_sub(b"SAC1/object\0".len() + 8 + count * 32);
        for size in [0, 1, 997, 1005, 1024, 2029, 2048, 4077, 4096, 8192, 65536]
            .into_iter()
            .chain(
                boundary
                    .into_iter()
                    .flat_map(|n| [n.saturating_sub(1), n, n + 1]),
            )
        {
            let mut object = sac::CanonicalObject {
                kind: 42000,
                version: 19,
                bytes: (0..size).map(|i| (i * 71) as u8).collect(),
                children: (0..count)
                    .map(|i| sac::ObjectRef {
                        hash: sac::ObjectHash::digest(&(i as u64).to_le_bytes()),
                        address: sac::ChunkAddress {
                            offset: 128 + i as u64 * 64,
                            length: 64,
                        },
                    })
                    .collect(),
            };
            let expected = sac::v1::domain_hash(b"SAC1/object\0", &object.canonical_bytes());
            assert_eq!(object.hash(), expected, "children={count} bytes={size}");
            for child in &mut object.children {
                child.address.offset += 4096;
                child.address.length += 8;
            }
            assert_eq!(
                object.hash(),
                expected,
                "relocated children={count} bytes={size}"
            );
        }
    }
}

#[test]
fn domain_hash_agrees_with_concatenated_input_at_batch_boundaries() {
    for domain_size in [0, 1, 12, 1024, 4095, 4096, 4097] {
        let domain = vec![0x73; domain_size];
        for size in [0, 1, 1012, 1024, 2048, 4083, 4084, 4085, 4096, 8192, 65536] {
            let bytes: Vec<_> = (0..size).map(|i| (i * 71) as u8).collect();
            let mut canonical = domain.clone();
            canonical.extend_from_slice(&bytes);
            assert_eq!(
                sac::v1::domain_hash(&domain, &bytes),
                sac::ObjectHash::digest(&canonical),
                "domain={domain_size} bytes={size}"
            );
        }
    }
}

#[test]
fn independent_sac1_vectors_agree_on_admission_snapshot_and_content() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("conformance");
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();
    for vector in manifest["vectors"].as_array().unwrap() {
        let name = vector["file"].as_str().unwrap();
        let bytes = std::fs::read(root.join(name)).unwrap();
        let result = (|| -> sac::Result<_> {
            let store = PositionalStore::open(bytes.as_slice())?;
            let reader = store.reader();
            let archive =
                ArchiveReader::open(&store, reader.snapshot().unwrap(), Limits::default())?;
            let report = archive.verify_commit(reader.publication.unwrap().root)?;
            let content = archive.read_range(
                &path_from_str("hello.txt")?,
                0,
                vector["content_hex"]
                    .as_str()
                    .map_or(0, |hex| hex.len() / 2),
            )?;
            Ok((hex::encode(report.snapshot_id), hex::encode(content)))
        })();
        if vector["valid"].as_bool().unwrap() {
            let (snapshot, content) = result.unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(snapshot, vector["snapshot"].as_str().unwrap(), "{name}");
            assert_eq!(content, vector["content_hex"].as_str().unwrap(), "{name}");
        } else {
            if vector["error_class"] == "unsupported" {
                assert!(
                    matches!(result, Err(sac::Error::Unsupported(_))),
                    "{name}: {result:?}"
                );
            }
            assert!(result.is_err(), "{name} must reject");
        }
    }
}

#[test]
fn positional_slice_reads_authenticate_and_account_like_copied_reads() {
    struct Source<'a> {
        bytes: &'a [u8],
        borrow: bool,
        reads: std::cell::Cell<usize>,
    }
    impl ReadAt for Source<'_> {
        fn len(&self) -> sac::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> sac::Result<()> {
            self.reads.set(self.reads.get() + 1);
            self.bytes.read_exact_at(offset, output)
        }
        fn slice_at(&self, offset: u64, length: usize) -> Option<&[u8]> {
            self.borrow
                .then(|| self.bytes.slice_at(offset, length))
                .flatten()
        }
    }
    for fixture in [
        include_bytes!("../conformance/valid/sealed.sac").as_slice(),
        include_bytes!("../conformance/valid/compressed.sac").as_slice(),
    ] {
        let mut stats = None;
        for borrow in [false, true] {
            let store = PositionalStore::open(Source {
                bytes: fixture,
                borrow,
                reads: std::cell::Cell::new(0),
            })
            .unwrap();
            let snapshot = store.reader().snapshot().unwrap();
            let before = store.source.reads.get();
            let archive = ArchiveReader::open(&store, snapshot, Limits::default()).unwrap();
            archive.verify().unwrap();
            assert_eq!(store.source.reads.get() == before, borrow);
            let current = store.reader().statistics();
            assert_eq!(stats.get_or_insert_with(|| current.clone()), &current);
            let mut wrong = snapshot;
            wrong.hash.0[0] ^= 1;
            assert!(store.get(wrong).is_err());
        }
    }
}
