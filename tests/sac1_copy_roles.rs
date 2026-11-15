use sac::cbor::{Value, encode};
use sac::resources::{Limits, copy_snapshot};
use sac::{CanonicalObject, Error, MemoryStore, ObjectRef, ObjectStore, Result, SealedWriter};
use std::cell::RefCell;
use std::collections::BTreeMap;

struct Counted<'a, S> {
    source: &'a S,
    reads: RefCell<BTreeMap<ObjectRef, usize>>,
}
impl<S: ObjectStore> ObjectStore for Counted<'_, S> {
    fn get(&self, r: ObjectRef) -> Result<CanonicalObject> {
        *self.reads.borrow_mut().entry(r).or_default() += 1;
        self.source.get(r)
    }
    fn put(&mut self, _: u16, _: u16, _: &[u8], _: &[ObjectRef]) -> Result<ObjectRef> {
        unreachable!()
    }
}
fn extent(store: &mut impl ObjectStore, leaf: ObjectRef, lengths: &[u64]) -> ObjectRef {
    let rows = lengths
        .iter()
        .map(|n| Value::Array(vec![Value::Uint(*n), Value::Uint(0)]))
        .collect();
    store
        .put(5, 1, &encode(&Value::Array(rows)), &[leaf])
        .unwrap()
}
fn copy(store: &impl ObjectStore, root: ObjectRef, limits: Limits) -> Result<ObjectRef> {
    copy_snapshot(store, &mut MemoryStore::sealed(), root, limits)
}

#[test]
fn byte_leaf_is_read_once_and_every_repeated_role_keeps_its_quota_charge() {
    let mut source = MemoryStore::sealed();
    let leaf = source.put(7, 1, b"data", &[]).unwrap();
    let root = extent(&mut source, leaf, &[4, 4]);
    let source = Counted {
        source: &source,
        reads: RefCell::new(BTreeMap::new()),
    };
    copy(&source, root, Limits::default()).unwrap();
    assert_eq!(source.reads.borrow()[&leaf], 1);

    // The original eager-role walk charged two root visits, one byte copy
    // and two declared byte roles. Preserve all five logical visits.
    let frames = 5;
    let physical = 2 * u64::from(root.address.length) + 3 * u64::from(leaf.address.length);
    let decoded = 2 * source.source.get(root).unwrap().canonical_len() as u64 + 3 * 12;
    let exact = Limits {
        max_frames: frames,
        max_source_bytes: physical,
        max_decoded_bytes: decoded,
        ..Limits::default()
    };
    copy(&source, root, exact.clone()).unwrap();
    for (limits, expected) in [
        (
            Limits {
                max_frames: frames - 1,
                ..exact.clone()
            },
            "frame visits",
        ),
        (
            Limits {
                max_source_bytes: physical - 1,
                ..exact.clone()
            },
            "source bytes",
        ),
        (
            Limits {
                max_decoded_bytes: decoded - 1,
                ..exact
            },
            "decoded bytes",
        ),
    ] {
        assert!(
            matches!(copy(&source, root, limits), Err(Error::Limit(actual)) if actual == expected)
        );
    }
}

#[test]
fn shared_completed_byte_leaf_still_checks_each_incoming_length_and_kind() {
    for kind in [7, 40000] {
        let mut source = MemoryStore::sealed();
        let leaf = source.put(kind, 1, b"data", &[]).unwrap();
        // First visit has no byte role; a later extent cannot use content
        // deduplication to escape its own kind/length check.
        let bad = extent(&mut source, leaf, &[5]);
        let root = source.put(40001, 1, b"", &[leaf, bad]).unwrap();
        let source = Counted {
            source: &source,
            reads: RefCell::new(BTreeMap::new()),
        };
        assert!(matches!(
            copy(&source, root, Limits::default()),
            Err(Error::Corrupt(_))
        ));
        assert_eq!(source.reads.borrow()[&leaf], 1);
    }
    let mut source = MemoryStore::sealed();
    let leaf = source.put(7, 1, b"data", &[]).unwrap();
    let conflict = extent(&mut source, leaf, &[4, 5]);
    assert!(matches!(
        copy(&source, conflict, Limits::default()),
        Err(Error::Corrupt(_))
    ));
}

#[test]
fn same_content_at_a_second_locator_must_authenticate_independently() {
    let mut writer = SealedWriter::new(Vec::new()).unwrap();
    writer.set_compression_level(0);
    let first = writer.put(7, 1, b"data", &[]).unwrap();
    let second = writer.put(7, 1, b"data", &[]).unwrap();
    assert_eq!(first.hash, second.hash);
    assert_ne!(first.address, second.address);
    let a = extent(&mut writer, first, &[4]);
    let b = extent(&mut writer, second, &[4]);
    let profile = writer
        .put(
            8,
            1,
            &encode(&Value::Array(vec![
                Value::Text("test.copy".into()),
                Value::Text("root".into()),
                Value::Uint(1),
                Value::Bytes(vec![]),
            ])),
            &[a, b],
        )
        .unwrap();
    let directory = writer.put(3, 1, &[0x80], &[]).unwrap();
    let root = sac::resources::snapshot(
        &mut writer,
        directory,
        vec![sac::resources::Profile {
            id: "test.copy".into(),
            version: 1,
            root: profile,
        }],
        vec![],
    )
    .unwrap();
    let mut bytes = writer.finish(root).unwrap();
    bytes[second.address.offset as usize + 56 + 8] ^= 1;
    let source = sac::PositionalStore::open(bytes).unwrap();
    assert!(matches!(
        copy(&source, root, Limits::default()),
        Err(Error::Corrupt(_))
    ));
}
