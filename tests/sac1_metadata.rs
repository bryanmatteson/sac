use sac::v1::metadata::{Lookup, MetadataEditor, MetadataReader, PROFILE_ID};
use sac::v1::resources::{
    self, ArchiveBuilder, ArchiveReader, Feature, Limits, Profile, path_from_str,
};
use sac::v1::{
    CanonicalObject, MemoryStore, ObjectRef, ObjectStore, Result,
    cbor::{self, Value as V},
};
use std::cell::Cell;

fn base(store: &mut impl ObjectStore) -> ObjectRef {
    let mut builder = ArchiveBuilder::new(store);
    builder
        .add_file(&path_from_str("input.bin").unwrap(), b"original input")
        .unwrap();
    builder.finish().unwrap()
}

#[test]
fn independent_profiles_unknown_keys_and_nested_binary_fields_survive_edits() {
    let mut store = MemoryStore::sealed();
    let original = base(&mut store);
    let directory = ArchiveReader::open(&store, original, Limits::default())
        .unwrap()
        .directory_root();
    let other = store
        .put(
            8,
            1,
            &cbor::encode(&V::Array(vec![
                V::text("org.example.app"),
                V::text("root"),
                V::Uint(37),
                V::bytes([0xff, 0, 9]),
            ])),
            &[],
        )
        .unwrap();
    let original = resources::snapshot(
        &mut store,
        directory,
        vec![Profile {
            id: "org.example.app".into(),
            version: 37,
            root: other,
        }],
        vec![Feature {
            scope: Some("org.example.app".into()),
            id: "org.example.required".into(),
            version: 9,
            required: true,
        }],
    )
    .unwrap();
    let unknown = cbor::text_map(vec![(
        "future",
        V::Array(vec![
            V::Bytes(vec![0xff, 0]),
            V::Uint(u64::MAX),
            V::NInt(u64::MAX),
        ]),
    )]);
    let mut editor = MetadataEditor::open(&mut store, original, Limits::default()).unwrap();
    editor.set("org.example.unknown", &unknown).unwrap();
    editor.set("org.example.title", &V::text("first")).unwrap();
    let first = editor.finish().unwrap();
    let mut editor = MetadataEditor::open(&mut store, first, Limits::default()).unwrap();
    editor.set("org.example.title", &V::text("second")).unwrap();
    let next = editor.finish().unwrap();
    let reader = MetadataReader::open(&store, next, Limits::default())
        .unwrap()
        .unwrap();
    assert_eq!(reader.get("org.example.unknown").unwrap(), Some(unknown));
    assert_eq!(
        reader.get("org.example.title").unwrap(),
        Some(V::text("second"))
    );
    reader.verify().unwrap();
    let snapshot = store.get(next).unwrap();
    assert!(snapshot.children.contains(&directory));
    assert!(snapshot.children.contains(&other));
    let V::Array(fields) = cbor::decode(&snapshot.bytes).unwrap() else {
        panic!()
    };
    assert_eq!(
        fields[2],
        V::Array(vec![V::Array(vec![
            V::text("org.example.app"),
            V::text("org.example.required"),
            V::Uint(9),
            V::Bool(true)
        ])])
    );
    assert_eq!(
        ArchiveReader::open(&store, next, Limits::default())
            .unwrap()
            .read_range(&path_from_str("input.bin").unwrap(), 0, 14)
            .unwrap(),
        b"original input"
    );
}

#[test]
fn canonical_bytes_absence_noop_and_removal_preserve_snapshot_and_input() {
    let mut store = MemoryStore::sealed();
    let snapshot = base(&mut store);
    let before = store.as_bytes().len();
    let mut editor = MetadataEditor::open(&mut store, snapshot, Limits::default()).unwrap();
    assert!(!editor.remove("org.example.missing").unwrap());
    assert_eq!(editor.finish().unwrap(), snapshot);
    assert_eq!(store.as_bytes().len(), before);
    let bytes = cbor::encode(&V::Map(vec![cbor::MapEntry {
        key: V::Bytes(vec![0xff]),
        key_bytes: vec![0x41, 0xff],
        value: V::Null,
    }]));
    let mut editor = MetadataEditor::open(&mut store, snapshot, Limits::default()).unwrap();
    editor.set_encoded("org.example.binary", &bytes).unwrap();
    let snapshot = editor.finish().unwrap();
    let reader = MetadataReader::open(&store, snapshot, Limits::default())
        .unwrap()
        .unwrap();
    assert_eq!(
        reader.get_encoded("org.example.binary").unwrap(),
        Some(bytes.clone())
    );
    assert_eq!(
        reader.lookup_encoded("org.example.missing").unwrap(),
        Lookup::NoMatchUnverified
    );
    assert_eq!(reader.get("org.example.missing").unwrap(), None);
    assert_eq!(
        reader.lookup_encoded("org.example.missing").unwrap(),
        Lookup::NotFound
    );
    let before = store.as_bytes().len();
    let mut editor = MetadataEditor::open(&mut store, snapshot, Limits::default()).unwrap();
    assert!(!editor.set_encoded("org.example.binary", &bytes).unwrap());
    assert_eq!(editor.finish().unwrap(), snapshot);
    assert_eq!(store.as_bytes().len(), before);
    let mut editor = MetadataEditor::open(&mut store, snapshot, Limits::default()).unwrap();
    assert!(editor.remove("org.example.binary").unwrap());
    let snapshot = editor.finish().unwrap();
    let reader = MetadataReader::open(&store, snapshot, Limits::default())
        .unwrap()
        .unwrap();
    assert_eq!(reader.get_encoded("org.example.binary").unwrap(), None);
    reader.verify().unwrap();
}

struct Counting {
    inner: MemoryStore,
    payload_reads: Cell<usize>,
    payload_writes: usize,
}
impl ObjectStore for Counting {
    fn get(&self, r: ObjectRef) -> Result<CanonicalObject> {
        let object = self.inner.get(r)?;
        if object.kind == 7 {
            self.payload_reads.set(self.payload_reads.get() + 1);
        }
        Ok(object)
    }
    fn put(&mut self, k: u16, v: u16, b: &[u8], c: &[ObjectRef]) -> Result<ObjectRef> {
        if k == 7 {
            self.payload_writes += 1;
        }
        self.inner.put(k, v, b, c)
    }
}
#[test]
fn point_reads_and_key_listing_leave_other_large_values_cold() {
    let mut store = Counting {
        inner: MemoryStore::sealed(),
        payload_reads: Cell::new(0),
        payload_writes: 0,
    };
    let snapshot = base(&mut store);
    let mut editor = MetadataEditor::open(&mut store, snapshot, Limits::default()).unwrap();
    editor
        .set("org.example.large", &V::Bytes(vec![0x75; 200_000]))
        .unwrap();
    editor.set("org.example.title", &V::text("small")).unwrap();
    let snapshot = editor.finish().unwrap();
    store.payload_reads.set(0);
    let reader = MetadataReader::open(&store, snapshot, Limits::default())
        .unwrap()
        .unwrap();
    assert_eq!(
        reader.get("org.example.title").unwrap(),
        Some(V::text("small"))
    );
    let mut keys = Vec::new();
    reader
        .visit_keys(&mut |k, _| {
            keys.push(k.to_owned());
            Ok(())
        })
        .unwrap();
    assert_eq!(keys, vec!["org.example.large", "org.example.title"]);
    assert_eq!(
        store.payload_reads.get(),
        0,
        "unrelated value chunks must stay unread"
    );
    assert_eq!(
        reader.get("org.example.large").unwrap(),
        Some(V::Bytes(vec![0x75; 200_000]))
    );
    assert!(store.payload_reads.get() > 0);
    let old = reader.get_encoded("org.example.large").unwrap();
    store.payload_writes = 0;
    let mut editor = MetadataEditor::open(&mut store, snapshot, Limits::default()).unwrap();
    editor
        .set("org.example.title", &V::text("updated"))
        .unwrap();
    let next = editor.finish().unwrap();
    assert_eq!(
        store.payload_writes, 0,
        "updating a small key must reuse large value extents"
    );
    assert_eq!(
        MetadataReader::open(&store, next, Limits::default())
            .unwrap()
            .unwrap()
            .get_encoded("org.example.large")
            .unwrap(),
        old
    );
    let directory = ArchiveReader::open(&store, snapshot, Limits::default())
        .unwrap()
        .directory_root();
    assert!(store.get(next).unwrap().children.contains(&directory));
}

#[test]
fn invalid_keys_values_versions_and_required_capabilities_are_rejected() {
    let mut store = MemoryStore::sealed();
    let snapshot = base(&mut store);
    let before = store.as_bytes().len();
    let mut editor = MetadataEditor::open(&mut store, snapshot, Limits::default()).unwrap();
    assert!(editor.set_encoded("plain", &[0]).is_err());
    assert!(editor.set_encoded("org.example.valid", &[0x18, 0]).is_err());
    assert!(editor.set_encoded("org.example.valid", &[0, 0]).is_err());
    assert_eq!(editor.finish().unwrap(), snapshot);
    assert_eq!(store.as_bytes().len(), before);
    let directory = ArchiveReader::open(&store, snapshot, Limits::default())
        .unwrap()
        .directory_root();
    let root = store
        .put(
            8,
            1,
            &cbor::encode(&V::Array(vec![
                V::text(PROFILE_ID),
                V::text("root"),
                V::Uint(2),
                V::bytes([0x81, 0]),
            ])),
            &[directory],
        )
        .unwrap();
    let future = resources::snapshot(
        &mut store,
        directory,
        vec![Profile {
            id: PROFILE_ID.into(),
            version: 2,
            root,
        }],
        vec![],
    )
    .unwrap();
    assert!(matches!(
        MetadataReader::open(&store, future, Limits::default()),
        Err(sac::v1::Error::Unsupported(_))
    ));
    assert!(MetadataEditor::open(&mut store, future, Limits::default()).is_err());
    let root = store
        .put(
            8,
            1,
            &cbor::encode(&V::Array(vec![
                V::text(PROFILE_ID),
                V::text("root"),
                V::Uint(1),
                V::bytes([0x81, 0]),
            ])),
            &[directory],
        )
        .unwrap();
    let required = resources::snapshot(
        &mut store,
        directory,
        vec![Profile {
            id: PROFILE_ID.into(),
            version: 1,
            root,
        }],
        vec![Feature {
            scope: Some(PROFILE_ID.into()),
            id: "org.example.future".into(),
            version: 1,
            required: true,
        }],
    )
    .unwrap();
    assert!(matches!(
        MetadataReader::open(&store, required, Limits::default()),
        Err(sac::v1::Error::Unsupported(_))
    ));
}

#[test]
fn entry_attributes_and_unknown_profiles_survive_edits_and_lossless_copy() {
    let mut store = MemoryStore::sealed();
    let snapshot = base(&mut store);
    let directory = ArchiveReader::open(&store, snapshot, Limits::default())
        .unwrap()
        .directory_root();
    let old = cbor::encode(&V::text("old"));
    let attributes = cbor::text_map(vec![
        ("org.example.future", V::Bytes(vec![255, 0])),
        (
            "byte_digest",
            V::bytes(blake3::hash(&old).as_bytes().to_vec()),
        ),
    ]);
    let mut builder = ArchiveBuilder::new(&mut store);
    builder
        .add_file_with_metadata(
            &path_from_str("org.example.custom").unwrap(),
            &old,
            attributes.clone(),
        )
        .unwrap();
    let values = builder.finish_directory().unwrap();
    let root = store
        .put(
            8,
            1,
            &cbor::encode(&V::Array(vec![
                V::text(PROFILE_ID),
                V::text("root"),
                V::Uint(1),
                V::bytes([0x81, 0]),
            ])),
            &[values],
        )
        .unwrap();
    let snapshot = resources::snapshot(
        &mut store,
        directory,
        vec![Profile {
            id: PROFILE_ID.into(),
            version: 1,
            root,
        }],
        vec![],
    )
    .unwrap();
    let new = cbor::encode(&V::text("new"));
    let mut editor = MetadataEditor::open(&mut store, snapshot, Limits::default()).unwrap();
    editor.set_encoded("org.example.custom", &new).unwrap();
    let snapshot = editor.finish().unwrap();
    let reader = MetadataReader::open(&store, snapshot, Limits::default())
        .unwrap()
        .unwrap();
    reader.verify().unwrap();
    let node = store.get(reader.directory_root()).unwrap();
    let V::Array(rows) = cbor::decode(&node.bytes).unwrap() else {
        panic!()
    };
    let V::Array(row) = &rows[0] else { panic!() };
    assert_eq!(
        row[2],
        cbor::text_map(vec![
            ("org.example.future", V::Bytes(vec![255, 0])),
            (
                "byte_digest",
                V::bytes(blake3::hash(&new).as_bytes().to_vec())
            )
        ])
    );
    let mut copied = MemoryStore::sealed();
    let copy = resources::copy_snapshot(&store, &mut copied, snapshot, Limits::default()).unwrap();
    assert_eq!(copy.hash, snapshot.hash);
    assert_eq!(
        MetadataReader::open(&copied, copy, Limits::default())
            .unwrap()
            .unwrap()
            .get_encoded("org.example.custom")
            .unwrap(),
        Some(new)
    );
}
