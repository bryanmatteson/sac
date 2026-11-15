#![cfg(feature = "native")]
#[path = "../tools/performance/src/bucket_trie.rs"]
mod bucket_trie;
#[path = "../tools/performance/src/dual_map.rs"]
mod dual_map;
#[path = "../tools/performance/src/prefix_trie.rs"]
mod prefix_trie;
use dual_map::DualMap;
use prefix_trie::{MAX_KEY, PROFILE, PrefixTrie};
use sac::cbor::{self, Value as V};
use sac::resources::{self, ArchiveBuilder, Profile};
use sac::{CanonicalObject, Error, MemoryStore, NativeStore, ObjectRef, ObjectStore, Result};
use std::collections::BTreeMap;

fn dual_from_base<S: ObjectStore + ?Sized>(
    store: &S,
    base: ObjectRef,
    layout: usize,
) -> Result<DualMap> {
    match layout {
        0 => DualMap::from_base(store, base),
        1 => DualMap::from_base_paged(store, base),
        _ => DualMap::from_base_bucket(store, base),
    }
}

fn record(store: &mut impl ObjectStore, typ: &str, value: V, children: &[ObjectRef]) -> ObjectRef {
    store
        .put(
            8,
            1,
            &cbor::encode(&V::Array(vec![
                V::text(PROFILE),
                V::text(typ),
                V::Uint(1),
                V::Bytes(cbor::encode(&value)),
            ])),
            children,
        )
        .unwrap()
}
fn snapshot(store: &mut impl ObjectStore, root: ObjectRef, count: u64) -> ObjectRef {
    let root = record(
        store,
        "root",
        V::Array(vec![V::Uint(count), V::Uint(0)]),
        &[root],
    );
    let directory = ArchiveBuilder::new(store).finish_directory().unwrap();
    resources::snapshot(
        store,
        directory,
        vec![Profile {
            id: PROFILE.into(),
            version: 1,
            root,
        }],
        vec![],
    )
    .unwrap()
}
fn leaf(store: &mut impl ObjectStore, key: &[u8]) -> ObjectRef {
    record(
        store,
        "leaf",
        V::Array(vec![V::Bytes(key.to_vec()), V::Uint(0), V::Bytes(vec![42])]),
        &[],
    )
}

#[test]
fn binary_prefixes_fanout_shared_children_empty_and_long_keys_are_canonical() {
    let mut keys = vec![
        vec![],
        b"a".to_vec(),
        b"ab".to_vec(),
        b"abc".to_vec(),
        vec![3; MAX_KEY],
    ];
    keys.extend((0..=255).map(|b| vec![b, 0, 255]));
    let expected: BTreeMap<_, _> = keys.iter().map(|key| (key.clone(), vec![42])).collect();
    let mut roots = vec![];
    for reverse in [false, true] {
        let mut store = MemoryStore::sealed();
        let mut trie = PrefixTrie::default();
        assert!(trie.verify(&store).unwrap().is_empty());
        let empty = trie.snapshot(&mut store).unwrap();
        assert_eq!(PrefixTrie::open(&store, empty).unwrap().len(), 0);
        if reverse {
            keys.reverse();
        }
        for key in &keys {
            trie.set(&mut store, key, &[42]).unwrap();
        }
        assert_eq!(trie.verify(&store).unwrap(), expected);
        for key in expected.keys() {
            assert_eq!(trie.get(&store, key).unwrap(), Some(vec![42]));
        }
        assert_eq!(trie.get(&store, b"abcd").unwrap(), None);
        let root = trie.snapshot(&mut store).unwrap();
        roots.push(root.hash);
        let packed = sac::pack_snapshot(&store, root, Vec::new()).unwrap();
        let packed = MemoryStore::from_bytes(packed).unwrap();
        packed.validate().unwrap();
        let root = sac::v1::Reader::open_at(packed.as_bytes())
            .unwrap()
            .snapshot()
            .unwrap();
        assert_eq!(
            PrefixTrie::open(&packed, root)
                .unwrap()
                .verify(&packed)
                .unwrap(),
            expected
        );
    }
    assert_eq!(roots[0], roots[1]);
}

#[test]
fn many_key_model_growing_shrinking_and_old_roots() {
    let mut store = MemoryStore::sealed();
    let mut trie = PrefixTrie::default();
    let mut expected = BTreeMap::new();
    let mut old = None;
    for ordinal in 0..1024 {
        let key = format!("prefix/{:04x}", ordinal * 197 % 257).into_bytes();
        let bytes = vec![ordinal as u8; [0, 8, 64, 512, 48 * 1024, 65536][ordinal % 6]];
        trie.set(&mut store, &key, &bytes).unwrap();
        expected.insert(key, bytes);
        if ordinal == 256 {
            old = Some((trie.clone(), expected.clone()));
        }
    }
    assert_eq!(trie.len(), 257);
    assert_eq!(trie.verify(&store).unwrap(), expected);
    for (key, value) in &expected {
        assert_eq!(trie.get(&store, key).unwrap().as_ref(), Some(value));
    }
    let (old, expected) = old.unwrap();
    assert_eq!(old.verify(&store).unwrap(), expected);
    let prior = trie.snapshot(&mut store).unwrap();
    assert!(trie.set(&mut store, &vec![0; MAX_KEY + 1], b"bad").is_err());
    assert!(
        trie.set(&mut store, b"bad", &vec![0; prefix_trie::MAX_VALUE + 1])
            .is_err()
    );
    assert_eq!(trie.snapshot(&mut store).unwrap().hash, prior.hash);
}

#[test]
fn publication_barriers_failed_publications_old_pins_reopen_and_seal() {
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
        let path = dir.path().join("trie.sac");
        let mut store = NativeStore::create_live(&path, [19; 16]).unwrap();
        let mut trie = PrefixTrie::default();
        for key in 0..128 {
            trie.set(&mut store, &format!("key-{key:04}").into_bytes(), &[7; 64])
                .unwrap();
        }
        let first = trie.snapshot(&mut store).unwrap();
        let (_, old_pin) = store.publish_pinned(first).unwrap();
        if case % 2 == 1 {
            store.set_append_index_memory_budget(0).unwrap();
            store.set_decoded_cache_budget(0);
        }
        for key in 0..192 {
            trie.set(
                &mut store,
                &format!("key-{key:04}").into_bytes(),
                &vec![key as u8; [0, 64, 65536][key % 3]],
            )
            .unwrap();
        }
        let expected = trie.verify(&store).unwrap();
        let next = trie.snapshot(&mut store).unwrap();
        if let Some(fault) = fault {
            store.inject_publication_fault_once(fault);
            assert!(store.publish(next).is_err());
            assert!(matches!(store.publish(next), Err(Error::Poisoned)));
        } else {
            let before = store.publication_statistics();
            store.publish(next).unwrap();
            let after = store.publication_statistics();
            assert_eq!(after.chunk_barriers - before.chunk_barriers, 1);
            assert_eq!(after.slot_syncs - before.slot_syncs, 1);
        }
        let old = PrefixTrie::open(&old_pin, first).unwrap();
        assert_eq!(old.verify(&old_pin).unwrap().len(), 128);
        assert_eq!(
            old.get(&old_pin, b"key-0000").unwrap().unwrap(),
            vec![7; 64]
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
        let current = PrefixTrie::open(&reopened, visible).unwrap();
        assert_eq!(
            current.verify(&reopened).unwrap(),
            if expect_new {
                expected
            } else {
                old.verify(&old_pin).unwrap()
            }
        );
        let packed =
            MemoryStore::from_bytes(sac::pack_snapshot(&reopened, visible, Vec::new()).unwrap())
                .unwrap();
        packed.validate().unwrap();
        let visible = sac::v1::Reader::open_at(packed.as_bytes())
            .unwrap()
            .snapshot()
            .unwrap();
        assert_eq!(
            PrefixTrie::open(&packed, visible)
                .unwrap()
                .verify(&packed)
                .unwrap(),
            current.verify(&reopened).unwrap()
        );
    }
}

#[test]
fn owning_verifier_rejects_authenticated_malformed_nodes() {
    for case in 0..9 {
        let mut store = MemoryStore::sealed();
        let a = leaf(&mut store, b"");
        let b = leaf(&mut store, b"b");
        let node = match case {
            0 => record(
                &mut store,
                "branch",
                V::Array(vec![
                    V::Bytes(vec![]),
                    V::Null,
                    V::Array(vec![
                        V::Array(vec![V::Uint(2), V::Uint(0)]),
                        V::Array(vec![V::Uint(1), V::Uint(1)]),
                    ]),
                ]),
                &[a, b],
            ),
            1 => record(
                &mut store,
                "branch",
                V::Array(vec![
                    V::Bytes(vec![]),
                    V::Null,
                    V::Array(vec![
                        V::Array(vec![V::Uint(1), V::Uint(0)]),
                        V::Array(vec![V::Uint(1), V::Uint(1)]),
                    ]),
                ]),
                &[a, b],
            ),
            2 => record(
                &mut store,
                "branch",
                V::Array(vec![
                    V::Bytes(vec![]),
                    V::Null,
                    V::Array(vec![
                        V::Array(vec![V::Uint(1), V::Uint(1)]),
                        V::Array(vec![V::Uint(2), V::Uint(0)]),
                    ]),
                ]),
                &[a, b],
            ),
            3 => record(
                &mut store,
                "branch",
                V::Array(vec![
                    V::Bytes(vec![]),
                    V::Null,
                    V::Array(vec![V::Array(vec![V::Uint(1), V::Uint(0)])]),
                ]),
                &[a],
            ),
            4 => record(
                &mut store,
                "branch",
                V::Array(vec![
                    V::Bytes(vec![]),
                    V::Uint(0),
                    V::Array(vec![V::Array(vec![V::Uint(1), V::Uint(1)])]),
                ]),
                &[b, a],
            ), // terminal suffix
            5 => record(
                &mut store,
                "leaf",
                V::Array(vec![V::Bytes(vec![]), V::Uint(1), V::Uint(65536)]),
                &[a],
            ), // not a blob
            6 => {
                let blob = store.put(7, 1, &[0; 65535], &[]).unwrap();
                record(
                    &mut store,
                    "leaf",
                    V::Array(vec![V::Bytes(vec![]), V::Uint(1), V::Uint(65536)]),
                    &[blob],
                )
            }
            7 => record(
                &mut store,
                "leaf",
                V::Array(vec![
                    V::Bytes(vec![0; MAX_KEY + 1]),
                    V::Uint(0),
                    V::Bytes(vec![]),
                ]),
                &[],
            ),
            _ => record(&mut store, "unknown", V::Null, &[]),
        };
        let root = snapshot(&mut store, node, 2);
        // Core authenticates the extension's bytes; only its owner can admit semantics.
        sac::validate_closure(&store, Some(root)).unwrap();
        assert!(
            PrefixTrie::open(&store, root)
                .unwrap()
                .verify(&store)
                .is_err(),
            "case {case}"
        );
    }
    let mut store = MemoryStore::sealed();
    let a = leaf(&mut store, b"a");
    let root = snapshot(&mut store, a, 2);
    assert!(
        PrefixTrie::open(&store, root)
            .unwrap()
            .verify(&store)
            .is_err()
    );
}

struct Substituted<'a> {
    store: &'a MemoryStore,
    target: ObjectRef,
    replacement: CanonicalObject,
}

struct FailingWriter {
    store: MemoryStore,
    remaining: usize,
}
impl ObjectStore for FailingWriter {
    fn get(&self, reference: ObjectRef) -> Result<CanonicalObject> {
        self.store.get(reference)
    }
    fn put(
        &mut self,
        kind: u16,
        version: u16,
        bytes: &[u8],
        children: &[ObjectRef],
    ) -> Result<ObjectRef> {
        if self.remaining == 0 {
            return Err(std::io::Error::other("injected append failure").into());
        }
        self.remaining -= 1;
        self.store.put(kind, version, bytes, children)
    }
}
#[test]
fn failed_path_rewrite_keeps_the_previous_root_and_cardinality() {
    let mut store = FailingWriter {
        store: MemoryStore::sealed(),
        remaining: usize::MAX,
    };
    let mut trie = PrefixTrie::default();
    trie.set(&mut store, b"prefix/aaa", b"first").unwrap();
    trie.set(&mut store, b"prefix/aab", b"second").unwrap();
    let prior = trie.verify(&store).unwrap();
    let root = trie.snapshot(&mut store).unwrap();
    for key in [b"prefix/aab", b"prefix/aac"] {
        store.remaining = 2; // blob + leaf succeed; parent rewrite fails
        assert!(trie.set(&mut store, key, &[9; 65536]).is_err());
        assert_eq!(trie.len(), 2);
        assert_eq!(trie.verify(&store).unwrap(), prior);
        store.remaining = usize::MAX;
        assert_eq!(trie.snapshot(&mut store).unwrap().hash, root.hash);
    }
    trie.set(&mut store, b"prefix/aac", &[9; 65536]).unwrap();
    assert_eq!(trie.len(), 3);
    assert_eq!(
        trie.get(&store, b"prefix/aac").unwrap().unwrap(),
        [9; 65536]
    );
}
impl ObjectStore for Substituted<'_> {
    fn get(&self, reference: ObjectRef) -> Result<CanonicalObject> {
        if reference == self.target {
            Ok(self.replacement.clone())
        } else {
            self.store.get(reference)
        }
    }
    fn put(&mut self, _: u16, _: u16, _: &[u8], _: &[ObjectRef]) -> Result<ObjectRef> {
        Err(Error::Unsupported("read only".into()))
    }
}
#[test]
fn default_adapters_authenticate_nodes_and_strong_children_bind_value_identity() {
    let mut store = MemoryStore::sealed();
    let mut trie = PrefixTrie::default();
    trie.set(&mut store, b"key", b"value").unwrap();
    let root = trie.snapshot(&mut store).unwrap();
    let snapshot_object = store.get(root).unwrap();
    let profile = store.get(snapshot_object.children[1]).unwrap();
    let node = profile.children[0];
    let other = leaf(&mut store, b"other");
    let replacement = store.get(other).unwrap();
    let substituted = Substituted {
        store: &store,
        target: node,
        replacement,
    };
    let opened = PrefixTrie::open(&substituted, root).unwrap();
    assert!(opened.get(&substituted, b"key").is_err());
    assert!(opened.verify(&substituted).is_err());
    let original = store.get(node).unwrap();
    for variant in 0..3 {
        let mut forged = node;
        match variant {
            0 => forged.hash.0[0] ^= 1,
            1 => forged.address.length += 8,
            _ => forged.address = root.address,
        }
        assert!(store.put(8, 1, &original.bytes, &[forged]).is_err());
    }
}

#[test]
fn dual_base_overlay_checkpoint_and_sealed_resource_export() {
    for layout in [0, 1, 2] {
        let mut store = MemoryStore::sealed();
        let mut builder = ArchiveBuilder::new(&mut store);
        for key in 0..128 {
            builder
                .add_file(&[format!("key-{key:04}").into_bytes()], &[7; 64])
                .unwrap();
        }
        let base = builder.finish().unwrap();
        let mut dual = dual_from_base(&store, base, layout).unwrap();
        let initial = dual.verify(&store).unwrap();
        let first = dual.snapshot(&mut store).unwrap();
        let mut expected = initial.clone();
        for key in 64..192 {
            let name = format!("key-{key:04}").into_bytes();
            let value = vec![key as u8; [0, 64, 65536][key % 3]];
            dual.set(&mut store, &name, &value).unwrap();
            expected.insert(name, value);
        }
        assert_eq!(dual.overlay_len(), 128);
        assert_eq!(dual.verify(&store).unwrap(), expected);
        let reader = dual.reader(&store).unwrap();
        for (key, value) in &expected {
            assert_eq!(reader.get(key).unwrap().as_ref(), Some(value));
        }
        assert_eq!(reader.get(b"missing").unwrap(), None);
        let mixed = dual.snapshot(&mut store).unwrap();
        let packed =
            MemoryStore::from_bytes(sac::pack_snapshot(&store, mixed, Vec::new()).unwrap())
                .unwrap();
        packed.validate().unwrap();
        let root = sac::v1::Reader::open_at(packed.as_bytes())
            .unwrap()
            .snapshot()
            .unwrap();
        assert_eq!(
            DualMap::open(&packed, root)
                .unwrap()
                .verify(&packed)
                .unwrap(),
            expected
        );
        let exported = dual.checkpoint(&mut store).unwrap();
        assert_eq!(dual.overlay_len(), 0);
        let resource =
            resources::ArchiveReader::open(&store, exported, resources::Limits::default()).unwrap();
        assert_eq!(resource.verify().unwrap().files, expected.len() as u64);
        for (key, value) in &expected {
            assert_eq!(
                &resource
                    .read_file_bounded(&[key.clone()], 65536)
                    .unwrap()
                    .unwrap()
                    .1,
                value
            );
        }
        assert_eq!(dual.verify(&store).unwrap(), expected);
        assert_eq!(
            DualMap::open(&store, first)
                .unwrap()
                .verify(&store)
                .unwrap(),
            initial
        );
        assert_eq!(
            DualMap::open(&store, mixed)
                .unwrap()
                .verify(&store)
                .unwrap(),
            expected
        );
        assert!(dual.set(&mut store, b"bad/name", b"bad").is_err());
        // Checkpoint is idempotent and subsequent edits override the new base.
        assert_eq!(dual.checkpoint(&mut store).unwrap().hash, exported.hash);
        dual.set(&mut store, b"key-0000", b"new").unwrap();
        assert_eq!(
            dual.reader(&store)
                .unwrap()
                .get(b"key-0000")
                .unwrap()
                .unwrap(),
            b"new"
        );
    }
}

#[test]
fn dual_failed_merge_keeps_both_roots() {
    for layout in [0, 1, 2] {
        let mut store = FailingWriter {
            store: MemoryStore::sealed(),
            remaining: usize::MAX,
        };
        let mut builder = ArchiveBuilder::new(&mut store);
        builder.add_file(&[b"base".to_vec()], b"original").unwrap();
        let base = builder.finish().unwrap();
        let mut dual = dual_from_base(&store, base, layout).unwrap();
        dual.set(&mut store, b"base", b"replacement").unwrap();
        dual.set(&mut store, b"added", b"new").unwrap();
        let expected = dual.verify(&store).unwrap();
        let before = dual.snapshot(&mut store).unwrap();
        store.remaining = 0;
        assert!(dual.checkpoint(&mut store).is_err());
        assert_eq!(dual.overlay_len(), 2);
        assert_eq!(dual.verify(&store).unwrap(), expected);
        store.remaining = usize::MAX;
        assert_eq!(dual.snapshot(&mut store).unwrap().hash, before.hash);
        dual.checkpoint(&mut store).unwrap();
        assert_eq!(dual.verify(&store).unwrap(), expected);
    }
}

#[test]
fn dual_owner_rejects_wrong_layer_roles_and_non_plain_bases() {
    for case in 0..4 {
        let mut store = MemoryStore::sealed();
        let base = ArchiveBuilder::new(&mut store).finish().unwrap();
        let delta = PrefixTrie::default().profile_root(&mut store).unwrap();
        let (children, payload) = match case {
            0 => (vec![delta, base], V::Array(vec![V::Uint(0), V::Uint(1)])),
            1 => (vec![base, base], V::Array(vec![V::Uint(0), V::Uint(1)])),
            2 => (vec![base, delta], V::Array(vec![V::Uint(1), V::Uint(0)])),
            _ => (vec![base], V::Array(vec![V::Uint(0), V::Uint(1)])),
        };
        let root = store
            .put(
                8,
                1,
                &cbor::encode(&V::Array(vec![
                    V::text(dual_map::PROFILE),
                    V::text("root"),
                    V::Uint(1),
                    V::Bytes(cbor::encode(&payload)),
                ])),
                &children,
            )
            .unwrap();
        let directory = ArchiveBuilder::new(&mut store).finish_directory().unwrap();
        let mixed = resources::snapshot(
            &mut store,
            directory,
            vec![Profile {
                id: dual_map::PROFILE.into(),
                version: 1,
                root,
            }],
            vec![],
        )
        .unwrap();
        sac::validate_closure(&store, Some(mixed)).unwrap();
        assert!(DualMap::open(&store, mixed).is_err());
        assert!(DualMap::from_base(&store, mixed).is_err());
    }
}

#[test]
fn dual_reference_checkpoint_preserves_bytes_across_inline_blob_and_zero_transitions() {
    for layout in [0, 1, 2] {
        let mut store = MemoryStore::sealed();
        let base = ArchiveBuilder::new(&mut store).finish().unwrap();
        let mut dual = dual_from_base(&store, base, layout).unwrap();
        let mut values = BTreeMap::new();
        for (index, length) in [0, 64, 48 * 1024, 65536, 262145, 65536]
            .into_iter()
            .enumerate()
        {
            let key = format!("key-{index}").into_bytes();
            let bytes = vec![if index == 5 { 0 } else { index as u8 }; length];
            dual.set(&mut store, &key, &bytes).unwrap();
            values.insert(key, bytes);
        }
        let mut rebuild_control = dual.clone();
        let actual = dual.checkpoint(&mut store).unwrap();
        let rebuilt = rebuild_control.checkpoint_rebuild(&mut store).unwrap();
        assert_ne!(actual.hash, rebuilt.hash); // reused blob boundaries/sparse policy differ
        assert_eq!(rebuild_control.verify(&store).unwrap(), values);
        let mut reference = ArchiveBuilder::bulk(&mut store, resources::Limits::default()).unwrap();
        for (key, bytes) in &values {
            reference.add_file(&[key.clone()], bytes).unwrap();
        }
        let reference = reference.finish().unwrap();
        assert_eq!(rebuilt.hash, reference.hash);
        let reader =
            resources::ArchiveReader::open(&store, reference, resources::Limits::default())
                .unwrap();
        reader.verify().unwrap();
        for (key, value) in &values {
            assert_eq!(
                &reader
                    .read_file_bounded(&[key.clone()], 262145)
                    .unwrap()
                    .unwrap()
                    .1,
                value
            );
        }
        let reader =
            resources::ArchiveReader::open(&store, actual, resources::Limits::default()).unwrap();
        reader.verify().unwrap();
        assert_eq!(dual.verify(&store).unwrap(), values);
    }
}

#[test]
fn prototype_admission_refuses_features_and_unowned_snapshot_contents() {
    for dual in [false, true] {
        let mut store = MemoryStore::sealed();
        let base = ArchiveBuilder::new(&mut store).finish().unwrap();
        let original = if dual {
            DualMap::from_base(&store, base)
                .unwrap()
                .snapshot(&mut store)
                .unwrap()
        } else {
            PrefixTrie::default().snapshot(&mut store).unwrap()
        };
        let object = store.get(original).unwrap();
        let profile = Profile {
            id: if dual { dual_map::PROFILE } else { PROFILE }.into(),
            version: 1,
            root: object.children[1],
        };
        let empty = ArchiveBuilder::new(&mut store).finish_directory().unwrap();
        let mut builder = ArchiveBuilder::new(&mut store);
        builder
            .add_file(&[b"must-not-disappear".to_vec()], b"keep")
            .unwrap();
        let nonempty = builder.finish_directory().unwrap();
        let extra = store
            .put(
                8,
                1,
                &cbor::encode(&V::Array(vec![
                    V::text("org.example.other"),
                    V::text("root"),
                    V::Uint(1),
                    V::Bytes(cbor::encode(&V::Null)),
                ])),
                &[],
            )
            .unwrap();
        let cases = [
            resources::snapshot(
                &mut store,
                empty,
                vec![profile.clone()],
                vec![resources::Feature {
                    scope: Some(profile.id.clone()),
                    id: "org.example.required".into(),
                    version: 1,
                    required: true,
                }],
            )
            .unwrap(),
            resources::snapshot(&mut store, nonempty, vec![profile.clone()], vec![]).unwrap(),
            resources::snapshot(
                &mut store,
                empty,
                vec![
                    profile,
                    Profile {
                        id: "org.example.other".into(),
                        version: 1,
                        root: extra,
                    },
                ],
                vec![],
            )
            .unwrap(),
        ];
        for root in cases {
            sac::validate_closure(&store, Some(root)).unwrap();
            assert!(if dual {
                DualMap::open(&store, root).is_err()
            } else {
                PrefixTrie::open(&store, root).is_err()
            });
        }
    }
}

#[test]
fn already_durable_prototype_roots_reuse_the_existing_publication() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = NativeStore::create_live(dir.path().join("idempotent.sac"), [31; 16]).unwrap();
    let mut trie = PrefixTrie::default();
    trie.set(&mut store, b"key", b"value").unwrap();
    let trie_root = trie.snapshot(&mut store).unwrap();
    let base = ArchiveBuilder::new(&mut store).finish().unwrap();
    let dual_root = DualMap::from_base(&store, base)
        .unwrap()
        .snapshot(&mut store)
        .unwrap();
    for root in [trie_root, dual_root] {
        let first = store.publish(root).unwrap();
        let before = store.publication_statistics();
        assert_eq!(store.publish(root).unwrap(), first);
        let after = store.publication_statistics();
        assert_eq!(after.chunk_barriers, before.chunk_barriers);
        assert_eq!(after.slot_syncs, before.slot_syncs);
    }
}

#[test]
fn dual_durable_publication_recovery_checks_both_layers_and_old_pins() {
    for layout in [0, 1, 2] {
        use sac::v1::native::PublicationFault;
        for fault in [
            None,
            Some(PublicationFault::ChunksBarrier),
            Some(PublicationFault::SlotWrite { bytes: 40 }),
            Some(PublicationFault::SlotSync),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("dual.sac");
            let mut store = NativeStore::create_live(&path, [23; 16]).unwrap();
            let mut builder = ArchiveBuilder::new(&mut store);
            builder
                .add_file(&[b"kept".to_vec()], b"base value")
                .unwrap();
            builder.add_file(&[b"updated".to_vec()], b"old").unwrap();
            let base = builder.finish().unwrap();
            let mut dual = dual_from_base(&store, base, layout).unwrap();
            let first = dual.snapshot(&mut store).unwrap();
            let (_, old) = store.publish_pinned(first).unwrap();
            store.set_append_index_memory_budget(0).unwrap();
            store.set_decoded_cache_budget(0);
            dual.set(&mut store, b"updated", &[3; 65536]).unwrap();
            dual.checkpoint(&mut store).unwrap();
            dual.set(&mut store, b"added", b"overlay value").unwrap();
            let expected = dual.verify(&store).unwrap();
            let next = dual.snapshot(&mut store).unwrap();
            if let Some(fault) = fault {
                store.inject_publication_fault_once(fault);
                assert!(store.publish(next).is_err());
                assert!(matches!(store.publish(next), Err(Error::Poisoned)));
            } else {
                let before = store.publication_statistics();
                store.publish(next).unwrap();
                let after = store.publication_statistics();
                assert_eq!(after.chunk_barriers - before.chunk_barriers, 1);
                assert_eq!(after.slot_syncs - before.slot_syncs, 1);
            }
            let old_values = DualMap::open(&old, first).unwrap().verify(&old).unwrap();
            assert_eq!(old_values[b"updated".as_slice()], b"old");
            drop(store);
            let reopened = NativeStore::open(path, false).unwrap();
            reopened.validate().unwrap();
            let selected = reopened.reader().snapshot().unwrap();
            let expect_new = fault.is_none() || fault == Some(PublicationFault::SlotSync);
            assert_eq!(
                selected.hash,
                if expect_new { next.hash } else { first.hash }
            );
            assert_eq!(
                DualMap::open(&reopened, selected)
                    .unwrap()
                    .verify(&reopened)
                    .unwrap(),
                if expect_new { expected } else { old_values }
            );
        }
    }
}

#[derive(Default)]
struct MergeObservations {
    reads: std::cell::RefCell<Vec<ObjectRef>>,
    puts: Vec<(u16, ObjectRef)>,
}
struct ObservedStore {
    inner: MemoryStore,
    observations: MergeObservations,
}
impl ObjectStore for ObservedStore {
    fn get(&self, reference: ObjectRef) -> Result<CanonicalObject> {
        self.observations.reads.borrow_mut().push(reference);
        self.inner.get(reference)
    }
    fn put(
        &mut self,
        kind: u16,
        version: u16,
        bytes: &[u8],
        children: &[ObjectRef],
    ) -> Result<ObjectRef> {
        let reference = self.inner.put(kind, version, bytes, children)?;
        self.observations.puts.push((kind, reference));
        Ok(reference)
    }
}
fn closure_objects(store: &impl ObjectStore, root: ObjectRef) -> BTreeMap<ObjectRef, u16> {
    let mut output = BTreeMap::new();
    let mut pending = vec![root];
    while let Some(reference) = pending.pop() {
        if output.contains_key(&reference) {
            continue;
        }
        let object = store.get_verified_shared(reference).unwrap();
        output.insert(reference, object.kind);
        pending.extend_from_slice(&object.children);
    }
    output
}

#[test]
fn dual_incremental_merge_keeps_untouched_pages_and_reuses_authenticated_blobs() {
    for layout in [0, 1, 2] {
        let mut store = ObservedStore {
            inner: MemoryStore::sealed(),
            observations: MergeObservations::default(),
        };
        let mut builder = ArchiveBuilder::new(&mut store);
        builder.set_page_limit(4096).unwrap();
        for key in 0..1024 {
            let value = vec![key as u8; if key % 64 == 0 { 65536 } else { 64 }];
            builder
                .add_file(&[format!("key-{key:04}").into_bytes()], &value)
                .unwrap();
        }
        let base = builder.finish().unwrap();
        let before = closure_objects(&store, base);
        let old_leaves: std::collections::BTreeSet<_> = before
            .iter()
            .filter_map(|(r, kind)| (*kind == 3).then_some(*r))
            .collect();
        assert!(old_leaves.len() > 20);
        let mut dual = dual_from_base(&store, base, layout).unwrap();
        // Adjacent replacements touch one existing leaf. Large values already live
        // in the authenticated delta; merging must not put byte objects again.
        dual.set(&mut store, b"key-0500", &[42; 65536]).unwrap();
        dual.set(&mut store, b"key-0501", b"").unwrap();
        let mixed = dual.snapshot(&mut store).unwrap();
        let mixed_objects = closure_objects(&store, mixed);
        let new_blob = *mixed_objects
            .iter()
            .find(|(r, kind)| **kind == 7 && !before.contains_key(r))
            .unwrap()
            .0;
        store.observations = MergeObservations::default();
        let merged = dual.checkpoint(&mut store).unwrap();
        let merge_reads = store.observations.reads.borrow().clone();
        let merge_puts = store.observations.puts.clone();
        let after = closure_objects(&store, merged);
        let new_leaves: std::collections::BTreeSet<_> = after
            .iter()
            .filter_map(|(r, kind)| (*kind == 3).then_some(*r))
            .collect();
        assert_eq!(old_leaves.difference(&new_leaves).count(), 1);
        assert_eq!(new_leaves.difference(&old_leaves).count(), 1);
        assert_eq!(merge_puts.iter().filter(|(kind, _)| *kind == 3).count(), 1);
        assert!(!merge_puts.iter().any(|(kind, _)| *kind == 7));
        assert!(after.contains_key(&new_blob)); // exact hash AND physical locator
        for (reference, kind) in &before {
            if *kind == 7 {
                assert!(
                    after.contains_key(reference),
                    "unchanged payload reference lost"
                );
                assert!(
                    !merge_reads.contains(reference),
                    "merge reread untouched file bytes"
                );
            }
        }
        let read_leaves: std::collections::BTreeSet<_> = merge_reads
            .into_iter()
            .filter(|r| old_leaves.contains(r))
            .collect();
        assert_eq!(
            read_leaves.len(),
            1,
            "merge traversed unrelated directory pages"
        );
        let resource =
            resources::ArchiveReader::open(&store, merged, resources::Limits::default()).unwrap();
        assert_eq!(resource.verify().unwrap().files, 1024);
        assert_eq!(
            resource
                .read_file_bounded(&[b"key-0500".to_vec()], 65536)
                .unwrap()
                .unwrap()
                .1,
            [42; 65536]
        );
        assert_eq!(
            DualMap::open(&store, mixed)
                .unwrap()
                .reader(&store)
                .unwrap()
                .get(b"key-0501")
                .unwrap(),
            Some(vec![])
        );
        let old =
            resources::ArchiveReader::open(&store, base, resources::Limits::default()).unwrap();
        assert_eq!(
            old.read_file_bounded(&[b"key-0500".to_vec()], 64)
                .unwrap()
                .unwrap()
                .1,
            [500u16 as u8; 64]
        );
    }
}

#[test]
fn dual_multibatch_merge_is_atomic_at_every_write_boundary() {
    for layout in [0, 1, 2] {
        let mut store = FailingWriter {
            store: MemoryStore::sealed(),
            remaining: usize::MAX,
        };
        let base = ArchiveBuilder::new(&mut store).finish().unwrap();
        let mut original = dual_from_base(&store, base, layout).unwrap();
        for key in 0..1025 {
            original
                .set(
                    &mut store,
                    format!("key-{key:04}").as_bytes(),
                    &[key as u8; 8],
                )
                .unwrap();
        }
        let expected = original.verify(&store).unwrap();
        let prior = original.snapshot(&mut store).unwrap();
        let mut success = original.clone();
        let before = store.remaining;
        success.checkpoint(&mut store).unwrap();
        let writes = before - store.remaining;
        assert!(writes > 3);
        // Includes failures after one or two complete batches and at final snapshot.
        for allowed in 0..writes {
            let mut candidate = original.clone();
            store.remaining = allowed;
            assert!(
                candidate.checkpoint(&mut store).is_err(),
                "boundary {allowed}"
            );
            assert_eq!(candidate.overlay_len(), 1025);
            assert_eq!(candidate.verify(&store).unwrap(), expected);
            store.remaining = usize::MAX;
            assert_eq!(candidate.snapshot(&mut store).unwrap().hash, prior.hash);
        }
        assert_eq!(success.overlay_len(), 0);
        assert_eq!(success.verify(&store).unwrap(), expected);
    }
}

#[test]
fn dual_admission_validates_the_entire_base_before_incremental_edits() {
    for variant in 0..3 {
        let mut store = MemoryStore::sealed();
        let mut builder = ArchiveBuilder::new(&mut store);
        match variant {
            0 => builder
                .add_file(&[b"parent".to_vec(), b"file".to_vec()], b"hierarchical")
                .unwrap(),
            1 => builder
                .add_file_with_metadata(
                    &[b"file".to_vec()],
                    b"metadata",
                    cbor::text_map(vec![("mode", V::Uint(0o600))]),
                )
                .unwrap(),
            _ => builder.add_symlink(&[b"link".to_vec()], b"target").unwrap(),
        }
        let base = builder.finish().unwrap();
        assert!(DualMap::from_base(&store, base).is_err());
    }
    let mut store = MemoryStore::sealed();
    let mut builder = ArchiveBuilder::new(&mut store);
    builder
        .add_file(&[b"file".to_vec()], b"authenticated")
        .unwrap();
    let base = builder.finish().unwrap();
    let directory = resources::ArchiveReader::open(&store, base, resources::Limits::default())
        .unwrap()
        .directory_root();
    // Supply a valid empty leaf under the nonempty directory's expected hash.
    let mut replacement_store = MemoryStore::sealed();
    let empty = ArchiveBuilder::new(&mut replacement_store)
        .finish_directory()
        .unwrap();
    let substituted = Substituted {
        store: &store,
        target: directory,
        replacement: replacement_store.get(empty).unwrap(),
    };
    assert!(DualMap::from_base(&substituted, base).is_err());
}

#[test]
fn paged_delta_rejects_unowned_layers_and_authenticates_leaf_substitution() {
    for variant in 0..5 {
        let mut store = MemoryStore::sealed();
        let base = ArchiveBuilder::new(&mut store).finish().unwrap();
        let delta = if variant == 0 {
            PrefixTrie::default().profile_root(&mut store).unwrap()
        } else {
            let mut builder = ArchiveBuilder::new(&mut store);
            match variant {
                1 => builder
                    .add_file(&[b"dir".to_vec(), b"file".to_vec()], b"bad")
                    .unwrap(),
                2 => builder.add_symlink(&[b"link".to_vec()], b"target").unwrap(),
                3 => builder
                    .add_file_with_metadata(
                        &[b"file".to_vec()],
                        b"bad",
                        cbor::text_map(vec![("mode", V::Uint(0o600))]),
                    )
                    .unwrap(),
                _ => builder.add_file(&[b"file".to_vec()], b"valid").unwrap(),
            }
            let snapshot = builder.finish().unwrap();
            if variant == 4 {
                let directory =
                    resources::ArchiveReader::open(&store, snapshot, resources::Limits::default())
                        .unwrap()
                        .directory_root();
                resources::snapshot(
                    &mut store,
                    directory,
                    vec![],
                    vec![resources::Feature {
                        scope: None,
                        id: "org.example.feature".into(),
                        version: 1,
                        required: false,
                    }],
                )
                .unwrap()
            } else {
                snapshot
            }
        };
        let root = store
            .put(
                8,
                1,
                &cbor::encode(&V::Array(vec![
                    V::text(dual_map::PAGED_PROFILE),
                    V::text("root"),
                    V::Uint(1),
                    V::Bytes(cbor::encode(&V::Array(vec![V::Uint(0), V::Uint(1)]))),
                ])),
                &[base, delta],
            )
            .unwrap();
        let directory = ArchiveBuilder::new(&mut store).finish_directory().unwrap();
        let snapshot = resources::snapshot(
            &mut store,
            directory,
            vec![Profile {
                id: dual_map::PAGED_PROFILE.into(),
                version: 1,
                root,
            }],
            vec![],
        )
        .unwrap();
        assert!(
            DualMap::open(&store, snapshot).is_err(),
            "variant {variant}"
        );
    }
    let mut store = MemoryStore::sealed();
    let base = ArchiveBuilder::new(&mut store).finish().unwrap();
    let mut map = DualMap::from_base_paged(&store, base).unwrap();
    map.set(&mut store, b"key", b"secret").unwrap();
    let root = map.snapshot(&mut store).unwrap();
    let snapshot = store.get(root).unwrap();
    let profile = store.get(snapshot.children[1]).unwrap();
    let delta = store.get(profile.children[1]).unwrap();
    let leaf = delta.children[0];
    let replacement = store.get(store.get(base).unwrap().children[0]).unwrap();
    let substituted = Substituted {
        store: &store,
        target: leaf,
        replacement,
    };
    assert!(DualMap::open(&substituted, root).is_err());
    assert!(
        map.reader(&substituted)
            .and_then(|reader| reader.get(b"key"))
            .is_err()
    );
}

#[test]
fn paged_delta_packs_small_records_and_reader_does_not_materialize_the_map() {
    let mut store = ObservedStore {
        inner: MemoryStore::sealed(),
        observations: MergeObservations::default(),
    };
    let base = ArchiveBuilder::new(&mut store).finish().unwrap();
    let mut trie = DualMap::from_base(&store, base).unwrap();
    let mut paged = DualMap::from_base_paged(&store, base).unwrap();
    for n in 0..1024 {
        let key = format!("record-{n:08x}");
        let mut value = [5u8; 64];
        value[..8].copy_from_slice(&(n as u64).to_le_bytes());
        trie.set(&mut store, key.as_bytes(), &value).unwrap();
        paged.set(&mut store, key.as_bytes(), &value).unwrap();
    }
    let old_root = trie.snapshot(&mut store).unwrap();
    let root = paged.snapshot(&mut store).unwrap();
    let old_size = sac::pack_snapshot(&store, old_root, vec![]).unwrap().len();
    let size = sac::pack_snapshot(&store, root, vec![]).unwrap().len();
    assert!(size * 4 < old_size, "old={old_size} paged={size}");
    assert_eq!(trie.verify(&store).unwrap(), paged.verify(&store).unwrap());
    store.observations = MergeObservations::default();
    let reader = paged.reader(&store).unwrap();
    assert!(
        store.observations.reads.borrow().len() <= 8,
        "reader construction walked the delta"
    );
    store.observations.reads.borrow_mut().clear();
    assert_eq!(reader.get(b"record-000000fe").unwrap().unwrap().len(), 64);
    assert!(
        store.observations.reads.borrow().len() <= 4,
        "lookup walked the map"
    );
    store.observations.reads.borrow_mut().clear();
    assert!(reader.get(b"absent").unwrap().is_none());
    assert!(
        store.observations.reads.borrow().len() <= 1,
        "verified range did not skip delta"
    );
}

#[test]
fn paged_delta_supports_maximum_resource_keys_and_preserves_failed_write_bounds() {
    let mut store = FailingWriter {
        store: MemoryStore::sealed(),
        remaining: usize::MAX,
    };
    let base = ArchiveBuilder::new(&mut store).finish().unwrap();
    let mut map = DualMap::from_base_paged(&store, base).unwrap();
    let mut keys = vec![];
    for n in 0..12 {
        let mut key = vec![b'q'; MAX_KEY];
        key[0] = b'a' + n;
        map.set(&mut store, &key, &[n; 64]).unwrap();
        keys.push(key);
    }
    let snapshot = map.snapshot(&mut store).unwrap();
    let mut opened = DualMap::open(&store, snapshot).unwrap();
    for (n, key) in keys.iter().enumerate() {
        assert_eq!(
            opened.reader(&store).unwrap().get(key).unwrap(),
            Some(vec![n as u8; 64])
        );
    }
    store.remaining = 0;
    assert!(
        opened
            .set(&mut store, b"zz-outside-bounds", b"new")
            .is_err()
    );
    assert!(
        opened
            .reader(&store)
            .unwrap()
            .get(b"zz-outside-bounds")
            .unwrap()
            .is_none()
    );
    store.remaining = usize::MAX;
    assert_eq!(opened.snapshot(&mut store).unwrap().hash, snapshot.hash);
    opened
        .set(&mut store, b"zz-outside-bounds", b"new")
        .unwrap();
    assert_eq!(
        opened
            .reader(&store)
            .unwrap()
            .get(b"zz-outside-bounds")
            .unwrap(),
        Some(b"new".to_vec())
    );
    opened.checkpoint(&mut store).unwrap();
    assert_eq!(opened.verify(&store).unwrap().len(), 13);
}

#[test]
fn bucket_canonical_model_binary_prefixes_and_value_transitions() {
    use bucket_trie::BucketTrie;
    let mut expected = BTreeMap::new();
    expected.insert(vec![], vec![]);
    expected.insert(b"a".to_vec(), vec![2; 129]);
    expected.insert(b"ab".to_vec(), vec![3; 128]);
    expected.insert(b"abc".to_vec(), vec![4; 65536]);
    expected.insert(vec![7; MAX_KEY], vec![8; 64]);
    for b in 0..=255 {
        expected.insert(vec![b, 0, 255], vec![b; 64]);
    }
    for n in 0..4096 {
        expected.insert(
            format!("record-{n:08x}").into_bytes(),
            vec![(n % 251) as u8; 64],
        );
    }
    let mut roots = vec![];
    for reverse in [false, true] {
        let mut store = MemoryStore::sealed();
        let mut trie = BucketTrie::default();
        let empty = trie.snapshot(&mut store).unwrap();
        assert_eq!(
            BucketTrie::open(&store, empty)
                .unwrap()
                .verify(&store)
                .unwrap(),
            BTreeMap::new()
        );
        let mut entries: Vec<_> = expected.iter().collect();
        if reverse {
            entries.reverse();
        }
        for (key, value) in entries {
            trie.set(&mut store, key, value).unwrap();
        }
        assert_eq!(trie.verify(&store).unwrap(), expected);
        for (key, value) in &expected {
            assert_eq!(trie.get(&store, key).unwrap().as_ref(), Some(value));
        }
        let root = trie.snapshot(&mut store).unwrap();
        roots.push(root.hash);
        for (i, length) in [0, 8, 64, 128, 129, 512, 4096, 65536, 0]
            .into_iter()
            .enumerate()
        {
            let value = vec![i as u8; length];
            trie.set(&mut store, b"ab", &value).unwrap();
            assert_eq!(trie.get(&store, b"ab").unwrap(), Some(value));
        }
        assert_eq!(
            BucketTrie::open(&store, root)
                .unwrap()
                .verify(&store)
                .unwrap(),
            expected
        );
        let packed = sac::pack_snapshot(&store, root, vec![]).unwrap();
        let packed = MemoryStore::from_bytes(packed).unwrap();
        packed.validate().unwrap();
        let root = sac::v1::Reader::open_at(packed.as_bytes())
            .unwrap()
            .snapshot()
            .unwrap();
        assert_eq!(
            BucketTrie::open(&packed, root)
                .unwrap()
                .verify(&packed)
                .unwrap(),
            expected
        );
    }
    assert_eq!(roots[0], roots[1]);
}

#[test]
fn bucket_shares_record_frames_and_never_preloads_reader_keys() {
    let mut store = ObservedStore {
        inner: MemoryStore::sealed(),
        observations: MergeObservations::default(),
    };
    let base = ArchiveBuilder::new(&mut store).finish().unwrap();
    let mut old = DualMap::from_base(&store, base).unwrap();
    let mut new = DualMap::from_base_bucket(&store, base).unwrap();
    for n in 0..4096 {
        let key = format!("record-{n:08x}");
        let mut value = [3; 64];
        value[..8].copy_from_slice(&(n as u64).to_le_bytes());
        old.set(&mut store, key.as_bytes(), &value).unwrap();
        new.set(&mut store, key.as_bytes(), &value).unwrap();
    }
    let old_root = old.snapshot(&mut store).unwrap();
    let root = new.snapshot(&mut store).unwrap();
    let old_size = sac::pack_snapshot(&store, old_root, vec![]).unwrap().len();
    let size = sac::pack_snapshot(&store, root, vec![]).unwrap().len();
    assert!(size * 3 < old_size, "old={old_size} bucket={size}");
    assert_eq!(new.verify(&store).unwrap(), old.verify(&store).unwrap());
    store.observations = MergeObservations::default();
    let reader = new.reader(&store).unwrap();
    assert!(store.observations.reads.borrow().len() <= 4);
    store.observations.reads.borrow_mut().clear();
    assert_eq!(reader.get(b"record-000000fe").unwrap().unwrap().len(), 64);
    assert!(
        store.observations.reads.borrow().len() <= 3,
        "lookup fetched too many nodes: {}",
        store.observations.reads.borrow().len()
    );
}

#[test]
fn bucket_rejects_malformed_rows_children_counts_and_substitution() {
    use bucket_trie::{BucketTrie, PROFILE as BP};
    fn put(store: &mut MemoryStore, typ: &str, payload: V, children: &[ObjectRef]) -> ObjectRef {
        store
            .put(
                8,
                1,
                &cbor::encode(&V::Array(vec![
                    V::text(BP),
                    V::text(typ),
                    V::Uint(1),
                    V::Bytes(cbor::encode(&payload)),
                ])),
                children,
            )
            .unwrap()
    }
    let mut store = MemoryStore::sealed();
    let blob = store.put(7, 1, &[7; 129], &[]).unwrap();
    // u16 prefix length, prefix, row count; then u16 suffix length,
    // suffix, inline length/data or tag 255 + u32 blob length.
    let valid = vec![0, 0, 1, 0, 0, 1, 5];
    let fixtures = vec![
        (vec![0, 0, 0], vec![], 1),
        (vec![0, 0, 17], vec![], 17),
        (vec![0, 0, 2, 1, 0, b'b', 1, 5, 1, 0, b'a', 1, 5], vec![], 2),
        (vec![0, 0, 2, 0, 0, 1, 5, 0, 0, 1, 5], vec![], 2),
        (vec![0, 0, 1, 1, 0, b'a', 1, 5], vec![], 1),
        (valid.clone(), vec![blob], 1),
        (vec![0, 0, 1, 0, 0, 255, 129, 0, 0, 0], vec![], 1),
        (vec![0, 0, 1, 0, 0, 129], vec![], 1),
        (valid.clone(), vec![], 2),
        ([valid.clone(), vec![0]].concat(), vec![], 1),
        (vec![255, 255, 0], vec![], 1),
    ];
    for (payload, children, count) in fixtures {
        let node = put(&mut store, "bucket", V::Bytes(payload), &children);
        let root = put(
            &mut store,
            "root",
            V::Array(vec![V::Uint(count), V::Uint(0)]),
            &[node],
        );
        assert!(
            BucketTrie::from_profile_root(&store, root)
                .unwrap()
                .verify(&store)
                .is_err()
        );
    }
    let mut trie = BucketTrie::default();
    trie.set(&mut store, b"key", b"secret").unwrap();
    let root = trie.profile_root(&mut store).unwrap();
    let node = store.get(root).unwrap().children[0];
    let replacement = store.get(blob).unwrap();
    let substituted = Substituted {
        store: &store,
        target: node,
        replacement,
    };
    assert!(trie.get(&substituted, b"key").is_err());
    assert!(trie.verify(&substituted).is_err());
}

#[test]
fn bucket_failed_split_and_large_value_writes_preserve_root_and_count() {
    use bucket_trie::BucketTrie;
    let mut store = FailingWriter {
        store: MemoryStore::sealed(),
        remaining: usize::MAX,
    };
    let mut original = BucketTrie::default();
    for n in 0..16 {
        original
            .set(&mut store, format!("key-{n:02x}").as_bytes(), &[n; 64])
            .unwrap();
    }
    let snapshot = original.snapshot(&mut store).unwrap();
    let expected = original.verify(&store).unwrap();
    for key in [b"key-10".as_slice(), b"key-00".as_slice()] {
        let mut succeeded = false;
        for allowed in 0..32 {
            let mut trie = original.clone();
            store.remaining = allowed;
            let result = trie.set(&mut store, key, &[42; 65536]);
            store.remaining = usize::MAX;
            if result.is_ok() {
                assert_eq!(trie.get(&store, key).unwrap(), Some(vec![42; 65536]));
                assert_eq!(trie.len(), if key == b"key-10" { 17 } else { 16 });
                succeeded = true;
                break;
            }
            assert_eq!(trie.len(), 16);
            assert_eq!(trie.snapshot(&mut store).unwrap().hash, snapshot.hash);
            assert_eq!(trie.verify(&store).unwrap(), expected);
        }
        assert!(succeeded, "did not exhaust every failed write boundary");
    }
}

#[test]
fn bucket_large_value_descriptor_roles_and_branch_indices_are_owned() {
    use bucket_trie::{BucketTrie, PROFILE as BP};
    fn put(store: &mut MemoryStore, typ: &str, payload: V, children: &[ObjectRef]) -> ObjectRef {
        store
            .put(
                8,
                1,
                &cbor::encode(&V::Array(vec![
                    V::text(BP),
                    V::text(typ),
                    V::Uint(1),
                    V::Bytes(cbor::encode(&payload)),
                ])),
                children,
            )
            .unwrap()
    }
    let mut store = MemoryStore::sealed();
    let blob = store.put(7, 1, &[8; 129], &[]).unwrap();
    let wrong_length = put(
        &mut store,
        "value",
        V::Array(vec![V::Uint(130), V::Uint(0), V::Bytes(vec![8; 129])]),
        &[blob],
    );
    let no_child = put(
        &mut store,
        "value",
        V::Array(vec![V::Uint(129), V::Uint(1), V::Uint(0)]),
        &[],
    );
    let large_no_child = put(
        &mut store,
        "value",
        V::Array(vec![V::Uint(65536), V::Uint(1), V::Uint(0)]),
        &[],
    );
    let large_wrong_length = put(
        &mut store,
        "value",
        V::Array(vec![V::Uint(65536), V::Uint(1), V::Uint(0)]),
        &[blob],
    );
    let large_wrong_kind = put(
        &mut store,
        "value",
        V::Array(vec![V::Uint(65536), V::Uint(1), V::Uint(0)]),
        &[wrong_length],
    );
    for (descriptor, length) in [
        (blob, 129u32),
        (wrong_length, 129),
        (no_child, 129),
        (large_no_child, 65536),
        (large_wrong_length, 65536),
        (large_wrong_kind, 65536),
    ] {
        let mut bytes = vec![3, 0, b'k', b'e', b'y', 1, 0, 0, 255];
        bytes.extend(length.to_le_bytes());
        let node = put(&mut store, "bucket", V::Bytes(bytes), &[descriptor]);
        let root = put(
            &mut store,
            "root",
            V::Array(vec![V::Uint(1), V::Uint(0)]),
            &[node],
        );
        let trie = BucketTrie::from_profile_root(&store, root).unwrap();
        assert!(trie.verify(&store).is_err());
        assert!(trie.get(&store, b"key").is_err());
    }
    let mut valid = BucketTrie::default();
    valid.set(&mut store, b"x", b"v").unwrap();
    let root = valid.profile_root(&mut store).unwrap();
    let child = store.get(root).unwrap().children[0];
    for raw in [
        vec![0, 0, 0, 0, 0],
        vec![0, 0, 0, 1, 0, 0],
        vec![0, 0, 0, 2, 0, 1, 0],
        vec![0, 0, 0, 2, 0, 0, 0],
        vec![0, 0, 2, 2, 0, 0, 1],
        vec![0, 0, 0, 2, 0, 0],
        vec![0, 0, 0, 2, 0, 0, 1, 9],
    ] {
        let node = put(&mut store, "branch", V::Bytes(raw), &[child, child]);
        let root = put(
            &mut store,
            "root",
            V::Array(vec![V::Uint(2), V::Uint(0)]),
            &[node],
        );
        assert!(
            BucketTrie::from_profile_root(&store, root)
                .unwrap()
                .verify(&store)
                .is_err()
        );
    }
}

#[test]
fn bucket_long_key_splits_keep_prefix_values_and_enforce_complete_key_limits() {
    use bucket_trie::BucketTrie;
    let mut store = MemoryStore::sealed();
    let mut trie = BucketTrie::default();
    let mut expected = BTreeMap::new();
    let mut near = vec![b'a'; MAX_KEY];
    near[MAX_KEY - 1] = b'b';
    let keys = vec![
        vec![b'a'; MAX_KEY],
        near,
        vec![b'b'; MAX_KEY],
        vec![b'c'; MAX_KEY],
        b"a".to_vec(),
        vec![],
    ];
    for (i, key) in keys.into_iter().enumerate() {
        let value = vec![i as u8; 129];
        trie.set(&mut store, &key, &value).unwrap();
        expected.insert(key, value);
    }
    assert_eq!(trie.verify(&store).unwrap(), expected);
    for (k, v) in &expected {
        assert_eq!(trie.get(&store, k).unwrap().as_ref(), Some(v));
    }
    let root = trie.snapshot(&mut store).unwrap();
    assert!(
        trie.set(&mut store, &vec![b'x'; MAX_KEY + 1], b"bad")
            .is_err()
    );
    assert!(trie.get(&store, &vec![b'x'; MAX_KEY + 1]).is_err());
    assert_eq!(trie.snapshot(&mut store).unwrap().hash, root.hash);
}
