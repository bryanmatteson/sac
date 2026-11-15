use sac::cbor::{self, Value as V};
use sac::resources::{self, ArchiveBuilder, ArchiveReader, Feature, Limits, Profile};
use sac::{CanonicalObject, Error, LiveMap, MemoryStore, ObjectRef, ObjectStore, Result};
#[cfg(feature = "native")]
#[allow(dead_code, unused_imports)]
#[path = "../tools/performance/src/bucket_trie.rs"]
mod bucket_trie;
#[cfg(feature = "native")]
#[allow(dead_code)]
#[path = "../tools/performance/src/dual_map.rs"]
mod dual_map;
#[cfg(feature = "native")]
#[allow(dead_code)]
#[path = "../tools/performance/src/prefix_trie.rs"]
mod prefix_trie;

#[test]
fn plain_import_live_update_checkpoint_and_pack_preserve_values() {
    let mut store = MemoryStore::sealed();
    let mut builder = ArchiveBuilder::new(&mut store);
    for i in 0..1024 {
        builder
            .add_file(&[format!("k{i:04}").into_bytes()], b"base")
            .unwrap();
    }
    let base = builder.finish().unwrap();
    let mut map = LiveMap::open(&store, base).unwrap();
    for i in 0..1536 {
        let key = format!("k{i:04}");
        map.set(
            &mut store,
            key.as_bytes(),
            &vec![i as u8; [0, 64, 129, 4096, 65536][i % 5]],
        )
        .unwrap();
    }
    for i in 0..256 {
        map.set(&mut store, format!("k{i:04}").as_bytes(), b"shrink")
            .unwrap();
    }
    let expected = map.verify(&store).unwrap();
    let root = map.snapshot(&mut store).unwrap();
    assert!(ArchiveReader::open(&store, root, Limits::default()).is_err());
    let packed = sac::pack_snapshot(&store, root, Vec::new()).unwrap();
    let copied = MemoryStore::from_bytes(packed).unwrap();
    let copied_root = sac::Reader::open_at(copied.as_bytes())
        .unwrap()
        .snapshot()
        .unwrap();
    assert_eq!(
        LiveMap::open(&copied, copied_root)
            .unwrap()
            .verify(&copied)
            .unwrap(),
        expected
    );
    let old = LiveMap::open(&store, root).unwrap();
    let exported = map.checkpoint(&mut store).unwrap();
    assert_eq!(map.overlay_len(), 0);
    assert_eq!(old.verify(&store).unwrap(), expected);
    assert_eq!(map.verify(&store).unwrap(), expected);
    let reader = ArchiveReader::open(&store, exported, Limits::default()).unwrap();
    assert_eq!(reader.verify().unwrap().files, expected.len() as u64);
    for (key, value) in expected {
        assert_eq!(
            reader.read_file_bounded(&[key], 65536).unwrap().unwrap().1,
            value
        );
    }
}
#[cfg(feature = "native")]
#[test]
fn experimental_bucket_snapshot_migrates_without_reencoding_delta() {
    let mut store = MemoryStore::sealed();
    let base = ArchiveBuilder::new(&mut store).finish().unwrap();
    let mut old = dual_map::DualMap::from_base_bucket(&store, base).unwrap();
    old.set(&mut store, b"key", &[7; 65536]).unwrap();
    let legacy = old.snapshot(&mut store).unwrap();
    let map = LiveMap::open(&store, legacy).unwrap();
    let root = map.snapshot(&mut store).unwrap();
    let delta = |snapshot| {
        let object = store.get(snapshot).unwrap();
        store.get(object.children[1]).unwrap().children[1]
    };
    assert_eq!(delta(legacy), delta(root));
    assert_eq!(
        map.reader(&store).unwrap().get(b"key").unwrap(),
        Some(vec![7; 65536])
    );
}
#[test]
fn reject_extra_features_profiles_metadata_nested_names_and_invalid_keys() {
    let mut store = MemoryStore::sealed();
    let mut map = LiveMap::new(&mut store).unwrap();
    for key in [b"".as_slice(), b".", b"..", b"a/b", b"a\0b"] {
        assert!(map.set(&mut store, key, b"v").is_err());
    }
    assert!(map.set(&mut store, &vec![b'x'; 4097], b"v").is_err());
    let root = map.snapshot(&mut store).unwrap();
    let object = store.get(root).unwrap();
    let directory = object.children[0];
    let profile_root = object.children[1];
    for features in [
        vec![],
        vec![Feature {
            scope: Some(resources::live_map::PROFILE.into()),
            id: resources::live_map::CAPABILITY.into(),
            version: 1,
            required: true,
        }],
        vec![Feature {
            scope: None,
            id: resources::live_map::CAPABILITY.into(),
            version: 2,
            required: true,
        }],
    ] {
        let forged = resources::snapshot(
            &mut store,
            directory,
            vec![Profile {
                id: resources::live_map::PROFILE.into(),
                version: 1,
                root: profile_root,
            }],
            features,
        )
        .unwrap();
        assert!(LiveMap::open(&store, forged).is_err());
    }
    let mut builder = ArchiveBuilder::new(&mut store);
    builder
        .set_file(&[b"nested".to_vec(), b"key".to_vec()], b"v", V::Map(vec![]))
        .unwrap();
    let nested = builder.finish().unwrap();
    assert!(LiveMap::open(&store, nested).is_err());
    let mut builder = ArchiveBuilder::new(&mut store);
    builder
        .set_file(
            &[b"key".to_vec()],
            b"v",
            V::Map(vec![cbor::MapEntry {
                key: V::text("org.test.label"),
                key_bytes: cbor::encode(&V::text("org.test.label")),
                value: V::text("value"),
            }]),
        )
        .unwrap();
    let metadata = builder.finish().unwrap();
    assert!(LiveMap::open(&store, metadata).is_err());
}
struct FailStore {
    inner: MemoryStore,
    remaining: usize,
}
impl ObjectStore for FailStore {
    fn get(&self, r: ObjectRef) -> Result<CanonicalObject> {
        self.inner.get(r)
    }
    fn put(&mut self, k: u16, v: u16, b: &[u8], c: &[ObjectRef]) -> Result<ObjectRef> {
        if self.remaining == 0 {
            return Err(Error::Corrupt("injected append failure".into()));
        }
        self.remaining -= 1;
        self.inner.put(k, v, b, c)
    }
}
#[test]
fn append_and_checkpoint_failures_leave_the_selected_view_unchanged() {
    let mut store = FailStore {
        inner: MemoryStore::sealed(),
        remaining: usize::MAX,
    };
    let mut map = LiveMap::new(&mut store).unwrap();
    map.set(&mut store, b"key", b"old").unwrap();
    let before = map.verify(&store).unwrap();
    for allowance in 0..3 {
        store.remaining = allowance;
        let mut candidate = map.clone();
        if candidate.set(&mut store, b"key", &[8; 65536]).is_err() {
            assert_eq!(candidate.verify(&store).unwrap(), before);
        }
    }
    for allowance in 0..3 {
        store.remaining = allowance;
        let mut candidate = map.clone();
        if candidate.checkpoint(&mut store).is_err() {
            assert_eq!(candidate.overlay_len(), 1);
            assert_eq!(candidate.verify(&store).unwrap(), before);
        }
    }
}
#[test]
fn full_admission_rejects_bad_counts_even_when_point_lookup_would_succeed() {
    let mut store = MemoryStore::sealed();
    let mut map = LiveMap::new(&mut store).unwrap();
    map.set(&mut store, b"key", b"v").unwrap();
    let snapshot = map.snapshot(&mut store).unwrap();
    let outer = store.get(snapshot).unwrap();
    let root = store.get(outer.children[1]).unwrap();
    let delta = store.get(root.children[1]).unwrap();
    let mut fields = match cbor::decode(&delta.bytes).unwrap() {
        V::Array(a) => a,
        _ => unreachable!(),
    };
    fields[3] = V::Bytes(cbor::encode(&V::Array(vec![V::Uint(2), V::Uint(0)])));
    let bad_delta = store
        .put(8, 1, &cbor::encode(&V::Array(fields)), &delta.children)
        .unwrap();
    let bad_root = store
        .put(8, 1, &root.bytes, &[root.children[0], bad_delta])
        .unwrap();
    let bad_snapshot = store
        .put(2, 1, &outer.bytes, &[outer.children[0], bad_root])
        .unwrap();
    assert!(LiveMap::open(&store, bad_snapshot).is_err());
}
#[cfg(feature = "native")]
#[test]
fn native_live_map_publication_pins_reopen_and_cache_disabled_updates() {
    for spill in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("live.sac");
        let mut store = sac::NativeStore::create_live(&path, [13; 16]).unwrap();
        if spill {
            store.set_append_index_memory_budget(0).unwrap();
            store.set_decoded_cache_budget(0);
        }
        let mut map = store.live_map().unwrap();
        map.set(&mut store, b"key", b"first").unwrap();
        let initial = map.publish(&mut store).unwrap();
        let pin = store.pin().unwrap();
        let old_root = store.reader().snapshot().unwrap();
        let before = store.publication_statistics();
        for bytes in [vec![2; 65536], vec![], vec![3; 129]] {
            map.set(&mut store, b"key", &bytes).unwrap();
            map.publish(&mut store).unwrap();
        }
        let after = store.publication_statistics();
        assert_eq!(after.chunk_barriers - before.chunk_barriers, 3);
        assert_eq!(after.slot_syncs - before.slot_syncs, 3);
        assert_eq!(
            LiveMap::open(&pin, old_root)
                .unwrap()
                .reader(&pin)
                .unwrap()
                .get(b"key")
                .unwrap(),
            Some(b"first".to_vec())
        );
        assert_eq!(initial.generation, 1);
        drop(store);
        let mut reopened = sac::NativeStore::open(&path, true).unwrap();
        if spill {
            reopened.set_append_index_memory_budget(0).unwrap();
            reopened.set_decoded_cache_budget(0);
        }
        let mut map = reopened.live_map().unwrap();
        assert_eq!(
            map.reader(&reopened).unwrap().get(b"key").unwrap(),
            Some(vec![3; 129])
        );
        map.set(&mut reopened, b"new", b"durable").unwrap();
        map.publish(&mut reopened).unwrap();
        reopened.validate().unwrap();
        if spill {
            assert_eq!(reopened.pin().unwrap().decoded_cache_bytes(), 0);
        }
    }
}
#[cfg(feature = "native")]
#[test]
fn native_publication_faults_recover_a_complete_generation_and_poison_writer() {
    use sac::{NativeStore, PublicationFault};
    for fault in [
        PublicationFault::ChunksBarrier,
        PublicationFault::SlotWrite { bytes: 40 },
        PublicationFault::SlotSync,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fault.sac");
        let mut store = NativeStore::create_live(&path, [19; 16]).unwrap();
        let mut map = store.live_map().unwrap();
        map.set(&mut store, b"key", b"old").unwrap();
        map.publish(&mut store).unwrap();
        let first = store.reader().snapshot().unwrap();
        let pin = store.pin().unwrap();
        map.set(&mut store, b"key", &[5; 65536]).unwrap();
        map.checkpoint(&mut store).unwrap();
        map.set(&mut store, b"new", b"delta").unwrap();
        let expected = map.verify(&store).unwrap();
        let next = map.snapshot(&mut store).unwrap();
        store.inject_publication_fault_once(fault);
        assert!(map.publish(&mut store).is_err());
        assert!(matches!(map.publish(&mut store), Err(Error::Poisoned)));
        let old = LiveMap::open(&pin, first).unwrap().verify(&pin).unwrap();
        drop(store);
        let mut recovered = NativeStore::open(&path, false).unwrap();
        recovered.validate().unwrap();
        assert_eq!(
            recovered.reader().snapshot().unwrap().hash,
            if fault == PublicationFault::SlotSync {
                next.hash
            } else {
                first.hash
            }
        );
        let selected = recovered.live_map().unwrap();
        assert_eq!(
            selected.verify(&recovered).unwrap(),
            if fault == PublicationFault::SlotSync {
                expected
            } else {
                old
            }
        );
    }
}

#[cfg(feature = "native")]
#[test]
fn resource_cli_rejects_live_view_and_reads_explicit_plain_export() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cli.sac");
    let mut store = sac::NativeStore::create_live(&path, [29; 16]).unwrap();
    let mut map = store.live_map().unwrap();
    map.set(&mut store, b"record", b"value").unwrap();
    map.publish(&mut store).unwrap();
    let executable =
        std::env::var_os("SAC_TEST_BIN").unwrap_or_else(|| env!("CARGO_BIN_EXE_sac").into());
    let rejected = std::process::Command::new(&executable)
        .arg("list")
        .arg(&path)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("sac.live-map"));
    let exported = map.checkpoint(&mut store).unwrap();
    store.publish(exported).unwrap();
    drop(store);
    let listing = std::process::Command::new(executable)
        .arg("list")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        listing.status.success(),
        "{}",
        String::from_utf8_lossy(&listing.stderr)
    );
    assert!(String::from_utf8_lossy(&listing.stdout).contains("record"));
}

#[test]
fn public_checkpoint_preserves_untouched_authenticated_pages() {
    fn pages(store: &MemoryStore, root: ObjectRef) -> Vec<ObjectRef> {
        let mut pending = vec![root];
        let mut seen = Vec::new();
        let mut pages = Vec::new();
        while let Some(r) = pending.pop() {
            if seen.contains(&r) {
                continue;
            }
            seen.push(r);
            let o = store.get(r).unwrap();
            if o.kind == 3 || o.kind == 4 {
                pages.push(r);
            }
            pending.extend(o.children);
        }
        pages
    }
    let mut store = MemoryStore::sealed();
    let mut builder = ArchiveBuilder::new(&mut store);
    for i in 0..4096 {
        builder
            .add_file(&[format!("k{i:05}").into_bytes()], &[1; 64])
            .unwrap();
    }
    let base = builder.finish().unwrap();
    let before = pages(&store, base);
    assert!(before.len() > 2);
    let mut map = LiveMap::from_base(&store, base).unwrap();
    map.set(&mut store, b"k00001", b"changed").unwrap();
    let next = map.checkpoint(&mut store).unwrap();
    let after = pages(&store, next);
    assert!(after.iter().any(|r| before.contains(r)));
    assert_ne!(base, next);
    assert_eq!(
        map.reader(&store).unwrap().get(b"k00001").unwrap(),
        Some(b"changed".to_vec())
    );
    assert_eq!(
        map.reader(&store).unwrap().get(b"k04095").unwrap(),
        Some(vec![1; 64])
    );
}

#[cfg(feature = "native")]
#[test]
fn native_compaction_preserves_profile_identity_old_pins_and_further_updates() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("compact.sac");
    let mut store = sac::NativeStore::create_live(&path, [31; 16]).unwrap();
    let mut map = store.live_map().unwrap();
    map.set(&mut store, b"base", &[1; 65536]).unwrap();
    map.checkpoint(&mut store).unwrap();
    map.set(&mut store, b"delta", &[2; 4096]).unwrap();
    map.publish(&mut store).unwrap();
    let old_root = store.reader().snapshot().unwrap();
    let old_pin = store.pin().unwrap();
    let expected = map.verify(&store).unwrap();
    store.compact().unwrap();
    let relocated = store.reader().snapshot().unwrap();
    assert_eq!(relocated.hash, old_root.hash);
    let mut map = store.live_map().unwrap();
    assert_eq!(map.verify(&store).unwrap(), expected);
    assert_eq!(
        LiveMap::open(&old_pin, old_root)
            .unwrap()
            .verify(&old_pin)
            .unwrap(),
        expected
    );
    map.set(&mut store, b"delta", b"after compaction").unwrap();
    map.publish(&mut store).unwrap();
    drop(store);
    let mut reopened = sac::NativeStore::open(&path, false).unwrap();
    assert_eq!(
        reopened
            .live_map()
            .unwrap()
            .reader(&reopened)
            .unwrap()
            .get(b"delta")
            .unwrap(),
        Some(b"after compaction".to_vec())
    );
}
