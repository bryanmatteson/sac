//! Paired map/trie workloads. Run one backend per process to avoid shared caches.
#[path = "../bucket_trie.rs"]
mod bucket_trie;
#[path = "../dual_map.rs"]
mod dual_map;
#[path = "../live_map_workload.rs"]
mod live_map_workload;
#[path = "../prefix_trie.rs"]
mod prefix_trie;
use live_map_workload::DualMap;
use prefix_trie::PrefixTrie;
use sac::resources::{ArchiveBuilder, ArchiveReader, Limits, path_from_str};
use sac::{MemoryStore, NativeStore, ObjectRef};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Instant;

fn payload(key: usize, ordinal: usize, variable: bool) -> Vec<u8> {
    let length = if variable {
        [0, 8, 64, 512, 4096, 65536][(key + ordinal / 4096) % 6]
    } else {
        64
    };
    let mut bytes = vec![(key.wrapping_mul(31) + ordinal) as u8; length];
    let n = length.min(8);
    bytes[..n].copy_from_slice(&(ordinal as u64).to_le_bytes()[..n]);
    bytes
}
enum Map {
    Current(ObjectRef),
    Trie(PrefixTrie),
    Dual(DualMap),
}
impl Map {
    fn snapshot(&self, store: &mut NativeStore) -> ObjectRef {
        match self {
            Self::Current(directory) => {
                ArchiveBuilder::from_directory(store, *directory, Limits::default())
                    .finish()
                    .unwrap()
            }
            Self::Trie(trie) => trie.snapshot(store).unwrap(),
            Self::Dual(dual) => dual.snapshot(store).unwrap(),
        }
    }
    fn set(&mut self, store: &mut NativeStore, path: &[Vec<u8>], bytes: &[u8]) {
        match self {
            Self::Current(directory) => {
                let mut builder =
                    ArchiveBuilder::from_directory(store, *directory, Limits::default());
                builder
                    .set_file(path, bytes, sac::cbor::Value::Map(vec![]))
                    .unwrap();
                *directory = builder.finish_directory().unwrap();
            }
            Self::Trie(trie) => trie.set(store, &path[0], bytes).unwrap(),
            Self::Dual(dual) => dual.set(store, &path[0], bytes).unwrap(),
        }
    }
}
fn main() {
    let mut args = std::env::args().skip(1);
    let backend = args
        .next()
        .expect("map | trie | dual | dual-rebuild | dual-paged | dual-bucket | live-map");
    assert!(matches!(
        backend.as_str(),
        "map" | "trie" | "dual" | "dual-rebuild" | "dual-paged" | "dual-bucket" | "live-map"
    ));
    let is_dual = backend.starts_with("dual") || backend == "live-map";
    let case = args.next().unwrap_or_else(|| "updates".into());
    assert!(matches!(
        case.as_str(),
        "updates" | "resize" | "inserts-ordered" | "inserts-shuffled"
    ));
    let iterations = std::env::var("SAC_MAP_ITERATIONS")
        .map(|s| s.parse::<usize>().unwrap())
        .unwrap_or(8192);
    assert!(iterations.is_power_of_two() && (64..=65536).contains(&iterations));
    let cadence = std::env::var("SAC_MAP_PUBLISH_EVERY")
        .map(|s| s.parse::<usize>().unwrap())
        .unwrap_or(0);
    let merge_every = std::env::var("SAC_MAP_MERGE_EVERY")
        .map(|s| s.parse::<usize>().unwrap())
        .unwrap_or(1024);
    let batch_size = if cadence == 0 { iterations } else { cadence };
    let spill = std::env::var_os("SAC_MAP_SPILL").is_some();
    let inserts = case.starts_with("inserts");
    let keys = if inserts { iterations } else { 4096 };
    let initial: BTreeMap<_, _> = (0..keys)
        .map(|key| {
            let key = if inserts { key * 2 } else { key };
            (
                format!("record-{key:08x}").into_bytes(),
                payload(key, 0, false),
            )
        })
        .collect();
    // Construct both fixtures in memory, then copy only their live closure.
    // Neither backend starts with a seed history of unreachable edit objects.
    let mut memory = MemoryStore::sealed();
    let first = if backend != "trie" {
        let mut builder = ArchiveBuilder::new(&mut memory);
        for (key, bytes) in &initial {
            builder.add_file(&[key.clone()], bytes).unwrap();
        }
        builder.finish().unwrap()
    } else {
        let mut trie = PrefixTrie::default();
        for (key, bytes) in &initial {
            trie.set(&mut memory, key, bytes).unwrap();
        }
        trie.snapshot(&mut memory).unwrap()
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("map.sac");
    let mut store = NativeStore::create_live(&path, [43; 16]).unwrap();
    if spill {
        store.set_append_index_memory_budget(0).unwrap();
        store.set_decoded_cache_budget(0);
    }
    let first = sac::copy_closure(&memory, &mut store, first).unwrap();
    let first = if is_dual {
        let map = if backend == "live-map" {
            DualMap::from_base_live(&store, first)
        } else if backend == "dual-bucket" {
            DualMap::from_base_bucket(&store, first)
        } else if backend == "dual-paged" {
            DualMap::from_base_paged(&store, first)
        } else {
            DualMap::from_base(&store, first)
        }
        .unwrap();
        map.snapshot(&mut store).unwrap()
    } else {
        first
    };
    drop(memory);
    let (_, old_pin) = store.publish_pinned(first).unwrap();
    let mut map = if backend == "map" {
        Map::Current(
            ArchiveReader::open(&old_pin, first, Limits::default())
                .unwrap()
                .directory_root(),
        )
    } else if backend == "trie" {
        Map::Trie(PrefixTrie::open(&old_pin, first).unwrap())
    } else if backend == "live-map" {
        Map::Dual(DualMap::Production(store.live_map().unwrap()))
    } else {
        Map::Dual(DualMap::open(&old_pin, first).unwrap())
    };
    let edits: Vec<_> = (0..iterations)
        .map(|ordinal| {
            let slot = if case == "inserts-ordered" {
                ordinal
            } else {
                (ordinal * 4051) % keys
            };
            let key = if inserts { slot * 2 + 1 } else { slot };
            (
                path_from_str(&format!("record-{key:08x}")).unwrap(),
                payload(key, ordinal, case == "resize"),
            )
        })
        .collect();
    let mut expected = initial.clone();
    for (path, bytes) in &edits {
        expected.insert(path[0].clone(), bytes.clone());
    }
    let logical_digest = {
        let mut data = Vec::new();
        for (key, value) in &expected {
            data.extend_from_slice(&(key.len() as u64).to_le_bytes());
            data.extend(key);
            data.extend_from_slice(&(value.len() as u64).to_le_bytes());
            data.extend(value);
        }
        sac::ObjectHash::digest(&data).to_string()
    };
    let before_io = store.physical_statistics();
    let before_len = store.file_len();
    let before_barriers = store.publication_statistics();
    let (mut cpu_ns, mut wall_ns, mut publication_cpu_ns, mut publication_ns) = (0, 0, 0, 0);
    let mut root = first;
    let mut publications = 0;
    let mut publication_attempts = 0;
    let (mut merge_cpu_ns, mut merge_ns, mut merges, mut completed) = (0, 0, 0, 0);
    for batch in edits.chunks(batch_size) {
        let cpu = cpu_time::ProcessTime::now();
        let start = Instant::now();
        let (mut batch_merge_cpu, mut batch_merge_wall) = (0, 0);
        for (path, bytes) in batch {
            map.set(&mut store, path, bytes);
            completed += 1;
            if is_dual && merge_every != 0 && completed % merge_every == 0 && completed < iterations
            {
                let cpu = cpu_time::ProcessTime::now();
                let start = Instant::now();
                if let Map::Dual(dual) = &mut map {
                    if backend == "dual-rebuild" {
                        dual.checkpoint_rebuild(&mut store).unwrap();
                    } else {
                        dual.checkpoint(&mut store).unwrap();
                    }
                }
                batch_merge_wall += start.elapsed().as_nanos();
                batch_merge_cpu += cpu.elapsed().as_nanos();
                merges += 1;
            }
        }
        wall_ns += start.elapsed().as_nanos() - batch_merge_wall;
        cpu_ns += cpu.elapsed().as_nanos() - batch_merge_cpu;
        merge_cpu_ns += batch_merge_cpu;
        merge_ns += batch_merge_wall;
        let cpu = cpu_time::ProcessTime::now();
        let start = Instant::now();
        let previous = store.root().unwrap();
        let published = if let Map::Dual(DualMap::Production(live)) = &map {
            let publication = live.publish(&mut store).unwrap();
            root = store.reader().snapshot().unwrap();
            publication
        } else {
            root = map.snapshot(&mut store);
            store.publish(root).unwrap()
        };
        if published.generation == previous.generation {
            // Re-publishing an already durable canonical root needs no barrier.
            assert_eq!(published, previous);
        } else {
            assert_eq!(published.generation, previous.generation + 1);
            publications += 1;
        }
        publication_ns += start.elapsed().as_nanos();
        publication_cpu_ns += cpu.elapsed().as_nanos();
        publication_attempts += 1;
    }
    let overlay_entries = if let Map::Dual(dual) = &map {
        dual.overlay_len()
    } else {
        0
    };
    let after_io = store.physical_statistics();
    let appended_bytes = store.file_len() - before_len;
    let barriers = store.publication_statistics();
    assert_eq!(
        barriers.chunk_barriers - before_barriers.chunk_barriers,
        publications
    );
    assert_eq!(
        barriers.slot_syncs - before_barriers.slot_syncs,
        publications
    );
    drop(store);
    let reopened = NativeStore::open(&path, false).unwrap();
    if spill {
        reopened.set_decoded_cache_budget(0);
    }
    assert_eq!(reopened.reader().snapshot().unwrap().hash, root.hash);
    reopened.validate().unwrap();
    let pin = reopened.pin().unwrap();
    let verify_start = Instant::now();
    let reader = if backend == "live-map" {
        None
    } else {
        Some(ArchiveReader::open(&pin, root, Limits::default()).unwrap())
    };
    if backend == "map" {
        assert_eq!(
            reader.as_ref().unwrap().verify().unwrap().files,
            expected.len() as u64
        );
    } else if is_dual {
        assert_eq!(
            DualMap::open(&pin, root).unwrap().verify(&pin).unwrap(),
            expected
        );
    } else {
        let trie = PrefixTrie::open(&pin, root).unwrap();
        assert_eq!(trie.len(), expected.len() as u64);
        assert_eq!(trie.verify(&pin).unwrap(), expected);
    }
    let verification_ns = verify_start.elapsed().as_nanos();
    if spill {
        assert_eq!(pin.decoded_cache_bytes(), 0);
    }
    let prepare_cpu = cpu_time::ProcessTime::now();
    let prepare_start = Instant::now();
    let trie = if backend == "trie" {
        Some(PrefixTrie::open(&pin, root).unwrap())
    } else {
        None
    };
    let dual = if is_dual {
        Some(DualMap::open(&pin, root).unwrap())
    } else {
        None
    };
    let dual_reader = dual.as_ref().map(|d| d.reader(&pin).unwrap());
    let lookup_prepare_cpu_ns = prepare_cpu.elapsed().as_nanos();
    let lookup_prepare_ns = prepare_start.elapsed().as_nanos();
    let lookups: Vec<_> = expected
        .iter()
        .map(|(key, value)| (vec![key.clone()], value))
        .collect();
    let cpu = cpu_time::ProcessTime::now();
    let start = Instant::now();
    let get = |path: &[Vec<u8>]| {
        if let Some(trie) = &trie {
            trie.get(&pin, &path[0]).unwrap()
        } else if let Some(dual) = &dual_reader {
            dual.get(&path[0]).unwrap()
        } else {
            reader
                .as_ref()
                .unwrap()
                .read_file_bounded(path, 65536)
                .unwrap()
                .map(|(_, bytes)| bytes)
        }
    };
    for (path, value) in &lookups {
        assert_eq!(&get(path).unwrap(), *value);
    }
    let lookup_ns = start.elapsed().as_nanos();
    let lookup_cpu_ns = cpu.elapsed().as_nanos();
    let cpu = cpu_time::ProcessTime::now();
    let start = Instant::now();
    for ordinal in 0..lookups.len() {
        let (path, value) = &lookups[(ordinal * 4051) % lookups.len()];
        assert_eq!(&get(path).unwrap(), *value);
    }
    let random_lookup_ns = start.elapsed().as_nanos();
    let random_lookup_cpu_ns = cpu.elapsed().as_nanos();
    let missing: Vec<_> = (0..4096)
        .map(|n| vec![format!("absent-{n:08x}").into_bytes()])
        .collect();
    let cpu = cpu_time::ProcessTime::now();
    let start = Instant::now();
    for path in &missing {
        assert!(get(path).is_none());
    }
    let miss_lookup_ns = start.elapsed().as_nanos();
    let miss_lookup_cpu_ns = cpu.elapsed().as_nanos();
    if backend == "map" {
        let old = ArchiveReader::open(&old_pin, first, Limits::default()).unwrap();
        assert_eq!(old.verify().unwrap().files, initial.len() as u64);
        for (key, value) in &initial {
            assert_eq!(
                &old.read_file_bounded(&[key.clone()], 64)
                    .unwrap()
                    .unwrap()
                    .1,
                value
            );
        }
    } else if is_dual {
        assert_eq!(
            DualMap::open(&old_pin, first)
                .unwrap()
                .verify(&old_pin)
                .unwrap(),
            initial
        );
    } else {
        assert_eq!(
            PrefixTrie::open(&old_pin, first)
                .unwrap()
                .verify(&old_pin)
                .unwrap(),
            initial
        );
    }
    // Generic packing preserves a live overlay without flattening it.
    let live_sealed = sac::pack_snapshot(&pin, root, Vec::new()).unwrap();
    let live_sealed_bytes = live_sealed.len();
    if is_dual {
        let copied = MemoryStore::from_bytes(live_sealed).unwrap();
        copied.validate().unwrap();
        let snapshot = sac::v1::Reader::open_at(copied.as_bytes())
            .unwrap()
            .snapshot()
            .unwrap();
        assert_eq!(
            DualMap::open(&copied, snapshot)
                .unwrap()
                .verify(&copied)
                .unwrap(),
            expected
        );
    }
    // Final export materializes any remaining delta to an ordinary resource snapshot.
    let mut export_store = if is_dual {
        Some(NativeStore::open(&path, true).unwrap())
    } else {
        None
    };
    if spill {
        if let Some(export_store) = &mut export_store {
            export_store.set_append_index_memory_budget(0).unwrap();
            export_store.set_decoded_cache_budget(0);
        }
    }
    let (export_root, export_cpu_ns, export_ns) = if let Some(export_store) = &mut export_store {
        let mut dual = DualMap::open(export_store, root).unwrap();
        let cpu = cpu_time::ProcessTime::now();
        let start = Instant::now();
        let export_root = if backend == "dual-rebuild" {
            dual.checkpoint_rebuild(export_store).unwrap()
        } else {
            dual.checkpoint(export_store).unwrap()
        };
        (
            export_root,
            cpu.elapsed().as_nanos(),
            start.elapsed().as_nanos(),
        )
    } else {
        (root, 0, 0)
    };
    let sealed = if let Some(export_store) = &export_store {
        sac::pack_snapshot(export_store, export_root, Vec::new()).unwrap()
    } else {
        sac::pack_snapshot(&pin, root, Vec::new()).unwrap()
    };
    let sealed_bytes = sealed.len();
    let packed = MemoryStore::from_bytes(sealed).unwrap();
    packed.validate().unwrap();
    let packed_root = sac::v1::Reader::open_at(packed.as_bytes())
        .unwrap()
        .snapshot()
        .unwrap();
    if is_dual {
        let packed_reader = ArchiveReader::open(&packed, packed_root, Limits::default()).unwrap();
        assert_eq!(packed_reader.verify().unwrap().files, expected.len() as u64);
        for (key, value) in &expected {
            assert_eq!(
                &packed_reader
                    .read_file_bounded(&[key.clone()], 65536)
                    .unwrap()
                    .unwrap()
                    .1,
                value
            );
        }
    } else if backend == "trie" {
        assert_eq!(
            PrefixTrie::open(&packed, packed_root)
                .unwrap()
                .verify(&packed)
                .unwrap(),
            expected
        );
    }
    println!(
        "{}",
        json!({"backend":backend,"case":case,"iterations":iterations,"initial_keys":keys,
        "publish_every":cadence,"spill":spill,"cpu_ns":cpu_ns,"wall_ns":wall_ns,
        "publication_cpu_ns":publication_cpu_ns,"publication_ns":publication_ns,"publications":publications,
        "publication_attempts":publication_attempts,
        "appended_bytes":appended_bytes,"sealed_bytes":sealed_bytes,"live_sealed_bytes":live_sealed_bytes,
        "merge_every":merge_every,"merges":merges,"overlay_entries":overlay_entries,"merge_cpu_ns":merge_cpu_ns,"merge_ns":merge_ns,
        "export_cpu_ns":export_cpu_ns,"export_ns":export_ns,
        "read_operations":after_io.read_operations-before_io.read_operations,
        "verification_ns":verification_ns,"lookup_ns":lookup_ns,"lookup_cpu_ns":lookup_cpu_ns,
        "lookup_prepare_cpu_ns":lookup_prepare_cpu_ns,"lookup_prepare_ns":lookup_prepare_ns,
        "random_lookup_cpu_ns":random_lookup_cpu_ns,"random_lookup_ns":random_lookup_ns,
        "miss_lookup_cpu_ns":miss_lookup_cpu_ns,"miss_lookup_ns":miss_lookup_ns,"miss_lookup_count":missing.len(),
        "lookup_cache_disabled":spill,
        "lookup_count":expected.len(),"logical_digest":logical_digest,"verified":true})
    );
}
