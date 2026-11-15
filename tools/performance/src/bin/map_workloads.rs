//! Real persistent map edits over a reproducible many-key workload.
use sac::NativeStore;
use sac::resources::{ArchiveBuilder, ArchiveReader, Limits, path_from_str};
use serde_json::json;
use std::time::Instant;

fn payload(key: usize, ordinal: usize, variable: bool) -> Vec<u8> {
    let length = if variable {
        [0, 8, 64, 512, 4096, 65536][(key + ordinal / 4096) % 6]
    } else {
        64
    };
    let mut bytes = vec![(key.wrapping_mul(31) + ordinal) as u8; length];
    let stamp = (ordinal as u64).to_le_bytes();
    let n = length.min(8);
    bytes[..n].copy_from_slice(&stamp[..n]);
    bytes
}
fn main() {
    let case = std::env::args().nth(1).unwrap_or_else(|| "updates".into());
    assert!(matches!(
        case.as_str(),
        "inserts-ordered" | "inserts-shuffled" | "updates" | "resize"
    ));
    let iterations = std::env::var("SAC_MAP_ITERATIONS")
        .map(|s| s.parse::<usize>().unwrap())
        .unwrap_or(8192);
    assert!(iterations.is_power_of_two() && (64..=65536).contains(&iterations));
    let page_limit = std::env::var("SAC_MAP_PAGE_LIMIT")
        .map(|s| s.parse::<usize>().unwrap())
        .ok();
    let inserts = case.starts_with("inserts");
    let keys = if inserts { iterations } else { 4096 };
    let dir = tempfile::tempdir().unwrap();
    let mut store = NativeStore::create_live(dir.path().join("map.sac"), [43; 16]).unwrap();
    if std::env::var_os("SAC_MAP_SPILL").is_some() {
        store.set_append_index_memory_budget(0).unwrap();
        store.set_decoded_cache_budget(0);
    }
    let mut builder = ArchiveBuilder::new(&mut store);
    if let Some(limit) = page_limit {
        builder.set_page_limit(limit).unwrap();
    }
    for key in 0..keys {
        let key = if inserts { key * 2 } else { key };
        builder
            .add_file(
                &path_from_str(&format!("record-{key:08x}")).unwrap(),
                &payload(key, 0, false),
            )
            .unwrap();
    }
    let snapshot = builder.finish().unwrap();
    let (_, old_pin) = store.publish_pinned(snapshot).unwrap();
    let old = ArchiveReader::open(&old_pin, snapshot, Limits::default()).unwrap();
    let mut directory = old.directory_root();
    let edits: Vec<_> = (0..iterations)
        .map(|ordinal| {
            let slot = if case == "inserts-ordered" {
                ordinal
            } else {
                (ordinal * 4051) % keys
            };
            let key = if inserts { slot * 2 + 1 } else { slot };
            (
                key,
                path_from_str(&format!("record-{key:08x}")).unwrap(),
                payload(key, ordinal, case == "resize"),
            )
        })
        .collect();
    let before_io = store.physical_statistics();
    let before_len = store.file_len();
    let cpu = cpu_time::ProcessTime::now();
    let start = Instant::now();
    for (_, path, bytes) in &edits {
        let mut builder = ArchiveBuilder::from_directory(&mut store, directory, Limits::default());
        if let Some(limit) = page_limit {
            builder.set_page_limit(limit).unwrap();
        }
        builder
            .set_file(path, bytes, sac::cbor::Value::Map(Vec::new()))
            .unwrap();
        directory = builder.finish_directory().unwrap();
    }
    let wall_ns = start.elapsed().as_nanos();
    let cpu_ns = cpu.elapsed().as_nanos();
    let after_io = store.physical_statistics();
    let appended_bytes = store.file_len() - before_len;
    let root = ArchiveBuilder::from_directory(&mut store, directory, Limits::default())
        .finish()
        .unwrap();
    let barriers = store.publication_statistics();
    let publication_start = Instant::now();
    store.publish(root).unwrap();
    let publication_ns = publication_start.elapsed().as_nanos();
    let after_barriers = store.publication_statistics();
    assert_eq!(after_barriers.chunk_barriers - barriers.chunk_barriers, 1);
    assert_eq!(after_barriers.slot_syncs - barriers.slot_syncs, 1);
    let mut expected = std::collections::BTreeMap::new();
    for (key, path, bytes) in &edits {
        expected.insert(*key, (path, bytes));
    }
    drop(store);
    let reopened = NativeStore::open(dir.path().join("map.sac"), false).unwrap();
    reopened.validate().unwrap();
    let pin = reopened.pin().unwrap();
    let current = ArchiveReader::open(&pin, root, Limits::default()).unwrap();
    current.verify().unwrap();
    for (path, bytes) in expected.values() {
        assert_eq!(
            &current.read_file_bounded(path, 65536).unwrap().unwrap().1,
            *bytes
        );
    }
    assert_eq!(
        old.read_file_bounded(&path_from_str("record-00000000").unwrap(), 64)
            .unwrap()
            .unwrap()
            .1,
        payload(0, 0, false)
    );
    println!(
        "{}",
        json!({"case":case,"iterations":iterations,"initial_keys":keys,"page_limit":page_limit,"cpu_ns":cpu_ns,"wall_ns":wall_ns,"appended_bytes":appended_bytes,"read_operations":after_io.read_operations-before_io.read_operations,"publication_ns":publication_ns,"snapshot":root.hash.to_string(),"verified":true})
    );
}
