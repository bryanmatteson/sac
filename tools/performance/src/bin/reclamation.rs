use sac::{
    NativeReader, NativeStore, ReclamationOptions,
    resources::{ArchiveBuilder, ArchiveReader, Limits, path_from_str},
};
use serde_json::json;
use std::{fs::File, os::unix::fs::MetadataExt};
fn data(seed: u64, length: usize) -> Vec<u8> {
    let mut x = seed;
    let mut b = vec![0; length];
    for n in &mut b {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *n = x as u8;
    }
    b
}
fn publish(store: &mut NativeStore, seed: u64) {
    let mut b = ArchiveBuilder::new(store);
    b.add_file(&path_from_str("payload").unwrap(), &data(seed, 16 << 20))
        .unwrap();
    let s = b.finish().unwrap();
    store.publish(s).unwrap();
}
fn main() {
    let case = std::env::args().nth(1).unwrap();
    let path = std::path::Path::new("benchmark.sac");
    let mut store = NativeStore::create_live(path, [45; 16]).unwrap();
    let mut pin = None;
    for seed in 1..=4 {
        publish(&mut store, seed);
        if seed == 1 && case == "online-pinned" {
            pin = Some(store.pin().unwrap());
        }
    }
    store.pin().unwrap().clear_decoded_cache();
    let initial = std::fs::metadata(path).unwrap();
    let root = store.root().unwrap().root.hash;
    let mut stats = None;
    let mut operation = || match case.as_str() {
        "copy-swap" => store.compact().unwrap(),
        "offline" => {
            stats = Some(store.compact_in_place(Default::default()).unwrap());
        }
        "online" | "online-pinned" | "online-reuse" | "online-no-punch" => {
            stats = Some(
                store
                    .reclaim_online(ReclamationOptions {
                        punch_holes: case != "online-no-punch",
                        ..Default::default()
                    })
                    .unwrap(),
            );
            if case == "online-reuse" {
                publish(&mut store, 5);
            }
        }
        _ => panic!("unknown case"),
    };
    #[cfg(feature = "allocations")]
    let allocations = {
        let a = allocation_counter::measure(&mut operation);
        json!({"count":a.count_total,"bytes":a.bytes_total,"peak_live_bytes":a.bytes_max,"net_live_bytes":a.bytes_current})
    };
    #[cfg(not(feature = "allocations"))]
    let allocations = serde_json::Value::Null;
    #[cfg(not(feature = "allocations"))]
    let (wall, cpu) = {
        let c = cpu_time::ProcessTime::now();
        let w = std::time::Instant::now();
        operation();
        (w.elapsed().as_nanos(), c.elapsed().as_nanos())
    };
    #[cfg(feature = "allocations")]
    let (wall, cpu) = (0u128, 0u128);
    let final_meta = std::fs::metadata(path).unwrap();
    if case != "online-reuse" {
        assert_eq!(root, store.root().unwrap().root.hash);
    }
    store.validate().unwrap();
    let expected = data(if case == "online-reuse" { 5 } else { 4 }, 16 << 20);
    let archive = ArchiveReader::open(
        &store,
        store.reader().snapshot().unwrap(),
        Limits::default(),
    )
    .unwrap();
    assert_eq!(
        archive
            .read_range(&path_from_str("payload").unwrap(), 0, expected.len())
            .unwrap(),
        expected
    );
    if let Some(pin) = pin {
        pin.validate().unwrap();
        let a =
            ArchiveReader::open(&pin, pin.reader().snapshot().unwrap(), Limits::default()).unwrap();
        assert_eq!(
            a.read_range(&path_from_str("payload").unwrap(), 0, 16 << 20)
                .unwrap(),
            data(1, 16 << 20)
        );
    }
    let copy=store.last_compaction_statistics().map(|s|json!({"peak_temporary_bytes":s.peak_aggregate_temporary_bytes,"copied_bytes":s.copied_bytes}));
    drop(store);
    let reopened = NativeReader::open_file(File::open(path).unwrap()).unwrap();
    reopened.validate().unwrap();
    println!(
        "{}",
        json!({"case":case,"initial_root":root.to_string(),"final_root":reopened.root().unwrap().root.hash.to_string(),"file_before":initial.len(),"file_after":final_meta.len(),"allocated_before":initial.blocks()*512,"allocated_after":final_meta.blocks()*512,"same_inode":initial.ino()==final_meta.ino(),"operation_wall_ns":wall,"operation_cpu_ns":cpu,"allocations":allocations,"copy":copy,"maintenance":stats.map(|s|json!({"retained_frames":s.retained_frames,"dead_frames":s.dead_frames,"punched_bytes":s.punched_bytes,"indexed_reuse_bytes":s.indexed_reuse_bytes,"moved_bytes":s.moved_bytes,"journal_peak_bound_bytes":s.journal_peak_bytes}))})
    );
}
