//! Paired, correctness-checked memtable/native consumer benchmark.
//! Build and run through tools/performance/run_memtable_comparison.py.
use sac::resources::{ArchiveBuilder, ArchiveReader, Limits, ResourcePath};
use sac::{MemtableOptions, MemtableStore, Mutation, NativeReader, NativeStore, ObjectRef};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

fn path(key: &[u8]) -> ResourcePath {
    let mut name = b"k".to_vec();
    for byte in key {
        name.push(b"0123456789abcdef"[(byte >> 4) as usize]);
        name.push(b"0123456789abcdef"[(byte & 15) as usize]);
    }
    vec![name]
}
fn payload(key: usize, generation: usize, size: usize) -> Vec<u8> {
    let mut x = (key as u64 + 1).wrapping_mul(0x9e3779b97f4a7c15) ^ generation as u64;
    let mut bytes = vec![0; size];
    for part in bytes.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        part.copy_from_slice(&x.to_le_bytes()[..part.len()]);
    }
    bytes[..8].copy_from_slice(&(generation as u64).to_le_bytes());
    bytes[8..16].copy_from_slice(&(key as u64).to_le_bytes());
    bytes
}
struct Fixture {
    keys: Vec<[u8; 8]>,
    paths: Vec<ResourcePath>,
    values: Vec<Vec<u8>>,
}
impl Fixture {
    fn new(keys: usize, size: usize) -> Self {
        let keys: Vec<_> = (0..keys).map(|i| (i as u64).to_be_bytes()).collect();
        Self {
            paths: keys.iter().map(|key| path(key)).collect(),
            values: (0..keys.len()).map(|key| payload(key, 0, size)).collect(),
            keys,
        }
    }
}
struct Edit {
    key: usize,
    value: Vec<u8>,
}
fn edits(fixture: &Fixture, count: usize, generation: usize) -> Vec<Edit> {
    (0..count)
        .map(|i| {
            let key = 1 + (i * 4051) % (fixture.keys.len() - 1);
            Edit {
                key,
                value: payload(key, generation + i, fixture.values[0].len()),
            }
        })
        .collect()
}
fn mutations<'a>(edits: &'a [Edit], fixture: &'a Fixture) -> Vec<Mutation<'a>> {
    edits
        .iter()
        .map(|edit| Mutation::Put {
            key: &fixture.keys[edit.key],
            value: &edit.value,
        })
        .collect()
}

struct Direct {
    store: NativeStore,
    directory: ObjectRef,
    snapshot: ObjectRef,
    dirty: bool,
    publications: u64,
}
enum Engine {
    Direct(Box<Mutex<Direct>>),
    Memtable(MemtableStore),
}
impl Engine {
    fn open(mode: &str, file: &Path, memory: usize, interval_ms: u64) -> Self {
        if mode == "memtable" {
            Self::Memtable(
                MemtableStore::open(
                    file,
                    MemtableOptions {
                        max_memory_bytes: memory,
                        flush_interval: Duration::from_millis(interval_ms),
                        ..Default::default()
                    },
                )
                .unwrap(),
            )
        } else {
            let store = NativeStore::open(file, true).unwrap();
            let snapshot = store.reader().snapshot().unwrap();
            let directory = ArchiveReader::open(&store, snapshot, Limits::default())
                .unwrap()
                .directory_root();
            Self::Direct(Box::new(Mutex::new(Direct {
                store,
                directory,
                snapshot,
                dirty: false,
                publications: 0,
            })))
        }
    }
    fn write(&self, records: &[Edit], batch: &[Mutation<'_>], fixture: &Fixture, durable: bool) {
        match self {
            Self::Memtable(store) => {
                store.write_batch(batch).unwrap();
            }
            Self::Direct(direct) => {
                let mut d = direct.lock().unwrap();
                let directory = d.directory;
                let mut builder =
                    ArchiveBuilder::from_directory(&mut d.store, directory, Limits::default());
                for edit in records {
                    builder
                        .set_file(
                            &fixture.paths[edit.key],
                            &edit.value,
                            sac::cbor::Value::Map(Vec::new()),
                        )
                        .unwrap();
                }
                let directory = builder.directory_root().unwrap();
                let snapshot = builder.finish().unwrap();
                d.directory = directory;
                d.snapshot = snapshot;
                d.dirty = true;
                if durable {
                    Self::publish(&mut d);
                }
            }
        }
    }
    fn publish(d: &mut Direct) {
        if d.dirty {
            d.store.publish(d.snapshot).unwrap();
            d.publications += 1;
            d.dirty = false;
        }
    }
    fn flush(&self) {
        match self {
            Self::Memtable(store) => {
                store.flush().unwrap();
            }
            Self::Direct(d) => Self::publish(&mut d.lock().unwrap()),
        }
    }
    fn delete(&self, keys: &[usize], fixture: &Fixture) {
        match self {
            Self::Memtable(store) => {
                let batch: Vec<_> = keys
                    .iter()
                    .map(|&key| Mutation::Delete {
                        key: &fixture.keys[key],
                    })
                    .collect();
                store.write_batch(&batch).unwrap();
            }
            Self::Direct(direct) => {
                let mut d = direct.lock().unwrap();
                let directory = d.directory;
                let mut builder =
                    ArchiveBuilder::from_directory(&mut d.store, directory, Limits::default());
                for &key in keys {
                    builder.remove_file(&fixture.paths[key]).unwrap();
                }
                let directory = builder.directory_root().unwrap();
                let snapshot = builder.finish().unwrap();
                d.directory = directory;
                d.snapshot = snapshot;
                d.dirty = true;
            }
        }
    }
    fn get(&self, key: usize, fixture: &Fixture) -> Option<Vec<u8>> {
        match self {
            Self::Memtable(store) => store.get(&fixture.keys[key]).unwrap(),
            Self::Direct(direct) => {
                let d = direct.lock().unwrap();
                ArchiveReader::open(&d.store, d.snapshot, Limits::default())
                    .unwrap()
                    .read_file_bounded(&fixture.paths[key], 8 * 1024 * 1024)
                    .unwrap()
                    .map(|(_, value)| value)
            }
        }
    }
    fn statistics(&self) -> Value {
        match self {
            Self::Memtable(store) => {
                let s = store.statistics().unwrap();
                assert!(s.failure.is_none());
                json!({"checkpoints":s.checkpoints,"pending_entries":s.pending_entries,
                    "pending_memory_bytes":s.pending_memory_bytes,"wal_bytes":s.wal_bytes,
                    "sequence":s.sequence,"checkpoint_sequence":s.checkpoint_sequence,
                    "active_memory_bytes":s.active_memory_bytes,"immutable_memory_bytes":s.immutable_memory_bytes,
                    "immutable_entries":s.immutable_entries,"flush_in_progress":s.flush_in_progress,
                    "backpressure_waits":s.backpressure_waits,"io":io_statistics(&s.io)})
            }
            Self::Direct(d) => {
                let d = d.lock().unwrap();
                json!({"checkpoints":d.publications,"pending_entries":null,
                    "pending_memory_bytes":null,"wal_bytes":0,"dirty":d.dirty,
                    "decoded_cache":d.store.cache_usage().decoded_bytes})
            }
        }
    }
    fn has_pending(&self) -> bool {
        match self {
            Self::Memtable(store) => store.statistics().unwrap().pending_entries > 0,
            Self::Direct(d) => d.lock().unwrap().dirty,
        }
    }
}
fn io_statistics(s: &sac::MemtableIoStatistics) -> Value {
    let p = s.native_publication;
    json!({"wal_batches":s.wal_batches,"wal_prepare_total_ns":s.wal_prepare_total_ns,
        "wal_sync_total_ns":s.wal_sync_total_ns,"wal_sync_max_ns":s.wal_sync_max_ns,
        "wal_finish_total_ns":s.wal_finish_total_ns,"write_prepare_total_ns":s.write_prepare_total_ns,
        "wal_gate_wait_total_ns":s.wal_gate_wait_total_ns,"admission_wait_total_ns":s.admission_wait_total_ns,
        "successor_prepare_total_ns":s.successor_prepare_total_ns,"successor_sync_total_ns":s.successor_sync_total_ns,
        "successor_directory_sync_total_ns":s.successor_directory_sync_total_ns,"handoff_wait_total_ns":s.handoff_wait_total_ns,
        "checkpoint_materialize_total_ns":s.checkpoint_materialize_total_ns,"checkpoint_publish_total_ns":s.checkpoint_publish_total_ns,
        "checkpoint_pin_total_ns":s.checkpoint_pin_total_ns,"checkpoint_retire_total_ns":s.checkpoint_retire_total_ns,
        "native_publication":{"completed":p.completed,"chunk_barriers":p.chunk_barriers,"chunk_barrier_total_ns":p.chunk_barrier_total_ns,
        "chunk_barrier_max_ns":p.chunk_barrier_max_ns,"slot_syncs":p.slot_syncs,"slot_sync_total_ns":p.slot_sync_total_ns,"slot_sync_max_ns":p.slot_sync_max_ns}})
}

fn distribution(samples: &[u64]) -> Value {
    if samples.is_empty() {
        return Value::Null;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let percentile = |p: usize| {
        sorted[(sorted.len() * p)
            .div_ceil(100)
            .saturating_sub(1)
            .min(sorted.len() - 1)]
    };
    json!({"count":sorted.len(),"p50_ns":percentile(50),"p95_ns":percentile(95),
        "p99_ns":percentile(99),"max_ns":sorted[sorted.len()-1],
        "mean_ns":sorted.iter().map(|&n| n as f64).sum::<f64>() / sorted.len() as f64})
}
fn rss() -> u64 {
    let out = std::process::Command::new("/bin/ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout)
        .unwrap()
        .trim()
        .parse::<u64>()
        .unwrap()
        * 1024
}
fn file_bytes(path: &Path) -> u64 {
    std::fs::metadata(path).unwrap().len()
}
fn verify(path: &Path, fixture: &Fixture, expected: &[Option<Vec<u8>>]) -> String {
    let reader = NativeReader::open(path).unwrap();
    reader.validate().unwrap();
    let archive = ArchiveReader::open(
        &reader,
        reader.reader().snapshot().unwrap(),
        Limits::default(),
    )
    .unwrap();
    archive.verify_commit(reader.root().unwrap().root).unwrap();
    let mut digest = String::new();
    // A deterministic logical digest from verified contents, independent of
    // profile declarations, physical encoding, and valid directory grouping.
    let mut sum = [0u64; 4];
    for (key, expected) in expected.iter().enumerate() {
        let value = archive
            .read_file_bounded(&fixture.paths[key], 8 * 1024 * 1024)
            .unwrap()
            .map(|(_, bytes)| bytes);
        assert_eq!(&value, expected, "reopened key {key}");
        for byte in (key as u64)
            .to_le_bytes()
            .into_iter()
            .chain([u8::from(value.is_some())])
            .chain(value.iter().flat_map(|v| v.iter().copied()))
        {
            for (i, hash) in sum.iter_mut().enumerate() {
                *hash = hash
                    .wrapping_mul(0x100000001b3 + i as u64 * 2)
                    .wrapping_add(u64::from(byte) + 1);
            }
        }
    }
    for hash in sum {
        digest.push_str(&format!("{hash:016x}"));
    }
    digest
}
fn warm(engine: &Engine, fixture: &Fixture) {
    for i in 0..32 {
        black_box(engine.get(i, fixture));
    }
}
fn read_samples(
    engine: &Engine,
    fixture: &Fixture,
    expected: &[Option<Vec<u8>>],
    keys: &[usize],
    count: usize,
) -> Value {
    for &key in keys {
        assert_eq!(engine.get(key, fixture), expected[key]);
    }
    let mut times = Vec::with_capacity(count);
    for i in 0..count {
        let key = keys[(i * 31) % keys.len()];
        let start = Instant::now();
        let value = engine.get(black_box(key), fixture);
        times.push(start.elapsed().as_nanos() as u64);
        assert_eq!(value, expected[key]);
        black_box(value);
    }
    distribution(&times)
}
fn probe_checkpoint(engine: &Arc<Engine>, fixture: &Arc<Fixture>) -> Value {
    let barrier = Arc::new(Barrier::new(2));
    let done = Arc::new(AtomicBool::new(false));
    let origin = Instant::now();
    let reader = {
        let engine = engine.clone();
        let fixture = fixture.clone();
        let barrier = barrier.clone();
        let done = done.clone();
        std::thread::spawn(move || {
            let mut reads = Vec::with_capacity(4096);
            barrier.wait();
            while !done.load(Ordering::Acquire) {
                let start = origin.elapsed().as_nanos() as u64;
                assert_eq!(engine.get(0, &fixture).unwrap(), fixture.values[0]);
                let end = origin.elapsed().as_nanos() as u64;
                if reads.len() < 100_000 {
                    reads.push((start, end));
                }
                std::thread::sleep(Duration::from_micros(50));
            }
            reads
        })
    };
    barrier.wait();
    std::thread::sleep(Duration::from_millis(2));
    let before = engine.statistics();
    let start = origin.elapsed().as_nanos() as u64;
    let cpu = cpu_time::ProcessTime::now();
    engine.flush();
    let cpu_ns = cpu.elapsed().as_nanos() as u64;
    let end = origin.elapsed().as_nanos() as u64;
    done.store(true, Ordering::Release);
    let reads = reader.join().unwrap();
    let overlapping: Vec<_> = reads
        .iter()
        .filter(|(a, b)| *a < end && *b > start)
        .map(|(a, b)| b - a)
        .collect();
    json!({"wall_ns":end-start,"cpu_ns":cpu_ns,"before":before,
        "overlapping_read_latency":distribution(&overlapping),"overlapping_reads":overlapping.len()})
}

// A separate probe of acknowledged write progress after the active table has
// actually been handed to the worker, with ample combined-budget headroom.
fn probe_concurrent_checkpoint(
    engine: &Arc<Engine>,
    fixture: &Arc<Fixture>,
    expected: &mut [Option<Vec<u8>>],
    generation: usize,
    memory: usize,
) -> Value {
    let Engine::Memtable(store) = engine.as_ref() else {
        panic!("memtable probe");
    };
    let staged: Vec<_> = (1..=128)
        .map(|key| Edit {
            key,
            value: payload(key, generation + key, fixture.values[0].len()),
        })
        .collect();
    let changes = mutations(&staged, fixture);
    for start in (0..128).step_by(64) {
        engine.write(
            &staged[start..start + 64],
            &changes[start..start + 64],
            fixture,
            false,
        );
    }
    for edit in &staged {
        expected[edit.key] = Some(edit.value.clone());
    }
    let writes: Vec<_> = (0..1024)
        .map(|i| {
            let key = 600 + i % 64;
            Edit {
                key,
                value: payload(key, generation + 1000 + i, fixture.values[0].len()),
            }
        })
        .collect();
    let changes = mutations(&writes, fixture);
    let done = Arc::new(AtomicBool::new(false));
    let origin = Instant::now();
    let reader = {
        let engine = engine.clone();
        let fixture = fixture.clone();
        let done = done.clone();
        std::thread::spawn(move || {
            let mut reads = Vec::new();
            while !done.load(Ordering::Acquire) {
                let start = origin.elapsed().as_nanos() as u64;
                assert_eq!(engine.get(0, &fixture).unwrap(), fixture.values[0]);
                let end = origin.elapsed().as_nanos() as u64;
                if reads.len() < 100_000 {
                    reads.push((start, end));
                }
                std::thread::sleep(Duration::from_micros(50));
            }
            reads
        })
    };
    let flush = {
        let engine = engine.clone();
        let done = done.clone();
        std::thread::spawn(move || {
            let start = origin.elapsed().as_nanos() as u64;
            engine.flush();
            let end = origin.elapsed().as_nanos() as u64;
            done.store(true, Ordering::Release);
            (start, end)
        })
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while !store.statistics().unwrap().flush_in_progress && !done.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_micros(100));
    }
    let mut calls = Vec::new();
    let mut completed = Vec::new();
    let mut max_pending = 0;
    for start in (0..writes.len()).step_by(64) {
        if done.load(Ordering::Acquire) {
            break;
        }
        let began = origin.elapsed().as_nanos() as u64;
        engine.write(
            &writes[start..start + 64],
            &changes[start..start + 64],
            fixture,
            false,
        );
        let ack = origin.elapsed().as_nanos() as u64;
        calls.push(ack - began);
        completed.push(ack);
        for edit in &writes[start..start + 64] {
            expected[edit.key] = Some(edit.value.clone());
        }
        let stats = store.statistics().unwrap();
        assert!(stats.pending_memory_bytes <= memory);
        max_pending = max_pending.max(stats.pending_memory_bytes);
    }
    let (start, end) = flush.join().unwrap();
    let reads = reader.join().unwrap();
    let overlapping: Vec<_> = reads
        .iter()
        .filter(|(a, b)| *a < end && *b > start)
        .map(|(a, b)| b - a)
        .collect();
    let acknowledged = completed
        .iter()
        .filter(|&&ack| ack > start && ack < end)
        .count();
    let result = json!({"wall_ns":end-start,"writes_completed_while_checkpoint":acknowledged,
        "concurrent_write_latency":distribution(&calls),"overlapping_read_latency":distribution(&overlapping),
        "max_pending_memory_bytes":max_pending,"statistics_after_probe":engine.statistics()});
    engine.flush();
    result
}

fn fixture_file(path: &Path, fixture: &Fixture) {
    let mut id = [0; 16];
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut id)
        .unwrap();
    let store = MemtableStore::create(
        path,
        id,
        MemtableOptions {
            flush_interval: Duration::from_secs(3600),
            ..Default::default()
        },
    )
    .unwrap();
    for start in (0..fixture.keys.len()).step_by(512) {
        let batch: Vec<_> = (start..(start + 512).min(fixture.keys.len()))
            .map(|i| Mutation::Put {
                key: &fixture.keys[i],
                value: &fixture.values[i],
            })
            .collect();
        store.write_batch(&batch).unwrap();
    }
    store.close().unwrap();
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args[1] == "fixture" {
        let keys: usize = args[3].parse().unwrap();
        let size: usize = args[4].parse().unwrap();
        fixture_file(Path::new(&args[2]), &Fixture::new(keys, size));
        println!(
            "{}",
            json!({"keys":keys,"value_bytes":size,"verified":true})
        );
        return;
    }
    let mode = &args[2];
    let phase = &args[3];
    let source = Path::new(&args[4]);
    let file = PathBuf::from(&args[5]).join("case.sac");
    let keys: usize = args[6].parse().unwrap();
    let count: usize = args[7].parse().unwrap();
    let size: usize = args[8].parse().unwrap();
    let batch_size: usize = args[9].parse().unwrap();
    let memory: usize = args[10].parse().unwrap();
    let interval_ms = if phase == "timer" { 100 } else { 3_600_000 };
    assert!(["direct-durable", "direct-deferred", "memtable"].contains(&mode.as_str()));
    assert!(["timing", "attribution", "memory", "timer", "contention"].contains(&phase.as_str()));
    assert!((512..=65536).contains(&keys) && (16..=65536).contains(&size));
    assert!(count > 0 && count <= 65536 && (1..=1024).contains(&batch_size));
    std::fs::copy(source, &file).unwrap();
    std::fs::copy(
        format!("{}.wal", source.display()),
        format!("{}.wal", file.display()),
    )
    .unwrap();
    let fixture = Arc::new(Fixture::new(keys, size));
    let writes = edits(&fixture, count, 1);
    let batch = mutations(&writes, &fixture);
    let mut expected: Vec<_> = fixture.values.iter().cloned().map(Some).collect();
    let engine = Arc::new(Engine::open(mode, &file, memory, interval_ms));
    warm(&engine, &fixture);
    let rss_start = rss();
    let bytes_start = file_bytes(&file);
    let mut result = BTreeMap::<String, Value>::new();
    if phase == "timing" || phase == "attribution" {
        let statistics_before = engine.statistics();
        let mut call_ns = Vec::with_capacity(count.div_ceil(batch_size));
        let mut batch_trace = Vec::new();
        let mut flush_ns = Vec::new();
        let mut explicit = 0;
        let start = Instant::now();
        let cpu = cpu_time::ProcessTime::now();
        for begin in (0..count).step_by(batch_size) {
            let end = (begin + batch_size).min(count);
            let offset_ns = start.elapsed().as_nanos() as u64;
            let call = Instant::now();
            engine.write(
                &writes[begin..end],
                &batch[begin..end],
                &fixture,
                mode == "direct-durable",
            );
            let elapsed_ns = call.elapsed().as_nanos() as u64;
            call_ns.push(elapsed_ns);
            if phase == "attribution" {
                batch_trace.push(json!({"offset_ns":offset_ns,"wall_ns":elapsed_ns,"statistics":engine.statistics()}));
            }
            if end.is_multiple_of(4096) && engine.has_pending() {
                let checkpoint = Instant::now();
                engine.flush();
                flush_ns.push(checkpoint.elapsed().as_nanos() as u64);
                explicit += 1;
            }
        }
        let before_final_flush_ns = start.elapsed().as_nanos() as u64;
        let checkpoint = Instant::now();
        let final_had_pending = engine.has_pending();
        engine.flush();
        let final_flush_ns = checkpoint.elapsed().as_nanos() as u64;
        let durable_ns = start.elapsed().as_nanos() as u64;
        let cpu_ns = cpu.elapsed().as_nanos() as u64;
        let stats = engine.statistics();
        result.insert(
            "write".into(),
            json!({"wall_ns":durable_ns,"cpu_ns":cpu_ns,
            "before_final_flush_ns":before_final_flush_ns,"final_flush_ns":final_flush_ns,
            "final_had_pending":final_had_pending,"explicit_checkpoints":explicit,
            "calls":distribution(&call_ns),"explicit_flushes":distribution(&flush_ns),
            "updates_per_second":count as f64 * 1e9 / durable_ns as f64,"statistics":stats,
            "statistics_before":statistics_before,"batch_trace":batch_trace,
            "sac_appended_bytes":file_bytes(&file)-bytes_start,"rss_after_checkpoint_bytes":rss()}),
        );
        for edit in &writes {
            expected[edit.key] = Some(edit.value.clone());
        }

        if phase == "timing" {
            // Controlled read classes: no timer can change overlay residency here.
            let read_edits: Vec<_> = (1..=256)
                .map(|key| Edit {
                    key,
                    value: payload(key, 100_000 + key, size),
                })
                .collect();
            let read_mutations = mutations(&read_edits, &fixture);
            for start in (0..read_edits.len()).step_by(64) {
                engine.write(
                    &read_edits[start..start + 64],
                    &read_mutations[start..start + 64],
                    &fixture,
                    false,
                );
            }
            for edit in &read_edits {
                expected[edit.key] = Some(edit.value.clone());
            }
            let deleted: Vec<_> = (129..=192).collect();
            engine.delete(&deleted, &fixture);
            for &key in &deleted {
                expected[key] = None;
            }
            result.insert("reads".into(), json!({
            "overlay_hit":read_samples(&engine,&fixture,&expected,&(1..=128).collect::<Vec<_>>(),4096),
            "base_hit":read_samples(&engine,&fixture,&expected,&(300..=427).collect::<Vec<_>>(),4096),
            "tombstone_miss":read_samples(&engine,&fixture,&expected,&deleted,4096),
            "residency":engine.statistics(),
        }));
            engine.flush();
            let mut checkpoints = Vec::new();
            for cycle in 0..4 {
                let probe: Vec<_> = (1..=512.min(keys - 1))
                    .map(|key| Edit {
                        key,
                        value: payload(key, 200_000 + cycle * keys + key, size),
                    })
                    .collect();
                let changes = mutations(&probe, &fixture);
                for start in (0..probe.len()).step_by(64) {
                    let end = (start + 64).min(probe.len());
                    engine.write(&probe[start..end], &changes[start..end], &fixture, false);
                }
                for edit in &probe {
                    expected[edit.key] = Some(edit.value.clone());
                }
                checkpoints.push(probe_checkpoint(&engine, &fixture));
            }
            result.insert("checkpoint_probes".into(), json!(checkpoints));
        }
    } else if phase == "memory" {
        for begin in (0..count).step_by(batch_size) {
            let end = (begin + batch_size).min(count);
            engine.write(&writes[begin..end], &batch[begin..end], &fixture, false);
        }
        for edit in &writes {
            expected[edit.key] = Some(edit.value.clone());
        }
        result.insert("dirty".into(),json!({"rss_bytes":rss(),"statistics":engine.statistics(),"sac_appended_bytes":file_bytes(&file)-bytes_start}));
        engine.flush();
        result.insert(
            "flushed".into(),
            json!({"rss_bytes":rss(),"statistics":engine.statistics()}),
        );
    } else if phase == "contention" {
        assert_eq!(mode, "memtable");
        let probes: Vec<_> = (0..4)
            .map(|cycle| {
                probe_concurrent_checkpoint(
                    &engine,
                    &fixture,
                    &mut expected,
                    300_000 + cycle * 10_000,
                    memory,
                )
            })
            .collect();
        result.insert("contention_probes".into(), json!(probes));
    } else {
        assert_eq!(mode, "memtable");
        // A fresh process and 256 dirty keys fit both overlay budgets. Only
        // the real timer, not an explicit flush or pressure, checkpoints them.
        let ready = Arc::new(Barrier::new(2));
        let done = Arc::new(AtomicBool::new(false));
        let reader = {
            let engine = engine.clone();
            let fixture = fixture.clone();
            let ready = ready.clone();
            let done = done.clone();
            std::thread::spawn(move || {
                let mut times = Vec::with_capacity(4096);
                ready.wait();
                while !done.load(Ordering::Acquire) {
                    let start = Instant::now();
                    let value = engine.get(0, &fixture);
                    let elapsed = start.elapsed().as_nanos() as u64;
                    assert_eq!(value.as_ref(), Some(&fixture.values[0]));
                    if times.len() < 100_000 {
                        times.push(elapsed);
                    }
                    std::thread::sleep(Duration::from_micros(50));
                }
                times
            })
        };
        ready.wait();
        let first = Instant::now();
        for start in (0..256).step_by(64) {
            engine.write(
                &writes[start..start + 64],
                &batch[start..start + 64],
                &fixture,
                false,
            );
        }
        let ack_ns = first.elapsed().as_nanos() as u64;
        for edit in &writes[..256] {
            expected[edit.key] = Some(edit.value.clone());
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while engine.has_pending() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        let published_ns = first.elapsed().as_nanos() as u64;
        done.store(true, Ordering::Release);
        let reads = reader.join().unwrap();
        result.insert("timer".into(),json!({"interval_ms":interval_ms,"accepted_after_first_start_ns":ack_ns,
            "published_after_first_start_ns":published_ns,"reader_latency":distribution(&reads),"statistics":engine.statistics()}));
    }
    let rss_end = rss();
    drop(engine);
    let digest = verify(&file, &fixture, &expected);
    result.insert("mode".into(), json!(mode));
    result.insert("phase".into(), json!(phase));
    result.insert("keys".into(), json!(keys));
    result.insert("updates".into(), json!(count));
    result.insert("value_bytes".into(), json!(size));
    result.insert("batch_size".into(), json!(batch_size));
    result.insert("max_memory_bytes".into(), json!(memory));
    result.insert("rss_open_bytes".into(), json!(rss_start));
    result.insert("rss_final_bytes".into(), json!(rss_end));
    result.insert("logical_digest".into(), json!(digest));
    result.insert("verified".into(), json!(true));
    println!("{}", json!(result));
}
