//! Production-path qualification. Run explicitly in release mode; all measured
//! results (including failures) are appended to the caller-owned JSONL report.
//! See tools/SAC1_QUALIFICATION.md for workloads and evidence boundaries.

#![cfg(feature = "native")]

use sac::v1::resources::{ArchiveBuilder, ArchiveReader, Limits, path_from_str};
use sac::v1::{
    Header, MemoryStore, NativeStore, ObjectHash, ObjectRef, ObjectStore, ReadAt, pack_snapshot,
};
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

#[path = "sac1_qualification/concurrent.rs"]
mod concurrent;

struct Results {
    output: PathBuf,
    report: File,
    failures: Vec<String>,
}

impl Results {
    fn new() -> Self {
        let output = PathBuf::from(
            std::env::var_os("SAC1_QUALIFY_DIR")
                .expect("set SAC1_QUALIFY_DIR to a caller-owned artifact directory"),
        );
        fs::create_dir_all(&output).unwrap();
        let report = OpenOptions::new()
            .create(true)
            .append(true)
            .open(output.join("measurements.jsonl"))
            .unwrap();
        Self {
            output,
            report,
            failures: vec![],
        }
    }

    fn record(&mut self, mut result: Value, passed: bool) {
        result["passed"] = json!(passed);
        if !passed {
            self.failures
                .push(result["case"].as_str().unwrap_or("unknown").into());
        }
        writeln!(self.report, "{result}").unwrap();
        self.report.flush().unwrap();
        println!("SAC1_MEASUREMENT {result}");
    }
}

#[derive(Clone, Copy, Debug)]
enum Content {
    Incompressible,
    Text,
    Repeated,
}

impl Content {
    fn name(self) -> &'static str {
        match self {
            Self::Incompressible => "incompressible",
            Self::Text => "text",
            Self::Repeated => "repeated",
        }
    }

    fn bytes(self, ordinal: usize, size: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; size];
        match self {
            Self::Incompressible | Self::Repeated => {
                let ordinal = if matches!(self, Self::Repeated) {
                    0
                } else {
                    ordinal
                };
                let seed = format!("sac1-qualification-fixed-v1/{ordinal}/{size}");
                let mut hasher = blake3::Hasher::new();
                hasher.update(seed.as_bytes());
                hasher.finalize_xof().fill(&mut bytes);
            }
            Self::Text => {
                let text = format!(
                    "function_{ordinal:08}: preserve names, comments, and exact input bytes.\n"
                );
                for (at, byte) in bytes.iter_mut().enumerate() {
                    *byte = text.as_bytes()[at % text.len()];
                }
            }
        }
        bytes
    }
}

fn pack(
    files: &[(String, Vec<u8>)],
    chunk_size: usize,
) -> sac::v1::Result<(MemoryStore, ObjectRef)> {
    pack_with_metadata(files, chunk_size, None)
}

fn pack_with_metadata(
    files: &[(String, Vec<u8>)],
    chunk_size: usize,
    metadata: Option<sac::v1::cbor::Value>,
) -> sac::v1::Result<(MemoryStore, ObjectRef)> {
    let mut source = MemoryStore::sealed();
    let snapshot = {
        let mut builder = ArchiveBuilder::bulk(&mut source, Limits::default())?;
        builder.set_chunk_size(chunk_size)?;
        for (name, bytes) in files {
            if let Some(metadata) = &metadata {
                builder.add_file_with_metadata(&path_from_str(name)?, bytes, metadata.clone())?;
            } else {
                builder.add_file(&path_from_str(name)?, bytes)?;
            }
        }
        builder.finish()?
    };
    // Immutable incremental builders can leave superseded index objects. A
    // compact-size comparison must count an actual fixed-root closure pack.
    let bytes = pack_snapshot(&source, snapshot, Vec::new())?;
    let packed = MemoryStore::from_bytes(bytes)?;
    let snapshot = packed.reader()?.snapshot().expect("packed snapshot");
    Ok((packed, snapshot))
}

fn zip_control(directory: &Path, files: &[(String, Vec<u8>)]) -> Value {
    let inputs = directory.join("inputs");
    fs::create_dir(&inputs).unwrap();
    let mut manifest = vec![];
    for (ordinal, (name, bytes)) in files.iter().enumerate() {
        let path = inputs.join(format!("{ordinal:08}"));
        fs::write(&path, bytes).unwrap();
        manifest.push(json!({"name":name,"path":path}));
    }
    let manifest_path = directory.join("zip-inputs.json");
    fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let result = Command::new("python3")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tools/sac1_zip_reference.py"))
        .arg(manifest_path)
        .arg(directory.join("control.zip"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "ZIP control failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = serde_json::from_slice(&result.stdout).unwrap();
    fs::remove_dir_all(inputs).unwrap();
    result
}

fn tiny(results: &mut Results) {
    let bytes = b"0123456789abcdefghij".to_vec();
    assert_eq!(bytes.len(), 20);
    let files = vec![("hello.txt".into(), bytes)];
    let started = Instant::now();
    match pack(&files, 1 << 20) {
        Ok((packed, snapshot)) => {
            let archive = ArchiveReader::open(&packed, snapshot, Limits::default()).unwrap();
            assert_eq!(
                archive
                    .read_range(&path_from_str("hello.txt").unwrap(), 0, 20)
                    .unwrap(),
                files[0].1
            );
            archive.verify().unwrap();
            let encoded = packed.as_bytes();
            fs::write(results.output.join("tiny.sac"), encoded).unwrap();
            let overhead = encoded.len().saturating_sub(20);
            results.record(
                json!({"case":"one-tiny-file","logical_bytes":20,
                "packed_bytes":encoded.len(),"overhead_bytes":overhead,
                "limit_overhead_bytes":768,"elapsed_ns":started.elapsed().as_nanos()}),
                overhead <= 768,
            );
        }
        Err(error) => results.record(
            json!({"case":"one-tiny-file","error":error.to_string()}),
            false,
        ),
    }
}

fn small_files(results: &mut Results, full: bool) {
    // Maximum bin sizes deliberately expose the inline/extent transition. The
    // exact 512/513 and 8192/8193 pairs are separate measured populations.
    let extra_sizes = std::env::var("SAC1_QUALIFY_SIZES").ok().map(|value| {
        value
            .split(',')
            .map(|size| size.parse::<usize>().unwrap())
            .collect::<Vec<_>>()
    });
    let sizes: &[usize] = if let Some(sizes) = &extra_sizes {
        sizes
    } else if full {
        &[32, 512, 1024, 4096, 8192, 16384, 65536, 513, 8193]
    } else {
        &[32, 512, 513, 8192, 8193]
    };
    let resources = if full { 4096 } else { 256 };
    let name_lengths: &[usize] = if full { &[8, 128] } else { &[8] };
    for &size in sizes {
        for content in [Content::Incompressible, Content::Text, Content::Repeated] {
            if std::env::var_os("SAC1_QUALIFY_TEXT_SHORT").is_some()
                && !matches!(content, Content::Text)
            {
                continue;
            }
            for &name_length in name_lengths {
                if std::env::var_os("SAC1_QUALIFY_TEXT_SHORT").is_some() && name_length != 8 {
                    continue;
                }
                for minimal_metadata in [false, true] {
                    let case = format!(
                        "small-{size}-{}-name{name_length}-n{resources}-meta{}",
                        content.name(),
                        if minimal_metadata { "minimal" } else { "empty" }
                    );
                    let directory = results.output.join(&case);
                    fs::create_dir(&directory).unwrap();
                    let files: Vec<_> = (0..resources)
                        .map(|ordinal| {
                            let base = format!("f{ordinal:07}");
                            let basename =
                                format!("{base}{}", "x".repeat(name_length - base.len()));
                            (
                                format!("d{}/{basename}", ordinal / 1024),
                                content.bytes(ordinal, size),
                            )
                        })
                        .collect();
                    let zip = zip_control(&directory, &files);
                    let zip_bytes = zip["bytes"].as_u64().unwrap();
                    let limit = if size <= 8192 {
                        zip_bytes
                    } else {
                        (zip_bytes + 256 * resources as u64)
                            .min((zip_bytes as f64 * 1.03).floor() as u64)
                    };
                    let started = Instant::now();
                    let metadata = minimal_metadata.then(|| {
                        use sac::v1::cbor::Value as Cbor;
                        let entry = |name: &str, value: Cbor| {
                            let key = Cbor::Text(name.to_owned());
                            sac::v1::cbor::MapEntry {
                                key_bytes: sac::v1::cbor::encode(&key),
                                key,
                                value,
                            }
                        };
                        Cbor::Map(vec![
                            entry("mode", Cbor::Uint(0o644)),
                            entry(
                                "mtime",
                                Cbor::Array(vec![Cbor::Uint(315532800), Cbor::Uint(0)]),
                            ),
                        ])
                    });
                    match pack_with_metadata(&files, 1 << 20, metadata) {
                        Ok((packed, snapshot)) => {
                            let pack_ns = started.elapsed().as_nanos();
                            // Verification and random boundary reads use the real
                            // consumer. A size-only malformed pack cannot pass.
                            let archive =
                                ArchiveReader::open(&packed, snapshot, Limits::default()).unwrap();
                            let verification_started = Instant::now();
                            archive.verify().unwrap();
                            let verification_ns = verification_started.elapsed().as_nanos();
                            for ordinal in [0, resources / 2, resources - 1] {
                                let (name, expected) = &files[ordinal];
                                let got = archive
                                    .read_range(&path_from_str(name).unwrap(), 0, expected.len())
                                    .unwrap();
                                assert_eq!(&got, expected, "round trip {case}/{name}");
                            }
                            let packed_bytes = packed.as_bytes().len() as u64;
                            let qualified = full && packed_bytes <= limit;
                            // Reduced populations are diagnostics, not the frozen
                            // 4096-resource many-file acceptance population.
                            results.record(
                            json!({"case":case,"scope":if full {"acceptance"} else {"diagnostic"},
                            "resources":resources,"file_bytes":size,"name_bytes":name_length,
                            "metadata":if minimal_metadata {"mode0644,mtime1980-01-01"} else {"empty; boilerplate ZIP attributes excluded from restored source facts"},
                            "content":content.name(),"packed_bytes":packed_bytes,
                            "zip":zip,"limit_bytes":limit,"meets_size_target":packed_bytes<=limit,
                                "pack_elapsed_ns":pack_ns,"verification_elapsed_ns":verification_ns,
                            "elapsed_ns":started.elapsed().as_nanos()}),
                            !full || qualified,
                        );
                        }
                        Err(error) => {
                            results.record(json!({"case":case,"error":error.to_string()}), false)
                        }
                    }
                    // Keep compact reports and failed packs, not one disposable ZIP
                    // control per population. All source bytes are reproducible.
                    fs::remove_file(directory.join("control.zip")).unwrap();
                    fs::remove_file(directory.join("zip-inputs.json")).unwrap();
                    fs::remove_dir(directory).unwrap();
                }
            }
        }
    }
}

fn distribution(samples: &[u64]) -> Value {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let percentile = |p: usize| sorted[(sorted.len() * p).div_ceil(100).saturating_sub(1)];
    json!({"count":sorted.len(),"p50_ns":percentile(50),"p95_ns":percentile(95),
        "p99_ns":percentile(99),"max_ns":sorted.last(),"samples_ns":samples})
}

fn host_load() -> Value {
    let output = |name: &str, args: &[&str]| {
        Command::new(name)
            .args(args)
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
            .unwrap_or_else(|error| error.to_string())
    };
    json!({"loadavg":output("sysctl",&["-n","vm.loadavg"]),"vm":output("vm_stat",&[]),"processes":output("ps",&["-axo","pid,pcpu,rss,comm","-r"]).lines().take(17).collect::<Vec<_>>()})
}

fn environment(results: &mut Results, full: bool) {
    let command = |name: &str, arguments: &[&str]| {
        Command::new(name).args(arguments).output().map(|output| json!({
            "success":output.status.success(),"stdout":String::from_utf8_lossy(&output.stdout).trim(),
            "stderr":String::from_utf8_lossy(&output.stderr).trim()}))
            .unwrap_or_else(|error| json!({"error":error.to_string()}))
    };
    results.record(
        json!({"case":"qualification-environment","full_population":full,
        "executable":std::env::current_exe().unwrap(),"rustc":command("rustc",&["--version"]),
        "os":command("uname",&["-a"]),
        "hardware":command("sysctl",&["-n","hw.model","hw.memsize","machdep.cpu.brand_string"]),
        "filesystem":command("df",&["-k",results.output.to_str().unwrap()]),
        "seed":"sac1-qualification-fixed-v1","zstd_level":1,"workers":1,
        "archive_limits_auxiliary_memory_bytes":Limits::default().max_memory_bytes}),
        true,
    );
}

fn native_publication(results: &mut Results, full: bool) {
    let path = results.output.join("native-core-publication.sac");
    let mut store = NativeStore::create(&path, Header::new([0x71; 16], [0x72; 16])).unwrap();
    let initial = {
        let mut builder = ArchiveBuilder::new(&mut store);
        builder
            .add_file(&path_from_str("value.txt").unwrap(), b"initial")
            .unwrap();
        builder.finish().unwrap()
    };
    store.publish(initial).unwrap();
    let samples = if full { 1000 } else { 100 };
    let mut elapsed = Vec::new();
    let mut growth = Vec::new();
    let mut read_bytes = Vec::new();
    let before_all = store.publication_statistics();
    for ordinal in 0..samples {
        let before_len = store.file_len();
        let before_reads = store.physical_statistics();
        let started = Instant::now();
        let snapshot = {
            let mut builder = ArchiveBuilder::new(&mut store);
            let value = format!("scalar value {ordinal:08}");
            builder
                .add_file(&path_from_str("value.txt").unwrap(), value.as_bytes())
                .unwrap();
            builder.finish().unwrap()
        };
        store.publish(snapshot).unwrap();
        elapsed.push(started.elapsed().as_nanos().min(u64::MAX as u128) as u64);
        growth.push(store.file_len() - before_len);
        read_bytes.push(store.physical_statistics().read_bytes - before_reads.read_bytes);
    }
    let after_all = store.publication_statistics();
    let counters_match = after_all.chunk_barriers - before_all.chunk_barriers == samples
        && after_all.slot_syncs - before_all.slot_syncs == samples
        && after_all.completed - before_all.completed == samples;
    results.record(json!({"case":"native-core-publication","scope":"core-diagnostic",
        "note":"actual native durable publication; does not qualify an application's semantic save or command-path latency",
        "timing":distribution(&elapsed),"append_bytes":growth,"read_bytes":read_bytes,
        "chunk_barriers":after_all.chunk_barriers-before_all.chunk_barriers,
        "slot_syncs":after_all.slot_syncs-before_all.slot_syncs,
        "completed":after_all.completed-before_all.completed,
        "target_reference_p95_ns":25_000_000}), counters_match);
    let previous = store.root().unwrap();
    let before_len = store.file_len();
    let before_noop = store.publication_statistics();
    store.publish_commit(previous.root).unwrap();
    let after_noop = store.publication_statistics();
    results.record(
        json!({"case":"native-durable-baseline-noop",
        "append_bytes":store.file_len()-before_len,
        "chunk_barriers":after_noop.chunk_barriers-before_noop.chunk_barriers,
        "slot_syncs":after_noop.slot_syncs-before_noop.slot_syncs,
        "generation_unchanged":store.root().unwrap()==previous}),
        before_len == store.file_len()
            && before_noop == after_noop
            && store.root().unwrap() == previous,
    );
    drop(store);

    fresh_process_open(results, &path, "fresh-process-native-root-open");
}
fn large_fresh_open(results: &mut Results, full: bool) {
    let path = PathBuf::from(
        std::env::var_os("SAC1_QUALIFY_EXTRACTION_SOURCE")
            .expect("large open requires SAC1_QUALIFY_EXTRACTION_SOURCE"),
    );
    assert!(!full || fs::metadata(&path).unwrap().len() >= 1 << 30);
    fresh_process_open(results, &path, "fresh-process-large-native-root-open");
}
fn fresh_process_open(results: &mut Results, path: &Path, case: &str) {
    // Every timed open executes in its own process. The file's bounded control
    // bytes are deliberately OS-warm; no private parsed cache crosses processes.
    let mut opens = Vec::new();
    let mut observations = Vec::new();
    let mut failures = Vec::new();
    for _ in 0..100 {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "sac1_child_open",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("SAC1_CHILD_FILE", path)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let measurement = stdout.lines().find_map(|line| {
            line.split_once("SAC1_CHILD_OPEN ")
                .and_then(|(_, value)| serde_json::from_str::<Value>(value).ok())
        });
        match (output.status.success(), measurement) {
            (true, Some(value)) => {
                opens.push(value["elapsed_ns"].as_u64().unwrap());
                observations.push(value);
            }
            _ => failures
                .push(json!({"stdout":stdout,"stderr":String::from_utf8_lossy(&output.stderr)})),
        }
    }
    let bounded = observations.iter().all(|v| {
        v["read_bytes"].as_u64().unwrap() <= 76 * 1024
            && v["read_operations"].as_u64().unwrap() <= 2
    });
    let timing = if opens.is_empty() {
        Value::Null
    } else {
        distribution(&opens)
    };
    let fast = timing["p95_ns"].as_u64().is_some_and(|v| v <= 5_000_000);
    results.record(json!({"case":case,"archive_physical_bytes":fs::metadata(path).unwrap().len(),"cache_state":"OS-warm, fresh process and empty application caches",
        "timing":timing,"observations":observations,"failures":failures,
        "limit_read_bytes":76*1024,"limit_reads":2,"limit_p95_ns":5_000_000}),
        failures.is_empty() && bounded && fast);
}

fn payload_ids(
    store: &impl ObjectStore,
    root: ObjectRef,
) -> sac::v1::Result<std::collections::BTreeSet<ObjectHash>> {
    let mut visited = std::collections::BTreeSet::new();
    let mut ids = std::collections::BTreeSet::new();
    let mut stack = vec![root];
    while let Some(reference) = stack.pop() {
        if !visited.insert(reference.hash) {
            continue;
        }
        let object = store.get(reference)?;
        if object.kind == 7 {
            ids.insert(reference.hash);
        }
        stack.extend(object.children);
    }
    Ok(ids)
}

fn bulk(results: &mut Results, full: bool) {
    let size = if full { 1 << 30 } else { 16 << 20 };
    let bytes = Content::Incompressible.bytes(0x1061, size);
    let expected = blake3::hash(&bytes);
    let files = vec![("bulk.bin".to_owned(), bytes)];
    let (packed, snapshot) = match pack(&files, 1 << 20) {
        Ok(packed) => packed,
        Err(error) => {
            results.record(
                json!({"case":"bulk-incompressible","error":error.to_string()}),
                false,
            );
            return;
        }
    };
    let size_limit = size as u64 + (size as u64 * 2 / 1000);
    let packed_bytes = packed.as_bytes().len() as u64;
    let archive_path = results.output.join("bulk-incompressible.sac");
    fs::write(&archive_path, packed.as_bytes()).unwrap();
    let control_path = results.output.join("bulk-incompressible.input");
    fs::write(&control_path, &files[0].1).unwrap();
    results.record(
        json!({"case":"bulk-incompressible","scope":if full {"acceptance"} else {"diagnostic"},
        "logical_bytes":size,"packed_bytes":packed_bytes,"limit_bytes":size_limit,
        "chunk_bytes":1<<20,"meets_size_target":packed_bytes<=size_limit}),
        !full || packed_bytes <= size_limit,
    );
    let one_ids = payload_ids(&packed, snapshot).unwrap();
    let both = vec![
        ("bulk.bin".to_owned(), files[0].1.clone()),
        ("copy.bin".to_owned(), files[0].1.clone()),
    ];
    let (duplicate_pack, duplicate_snapshot) = pack(&both, 1 << 20).unwrap();
    let two_ids = payload_ids(&duplicate_pack, duplicate_snapshot).unwrap();
    let delta = duplicate_pack.as_bytes().len() as i64 - packed_bytes as i64;
    results.record(
        json!({"case":"identical-resource-dedup","scope":if full {"acceptance"} else {"diagnostic"},
        "one_resource_bytes":packed_bytes,"two_resource_bytes":duplicate_pack.as_bytes().len(),
        "delta_bytes":delta,"one_payload_objects":one_ids.len(),"two_payload_objects":two_ids.len(),
        "identical_payload_ids":one_ids==two_ids,"limit_delta_bytes":64*1024}),
        delta <= 64 * 1024 && one_ids == two_ids,
    );
    drop(duplicate_pack);
    drop(both);
    drop(packed);
    drop(files);
    let disk = NativeStore::open(&archive_path, false).unwrap();
    let snapshot = disk.reader().snapshot().unwrap();
    let archive = ArchiveReader::open(&disk, snapshot, Limits::default()).unwrap();
    archive.verify().unwrap();
    let control = File::open(&control_path).unwrap();
    let path = path_from_str("bulk.bin").unwrap();
    let mut raw_times = Vec::new();
    let mut archive_times = Vec::new();
    let mut reads = Vec::new();
    // Prewarm both paths explicitly. This controls OS-cache state without
    // requiring privileged system-wide cache eviction on a shared host.
    let run_raw = || {
        let mut output = Vec::with_capacity(size);
        let mut verification = blake3::Hasher::new();
        let started = Instant::now();
        let mut buffer = vec![0; 1 << 20];
        for offset in (0..size).step_by(buffer.len()) {
            control.read_exact_at(offset as u64, &mut buffer).unwrap();
            verification.update(&buffer);
            output.write_all(&buffer).unwrap();
        }
        let raw_ns = started.elapsed().as_nanos() as u64;
        assert_eq!(verification.finalize(), expected);
        assert_eq!(output.len(), size);
        drop(output);
        raw_ns
    };
    let run_archive = || {
        let before = disk.physical_statistics();
        let mut output = Vec::with_capacity(size);
        let started = Instant::now();
        archive.read_to(&path, &mut output).unwrap();
        let archive_ns = started.elapsed().as_nanos() as u64;
        assert_eq!(output.len(), size);
        assert_eq!(blake3::hash(&output), expected);
        (
            archive_ns,
            disk.physical_statistics().read_bytes - before.read_bytes,
        )
    };
    let mut pairs = Vec::new();
    for round in 0..6 {
        let sac_first =
            blake3::hash(format!("sac1-throughput-order-v1/{round}").as_bytes()).as_bytes()[0] & 1
                != 0;
        let (raw_ns, (archive_ns, physical)) = if sac_first {
            run_archive();
            let candidate = run_archive();
            run_raw();
            (run_raw(), candidate)
        } else {
            run_raw();
            let control = run_raw();
            run_archive();
            (control, run_archive())
        };
        if round != 0 {
            raw_times.push(raw_ns);
            archive_times.push(archive_ns);
            reads.push(physical);
            pairs.push(json!({"round":round,"order":if sac_first {"sac,raw"} else {"raw,sac"},"control_ns":raw_ns,"candidate_ns":archive_ns,"ratio":raw_ns as f64/archive_ns as f64,"host":host_load()}));
        }
    }
    let raw_total: u64 = raw_times.iter().sum();
    let archive_total: u64 = archive_times.iter().sum();
    let ratio = raw_total as f64 / archive_total as f64;
    results.record(json!({"case":"verified-stored-sequential","scope":if full {"acceptance"} else {"diagnostic"},
        "cache_state":"each timed path immediately preceded by a complete untimed verified read of that same path; output allocation reserved outside timing","decoded_cache_budget_bytes":32<<20,
        "logical_bytes_per_sample":size,"baseline":"raw positional 1MiB reads plus BLAKE3 and Vec materialization; output capacity reserved outside timing on both paths",
        "raw":distribution(&raw_times),"sac":distribution(&archive_times),"pairs":pairs,"order_seed":"sac1-throughput-order-v1",
        "sac_physical_read_bytes":reads,"throughput_ratio":ratio,"minimum_ratio":0.90}),!full || ratio>=0.90);
    // Compact reports and the SAC artifact suffice after byte-equality checks.
    fs::remove_file(control_path).unwrap();
}

fn compressed_bulk(results: &mut Results, full: bool) {
    let chunk_size = 1 << 20;
    let chunks = if full { 1024 } else { 16 };
    let size = chunk_size * chunks;
    let mut bytes = Vec::with_capacity(size);
    let control_path = results.output.join("bulk-zstd-independent.frames");
    let mut control = File::create(&control_path).unwrap();
    let mut ranges = Vec::with_capacity(chunks);
    let mut z = 0u64;
    for ordinal in 0..chunks {
        // All chunks are nonzero, distinct, and highly compressible. This case
        // exposes per-object framing overhead that a compressibility average
        // can conceal.
        let chunk = Content::Text.bytes(ordinal, chunk_size);
        let compressed = zstd::bulk::compress(&chunk, 1).unwrap();
        assert!(compressed.len() < chunk.len());
        ranges.push((z, compressed.len()));
        control.write_all(&compressed).unwrap();
        z += compressed.len() as u64;
        bytes.extend(chunk);
    }
    drop(control);
    let expected = blake3::hash(&bytes);
    let files = vec![("bulk.bin".to_owned(), bytes)];
    let (packed, _) = pack(&files, chunk_size).unwrap();
    let packed_bytes = packed.as_bytes().len() as u64;
    let m = 10u64; // deterministic CBOR bstr("bulk.bin") plus empty metadata map
    let h = 1024 + 128 * chunks as u64 + 128 + m;
    let ratio_limit = (1.05 * z as f64).floor() as u64 + h;
    let logical_limit = z + size as u64 * 2 / 1000 + m;
    results.record(
        json!({"case":"bulk-compressed-distinct-nonzero-chunks",
        "scope":if full {"acceptance"} else {"diagnostic"},"logical_bytes":size,
        "z_bytes":z,"unique_chunks":chunks,"files":1,"metadata_name_bytes":m,
        "h_bytes":h,"packed_bytes":packed_bytes,"ratio_limit_bytes":ratio_limit,
        "logical_limit_bytes":logical_limit,"zstd_level":1,"chunk_bytes":chunk_size,
        "meets_size_target":packed_bytes<=ratio_limit && packed_bytes<=logical_limit}),
        !full || (packed_bytes <= ratio_limit && packed_bytes <= logical_limit),
    );
    let archive_path = results.output.join("bulk-compressed.sac");
    fs::write(&archive_path, packed.as_bytes()).unwrap();
    drop(packed);
    drop(files);
    let disk = NativeStore::open(&archive_path, false).unwrap();
    let archive =
        ArchiveReader::open(&disk, disk.reader().snapshot().unwrap(), Limits::default()).unwrap();
    archive.verify().unwrap();
    let control = File::open(&control_path).unwrap();
    let path = path_from_str("bulk.bin").unwrap();
    let mut independent_times = Vec::new();
    let mut archive_times = Vec::new();
    let run_control = || {
        let mut output = Vec::with_capacity(size);
        let mut verification = blake3::Hasher::new();
        let started = Instant::now();
        for &(offset, length) in &ranges {
            let mut compressed = vec![0; length];
            control.read_exact_at(offset, &mut compressed).unwrap();
            let decoded = zstd::bulk::decompress(&compressed, chunk_size).unwrap();
            verification.update(&decoded);
            output.extend(decoded);
        }
        let independent_ns = started.elapsed().as_nanos() as u64;
        assert_eq!(verification.finalize(), expected);
        assert_eq!(output.len(), size);
        drop(output);
        independent_ns
    };
    let run_archive = || {
        let mut output = Vec::with_capacity(size);
        let started = Instant::now();
        archive.read_to(&path, &mut output).unwrap();
        let archive_ns = started.elapsed().as_nanos() as u64;
        assert_eq!(output.len(), size);
        assert_eq!(blake3::hash(&output), expected);
        archive_ns
    };
    let mut pairs = Vec::new();
    for round in 0..6 {
        let sac_first =
            blake3::hash(format!("sac1-throughput-order-v1/{round}").as_bytes()).as_bytes()[0] & 1
                != 0;
        let (independent_ns, archive_ns) = if sac_first {
            run_archive();
            let candidate = run_archive();
            run_control();
            (run_control(), candidate)
        } else {
            run_control();
            let control = run_control();
            run_archive();
            (control, run_archive())
        };
        if round != 0 {
            independent_times.push(independent_ns);
            archive_times.push(archive_ns);
            pairs.push(json!({"round":round,"order":if sac_first {"sac,zstd"} else {"zstd,sac"},"control_ns":independent_ns,"candidate_ns":archive_ns,"ratio":independent_ns as f64/archive_ns as f64,"host":host_load()}));
        }
    }
    let ratio =
        independent_times.iter().sum::<u64>() as f64 / archive_times.iter().sum::<u64>() as f64;
    results.record(json!({"case":"verified-zstd-sequential","scope":if full {"acceptance"} else {"diagnostic"},
        "cache_state":"each timed path immediately preceded by complete untimed verified read of that same path; output allocation reserved outside timing","decoded_cache_budget_bytes":32<<20,
        "logical_bytes_per_sample":size,"zstd_level":1,"chunk_bytes":chunk_size,"workers":1,
        "baseline":"independent Zstandard chunks plus BLAKE3 and Vec materialization; capacity reserved outside timing on both paths",
        "independent":distribution(&independent_times),"sac":distribution(&archive_times),"pairs":pairs,"order_seed":"sac1-throughput-order-v1",
        "throughput_ratio":ratio,"minimum_ratio":0.85}), !full || ratio>=0.85);
    fs::remove_file(control_path).unwrap();
}

fn native_compaction(results: &mut Results, full: bool) {
    let size = if full { 1 << 30 } else { 16 << 20 };
    let path = results.output.join("native-compaction.sac");
    let mut store = NativeStore::create(&path, Header::new([0x81; 16], [0x82; 16])).unwrap();
    let bytes = Content::Incompressible.bytes(0x2071, size);
    let expected_tail = bytes[size - 65536..].to_vec();
    let snapshot = {
        let mut builder = ArchiveBuilder::new(&mut store);
        builder.set_chunk_size(1 << 20).unwrap();
        builder
            .add_file(&path_from_str("captured.bin").unwrap(), &bytes)
            .unwrap();
        builder.finish().unwrap()
    };
    drop(bytes);
    store.publish(snapshot).unwrap();
    let directory = store.get(snapshot).unwrap().children[0];
    let before_garbage = store.file_len();
    for ordinal in 0..size / (2 << 20) {
        let bytes = Content::Incompressible.bytes(0x3000 + ordinal, 1 << 20);
        store.put(7, 1, &bytes, &[]).unwrap();
    }
    let garbage_bytes = store.file_len() - before_garbage;
    let snapshot = {
        let mut builder = ArchiveBuilder::from_directory(&mut store, directory, Limits::default());
        builder
            .add_file(
                &path_from_str("counter.txt").unwrap(),
                b"retained after garbage",
            )
            .unwrap();
        builder.finish().unwrap()
    };
    store.publish(snapshot).unwrap();
    let pinned = store.pin().unwrap();
    let original = store.root().unwrap();
    let old_physical_bytes = store.file_len();
    let started = Instant::now();
    let outcome = store.compact();
    let elapsed_ns = started.elapsed().as_nanos();
    match outcome {
        Err(error) => results.record(
            json!({"case":"native-quiescent-compaction",
            "scope":"core-diagnostic","old_physical_bytes":old_physical_bytes,
            "generated_unreachable_payload_bytes":garbage_bytes,"elapsed_ns":elapsed_ns,
            "error":error.to_string()}),
            false,
        ),
        Ok(()) => {
            let old_archive = ArchiveReader::open(
                &pinned,
                pinned.reader().snapshot().unwrap(),
                Limits::default(),
            )
            .unwrap();
            let new_archive = ArchiveReader::open(
                &store,
                store.reader().snapshot().unwrap(),
                Limits::default(),
            )
            .unwrap();
            let path = path_from_str("captured.bin").unwrap();
            let old_tail = old_archive
                .read_range(&path, (size - 65536) as u64, 65536)
                .unwrap();
            let new_tail = new_archive
                .read_range(&path, (size - 65536) as u64, 65536)
                .unwrap();
            new_archive.verify().unwrap();
            let identity_preserved = original.root.hash == store.root().unwrap().root.hash;
            let compact_bytes = store.file_len();
            let content_equal = old_tail == expected_tail && new_tail == expected_tail;
            results.record(json!({"case":"native-quiescent-compaction","scope":"core-diagnostic",
                "note":"does not qualify concurrent ten-minute workload or100cutoverpausepopulation",
                "retained_input_bytes":size,"old_physical_bytes":old_physical_bytes,
                "generated_unreachable_payload_bytes":garbage_bytes,"compact_bytes":compact_bytes,
                "elapsed_ns":elapsed_ns,"reference_deadline_ns":120_000_000_000u64,
                "old_pin_retained_bytes":old_physical_bytes,"same_commit_id":identity_preserved,
                "pinned_old_and_installed_bytes_equal":content_equal}),
                identity_preserved && content_equal && compact_bytes<old_physical_bytes && elapsed_ns<=120_000_000_000);
        }
    }
}

fn file_scale(results: &mut Results, full: bool) {
    use sac::v1::resources::{EntryKind, Lookup};
    let files = if full { 1_000_000usize } else { 4096 };
    let path = results.output.join("million-files.sac");
    let mut store = NativeStore::create_sealed(&path, Header::new([0xa1; 16], [0xa2; 16])).unwrap();
    store.set_decoded_cache_budget(8 << 20);
    let limits = Limits {
        max_entries: files as u64 + 16,
        ..Default::default()
    };
    let began = Instant::now();
    let (snapshot, sort_statistics) = {
        let mut builder = ArchiveBuilder::bulk(&mut store, limits.clone()).unwrap();
        for ordinal in 0..files {
            let path = path_from_str(&format!("d{:02}/f{ordinal:07}", ordinal % 16)).unwrap();
            builder.add_file(&path, &[]).unwrap();
        }
        builder.finish_with_statistics().unwrap()
    };
    store.publish(snapshot).unwrap();
    let build_ns = began.elapsed().as_nanos();
    let archive = ArchiveReader::open(&store, store.reader().snapshot().unwrap(), limits).unwrap();
    let began = Instant::now();
    let mut seen_files = 0usize;
    let mut seen_directories = 0usize;
    let mut names = blake3::Hasher::new();
    archive
        .visit_entries(&mut |entry| {
            if entry.kind == EntryKind::File {
                seen_files += 1;
            } else {
                seen_directories += 1;
            }
            for component in entry.path {
                names.update(&component);
                names.update(&[0]);
            }
            Ok(())
        })
        .unwrap();
    let list_ns = began.elapsed().as_nanos();
    let mut expected_names = blake3::Hasher::new();
    for directory in 0..16 {
        let name = format!("d{directory:02}");
        expected_names.update(name.as_bytes());
        expected_names.update(&[0]);
        for ordinal in (directory..files).step_by(16) {
            expected_names.update(name.as_bytes());
            expected_names.update(&[0]);
            expected_names.update(format!("f{ordinal:07}").as_bytes());
            expected_names.update(&[0]);
        }
    }
    assert_eq!(
        names.finalize(),
        expected_names.finalize(),
        "complete resource namespace differs from input population"
    );
    let mut query_ns = Vec::new();
    let before = store.physical_statistics();
    for ordinal in (0..files).step_by(if full { 997 } else { 17 }) {
        let path = path_from_str(&format!("d{:02}/f{ordinal:07}", ordinal % 16)).unwrap();
        let began = Instant::now();
        let result = archive.lookup(&path).unwrap();
        query_ns.push(began.elapsed().as_nanos() as u64);
        assert!(
            matches!(result,Lookup::Found{entry,..} if entry.path==path && entry.length==0 && entry.kind==EntryKind::File)
        );
    }
    results.record(json!({"case":"million-files-streaming-list-and-query","scope":if full {"acceptance"} else {"diagnostic"},
        "files":seen_files,"directories":seen_directories,"packed_bytes":store.file_len(),"build_ns":build_ns,"streaming_list_ns":list_ns,
        "query_timing":distribution(&query_ns),"enumerated_name_digest":names.finalize().to_hex().to_string(),"independent_expected_namespace_digest":expected_names.finalize().to_hex().to_string(),
        "query_physical_read_bytes":store.physical_statistics().read_bytes-before.read_bytes,
        "decoded_cache_budget":8<<20,"cache_usage":format!("{:?}",store.cache_usage()),
        "list_api":"visit_entries callback; no accumulated directory or resource output",
        "sort_spool_peak_bytes":sort_statistics.temporary_peak_bytes,"sort_spool_read_bytes":sort_statistics.temporary_read_bytes,"sort_spool_write_bytes":sort_statistics.temporary_write_bytes,"temporary":format!("{:?}",store.temporary_statistics())}),seen_files==files && seen_directories==16);
}

fn extraction_memory(results: &mut Results, full: bool) {
    use std::io::Read;
    struct Generated {
        stream: blake3::OutputReader,
        hash: blake3::Hasher,
        remaining: u64,
    }
    impl Read for Generated {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            let n = bytes.len().min(self.remaining as usize);
            self.stream.fill(&mut bytes[..n]);
            self.hash.update(&bytes[..n]);
            self.remaining -= n as u64;
            Ok(n)
        }
    }
    let size = if full { 1u64 << 30 } else { 16u64 << 20 };
    let files = if full { 4096 } else { 64 };
    let seed = blake3::hash(b"sac1-extraction-memory-fixed-v1");
    let mut generator = blake3::Hasher::new();
    generator.update(seed.as_bytes());
    let mut generated = Generated {
        stream: generator.finalize_xof(),
        hash: blake3::Hasher::new(),
        remaining: size,
    };
    let external_source = std::env::var_os("SAC1_QUALIFY_EXTRACTION_SOURCE").map(PathBuf::from);
    let path = external_source
        .clone()
        .unwrap_or_else(|| results.output.join("extraction-memory.sac"));
    let destination = results.output.join("extracted");
    let (store, sort_statistics, build_ns) = if external_source.is_some() {
        std::io::copy(&mut generated, &mut std::io::sink()).unwrap();
        let store = NativeStore::open(&path, false).unwrap();
        store.set_decoded_cache_budget(8 << 20);
        (store, sac::v1::resources::PackingStatistics::default(), 0)
    } else {
        let mut store =
            NativeStore::create_sealed(&path, Header::new([0xb1; 16], [0xb2; 16])).unwrap();
        store.set_decoded_cache_budget(8 << 20);
        let began = Instant::now();
        let (snapshot, statistics) = {
            let mut builder = ArchiveBuilder::bulk(&mut store, Limits::default()).unwrap();
            builder.set_chunk_size(1 << 20).unwrap();
            builder
                .add_reader(&path_from_str("captured.bin").unwrap(), &mut generated)
                .unwrap();
            for ordinal in 0..files {
                builder
                    .add_file(
                        &path_from_str(&format!("d{}/f{ordinal:07}", ordinal % 4)).unwrap(),
                        &Content::Incompressible.bytes(ordinal, 512),
                    )
                    .unwrap();
            }
            builder.finish_with_statistics().unwrap()
        };
        store.publish(snapshot).unwrap();
        (store, statistics, began.elapsed().as_nanos())
    };
    let expected = *generated.hash.finalize().as_bytes();
    let began = Instant::now();
    let validation = store.validate().unwrap();
    let validation_ns = began.elapsed().as_nanos();
    let archive = ArchiveReader::open(
        &store,
        store.reader().snapshot().unwrap(),
        Limits::default(),
    )
    .unwrap();
    let began = Instant::now();
    let extracted = archive.extract(&destination).unwrap();
    let extraction_ns = began.elapsed().as_nanos();
    let mut input = File::open(destination.join("content/captured.bin")).unwrap();
    let mut hash = blake3::Hasher::new();
    let mut buffer = vec![0; 1 << 20];
    let mut read = 0u64;
    loop {
        let n = input.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
        read += n as u64;
    }
    assert_eq!(*hash.finalize().as_bytes(), expected);
    assert_eq!(read, size);
    for ordinal in 0..files {
        assert_eq!(
            fs::read(destination.join(format!("content/d{}/f{ordinal:07}", ordinal % 4))).unwrap(),
            Content::Incompressible.bytes(ordinal, 512)
        );
    }
    results.record(json!({"case":"streaming-open-and-confined-extraction-memory","scope":if full {"acceptance"} else {"diagnostic"},
        "retained_stream_bytes":size,"small_files":files,"files_extracted":extracted.files,"source_path":path,"producer_in_measured_process":external_source.is_none(),"entries_extracted":extracted.entries,
        "logical_output_bytes":extracted.logical_bytes,"packed_bytes":store.file_len(),"build_ns":build_ns,"full_physical_validation_ns":validation_ns,"extraction_ns":extraction_ns,
        "full_physical_validation_objects":validation.objects,"captured_blake3":hex::encode(expected),"all_output_bytes_checked":true,
        "decoded_cache_budget_bytes":8<<20,"cache_usage":format!("{:?}",store.cache_usage()),
        "sort_spool_peak_bytes":sort_statistics.temporary_peak_bytes,"sort_spool_read_bytes":sort_statistics.temporary_read_bytes,"sort_spool_write_bytes":sort_statistics.temporary_write_bytes,
        "memory_note":"source generated through a bounded Read and output remains on disk; OS process RSS includes parser, caches, preflight, verification and I/O buffers; no output-memory exclusion"}),
        extracted.files==files as u64+1 && extracted.logical_bytes==size+files as u64*512);
}

#[test]
#[ignore = "subprocess entry point used by the explicit qualification runner"]
fn sac1_child_open() {
    let Some(path) = std::env::var_os("SAC1_CHILD_FILE") else {
        return;
    };
    let started = Instant::now();
    let store = NativeStore::open(path, false).unwrap();
    let elapsed = started.elapsed().as_nanos();
    let io = store.physical_statistics();
    println!(
        "SAC1_CHILD_OPEN {}",
        json!({"elapsed_ns":elapsed,
        "read_operations":io.read_operations,"read_bytes":io.read_bytes,
        "bootstrap_bytes":io.bootstrap_bytes,"metadata_bytes":io.metadata_bytes,"object_bytes":io.object_bytes})
    );
}

#[test]
fn sac1_virtual_offsets_preserve_u64() {
    use sac::v1::{PositionalStore, Preamble, Reader, Trailer, encode_frame};
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    struct VirtualSource {
        length: u64,
        segments: BTreeMap<u64, Vec<u8>>,
        calls: Mutex<Vec<(u64, usize)>>,
    }
    impl ReadAt for VirtualSource {
        fn len(&self) -> sac::v1::Result<u64> {
            Ok(self.length)
        }
        fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> sac::v1::Result<()> {
            let end = offset
                .checked_add(output.len() as u64)
                .ok_or(sac::v1::Error::Limit("virtual offset"))?;
            if end > self.length {
                return Err(sac::v1::Error::Corrupt("virtual short read".into()));
            }
            self.calls.lock().unwrap().push((offset, output.len()));
            output.fill(0);
            for (&start, bytes) in self.segments.range(..end) {
                let from = start.max(offset);
                let to = (start + bytes.len() as u64).min(end);
                if from < to {
                    output[(from - offset) as usize..(to - offset) as usize]
                        .copy_from_slice(&bytes[(from - start) as usize..(to - start) as usize]);
                }
            }
            Ok(())
        }
    }
    fn relocate(
        store: &MemoryStore,
        reference: ObjectRef,
        delta: u64,
        segments: &mut BTreeMap<u64, Vec<u8>>,
    ) {
        let mut object = store.get(reference).unwrap();
        for child in &mut object.children {
            relocate(store, *child, delta, segments);
            child.address.offset += delta;
        }
        let frame = encode_frame(&object, 1).unwrap();
        assert_eq!(frame.len(), reference.address.length as usize);
        segments.insert(reference.address.offset + delta, frame);
    }
    let expected = b"exact offsets survive beyond JavaScript safe integers".to_vec();
    let (packed, _) = pack(&[("exact.bin".into(), expected.clone())], 1 << 20).unwrap();
    let original = packed.root().unwrap();
    for delta in [1u64 << 32, (1u64 << 53) + 8] {
        let mut segments = BTreeMap::new();
        segments.insert(0, Preamble::sealed().encode().to_vec());
        relocate(&packed, original.root, delta, &mut segments);
        let mut root = original.root;
        root.address.offset += delta;
        let length = packed.as_bytes().len() as u64 + delta;
        segments.insert(
            length - 160,
            Trailer {
                preamble_digest: Preamble::sealed().digest(),
                generation: 1,
                committed_end: length,
                commit: root,
            }
            .encode()
            .to_vec(),
        );
        let source = VirtualSource {
            length,
            segments,
            calls: Mutex::new(Vec::new()),
        };
        let reader = Reader::open_at(&source).unwrap();
        let calls = source.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].0, length - 65536);
        assert!(reader.snapshot().unwrap().address.offset >= delta);
        let store = PositionalStore::open(source).unwrap();
        let archive = ArchiveReader::open(
            &store,
            store.reader().snapshot().unwrap(),
            Limits::default(),
        )
        .unwrap();
        assert_eq!(
            archive
                .read_range(&path_from_str("exact.bin").unwrap(), 0, expected.len())
                .unwrap(),
            expected
        );
        // The virtual gap is intentionally not a conforming top-level record
        // inventory. This checks exact adapter offsets and content admission,
        // and makes no claim of full physical-layout verification.
    }
}

#[test]
#[ignore = "explicit production qualification; requires SAC1_QUALIFY_DIR and release build"]
#[allow(
    clippy::assertions_on_constants,
    reason = "ignored test must compile in debug and reject only when explicitly executed"
)]
fn sac1_production_qualification() {
    assert!(!cfg!(debug_assertions), "run qualification with --release");
    let mut results = Results::new();
    let full = std::env::var_os("SAC1_QUALIFY_FULL").is_some();
    environment(&mut results, full);
    let selected = |name: &str| {
        std::env::var("SAC1_QUALIFY_CASES")
            .map_or(true, |names| names.split(',').any(|s| s == name))
    };
    type Qualification = (&'static str, fn(&mut Results, bool));
    let groups: [Qualification; 10] = [
        ("tiny", |results, _| tiny(results)),
        ("small", small_files),
        ("bulk", bulk),
        ("compressed", compressed_bulk),
        ("native", native_publication),
        ("compaction", native_compaction),
        ("concurrent", concurrent::run),
        ("scale", file_scale),
        ("extract", extraction_memory),
        ("open", large_fresh_open),
    ];
    if let Ok(names) = std::env::var("SAC1_QUALIFY_CASES") {
        assert!(
            names
                .split(',')
                .all(|name| groups.iter().any(|(known, _)| name == *known)),
            "unknown SAC1_QUALIFY_CASES group: {names}"
        );
    }
    for (name, operation) in groups {
        if selected(name) {
            // A consumer failure remains in the report and fails qualification;
            // it must not erase already measured populations or hide later
            // independent groups behind an early panic.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                operation(&mut results, full)
            }));
            if let Err(error) = outcome {
                let message = error
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| error.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                    .unwrap_or_else(|| "non-string panic".into());
                results.record(
                    json!({"case":format!("{name}-consumer-failure"),"error":message,
                    "remaining_group_cases":"unmeasured after failure"}),
                    false,
                );
            }
        }
    }
    assert!(
        results.failures.is_empty(),
        "failed measured cases: {:?}",
        results.failures
    );
}
