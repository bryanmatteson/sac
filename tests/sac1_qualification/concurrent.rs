//! Fixed offered-load native interference control. An application command-path
//! comparison is a separate owning-consumer measurement, never inferred here.
use super::*;
use std::io::Read;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc,
};
use std::thread;
use std::time::Duration;

struct Generated(blake3::OutputReader);
impl std::io::Read for Generated {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.0.fill(bytes);
        Ok(bytes.len())
    }
}
enum Event {
    Analysis {
        ordinal: usize,
        offered: Instant,
        bytes: Vec<u8>,
    },
    Scalar {
        ordinal: usize,
        offered: Instant,
    },
}
struct Offered {
    analysis: AtomicU64,
    scalar: AtomicU64,
    dropped: AtomicU64,
    queued: AtomicU64,
    peak_queue: AtomicU64,
}
fn produce(
    tx: mpsc::SyncSender<Event>,
    offered: Arc<Offered>,
    stop: Arc<AtomicBool>,
    start: Instant,
    maximum: Duration,
    mut dropped_log: File,
) -> Duration {
    let mut analysis = 0usize;
    let mut scalar = 0usize;
    loop {
        let analysis_at = Duration::from_millis(100 * analysis as u64);
        let scalar_at = Duration::from_millis(60 * scalar as u64);
        let (deadline, is_analysis) = if analysis_at <= scalar_at {
            (analysis_at, true)
        } else {
            (scalar_at, false)
        };
        if deadline >= maximum || stop.load(Ordering::Acquire) {
            break;
        }
        let at = start + deadline;
        if let Some(wait) = at.checked_duration_since(Instant::now()) {
            thread::sleep(wait);
        }
        let event = if is_analysis {
            offered.analysis.fetch_add(1, Ordering::Relaxed);
            let bytes = Content::Incompressible.bytes(0x6000 + analysis, 1 << 20);
            let event = Event::Analysis {
                ordinal: analysis,
                offered: at,
                bytes,
            };
            analysis += 1;
            event
        } else {
            offered.scalar.fetch_add(1, Ordering::Relaxed);
            let event = Event::Scalar {
                ordinal: scalar,
                offered: at,
            };
            scalar += 1;
            event
        };
        let queued = offered.queued.fetch_add(1, Ordering::Relaxed) + 1;
        offered.peak_queue.fetch_max(queued, Ordering::Relaxed);
        match tx.try_send(event) {
            Ok(()) => {}
            Err(error) => {
                offered.queued.fetch_sub(1, Ordering::Relaxed);
                offered.dropped.fetch_add(1, Ordering::Relaxed);
                writeln!(
                    dropped_log,
                    "{},{},{},{}",
                    deadline.as_nanos(),
                    start.elapsed().as_nanos(),
                    if is_analysis { "analysis" } else { "scalar" },
                    queued
                )
                .unwrap();
                if matches!(error, mpsc::TrySendError::Disconnected(_)) {
                    break;
                }
            }
        }
    }
    start.elapsed()
}
fn check_head(
    store: &impl ObjectStore,
    snapshot: ObjectRef,
    latest_analysis: Option<usize>,
    latest_scalar: Option<usize>,
    retained_bytes: u64,
    tail: &[u8],
) {
    let archive = ArchiveReader::open(store, snapshot, Limits::default()).unwrap();
    assert_eq!(
        archive
            .read_range(
                &path_from_str("captured.bin").unwrap(),
                retained_bytes - tail.len() as u64,
                tail.len()
            )
            .unwrap(),
        tail
    );
    if let Some(ordinal) = latest_analysis {
        assert_eq!(
            archive
                .read_range(&path_from_str("analysis.bin").unwrap(), 0, 64)
                .unwrap(),
            Content::Incompressible.bytes(0x6000 + ordinal, 1 << 20)[..64]
        );
    }
    if let Some(ordinal) = latest_scalar {
        assert_eq!(
            archive
                .read_range(
                    &path_from_str("scalar.txt").unwrap(),
                    0,
                    format!("scalar-{ordinal:08}").len()
                )
                .unwrap(),
            format!("scalar-{ordinal:08}").as_bytes()
        );
    }
}

fn temporary(statistics: sac::v1::native::TemporaryIoStatistics) -> Value {
    json!({"reserved_bytes":statistics.reserved_bytes,"peak_reserved_bytes":statistics.peak_reserved_bytes,"read_bytes":statistics.read_bytes,"write_bytes":statistics.write_bytes})
}
fn scratch_peak(statistics: &sac::v1::native::CompactionStatistics) -> u64 {
    statistics.copier_temporary.peak_reserved_bytes
        + statistics.validation_temporary.peak_reserved_bytes
        + statistics.retention_temporary.peak_reserved_bytes
        + statistics.target_index_temporary.peak_reserved_bytes
        + statistics.layout_temporary.peak_reserved_bytes
}

pub(super) fn run(results: &mut Results, full: bool) {
    let duration = Duration::from_secs(if full { 600 } else { 12 });
    let retained_bytes: u64 = std::env::var("SAC1_QUALIFY_RETAINED_BYTES")
        .ok()
        .map(|value| value.parse().unwrap())
        .unwrap_or(if full { 1 << 30 } else { 16 << 20 });
    let target_cutovers = if full { 100 } else { 2 };
    let maximum_duration = Duration::from_secs(if full { 3600 } else { 120 });
    let path = results.output.join("native-concurrent.sac");
    let mut store = NativeStore::create(&path, Header::new([0x91; 16], [0x92; 16])).unwrap();
    store.set_decoded_cache_budget(8 << 20);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sac1-concurrent-retained-fixed-v1");
    let mut generated = Generated(hasher.finalize_xof());
    let snapshot = {
        let mut builder = ArchiveBuilder::new(&mut store);
        builder.set_chunk_size(1 << 20).unwrap();
        builder
            .add_reader(
                &path_from_str("captured.bin").unwrap(),
                (&mut generated).take(retained_bytes),
            )
            .unwrap();
        builder.finish().unwrap()
    };
    store.publish(snapshot).unwrap();
    let matched_compact_bytes = store.file_len();
    let mut tail = vec![0; 65536];
    let mut xof = hasher.finalize_xof();
    xof.set_position(retained_bytes - tail.len() as u64);
    xof.fill(&mut tail);
    let before_garbage = store.file_len();
    for ordinal in 0..retained_bytes / (2 << 20) {
        store
            .put(
                7,
                1,
                &Content::Incompressible.bytes(0x5000 + ordinal as usize, 1 << 20),
                &[],
            )
            .unwrap();
    }
    let garbage_bytes = store.file_len() - before_garbage;
    let directory = store.get(snapshot).unwrap().children[0];
    let snapshot = {
        let mut builder = ArchiveBuilder::from_directory(&mut store, directory, Limits::default());
        builder
            .add_file(&path_from_str("scalar.txt").unwrap(), b"initial")
            .unwrap();
        builder.finish().unwrap()
    };
    store.publish(snapshot).unwrap();
    let old_physical = store.file_len();
    let (tx, rx) = mpsc::sync_channel(8);
    let offered = Arc::new(Offered {
        analysis: AtomicU64::new(0),
        scalar: AtomicU64::new(0),
        dropped: AtomicU64::new(0),
        queued: AtomicU64::new(0),
        peak_queue: AtomicU64::new(0),
    });
    let started = Instant::now();
    let stop = Arc::new(AtomicBool::new(false));
    let mut dropped_log = File::create(results.output.join("concurrent-dropped.csv")).unwrap();
    writeln!(dropped_log, "offered_ns,observed_ns,kind,queue_depth").unwrap();
    let mut activity = File::create(results.output.join("concurrent-activity.csv")).unwrap();
    writeln!(
        activity,
        "stage,start_ns,end_ns,offered_ns,queue_depth,dropped"
    )
    .unwrap();
    let latest_pin = Arc::new(Mutex::new(None));
    let (observer_stop, observer_rx) = mpsc::channel();
    let mut host_log = File::create(results.output.join("concurrent-host.jsonl")).unwrap();
    let observer = thread::spawn(move || {
        while observer_rx.recv_timeout(Duration::from_secs(10)).is_err() {
            let sample_started = Instant::now();
            let host = host_load();
            writeln!(host_log,"{}",json!({"started_ns":sample_started.duration_since(started).as_nanos(),"finished_ns":started.elapsed().as_nanos(),"host":host})).unwrap();
        }
    });
    let stop_on_drop = std::env::var_os("SAC1_QUALIFY_STOP_ON_DROPPED").is_some();
    let producer = {
        let offered = offered.clone();
        let stop = stop.clone();
        thread::spawn(move || produce(tx, offered, stop, started, maximum_duration, dropped_log))
    };
    let mut worker: Option<thread::JoinHandle<(sac::v1::native::Compaction, Result<(), String>)>> =
        None;
    let mut next_copy = started;
    let mut attempts = 0u64;
    let mut cutovers = 0u64;
    let mut aborts = Vec::new();
    let mut pauses = Vec::new();
    let mut successful_pauses = Vec::new();
    let mut aborted_pauses = Vec::new();
    let mut analysis_times = Vec::new();
    let mut scalar_times = Vec::new();
    let mut scalar_service = Vec::new();
    let mut latest_analysis = None;
    let mut latest_scalar = None;
    let mut source_appends = 0u64;
    let mut replacement_catch_up = 0u64;
    let mut peak_named_disk = old_physical;
    let mut candidate_archive_upper = old_physical;
    let mut aggregate_disk_upper = old_physical;
    let mut peak_scratch_bytes = 0u64;
    let mut source_index_peak_bytes = store.temporary_statistics().peak_reserved_bytes;
    let mut source_index_write_bytes = 0u64;
    let mut checkpoints = Vec::new();
    let mut disconnected = false;
    let mut next_progress = Duration::from_secs(10);
    loop {
        if worker
            .as_ref()
            .is_some_and(|worker: &thread::JoinHandle<_>| worker.is_finished())
        {
            let (job, copied) = worker.take().unwrap().join().unwrap();
            latest_pin.lock().unwrap().take();
            peak_scratch_bytes = peak_scratch_bytes.max(scratch_peak(job.statistics()));
            aggregate_disk_upper = aggregate_disk_upper
                .max(store.file_len() + job.statistics().peak_aggregate_temporary_bytes);
            candidate_archive_upper = candidate_archive_upper
                .max(store.file_len() + job.candidate_file_bytes().unwrap() + (16 << 20));
            match copied {
                Err(error) => aborts.push(
                    json!({"stage":"copy","error":error,"elapsed_ns":started.elapsed().as_nanos()}),
                ),
                Ok(()) => {
                    let old = store.pin().unwrap();
                    let logical = store.root().unwrap().root.hash;
                    let source_extent = store.file_len();
                    let publication_before = store.publication_statistics();
                    let pause = Instant::now();
                    let result = store.finish_compaction(job);
                    let elapsed = pause.elapsed().as_nanos() as u64;
                    writeln!(
                        activity,
                        "fence,{},{},0,{},{}",
                        pause.duration_since(started).as_nanos(),
                        started.elapsed().as_nanos(),
                        offered.queued.load(Ordering::Relaxed),
                        offered.dropped.load(Ordering::Relaxed)
                    )
                    .unwrap();
                    pauses.push(elapsed);
                    let stats = store.last_compaction_attempt_statistics().unwrap().clone();
                    aggregate_disk_upper = aggregate_disk_upper
                        .max(source_extent + stats.peak_aggregate_temporary_bytes);
                    replacement_catch_up += stats.catch_up_total_write_bytes;
                    peak_scratch_bytes = peak_scratch_bytes.max(scratch_peak(&stats));
                    results.record(json!({"case":"native-concurrent-fence","scope":"core-diagnostic","at_ns":pause.duration_since(started).as_nanos(),"external_pause_ns":elapsed,"internal_pause_ns":stats.pause_ns,"candidate_elapsed_ns":stats.elapsed_ns,"installed":result.is_ok(),"error":result.as_ref().err().map(ToString::to_string),"catch_up_total_write_bytes":stats.catch_up_total_write_bytes,"aggregate_peak_temporary_bytes":stats.peak_aggregate_temporary_bytes}),true);
                    let validation_started = Instant::now();
                    match result {
                        Err(error) => {
                            aborted_pauses.push(elapsed);
                            assert_eq!(
                                logical,
                                store.root().unwrap().root.hash,
                                "aborted candidate changed acknowledged head"
                            );
                            check_head(
                                &store,
                                store.reader().snapshot().unwrap(),
                                latest_analysis,
                                latest_scalar,
                                retained_bytes,
                                &tail,
                            );
                            aborts.push(json!({"stage":"cutover","error":error.to_string(),"elapsed_ns":elapsed,"candidate_elapsed_ns":stats.elapsed_ns,"catch_up_total_write_bytes":stats.catch_up_total_write_bytes,"aggregate_peak_temporary_bytes":stats.peak_aggregate_temporary_bytes}));
                        }
                        Ok(()) => {
                            successful_pauses.push(elapsed);
                            cutovers += 1;
                            assert_eq!(
                                logical,
                                store.root().unwrap().root.hash,
                                "acknowledged current publication lost"
                            );
                            check_head(
                                &old,
                                old.reader().snapshot().unwrap(),
                                latest_analysis,
                                latest_scalar,
                                retained_bytes,
                                &tail,
                            );
                            check_head(
                                &store,
                                store.reader().snapshot().unwrap(),
                                latest_analysis,
                                latest_scalar,
                                retained_bytes,
                                &tail,
                            );
                            peak_named_disk = peak_named_disk
                                .max(store.file_len() + old.reader().committed_end());
                            let publication_after = store.publication_statistics();

                            checkpoints.push(json!({"cutover":cutovers,"at_ns":started.elapsed().as_nanos(),"copied_bytes":stats.copied_bytes,
                                "catch_up_bytes":stats.catch_up_bytes,"catch_up_index_write_bytes":stats.catch_up_index_write_bytes,"catch_up_slot_write_bytes":stats.catch_up_slot_write_bytes,"catch_up_total_write_bytes":stats.catch_up_total_write_bytes,
                                "copier_temporary":temporary(stats.copier_temporary),"validation_temporary":temporary(stats.validation_temporary),"retention_temporary":temporary(stats.retention_temporary),"target_index_temporary":temporary(stats.target_index_temporary),"residual_garbage_bytes":stats.residual_garbage_bytes,
                                "pause_ns":stats.pause_ns,"elapsed_ns":stats.elapsed_ns,"aggregate_peak_temporary_bytes":stats.peak_aggregate_temporary_bytes,
                                "chunks_barrier_ns":publication_after.compaction_chunk_barrier_total_ns-publication_before.compaction_chunk_barrier_total_ns,"slot_barrier_ns":publication_after.compaction_slot_sync_total_ns-publication_before.compaction_slot_sync_total_ns,"old_pin_bytes":old.reader().committed_end(),
                                "cleanup":format!("{:?}",store.compaction_cleanup_statistics()),"installed_bytes":store.file_len(),"commit_id":hex::encode(logical.0),"acknowledged_analysis_ordinal":latest_analysis,"acknowledged_scalar_ordinal":latest_scalar}));
                        }
                    }
                    writeln!(
                        activity,
                        "head_checks,{},{},0,{},{}",
                        validation_started.duration_since(started).as_nanos(),
                        started.elapsed().as_nanos(),
                        offered.queued.load(Ordering::Relaxed),
                        offered.dropped.load(Ordering::Relaxed)
                    )
                    .unwrap();
                }
            }
        }
        if worker.is_none()
            && Instant::now() >= next_copy
            && started.elapsed() < maximum_duration
            && cutovers < target_cutovers
            && !stop.load(Ordering::Acquire)
        {
            attempts += 1;
            next_copy = Instant::now() + Duration::from_secs(5);
            let begin_started = Instant::now();
            match store.begin_compaction() {
                Err(error) => aborts.push(json!({"stage":"begin","error":error.to_string()})),
                Ok(mut job) => {
                    *latest_pin.lock().unwrap() = Some(store.pin().unwrap());
                    let latest_pin = latest_pin.clone();
                    worker = Some(thread::spawn(move || {
                        let result = sac::v1::native::with_maintenance_read_accounting(|| {
                            job.copy()?;
                            loop {
                                let pin = latest_pin.lock().unwrap().take();
                                let Some(pin) = pin else {
                                    break;
                                };
                                job.refresh_cancellable(&pin, || false)?;
                            }
                            Ok(())
                        })
                        .map_err(|error: sac::v1::Error| error.to_string());
                        (job, result)
                    }));
                }
            }
            writeln!(
                activity,
                "begin,{},{},0,{},{}",
                begin_started.duration_since(started).as_nanos(),
                started.elapsed().as_nanos(),
                offered.queued.load(Ordering::Relaxed),
                offered.dropped.load(Ordering::Relaxed)
            )
            .unwrap();
        }
        match rx.recv_timeout(Duration::from_millis(2)) {
            Ok(event) => {
                offered.queued.fetch_sub(1, Ordering::Relaxed);
                let operation_started = Instant::now();
                let (kind, event_offered) = match &event {
                    Event::Analysis { offered, .. } => ("analysis", *offered),
                    Event::Scalar { offered, .. } => ("scalar", *offered),
                };
                let before = store.file_len();
                let index_before = store.temporary_statistics().write_bytes;
                let snapshot = store.reader().snapshot().unwrap();
                let directory = store.get(snapshot).unwrap().children[0];
                let snapshot = {
                    let mut builder =
                        ArchiveBuilder::from_directory(&mut store, directory, Limits::default());
                    match &event {
                        Event::Analysis { bytes, .. } => builder
                            .set_file(
                                &path_from_str("analysis.bin").unwrap(),
                                bytes,
                                sac::v1::cbor::Value::Map(vec![]),
                            )
                            .unwrap(),
                        Event::Scalar { ordinal, .. } => builder
                            .set_file(
                                &path_from_str("scalar.txt").unwrap(),
                                format!("scalar-{ordinal:08}").as_bytes(),
                                sac::v1::cbor::Value::Map(vec![]),
                            )
                            .unwrap(),
                    }
                    builder.finish().unwrap()
                };
                store.publish(snapshot).unwrap();
                if worker.is_some() {
                    *latest_pin.lock().unwrap() = Some(store.pin().unwrap());
                }
                source_appends += store.file_len() - before;
                let index_after = store.temporary_statistics();
                source_index_write_bytes += index_after.write_bytes - index_before;
                source_index_peak_bytes =
                    source_index_peak_bytes.max(index_after.peak_reserved_bytes);
                writeln!(
                    activity,
                    "{},{},{},{},{},{}",
                    kind,
                    operation_started.duration_since(started).as_nanos(),
                    started.elapsed().as_nanos(),
                    event_offered.duration_since(started).as_nanos(),
                    offered.queued.load(Ordering::Relaxed),
                    offered.dropped.load(Ordering::Relaxed)
                )
                .unwrap();
                match event {
                    Event::Analysis {
                        ordinal, offered, ..
                    } => {
                        latest_analysis = Some(ordinal);
                        analysis_times.push(offered.elapsed().as_nanos() as u64);
                    }
                    Event::Scalar { ordinal, offered } => {
                        latest_scalar = Some(ordinal);
                        scalar_times.push(offered.elapsed().as_nanos() as u64);
                        scalar_service.push(operation_started.elapsed().as_nanos() as u64);
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                disconnected = true;
                thread::sleep(Duration::from_millis(2));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        let mut inodes = std::collections::BTreeSet::new();
        let named = fs::read_dir(&results.output)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !name.starts_with("native-concurrent.") && !name.starts_with(".sac1-create-") {
                    return None;
                }
                let metadata = entry.metadata().ok()?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if !inodes.insert((metadata.dev(), metadata.ino())) {
                        return None;
                    }
                }
                Some(metadata.len())
            })
            .sum();
        peak_named_disk = peak_named_disk.max(named);
        if started.elapsed() >= next_progress {
            results.record(json!({"case":"native-concurrent-progress","scope":"core-diagnostic","elapsed_ns":started.elapsed().as_nanos(),
                "completed_analysis":analysis_times.len(),"completed_scalar":scalar_times.len(),"successful_cutovers":cutovers,
                "offered_analysis":offered.analysis.load(Ordering::Relaxed),"dropped":offered.dropped.load(Ordering::Relaxed),
                "queue_depth":offered.queued.load(Ordering::Relaxed),"host_observer":"concurrent-host.jsonl"}), true);
            next_progress += Duration::from_secs(10);
        }
        if stop_on_drop && offered.dropped.load(Ordering::Relaxed) > 0 {
            stop.store(true, Ordering::Release);
        }
        if cutovers >= target_cutovers && started.elapsed() >= duration {
            stop.store(true, Ordering::Release);
        }
        if disconnected && worker.is_none() {
            break;
        }
    }
    let offered_duration = producer.join().unwrap();
    observer_stop.send(()).unwrap();
    observer.join().unwrap();
    latest_pin.lock().unwrap().take();
    check_head(
        &store,
        store.reader().snapshot().unwrap(),
        latest_analysis,
        latest_scalar,
        retained_bytes,
        &tail,
    );
    let elapsed = started.elapsed();
    let expected_analysis = offered.analysis.load(Ordering::Relaxed) as usize;
    let expected_scalar = offered.scalar.load(Ordering::Relaxed) as usize;
    let pauses_dist = if pauses.is_empty() {
        Value::Null
    } else {
        distribution(&pauses)
    };
    let conservative_peak_disk_upper = (candidate_archive_upper.max(peak_named_disk)
        + peak_scratch_bytes)
        .max(aggregate_disk_upper)
        + source_index_peak_bytes;
    let strict_base_capacity =
        old_physical + matched_compact_bytes + (old_physical + matched_compact_bytes) / 10;
    let capacity_reference = old_physical
        + matched_compact_bytes
        + (old_physical + matched_compact_bytes) / 10
        + source_appends
        + replacement_catch_up;
    let load_met = analysis_times.len() == expected_analysis
        && scalar_times.len() == expected_scalar
        && offered.dropped.load(Ordering::Relaxed) == 0
        && analysis_times.len() as f64 * (1 << 20) as f64 / offered_duration.as_secs_f64()
            >= (8 << 20) as f64;
    let completed = cutovers >= target_cutovers
        && offered_duration >= duration
        && (!full || retained_bytes >= (1 << 30))
        && checkpoints
            .iter()
            .all(|checkpoint| checkpoint["elapsed_ns"].as_u64().unwrap() <= 120_000_000_000);
    let capacity_accounting_complete = true;
    let capacity_met =
        capacity_accounting_complete && conservative_peak_disk_upper <= capacity_reference;
    let pause_met = pauses_dist["p95_ns"]
        .as_u64()
        .is_some_and(|n| n <= 25_000_000)
        && pauses_dist["p99_ns"]
            .as_u64()
            .is_some_and(|n| n <= 100_000_000);
    let mut report = json!({"case":"native-concurrent-compaction","scope":"core-diagnostic",
        "note":"actual native fixed offered load and scalar durable edits; does not qualify an application's command path or semantic projection",
        "stop_on_dropped_diagnostic":stop_on_drop,"compaction_consumer":"ordinary background copy+latest immutable pin refresh before bounded finish","host_observation":"separate worker; concurrent-host.jsonl","minimum_offered_duration_ns":duration.as_nanos(),"maximum_offered_duration_ns":maximum_duration.as_nanos(),"offered_duration_ns":offered_duration.as_nanos(),"actual_elapsed_ns":elapsed.as_nanos(),"retained_input_bytes":retained_bytes,
        "initial_unreachable_payload_frame_bytes":garbage_bytes,"old_physical_bytes":old_physical,"matched_compact_bytes":matched_compact_bytes,
        "analysis_publications_offered":offered.analysis.load(Ordering::Relaxed),"analysis_publications_completed":analysis_times.len(),
        "unique_analysis_bytes":analysis_times.len() as u64 * (1<<20),"unique_analysis_bytes_per_offered_second":analysis_times.len() as f64 * (1<<20) as f64/offered_duration.as_secs_f64(),
        "scalar_edits_offered":offered.scalar.load(Ordering::Relaxed),"scalar_edits_completed":scalar_times.len(),
        "dropped_events":offered.dropped.load(Ordering::Relaxed),"peak_queue_depth":offered.peak_queue.load(Ordering::Relaxed),
        "successful_cutovers":cutovers,"attempts":attempts,"aborted_fences":aborts,"cutovers":checkpoints,
        "pause_timing":pauses_dist,"pause_population":"every attempted foreground cutover fence, successful or aborted","total_pause_ns":pauses.iter().sum::<u64>(),
        "analysis_enqueue_to_durable":distribution(&analysis_times),"scalar_enqueue_to_durable":distribution(&scalar_times),"scalar_service":distribution(&scalar_service),
        "physical_reads":format!("{:?}",store.physical_statistics()),"cache_usage":format!("{:?}",store.cache_usage()),
        "meets_offered_load":load_met,"meets_cutover_population_deadline":completed,"meets_pause_targets":pause_met});
    report.as_object_mut().unwrap().extend(json!({
        "successful_cutover_pause_timing":if successful_pauses.is_empty() {Value::Null} else {distribution(&successful_pauses)},"aborted_fence_pause_timing":if aborted_pauses.is_empty(){Value::Null}else {distribution(&aborted_pauses)},
        "aggregate_reservation_disk_upper_bytes":aggregate_disk_upper,"actual_physical_source_appends":source_appends,"actual_source_index_write_bytes":source_index_write_bytes,"source_index_peak_reserved_bytes":source_index_peak_bytes,"all_candidate_scratch_peak_upper_bytes":peak_scratch_bytes,"actual_replacement_catch_up_writes":replacement_catch_up,
        "peak_named_archive_disk_bytes":peak_named_disk,"all_candidate_archive_upper_bytes":candidate_archive_upper,"conservative_peak_total_disk_upper_bytes":conservative_peak_disk_upper,
        "strict_base_only_capacity_bytes":strict_base_capacity,"meets_stronger_base_only_capacity":conservative_peak_disk_upper<=strict_base_capacity,"capacity_reference_bytes":capacity_reference,"capacity_accounting_complete":capacity_accounting_complete,"meets_capacity_target":capacity_met,
        "disk_accounting_note":"upper bound sums per-candidate monotonic source and replacement extents with full 16 MiB catch-up allowance, plus source-index peak and sum of measured independent scratch reservation peaks (including overlapping resize allocations); no layout plan/sort files in this fixture; shared aggregate reservations cover failed and successful candidates; every fence attempt reports append, slot and index writes; failed attempts remain in the pause population"
    }).as_object().unwrap().clone());
    results.record(report, load_met && completed && pause_met && capacity_met);
}
