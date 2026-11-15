# Durable memtable comparison

Build the uninstrumented release consumer and run it directly through the paired
runner on macOS:

```sh
cargo +1.97.1 build --locked --release --manifest-path tools/performance/Cargo.toml --bin memtable_bench
python3 tools/performance/run_memtable_comparison.py \
  --binary tools/performance/target/release/memtable_bench \
  --output "$HOME/Documents/Developer/sac/memtable-comparison" \
  --repeats 3
```

Use a fresh output directory. `--smoke --repeats 1` exercises every backend and
measurement phase with 512 updates. The runner performs sequential fresh-process
runs, rotates backend order between repetitions, writes raw per-run JSON and
`/usr/bin/time -lp` output, and records hardware, load, compiler, executable hash
and checkout state. `summary.json` reports median, minimum and maximum of the
per-run measurements; a median p99 is the median of per-run p99s, not a pooled
percentile. The logical contents are checked after reopening every case, including
full native validation and archive commit verification. Corresponding backends
must finish with identical logical content checksums.

## Workloads and durability

All backends start from a copy of the same published image and receive the same
prepared 8-byte keys and deterministic, relatively incompressible values. Three
workloads cover 8,192 updates on 1,024 keys with 128-byte values, 8,192 updates on
8,192 keys with 128-byte values, and 4,096 updates on 2,048 keys with 1,024-byte
values. Updates cycle a permutation of all keys except key zero, reserved for
concurrent read probes. The hot workload allows substantial overwrite coalescing;
the wide 128-byte workload mostly visits distinct keys. Inputs, paths and mutation
slices are prepared outside timing. Both use the native defaults, including
compression level 1, on the same filesystem.

Timing runs compare batches of one and 64 mutations:

- **Direct durable:** public `ArchiveBuilder::set_file` calls followed by one
  `NativeStore::publish` per batch. The return acknowledges a published SAC root
  and its durability barriers.
- **Direct deferred:** the same SAC updates and builder snapshots, with publication
  deferred until each 4,096 updates and the end. This measures direct edit cost
  with a weaker acknowledgment guarantee: accepted updates can be lost on a crash
  before publication.
- **Memtable 16 MiB / 1 MiB:** public `MemtableStore::write_batch`, which syncs its
  WAL before acknowledging each batch. Explicit checkpoints occur after each
  4,096 updates and at the end, in addition to actual memory-pressure checkpoints.
  The small budget exercises pressure and backpressure. Timer flushing is disabled
  for this controlled phase by setting its interval to one hour.

Write throughput includes all writes, capacity backpressure/pressure flushes, the controlled
checkpoints and the final flush. Its CPU measurement covers the same interval.
Latency distributions measure individual batch calls; a 64-record call is not
reported as a single-record latency. Prepared input memory is present equally in
all modes and excluded from the timed loop.

## Read latency and checkpoint stalls

After throughput measurement, the harness stages 256 changes and 64 deletions.
It verifies and warms each read class before collecting 4,096 individually timed
owned-value reads: 128 overlay hits, 128 unchanged/base hits and 64 tombstone
misses. The native baseline reads its corresponding staged snapshot. The timer
is disabled, and the data fits both overlay limits. These are warm-cache API
latencies, including result allocation, without concurrent writers. They do not
represent cold storage reads or application network latency.

Each timing run then stages 512 dirty keys and measures four explicit checkpoints
with a concurrent reader fetching the unchanged sentinel every roughly 50 µs.
The report records checkpoint wall and process CPU time and reader calls whose
start/end interval overlaps that checkpoint. Scheduling can miss a very short
checkpoint, in which case its overlapping-read distribution is null. The observed
maximum is an observed read delay, not a guaranteed upper bound. The direct
baseline serializes access through a mutex. The current memtable worker owns SAC
checkpoint I/O independently: reads check active/immutable overlays and use a
pinned native reader for base hits, while writes append/sync the successor WAL. Native direct writes already materialized their directory edits,
so their checkpoint measures publication; a memtable checkpoint additionally
materializes coalesced directory edits and retires the WAL. Compare total durable
throughput together with these pauses, because the work occurs at different times.

A separate fresh-process phase enables the real 100 ms timer, writes 256 mutations
in four durable batches, and waits for the background worker to publish them,
without calling `flush`. These changes fit either memory budget. It records time
from the first write's start through observed publication and reader latency while
the worker runs. This observation includes WAL acknowledgment, timer scheduling,
checkpoint execution and up to approximately 1 ms of polling delay; it is not a
precise timer wake-up measurement.

## Memory and CPU interpretation

Memory uses a separate process for each backend and workload, with batches of 64,
no count-based explicit checkpoint, and a one-hour timer. It records current RSS
via `ps` after opening/warming, after all dirty writes, and after a final flush.
Pressure checkpoints remain enabled. Compare dirty RSS and its increase from the
open baseline. The memtable's conservative combined active/immutable accounting and WAL size
are recorded separately. Its configured memory limit bounds this accounting, not
the entire process: native caches, prepared inputs, allocator retention, codec
scratch, mapped pages and transient checkpoint buffers also consume memory.
Direct deferred is the memory baseline; its dirty staging behavior is the same
as the durable direct writer apart from publication bookkeeping.

`/usr/bin/time -lp` reports whole-process user CPU, system CPU and peak RSS,
including open, input preparation, read/probe phases, child `ps` calls and final
verification. These whole-process counters must not be confused with the Rust
write/checkpoint CPU intervals. Peak RSS can occur during verification and is not
an exact overlay heap measurement. No allocator instrumentation is enabled during
timing. Host load is recorded before and after every run; filesystem durability
latency and busy-host scheduling can dominate wall time even with little CPU.

The benchmark verifies data preservation in normal execution. Crash recovery and
WAL corruption behavior are exercised separately by `tests/sac1_memtable.rs` and
the native memtable unit tests; timing results alone do not establish crash safety.


## Immutable checkpoint comparison

Retain the old executable before rebuilding. `--baseline-binary` pairs old and
new memtables on fixtures created by the baseline executable; v1 fixtures are
recovered/upgraded before timing when needed. Alternating order and the two
binary hashes are recorded. To reproduce a shorter checkpoint/read comparison:

```sh
python3 tools/performance/run_memtable_comparison.py \
  --binary /path/to/memtable-after --baseline-binary /path/to/memtable-before \
  --memtable-only --phases timing --workloads wide-128 --batches 64 --updates 512 \
  --output "$HOME/Documents/Developer/sac/memtable-paired" --repeats 3
```

For the original full workloads with only memtable modes, use `--memtable-only`
without update/workload overrides. The retained historical direct and memtable
measurements can then be compared with the new run; account for changed host
load, and use the paired runs to assess checkpoint interference on the same host.

For a paired throughput regression comparison, retain both binaries and use
`--baseline-binary /path/to/before --memtable-only --phases timing --batches 64
--repeats 5` without `--updates` or workload overrides. This exercises the complete
hot working set and the small-budget pressure cycles. Compare checkpoint counts,
SAC append bytes, write CPU and call tails alongside throughput. A capacity wait
during an immutable checkpoint now reassesses admission after that retirement,
without automatically requesting a second checkpoint through newer active writes.

`--phases contention --memtable-only` adds a foreground-write progress probe.
It stages 128 dirty keys, starts a flush on a separate caller, waits until an
immutable generation is actually in progress, and runs durable 64-record batches
while a sentinel reader continues. It reports batches acknowledged before that
checkpoint completes, batch latencies, overlapping read latencies, and observed
combined pending memory. The probe leaves budget headroom even for 1 KiB values
under the 1 MiB limit; capacity exhaustion is tested separately. Every final key
is checked against expected values, but the number of completed batches is timing
dependent, so cross-run final-content checksums need not match in this phase.

The worker proactively freezes an active table at seven-eighths of the aggregate
memory budget to preserve hot-set coalescing while reserving headroom. Admission
still bounds active + immutable + incoming memory; large batches can exhaust
that headroom and wait. The earlier half-budget trigger could start a 1 MiB /
1 KiB checkpoint before all 512 keys in the original checkpoint probe had been
staged. The current 512-key probes fit below the proactive threshold for both
budgets and value sizes. Inspect recorded pre-flush residency when comparing
older runs of the 1 MiB / 1 KiB case.

The empty successor WAL is now prepared during the dirty interval. Checkpoint
elapsed time includes any unfinished preparation, SAC publication, WAL promotion and
resource retirement; the explicit `flush` caller still waits for its target.
Foreground read/write delay during that interval is the interference metric.
WAL acknowledgment still requires full synchronization, and writers must wait
when the combined table or retained-record budgets have no admission capacity.

## Storage contention isolation

`--phases attribution --memtable-only` runs the initial write workload and final
checkpoint with a bounded per-batch timeline, then reopens and verifies all keys.
It omits subsequent read/probe phases. Each batch records cumulative
`statistics().io`; the extra statistics sampling is diagnostic overhead, so use
`timing` for throughput comparisons. Subtract `write.statistics_before` when
examining native publication counters, which may include work during open.
Worker stage times overlap foreground WAL times and cannot be added together.

On macOS, the focused storage experiment accepts prebuilt executables:

```sh
python3 tools/performance/run_memtable_storage_isolation.py \
  --binary original=/absolute/path/to/previous/memtable_bench \
  --binary candidate=/absolute/path/to/current/memtable_bench \
  --output "$HOME/Documents/Developer/sac/storage-isolation" --repeats 5
```

It rotates variant and condition order for wide-1024, 4,096 updates, batches of
64 and a 16 MiB overlay budget. Every consumer uses real WAL `F_FULLFSYNC`
acknowledgements and verifies reopened state. Conditions use no injected load
or two concurrent same-volume durable writers, each limited to an 8 MiB ring
file. Independent, similarly sized write/full-sync controls run before/after
each consumer, with `iostat` and host load recorded. No injected load does not
mean the shared host or device is idle. Two conditioning sequences also test
whether the original preceding single-record/1 MiB workload changes the result.
Variant binaries must have distinct SHA-256 hashes; the runner rejects duplicate
executables before starting any work. Locate build outputs through Cargo metadata
when using a source snapshot, because the managed build wrapper can select its
own target directory. Raw logs, binary hashes and bounded batch traces are
retained; task-owned
scratch files are removed after processes and load threads finish.

## Bounded scatter/gather WAL writes

The Unix WAL encoder gathers up to 64 mutations. A fixed 4 KiB framing buffer
packs prefixes, keys that fit and small values (up to 256 bytes), reserving
space for every prefix/key before packing values. Other payloads are borrowed;
long keys retain 64-entry groups. The framing and descriptor arrays total
7,200 bytes on a 64-bit host, below the existing 8 KiB output scratch ceiling.
Adjacent packed entries share a slice. For 64 entries with 8-byte keys, this
reduces 194 slices to 88 with 128-byte values or 130 with 1 KiB values.
The wide-1024 batch of 64 encodes 66,976 bytes: the previous 8 KiB buffered
encoder made ten file writes,
while the gather encoder needs one when the OS accepts the whole vector. Large
batches stream across groups, and partial writes, limited vector acceptance and
interruptions are retried before the unchanged full WAL synchronization. The
non-Unix path retains the previous 8 KiB buffering.

For a matched comparison, build baseline and candidate from one captured source
cohort, pin each executable from the `target_directory` returned by Cargo
metadata, and pass both to `run_memtable_storage_isolation.py`. The runner rotates
start position and reverses direction after a full variant cycle, so two-variant
runs also alternate which executable runs first. Use `--conditioning-repeats 0`
when measuring this file-write change without repeating workload-order diagnosis.
`--load-workers 0` runs only the no-injection condition and traces, useful for a
longer paired follow-up; it does not establish that the shared device is idle.
Compare `wal_prepare_total_ns` as well as `wal_sync_total_ns`: fewer file-write
calls can reduce framing/file-write stalls while durable full-sync cost remains.

Both comparison runners accept `--scratch-directory /existing/directory` to
place their private fixtures, containers, WALs and load ring files on the device
under test while retaining logs in `--output`. The default uses the output
device. Storage isolation monitors up to 16 drives so external devices are
included. Use independent full-sync controls and device I/O observations before
calling a run uncontended; `--load-workers 0` only disables injected load.
