# SAC1 production qualification

`tests/sac1_qualification.rs` measures actual resource builders, sealed writers,
archive readers, native durable publications, and native file admission. It is
an explicitly invoked release-build integration test. It does not treat generated
inventories or the existence of a code path as performance evidence.

Run with the pinned toolchain and a new caller-owned artifact directory:

```sh
SAC1_QUALIFY_DIR="$HOME/Documents/Developer/binary-toolkit/sac1-implementation/core-full" \
SAC1_QUALIFY_FULL=1 \
cargo +1.97.1 test --release --test sac1_qualification \
  -- --ignored --exact sac1_production_qualification --nocapture --test-threads=1
```

For database-producing comparisons, invoke this command through the owning
workspace's `tools/artifact-retention/retain.py run`, choose a stable workload
series, and point `SAC1_QUALIFY_DIR` at its output working directory. Original
external inputs belong outside the managed output. The generated core fixtures
in this test have a fixed `sac1-qualification-fixed-v1` seed and need no private
input files.

The full run uses 4,096 files in four directories of 1,024 files for each
small-file bin/content/name population. The 8-byte and 128-byte name populations
are separate. It includes incompressible, repetitive text, repeated content, and
the 512/513 and 8,192/8,193 transitions. The ZIP control is an actual seekable
ordinary ZIP produced by `sac1_zip_reference.py` from the exact SAC source bytes.
Its implementation, zlib version, level, metadata, and complete encoded size are
reported. Fixed-root sealed production packing removes builder garbage before
size comparison; the consumer verifies and reads the resulting resources.

`run_sac1_qualification.py` records source hashes before and after the optimized
build and freezes the executed test binary. To select another independent group
without rebuilding, pass `--binary /retained/run/qualification-runner
--build-provenance /retained/run/invocation.json`; the new managed run copies
that exact binary and records the original build metadata. Each group retains
all measurements and failures. The driver separately records process user/system
CPU, elapsed time and host load, excluding compiler time. `--rss` adds the OS
whole-process high-water measurement.

Full bulk populations contain 1 GiB in fixed 1 MiB chunks. The incompressible
case measures the 0.2% overhead target, and two identical resources compare
complete packed sizes and the exact sets of retained kind-7 object IDs. The
compressed population has distinct, highly compressible nonzero chunks, with
independently compressed Zstandard controls at level 1. It reports both the
`1.05*Z+H` and logical-payload-relative limits.

Sequential throughput reads actual native files. Both controls and SAC
materialize into a `Vec` whose capacity is reserved outside timing. Controls
perform BLAKE3 verification during the timed operation; SAC performs its
production canonical-frame verification. Complete byte equality is checked
outside timing. Each measured operation is immediately preceded by an untimed complete read
of that same path to establish OS-warm cache state. Five paired samples use a
frozen seeded order; the report retains each pair, CPU and host load, cache
budget, and output digests. These comparisons are single-worker and do not
claim an OS-cold result. The runner copies the exact executable into its output
and records its SHA-256 before execution, so concurrent rebuilds cannot change
a running cohort.

Native publication measurements include 1,000 durable publications after
initial namespace installation, all individual latencies, append growth, reads,
and actual barrier counters. This is a **core diagnostic**, not a qualification of an
application's checked save or command path: it does not have a million-record
semantic fixture or a ten-minute application workload. The no-op
case checks no extent growth, no generation change, and no barriers against the
writer's established durable baseline.

Native root admission runs 100 independently spawned fresh processes. Only the
bounded file control bytes are OS-warm; no parsed application cache crosses
processes. It checks the real physical read counts, bytes, and p95 elapsed time.
Process startup is outside the measured open interval and child failures remain
in the result population.

The native compaction diagnostic retains a 1 GiB captured file in full mode,
adds half that size in distinct unreferenced byte objects, and commits a changed
directory root so those garbage frames are inside the selected physical extent.
It times production compaction, verifies the installed archive, and reads the
same tail bytes through a pin held across replacement. It reports source size,
compacted size, and retained old-inode bytes. This quiescent check does not
qualify the ten-minute concurrent workload or the 100-cutover pause population.

The separately selected `concurrent` group uses a fixed deadline producer for
at least 600 seconds in full mode, continuing the same offered load until 100
successful cutovers have completed (with a declared one-hour safety bound). It
offers ten distinct 1 MiB analysis updates and
about 16.7 scalar edits per second through a bounded eight-event queue. It
reports offered/completed events, queue peaks, dropped events, enqueue-to-durable
latency, actual source append bytes, replacement catch-up append/slot/index
writes, and all copy or
cutover aborts. Background workers perform real production closure copies and use
`Compaction::refresh_cancellable` with the latest immutable pin before final
cutover while the native writer continues publishing. This ordinary refresh
uses preparation quotas; the final 16 MiB/100 ms fence is unchanged. Host
observations run on a separate worker, and immediate event/drop/fence CSV/JSONL
records preserve attribution even if a population fails or is interrupted.
`SAC1_QUALIFY_STOP_ON_DROPPED=1` closes an explicitly incomplete diagnostic
after its first dropped event; it cannot pass the full-duration/population gate. Every successful cutover checks the
unchanged acknowledged head and exact current records through both an old pin
and the installed reader. Full mode retains a 1 GiB input, starts with 512 MiB
unreachable payload, and requires 100 successful cutovers with the specified
pause distribution. Disk observations explicitly distinguish sampled named
archives from measured unlinked scratch reservations, including simultaneous
old/new table allocations during rehashing. Capacity uses a conservative sum of
independent scratch peaks and a complete append-only candidate extent bound;
every successful or aborted candidate contributes its exact aggregate peak,
actual writes, and external fence duration. Pause percentiles include all fence
attempts, while successful and aborted distributions are also reported separately.
The production
compactor also enforces one aggregate temporary quota: candidate extent, copier
frontiers/maps, validation, retention indexes, and optional layout spools reserve
against it before growth, including both table generations during resize and
both layout files during replacement. Successful installation releases the
now-primary extent/index from that candidate quota. This is the native
storage interference control; it does not qualify an application's command
path, semantic projection, or complete auxiliary RSS target.

Unpublished native staging also accepts a total temporary disk limit covering its
file and disposable index. During native sealed publication, the same aggregate
counts the original staging inode, replacement file, closure validation, copy
maps, and traversal frontier. The caller's separate index limit survives repack.
Reservations release after successful installation; historical peaks remain
available through `total_temporary_statistics`. The sealed quota regression uses
4,096 distinct chunks to force real spill tables and rejects a quota that would
cover both archive files but omit their scratch. It also checks that a zero index
allowance remains in force during repack.

The separately selected `scale` group builds and publishes one million empty
files in sixteen directories through the production bulk builder, streams all
entries without retaining output, and performs deterministic individual queries.
Invoke `run_sac1_qualification.py --full --groups scale --rss
--rss-limit-bytes 67108864` through the managed runner to enforce a whole-process
64 MiB peak RSS bound, including parser, cache, live buffers, and test harness.
The OS time utility records this peak separately in `process-peak-rss.json`;
there is no application-output memory exclusion in this fixture. External-sort
read/write bytes include every merge pass and temporary peak includes overlapping
input/output runs. The `extract` group applies the same RSS gate to a streaming
1 GiB input plus 4,096 small files, full physical admission, and real confined
atomic extraction. It rehashes every output byte using bounded buffers. By
default it also produces and seals the input in that same process, providing a
stronger combined producer/consumer high-water check. To measure the specified
single-stream consumer independently, set `SAC1_QUALIFY_EXTRACTION_SOURCE` to
that exact retained archive and declare its managed run with `--depends-on`.
The consumer reconstructs the frozen source digest through bounded reads,
opens the archive afresh, and checks all extracted bytes; its RSS excludes no
live memory. Producer packing high-water and consumer RSS are separate results.
The `open` group uses this same external archive for 100 fresh-process root
admissions and retains every physical-read count and individual latency.

`SAC1_QUALIFY_SIZES=16385,32768,49152,49153` and
`SAC1_QUALIFY_TEXT_SHORT=1` select additional transition controls using the same
frozen generator and ZIP implementation. These supplement the complete fixed
populations and never replace a failed bin or change its size limit.

Without `SAC1_QUALIFY_FULL`, reduced populations are explicitly reported as
diagnostics and cannot qualify the frozen full-size acceptance populations.
`SAC1_QUALIFY_CASES=tiny,small,bulk,compressed,native,compaction` selects groups; select only
the affected group when verifying a concrete implementation fix. Every result
is appended to `measurements.jsonl`; failing measurements remain present and the
test fails at the end. Reuse an output directory only when its existing report
is intentionally part of the same comparison and its case files do not collide.

A complete qualification of an application that uses SAC additionally requires
that application's semantic admission and checked save at both record scales,
its real command dispatch, current-format retention and HTTP
RTT/representation controls. Earlier
prerelease formats are unsupported and are not qualification dependencies. The core
compaction and memory controls do not imply those owning-consumer requirements
have passed. Fault cases are owned by the native and
wire test suites; the independent recovery reader consumes the retained tiny
and bulk SAC files as cross-reader inputs.

`run_sac1_crossovers.py --cli <frozen-sac> --metadata-producer <sac1_bulk-test-executable>`
reports the separate 1/2/16/256-resource crossover populations through the actual
CLI. Build the owning producer with pinned `cargo test --features native --test
sac1_bulk --no-run`; the producer is the
`metadata_prevents_inline_placement_and_uses_bounded_extents` test. Run the script
through the managed artifact runner. It copies both executables before use,
records their SHA256 identities, checks physical verification and representative
reads, and reports signed total/per-resource overhead and ordinary ZIP crossover.
Pass `--profile release` when both supplied executables were optimized; elapsed
packing times remain diagnostic. These cases have no many-file parity gate. Its seeded SHAKE256 byte generator and
text template are recorded separately from the many-file acceptance corpus.

The metadata subcase uses two 8 KiB files with 12 KiB of namespaced metadata per
file and a 16 KiB writer page target. The complete entry exceeds that target, so
the production writer uses extents while preserving the metadata. The generic
128 KiB leaf admits the maximum 16 KiB metadata without this special placement
condition. The frozen CLI verifies, reads and compacts the produced fixture and
checks that the snapshot identity survives. Its ZIP control preserves identical
opaque metadata CBOR in a private extra field and reports that fixed cost; it
imposes no parity gate. `--metadata-only` reruns this subcase without repeating
completed crossover populations. Debug-profile executions qualify size and
content behavior only; elapsed packing times are diagnostics.
