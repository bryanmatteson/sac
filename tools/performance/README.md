# Rust allocation, CPU and memory benchmark

This separate development package keeps allocator instrumentation out of SAC's
library and production binaries. Use the same source fixture, dependency lock,
compiler, feature set and host for comparisons. Build two binaries: instrumented
counts and uninstrumented timings. `optimized-api` adds cases requiring the new
borrowed/workspace APIs; disable it when compiling an older SAC source snapshot.

```sh
cargo +1.97.1 build --locked --release --manifest-path tools/performance/Cargo.toml --features optimized-api
cp tools/performance/target/release/sac-performance /tmp/sac-performance-cpu
cargo +1.97.1 build --locked --release --manifest-path tools/performance/Cargo.toml --features optimized-api,allocations
cp tools/performance/target/release/sac-performance /tmp/sac-performance-alloc
/usr/bin/time -lp /tmp/sac-performance-cpu read
/tmp/sac-performance-alloc read
```

Each invocation builds and publishes the same 128-file native fixture, warms the
operation eight times, and prints its snapshot identity plus JSON measurements.
Cases `lookup` and `read` exercise the existing owned lookup and streaming APIs.
`encode` and `decode` process 1 MiB raw frames using the convenience APIs.
`write` and `compressed-write` append unique 1 MiB byte objects to a native store,
using respectively relatively incompressible and repeated input bytes. Each
case checks errors; range cases additionally check lengths or contents.
`duplicate-write` puts an already indexed 1 MiB object into a native store
and asserts that it reuses the existing reference with no append growth.
`duplicate-uncached-write` repeats that check with the decoded/type cache
disabled; exact writer provenance must avoid reading or decompressing the old
occurrence. `append-small-raw` compares the 32-byte `append-cache-churn` fixture
with compression disabled. `append-map-steady` and `append-map-raw` write
synthetic 512-byte extension pages with 16 distinct authenticated children,
using respectively default compression and raw frames. These are strict puts,
with a warmed cache and a spilled index; these steady cases enforce
zero warmed Rust allocations. `append-raw-steady` is the raw 16 KiB counterpart
to `append-steady`; it includes append-buffer drains and can become I/O bound.
`live-map-updates` and `live-map-updates-raw` exercise the resource consumer:
repeatedly replace a small file in the 128-file fixture using `ArchiveBuilder`,
then publish, read back and verify the final snapshot. Timing covers directory
updates; the final durable publication and verification are outside the loop.
`SAC_MAP_ITERATIONS` selects 1 through 100,000 measured updates (default 1,024),
in addition to the eight warmups. Use the same count for both binaries; final
snapshot identities must match.
These consumer cases include normal builder allocations and do not claim zero
allocations. Raw writes trade disk space for less compression CPU; report both
modes rather than assuming raw is faster for every payload size.

For attribution, build `--bin map_profile` with the same release manifest and
run `tools/performance/target/release/map_profile` directly. It performs 10,000
real `ArchiveBuilder::set_file` edits, timing store reads, puts, rewrite-source
admission and rewrites while forwarding all checks to `NativeStore`. Separate
1,000-call components measure ordinary uncached object hashing, directory schema
admission and reused frame encoding including hashing and schema checks.
These instrumented wall-time phases explain costs; use the uninstrumented
`sac-performance live-map-updates` case for throughput comparisons.
`map_profile` also accepts `SAC_MAP_KEYS` (default 128), `SAC_MAP_RESIZE=1`, and
`SAC_MAP_PAGE_LIMIT` for many-key attribution. It samples the first leaf's
component costs even when the directory root is a branch.

Build `--bin map_workloads` from this manifest for many-key consumer comparisons:

```sh
./tools/performance/target/release/map_workloads updates
./tools/performance/target/release/map_workloads inserts-ordered
./tools/performance/target/release/map_workloads inserts-shuffled
./tools/performance/target/release/map_workloads resize
```

These cases default to 8,192 measured edits with payloads and paths prepared
outside the loop. `updates` cycles a deterministic permutation of 4,096 keys,
replacing 64-byte records. Insert cases fill missing odd keys between existing
even keys, either in order or in a deterministic permutation. `resize` visits
4,096 keys and rotates their sizes through 0, 8, 64, 512, 4,096 and 65,536 bytes
across passes, covering growth, shrinkage, page splits and inline/extent
transitions. Use at least 8,192 iterations to cover two complete resize passes.
`SAC_MAP_ITERATIONS` accepts powers of two from 64 through 65,536;
`SAC_MAP_PAGE_LIMIT` applies the same explicit writer target during fixture
construction and edits; `SAC_MAP_SPILL=1` forces a spilled append index and
disables the decoded cache. Each invocation checks both publication barriers,
old pinned contents, reopen, full validation and the last written value of
every edited key. Publication time, appended bytes and physical reads are
reported separately from update CPU and elapsed time. With matching page
policies, compare final snapshot identities as well as performance; different
page targets or writer grouping policies may produce different valid tree
shapes and identities. Persistent leaves now have a 192-row writer limit as
well as their byte limit, so before/after comparisons of this policy should
compare verified contents and appended bytes, while retaining the distinct
root IDs in their reports.
`append-steady` writes unique compressed byte objects with a warmed encoder
and a spilled index. `authenticate-steady` writes unique parents whose old
compressed child must be read and authenticated on every put. Both disable
the optional decoded cache and keep the index within one mapped capacity
during measurement. `append-cached-steady` repeats the unique append with
the default cache and warmed authentication-index capacity.
`append-final-page-steady` writes distinct valid directory pages through
`put_unretained`, keeping exact type authentication with no eager decoded
payload copies. `append-extent-leaf-steady` writes distinct valid extent leaves
through ordinary `put`, exercising deferred payload admission with the default
cache enabled. Both check zero warmed Rust allocations and stable spill size.
These spill fixtures explicitly cap the append index at a 2,048-entry
resident allowance, independently of the production default memory budget.
`append-cache-churn` uses 32-byte payloads and a 4 KiB decoded cache so
each append replaces a resident authentication entry. These cases assert zero Rust
allocations after warming.
`rewrite-layout-steady` appends unique parents with eight old compressed child
references, crossing buffered rewrite-record flushes while the address table
stays within one capacity. It also asserts zero warmed Rust allocations and
bounds scratch growth to the fixed-width provenance records.
`positional-read` reads 4 KiB from a stored 1 MiB chunk in a byte-slice-backed
sealed archive and checks the returned bytes on each iteration.
`extent-read` adds a 1 MiB chunked file and reads 4 KiB across a 256 KiB chunk
boundary with the owned range API. `extent-opened` measures that same range
through an opened file into caller storage and checks exact byte equivalence.
`extent-build` constructs an extent tree from 2,048 distinct small byte objects;
it reports the resulting root hash to check identical page construction across
implementations. This isolates the append/frontier cost from payload I/O.

New API cases are `lookup-shared`, `read-opened`, `encode-reuse`, `decode-view`
and `compressed-decode-view`, plus `extent-opened`. These measure warmed reuse. Frame
operations still authenticate every object: zero allocations does not mean
zero hashing or zero decompression. Workspaces grow to the largest observed
frame within SAC's 8 MiB canonical bound. Caller-retained views keep backing
pages alive separately from cache residency.

`result.cpu_ns` is process CPU consumed during the operation loop;
`result.wall_ns` is elapsed time for that loop. Read timing from the binary built
without `allocations`. `/usr/bin/time -lp` on macOS additionally reports whole
process user/system CPU and peak RSS, including fixture setup, native codec
allocations, cache residency, runtime and mapped libraries. On macOS versions
that expose retired instructions through `/usr/bin/time -l`, record that
counter for each whole-process comparison. Record host load and repeat cases
in alternating baseline/candidate order. A busy host can inflate wall time,
so report CPU and wall time independently.

The `allocations` feature measures Rust allocations on the current thread after
warmup: total allocation calls, cumulative allocated bytes, peak additional
live bytes and net retained bytes. It does not intercept Zstandard's C allocator
or other threads. Its loop precedes the timing loop; do not compare its timing
with an uninstrumented build. Peak additional live allocation is not process
RSS or a complete resident-heap measurement. Native codec memory is included in
process RSS and, for pooled native decoders, the cache budget.

Keep database-producing comparison artifacts under the consumer project's
managed artifact directory. These microbenchmarks establish these workload
costs; they do not qualify cold random I/O, concurrent-reader scaling, sustained
compaction latency or a whole application workload.

With `allocations,optimized-api`, the harness fails if warmed streaming reads,
shared lookup, opened-file reads or reused frame encode/decode allocate Rust
heap memory. Owned convenience APIs retain their separate allocation results.

`reclamation` is a separate native maintenance benchmark binary. Build it with
`--bin reclamation`, then run `run_reclamation.py /absolute/path/to/binary` from
a managed artifact run directory. It creates four distinct 16 MiB generations
(64 MiB total input), measures one destructive operation per fresh process, and
checks physical validity, exact payload bytes, canonical root preservation
(except the deliberately new reuse publication), old pinned bytes and reopen.
Modes compare copy and replace, offline sliding, online punching, pinned online
punching, index-only sweep and sweep followed by a new 16 MiB publication using
reclaimed spans. CPU/wall measurements exclude fixture setup and verification;
whole-process RSS includes both. Allocation builds execute the operation once
under the current-thread Rust allocator counter, with timing deliberately zero.
The runner alternates mode order and stops each process after two minutes.
Allocated file bytes come from `st_blocks`, logical bytes from `st_size`.
The offline journal figure is a conservative bound, not a sampled disk peak.

## Deferred-identity journal and transient map trial

`src/journal.rs` implements the experimental mutable journal used by the real
Splice replay benchmark. It remains in this development package, outside SAC's
production API and canonical wire format. Inspect a completed journal with its
immutable predecessor database:

```sh
cargo +1.97.1 build --release --manifest-path tools/performance/Cargo.toml --bin journal
./tools/performance/target/release/journal /absolute/path/to/journal.raw /absolute/path/to/base.sac
cargo +1.97.1 test --release --manifest-path tools/performance/Cargo.toml --bin journal --features allocations
```

The `SACJTRY3` format uses **eight-byte serialized child handles**. An aligned
base-file offset has its low bit clear; a local logical ID is shifted left one
and tagged with a low bit of one. The header binds the handles to the exact base
preamble, selected generation, committed extent and root identity. Opening the
base takes a native reader pin for the lifetime of the writer/materializer.
The in-memory `Reference` enum also carries a journal scope for local handles;
it is deliberately larger than the eight-byte serialized representation.
Caller-supplied scopes must be unique to their journal epochs. The prerelease
reader accepts only version 3; it includes no older-format compatibility path.

`Journal::existing` checks an external canonical reference against the base
header. `base_hint` imports a producer-supplied identity within the admitted
base's bounds, deferring authentication to ordinary NativeStore materialization.
Each existing-base handle carries a 36-byte sideband hint (hash and frame span)
after the handle table. Local handles require no hint. These CRC-protected
hints preserve identities the producer already has, eliminating the separate
base-header scan and retained identity index. They make no claim of payload
authentication: NativeStore still authenticates referenced payloads and child
roles before accepting canonical objects. A forged hint cannot bypass those
checks. Eight bytes describes each handle, not the total storage of a base edge.

`TransientJournal` stages native map kinds 4096/4097 and parents that contain
transient handles. A publication selects its reachable resident graph,
resolving shared descendants once in topological order. Arena overflow resolves
private descendants and appends the immutable record directly to the journal.
This writes each spilled payload once, without a separate map-spill file.
Latest-root materialization excludes unreachable spilled records. The replay
supplies the exact original page bodies, including page cuts and key order;
this trial does not yet remove encoding performed by Splice's typed map editor.
Private nodes can survive a publication: the real producer can retain a handle
and attach it to a later root. `finish` retires never-published resident nodes,
releases arena bytes, and terminates the writer. Already written
journal records remain readable. Publication flushes and syncs its full closure;
unpublished arena nodes are temporary and have no crash-recovery guarantee.

Staging uses a configurable resident arena (64 KiB in the real replay, at most
1 MiB); overflow uses the journal's bounded append buffer. Logical IDs are
bounded to 100,000, and the candidate table to 65,536 entries (4,096 in replay).
Transient traversal is iterative and marks shared nodes when queued. It never
uses recursive graph walks. Allocation tests exercise warmed resident append
and forced-spill append, traversal and publication with zero Rust allocator
calls within established capacities. Arena/index growth and complete-process
setup still allocate.

Ordinary journal writes use a bounded, publication-local candidate table keyed
by object shape and small samples from body and child list. A possible match
undergoes an exact comparison of the complete serialized child list and body.
Collisions can add a comparison or miss a deduplication; they cannot merge
unequal records. The table is opportunistic. Final canonical deduplication
still belongs to materialization/compaction. Raw journal frames use CRC32C,
without canonical hashing or compression on append.

Logical IDs preserve producer order even when transient nodes reach disk later.
The reader checks checksums, padding, bounds, duplicate IDs and both logical and
physical backward references. `retained_records` selects the latest publication
with one reverse pass, bounded to 100,000 IDs and 1,000,000 local and base edges
each. Earlier publication roots retire only under this explicit latest-only
policy. `object_at` reads the selected frames in logical order using two bounded
64 KiB windows, reproducing the original canonical append order without copying
payloads into another sorted file. `MaterializedReferences::with_lifetimes`
uses selected-edge counts to recycle canonical-reference slots after their last
use. The replay holds the active frontier, instead of all prior full references.
The latest-only materializer retires its reference mapping, read buffers,
reachability metadata and finished directory arena before canonical publication
builds its own graph metadata; the base pin remains held through publication. `OffsetReferences`
replaces the replay adapter's per-entry tree allocations with a bounded sorted
vector; production callers retaining handles directly do not need this adapter.

This is a replay trial, not a replacement ProgramDB backend. It deliberately
does not implement `ObjectStore`: local IDs do not satisfy canonical identity
contracts. Automatic tail recovery, a production live read path, producer
integration and reader-aware retention policy remain adoption work. The reader
rejects torn/corrupt tails. Do not delete the journal before successful canonical
publication. Latest-only retirement preserves the latest snapshot, not access
to historical roots.

Benchmark write and later materialization separately and report their sum;
deferred work is still work. Also measure the full path through sealing. Disk
accounting includes the predecessor/live database, raw journal, named and
anonymous spill, and the seal while it is being produced. `finish` reports the
allocated journal high-water mark. Overflow map records are included in that
file; directory and sealing spill remain separate sampled allocations. Compare the same captured real Splice
writes against the preceding journal implementation, authenticate the same
input frames in both builds, check exact live/seal hashes, and run Splice's
existing verifier on the original, materialized live and sealed databases.
Rust allocation counts are current-thread counts, excluding native codec C
allocations; process RSS and allocated disk are separate measurements.
