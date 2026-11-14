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
`append-steady` writes unique compressed byte objects with a warmed encoder
and a spilled index. `authenticate-steady` writes unique parents whose old
compressed child must be read and authenticated on every put. Both disable
the optional decoded cache and keep the index within one mapped capacity
during measurement. `append-cached-steady` repeats the unique append with
the default cache and warmed authentication-index capacity.
`append-final-page-steady` writes distinct valid directory pages through
`put_unretained`, keeping exact type authentication with no eager decoded
payload copies. It checks zero warmed Rust allocations and stable spill size.
These spill fixtures explicitly cap the append index at a 2,048-entry
resident allowance, independently of the production default memory budget.
`append-cache-churn` uses 32-byte payloads and a 4 KiB decoded cache so
each append replaces a resident entry. These cases assert zero Rust
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
