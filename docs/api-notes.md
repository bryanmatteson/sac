# Rust API notes

These notes describe the behavior of the Rust API that affects performance and
ownership. Read the [README](../README.md) first. The
[core specification](../specs/01-sac-core-v1.md) defines the wire format and the
verification boundaries.

## Module layout

The public API lives in `v1`; principal container types and the strict CBOR
module are also available at the crate root. `resources::ArchiveBuilder` builds
portable byte-name trees, and `resources::ArchiveReader` reads bounded ranges,
streams entries and performs confined extraction. `NativeStore` owns durable
local publication; `NativeReader` pins an immutable admitted view.

## Write buffering

Appended frames share a bounded 64 KiB write buffer, packing full writes across
frame boundaries. Large frame prefixes write directly; only their short tails
occupy the buffer. A cache miss drains it only when the requested frame includes
buffered bytes. Reads of older frames keep pending writes coalesced and bound
read-ahead to the written prefix. Reader
pins and publication drain the buffer before exposing bytes or running the
ordered durability barriers. Appending alone does not publish data.
On macOS, published writers write within bounded sparse file extensions in
1 MiB increments, amortizing length changes and limiting speculative allocation
from extending writes. Unused logical headroom has no data payload, never exceeds
the file byte limit, and is removed before publication returns or a new limit
takes effect. Staging writes stay within their already reserved extent.
Publication barriers are unchanged; failed append or publication writes poison
subsequent writes.

A native writer checks its destination when staging begins. Immutable object
appends then stay local to that descriptor, without repeating the path lookup
for each object. Publication checks the complete path before its commit write
and after durability. A replaced or removed file, or a replaced ancestor
directory, fails publication; previously published pins remain readable.
`NativeStore::verify_current_path` provides an explicit check at any time.

## Parallel encoding

`NativeStore::set_encode_threads(n)` lets resource builders hash and compress
up to `n` file chunks at the same time. `ObjectStore::prepare` encodes the
chunk bodies and `ObjectStore::put_prepared` appends each result. The builder
puts the results in the order of the chunks, so the file has the same bytes as
with one thread. The default is one thread, and a store that does not encode
ahead keeps the ordinary `put`. A builder reads as many chunks as the store
encodes together, to a maximum of one quarter of `Limits::max_memory_bytes`;
each encoder thread also holds one object and its frame. The whole-file digest
is computed only for a file declaring `byte_digest`, on one more thread during
a parallel batch. An object already in the native append index can skip frame
encoding during preparation. Its destination verifies the existing occurrence
before reuse, or encodes the object if the occurrence is unavailable.
`ExtentAccumulator::push_data_batch` gives the same path to a caller that
builds its own extent trees.

## Bulk directory construction

`ArchiveBuilder::bulk` sorts resident entries in memory until it reaches its
sort budget. Larger inputs spill into quota-charged merge runs. A directory
whose entries fit one leaf can publish that leaf without a temporary node run.
Resident and spilled construction share the same directory page boundaries.
`finish_with_statistics` reports the scratch bytes used by runs.

## Allocation-sensitive reads

For allocation-sensitive reads, `lookup_shared` retains an authenticated page
and exposes borrowed names and CBOR metadata. `open_file` resolves a file once;
its `read_into` fills caller storage across inline, chunked and sparse ranges.
`read_range_into` and `read_to` also avoid allocating an output vector. Owned
lookup and range APIs remain available when ownership is useful. A retained
view pins its page outside the store cache's residency budget.

## Frame encoding and decoding

`v1::wire::FrameEncoder` and `FrameDecoder` provide reusable workspaces and
native codec contexts. Raw frame views borrow input without moving the payload;
compressed views borrow the decoder's reusable output. Native writers compute
canonical identity from the caller's bytes before allocating a new object.
For compressed writes, the encoder assembles the domain and canonical bytes in
its existing reusable buffer, hashes that contiguous input, then compresses the
canonical portion without assembling it again. A matching canonical ID permits
reuse across relocated child hints; physical locators are always encoded from
the current references. An unused preparation cannot supply bytes for a different
ID. Raw writes and control objects retain bounded stack hashing.
Compressed reads place decoded bytes after the identity domain in the existing
output buffer and hash the complete contiguous input. Borrowed views exclude
that domain; owned reads remove it with the canonical header and child IDs.
Compression uses the direct complete-frame Zstandard API with a reusable
context and the selected level; it retains the same raw fallback and compressed
bytes as the bulk API. Native decoding checks single-block frame extents from
the already parsed header, including RLE storage and optional checksum bytes.
Multi-block frames use Zstandard's general extent parser. Both paths still
decompress and authenticate the entire canonical object before returning it.
Object hashing batches the domain, header and child IDs into 4 KiB stack
scratch, filling the last batch from the body before streaming its remainder.
Objects that fit use a single BLAKE3 call. This avoids per-child hash updates
and enables SIMD from the first chunks without allocating or changing object
ownership, cache weights or wire bytes.
Domain-separated hashes likewise combine a short domain with the first input
batch in stack scratch and stream the rest. Domains at least 4 KiB retain the
ordinary incremental path. Decoder output and ownership remain unchanged.
For memory-backed `ReadAt` sources, positional reads borrow the input frame
through `ReadAt::slice_at`. They still authenticate each requested frame and
return an owned canonical object.

## Caches

The disposable append index stays resident within an 8 MiB default memory
budget. `NativeStore::set_append_index_memory_budget` changes this limit;
reducing it spills an oversized table without losing deduplication, and a
failed spill preserves its previous table and limit. The conservative resident
charge is available through `append_index_memory_bytes`. This budget is
separate from decoded objects and survives disposable-cache clearing and
compaction. The index stores each hash only in its key and retains its
12-byte physical address as the value. Its mapped slots occupy 60 bytes. Full
rewrite digests and physical-size estimates use 40-byte side records, buffered
in batches of 64; their eight-byte record IDs share the same index. Both files
and index resize overlap use the same temporary-storage budget. Side records
retain the complete digest and never grant authority over an unauthenticated
frame or a different physical occurrence.

Native cache hits, inserts and evictions take constant time: decoded objects
and authenticated occurrences are in hash maps with an exact
least-recently-used order. Under payload churn, a small authenticated occurrence
metadata working set is protected within the same cache budget (one eighth of
it, capped at 4 MiB). This avoids decoding a large child again merely to link
its exact physical edge. The idle decoder stays in the cache when the cache is
full, within one quarter of the budget; it is the last entry to go.
`ObjectStore::object_type` also reuses the
authenticated kind and version after payload eviction. Entries bind the file
identity, expected hash, offset and span; every lookup checks the active
reader's extent before using a cached result.

A store and its pinned readers share one cache. While one thread uses it, or
threads never find it in use, each hit takes the cache lock, as before. A
reader that finds the lock held changes the cache to shared hits: a hit then
takes a shared lock on one of 256 groups of keys, which hold copies of the
entries that readers have hit, and adds itself to a record of 256 hits for its
thread. The next exclusive access gives the recorded hits their ages, in
order, before any other change. One thread has the same eviction victims as
before. Hits that several threads make between two exclusive accesses keep
the order of each thread. A thread whose record is full while another thread
holds the cache does not record its hit. The copies add no charge: they are
within the fixed allowance of each entry. The cache goes back to exclusive
hits after 64 full records in sequence found it free.

Raw metadata windows share the existing decoded budget, using at most one eighth
of it and no more than 1 MiB, so a cold publication can reuse its complete small
metadata working set without rereading evicted windows. Interval lookup finds
containing windows through overlapping smaller windows; each individual
coalesced read remains bounded to 32 KiB.

Native indexed-file readers disable speculative sequential read-ahead on macOS
and Linux; explicit bounded byte reads and the normal file cache remain
available.

## Verified objects and closure copies

`ClosureCopy` shares a 16 MiB resident index allowance between remapping,
physical validation, retained-root counts and the active traversal index.
`set_index_memory_budget` changes that allowance; oversized tables spill
without losing identities. `index_memory_bytes` reports the conservative
resident charge between copies. Disk-only constructors start with a zero
allowance. Traversal frames and the existing 1 MiB parent cache remain
separately bounded.

When a closure copy moves an object between native stores, the destination
stores the Zstandard bytes of the source frame again. The bytes come from the
read that authenticated the object, so a cache hit has none and the
destination compresses the object. A raw source frame, a commit and a snapshot
also take the destination's encoder. A copy from a file that this library
wrote has the same bytes with and without this path; a copy from a file with
frames from a different encoder keeps those frames.

A native writer checks each child of a put. For freshly appended byte and opaque
data objects whose bodies and decoded child vectors exceed 2 KiB, it caches
authentication metadata and admits their decoded payloads on read. Small data
objects and core structural pages retain immediate read-after-write caching.
The first payload read of a large data object decompresses it normally, then
caches it under the existing byte budget. This keeps streams of newly written
data from displacing decoded tree pages. A child with an authenticated occurrence
in the cache needs no read. The append index also authenticates children the writer
appended when the hash, offset and length all match. The writer reads and
authenticates every other child with a borrowed frame decoder. This records
the child's type without creating a decoded cache entry or a child vector.
The writer reuses its frame and decode buffers up to 256 KiB each and
releases larger buffers after the operation. The index is empty after
`discard_disposable_caches`, after maintenance and in a writer that opens an
existing file. The writer does not read an appended frame again for this
check, so the check does not find bytes that changed in the file after the
append; `validate` reads every frame of the published graph.

`VerifiedObject` carries immutable bytes and their authenticated identity from a
store read into a closure copy. Native and private staging writers reuse that
identity while still checking destination child occurrences; relocation must
preserve every ordered child hash. The capability cannot be constructed from a
caller-supplied hash. Generic writers retain strict `put` behavior.
`cached_object_type` reports an authenticated hit without loading a payload on a
miss, so generic callers can use the body and type from one verified read.
Unknown store adapters authenticate the complete object through the default API.

Staged rewrite provenance also covers expensive generic child fanouts, using
exact physical references and bounded disposable indexes independently of any
application profile. Cheap fanouts retain ordinary child authentication.
Closure copying validates physical edges and copies their canonical contents in
one postorder traversal. Large byte leaves are read once, and canonical content
deduplication still checks alternate physical occurrences before reuse.

Checked persistent-tree rewrites can carry exact unchanged child edges from an
authenticated committed parent; they preserve deferred subtree validation and
never certify skipped children.

The [performance harness](../tools/performance/README.md) measures allocation,
CPU and process-memory costs on identical workloads.

## Projected compaction

Applications that prune their own records can use
`Compaction::copy_projected_cancellable` and
`NativeStore::finish_compaction_projected_pinned_cancellable` to rebuild derived
public resources from the retained component closures. The callback receives a
source pin, private candidate, bounded copier, previous candidate Commit and
cancellation predicate. It runs off the writer path during preparation and
within the ordinary catch-up limits at cutover. An unchanged source Commit
reuses the prepared candidate. The callback owns its new control roots;
previous source locality plans are skipped. `ClosureCopy::update_retained_roots`
tracks up to eight component roots and reports at most 512 removed objects per
update so applications can bound obsolete derived resources in the catch-up
tail. Callback or budget errors abort installation and preserve the source.

Both ordinary and projected compaction can retain obsolete frames introduced
during catch-up. The usual allowance is five percent of the candidate record
bytes. A replacement can retain up to 16 MiB under the savings allowance,
which uses half the estimated net space savings before publication.
`CompactionBudget::max_garbage_bytes` caps both allowances. Catch-up work
and cutover still use their separate byte and time limits.

## HTTP range reads

HTTP is opt-in through the `http` feature. Its interactive source shares a
bounded raw cache, authenticates object IDs on every route, and reports
requested ranges separately from response body bytes. The
[CLI guide](sac1-cli.md#http-range-reads) gives the request rules and limits.

## Generic container metadata

The optional [`sac.metadata.v1` profile](../specs/02-generic-metadata-v1.md)
stores namespaced, deterministic CBOR values alongside any application
profiles. It has no application dependencies. `v1::metadata::MetadataReader`
provides point reads, streaming key enumeration, verification and lossless
export; `MetadataEditor` applies persistent key edits and returns a snapshot for
the caller to publish. Small values remain inline; larger values use core
extents. Unchanged keys, profiles and file content are shared across edits.
Encoded-value APIs preserve unknown structured and binary fields without
rebuilding value trees.

## Identity and repacking

Application extensions use namespaced kind-8 envelopes and declare portable
dependencies through strong child edges. Allocation budgets are operational
limits. Repacking preserves canonical graph identity; rebuilding the same file
bytes under different chunking or metadata may produce a different snapshot.
