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

Small appended frames share a bounded 64 KiB write buffer. A cache miss drains
it only when the requested frame includes buffered bytes. Reads of older frames
keep pending writes coalesced and bound read-ahead to the written prefix. Reader
pins and publication drain the buffer before exposing bytes or running the
ordered durability barriers. Appending alone does not publish data.

Before each write, a native writer checks that the destination name, in the
directory that it opened, still names its file. A replaced or removed
destination file fails that write. A replaced ancestor directory does not fail
a write: each publication and maintenance operation examines the complete
path, and `NativeStore::verify_current_path` does so at any time.

## Parallel encoding

`NativeStore::set_encode_threads(n)` lets resource builders hash and compress
up to `n` file chunks at the same time. `ObjectStore::prepare` encodes the
chunk bodies and `ObjectStore::put_prepared` appends each result. The builder
puts the results in the order of the chunks, so the file has the same bytes as
with one thread. The default is one thread, and a store that does not encode
ahead keeps the ordinary `put`. A builder reads as many chunks as the store
encodes together, to a maximum of one quarter of `Limits::max_memory_bytes`;
each encoder thread also holds one object and its frame. The whole-file digest
is computed on one more thread during a parallel batch.
`ExtentAccumulator::push_data_batch` gives the same path to a caller that
builds its own extent trees.

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
canonical identity once per inserted object.

## Caches

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

When a closure copy moves an object between native stores, the destination
stores the Zstandard bytes of the source frame again. The bytes come from the
read that authenticated the object, so a cache hit has none and the
destination compresses the object. A raw source frame, a commit and a snapshot
also take the destination's encoder. A copy from a file that this library
wrote has the same bytes with and without this path; a copy from a file with
frames from a different encoder keeps those frames.

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
