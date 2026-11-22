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

## Application profile discovery and validation

`sac::profiles::SnapshotProfiles::discover(store, snapshot, &limits)` authenticates
one schema-1 snapshot. `profiles()` and `features()` preserve canonical declaration
order. `profile(id)` looks up an owner and `directory()` returns the resource
root. Each declared profile has its exact version and an `ObjectRef`. Discovery
also works on a snapshot with an unknown required core capability.

`open_root(store, id, version, &limits, supports_feature)` returns an authenticated
root or `None` for an absent profile. It checks required core and scoped capabilities
and the root's kind, namespace, record type and version before exposing its payload
and strong children. The owner interprets those bytes and validates its dependencies.

Call `validate(store, validators, &limits)` with a slice of caller-selected
`ProfileValidator` implementations for independent per-profile reports. A matching
owner receives the bound root. An unknown owner stays unchecked, and an unsupported
version or required feature is reported separately from an invalid payload.
Resource limits and I/O failures return an operation error. The built-in
`sac::v1::metadata::MetadataValidator` checks the flat key directory and every CBOR
value. Profile reports apply to this snapshot and do not establish publisher trust.

## Write buffering

### Durable memtable

`MemtableStore` is a native, thread-safe byte-key/value API in front of a
dedicated live SAC container. Unlike native frame buffering, it defers SAC
object construction and coalesces repeated changes to each pending key. It
uses the `sac.memtable.v2` application profile and recovers/upgrades v1 stores.
It adds no core wire format changes.

```rust,no_run
use sac::{MemtableOptions, MemtableStore, Mutation};
use std::{io::Read, time::Duration};

# fn main() -> sac::Result<()> {
let mut incarnation = [0; 16];
std::fs::File::open("/dev/urandom")?.read_exact(&mut incarnation)?;
let store = MemtableStore::create("state.sac", incarnation, MemtableOptions {
    max_memory_bytes: 16 * 1024 * 1024,
    max_wal_bytes: 64 * 1024 * 1024,
    flush_interval: Duration::from_millis(500),
    ..Default::default()
})?;
store.write_batch(&[
    Mutation::Put { key: b"analysis/function/42", value: b"result" },
    Mutation::Delete { key: b"analysis/stale" },
])?; // one full WAL synchronization for the entire atomic batch
assert_eq!(store.get(b"analysis/function/42")?.as_deref(), Some(&b"result"[..]));
store.close()?; // final checkpoint, reporting any failure

let reopened = MemtableStore::open("state.sac", MemtableOptions::default())?;
assert_eq!(reopened.get(b"analysis/stale")?, None);
reopened.close()?;
# Ok(())
# }
```

On Unix, WAL output gathers up to 64 mutations from the admitted batch into a
file write using a fixed 4 KiB framing buffer and descriptor array below the
existing 8 KiB output scratch bound. Prefixes, keys that fit and small values
(up to 256 bytes) share that buffer. Other payloads are borrowed. Groups retain
64 mutations even when keys are too large to pack. Partial writes and
interruptions are completed before the full WAL synchronization; other
platforms retain bounded buffered output.

Single writes also synchronize the WAL before returning. Use `write_batch` to
amortize that barrier across up to 1,024 mutations. Keys may be empty or contain
arbitrary bytes, up to 2,047 bytes; duplicate keys in one batch use the last
mutation. Value size is configurable up to 8 MiB. Overlay hits and tombstones
take precedence over the last checkpoint.

`max_memory_bytes` charges key/value bytes and conservative per-entry overhead;
the active table, one immutable table and incoming batch fit together. The
worker freezes at seven-eighths occupancy, retaining headroom without repeatedly
flushing smaller hot sets. It prepares the durable empty successor WAL during
the dirty interval, before a checkpoint is requested. A write that
would exceed the combined memory or retained WAL bound waits for background
retirement before allocation or acknowledgment. An individually
oversized batch fails before WAL acceptance. A capacity wait during a checkpoint
does not implicitly schedule another active-table checkpoint; admission is
retried after retirement. Native caches and bounded
encoding/recovery scratch have separate budgets; this is not a process RSS cap.
The worker starts a checkpoint at the oldest pending write's deadline, including
when callers are idle. Checkpoints build/publish outside the state lock. Reads resolve
active values/tombstones, then immutable values/tombstones, then a pinned SAC
checkpoint; WAL sync and base reads also run outside that lock. There is no
queue of immutable generations. Capacity exhaustion applies bounded backpressure. The interval does not guarantee filesystem completion latency.

`request_flush()` schedules a checkpoint and returns its target sequence;
`flush()` waits until the worker has durably published and retired records through
all batches accepted before the call. Later writes can continue and may remain
in the active table when it returns.

`statistics` exposes combined pending bytes/entries, active/immutable charges,
immutable entry count, flush activity, admission waits, WAL bytes, accepted/checkpoint
sequences, recovered batches, discarded incomplete-tail bytes and the first
failure. Its fixed-size `io` counters attribute cumulative wall time since open
to WAL encoding/synchronization, write preparation, lock/admission waits,
successor preparation, and checkpoint construction/publication/retirement.
`io.native_publication` exposes the native barrier counters shared with the
checkpoint writer. WAL totals cover successful batches; checkpoint totals cover successfully
returned work (failed jobs can omit elapsed time), and native barrier counters
include attempts. Worker and
foreground durations overlap and must not be summed as process CPU or elapsed
time. WAL/checkpoint failures poison the handle until reopen. A full invalid
WAL record is an error; only an incomplete final record may be discarded. A
failed call can have an indeterminate outcome. Applications requiring request
deduplication should store their request ID in the same atomic batch.

`open` validates the complete WAL before replay, publishes recovered changes
under the configured memory limit, and safely retires covered records. It can
recover an interrupted publication through a private, validated native recovery
path that preserves damaged SAC input; ordinary writable native admission still
rejects torn slots. Missing or foreign WALs fail closed. Reducing limits below
the largest existing batch requires reopening with sufficient limits. Drop
stops the worker without a silent final checkpoint; `close` reports errors.
Back up or move the SAC file, `.wal` and any `.wal.next` while quiescent, or
export a completed SAC snapshot. Retained record bytes plus one header obey
`max_wal_bytes`; the second segment adds one fixed 64-byte header on disk.

See [the full WAL and profile contract](../specs/04-memtable-v1.md) and
[`examples/memtable.rs`](../examples/memtable.rs).

### Native frame buffering

Appended frames share a bounded 1 MiB write buffer, packing full writes across
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

## Live append latency

`NativeStore::set_compression_level(0)` writes future unique objects as raw
frames, avoiding Zstandard work for latency-sensitive small records and map
updates. Negative levels select Zstandard's fast modes; the default remains
level 1. Raw frames can use more disk space. This is a per-handle setting,
including prepared writes and future appends after replacement compaction;
reopening a store uses the default again. Deduplication can reuse an existing
occurrence regardless of its codec. Canonical identities, child authentication
and the two durable publication barriers are independent of this setting.

Exact append-index hits reuse the writer's authentication even if the optional
decoded/type cache is disabled or has evicted the occurrence. A put also keeps
a bounded table of child indices to avoid authenticating repeated exact edges
again within that call. Table collisions can repeat work, but every hit compares
the complete hash, offset and frame span. Losing disposable state falls back to
ordinary authentication. Small-record benchmarks measure staged appends;
durable publication remains a separate operation with filesystem barriers.
Directory leaves containing only inline data and symlinks copy unchanged rows
as two contiguous byte ranges around an edit. Introducing an extent or child
directory still builds the correct new child table; page-size overflow uses
the ordinary split path. This preserves the canonical pages of decoded edits.

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
native codec contexts. Borrowed CBOR navigation uses each validated value's
exact boundary for its last child, so a nested final field is not scanned again
to find its end. Directory leaf admission consumes the outer arrays and fields
in one forward pass, retaining deterministic CBOR, shared depth/item limits,
metadata, ordering and child-index checks. Other schemas validate the complete
value before navigation.
Schema-known unsigned integers and byte strings consume their checked header
once. Empty metadata maps take a direct path after deterministic CBOR admission;
nonempty maps retain all namespace, type and value checks. Persistent directory
branch edits borrow existing fence names and directly encode the changed child
path. Their bounded 2,048-slot child lookup retains the same first-use identity
order and physical hint selection, including repeated IDs. Oversized results
use the existing balanced split policy. Page limits and the wire format are
unchanged.
Persistent directory writes also bound leaves to 192 rows, preventing thousands
of small records from sharing one mutable page. This writer grouping policy
preserves the 128 KiB core admission cap and individual row limits. Dense bulk
and older leaves remain legal; an edited wide leaf splits lazily. Bulk packing
retains its dense normalization policy. Grouping changes can change the root
ID of a newly written tree; existing roots and authenticated pins retain their
identities. The policy applies to both single-file and batch edits.
`ArchiveBuilder::set_files_batch` applies up to 512 sorted, unique,
nonoverlapping path replacements with mixed `FileContents::Inline` byte slices
and `FileContents::Extents { length, root }` descriptors. It authenticates touched
directory routes and shared extent roots, retains untouched physical references,
and rewrites each touched page once per batch (splits may emit several pages).
Inline data is bounded by `INLINE_LIMIT`; complete extent graphs and the initial
directory remain the caller's validation responsibility. Failure preserves the
builder root and input accounting; append-only stores can retain unreachable
objects from an interrupted operation. The existing extent-only batch API shares
this path and retains its contract. No wire format or publication policy changes.
`ResourceView::file_contents` borrows inline bytes or returns an exact shared
extent descriptor without materializing file contents. It returns `None` for
nonfiles. Validate the complete extent graph before sharing the descriptor into
a new snapshot; descriptor access alone is not full-file verification.

Raw frame views borrow input without moving the payload;
compressed views borrow the decoder's reusable output. Native writers compute
canonical identity from the caller's bytes before allocating a new object.
For compressed writes, the encoder assembles the domain and canonical bytes in
its existing reusable buffer, hashes that contiguous input, then compresses the
canonical portion without assembling it again. A matching canonical ID permits
reuse across relocated child hints; physical locators are always encoded from
the current references. An unused preparation cannot supply bytes for a different
ID. Raw directory writes also assemble this reusable canonical buffer.
Directory leaves, including raw writes, reuse standard BLAKE3 chaining
values for 4 KiB subtrees only when their complete canonical input bytes match
at the same offset. The comparison includes the identity domain, header and
ordered child IDs. Growth, shrinkage and changed bytes recompute the affected
subtrees; the result remains the ordinary canonical BLAKE3 hash. This cache
adds at most 131,084 bytes of comparison storage and 33 chaining values (1,056
bytes) per encoder, allocated on the first eligible page and included in
`buffer_capacity()`. Pages up to 4 KiB use ordinary hashing. This optimization
does not supply schema or child authentication, which still run on each write.
Other raw writes and control objects retain bounded stack hashing.
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

A native writer checks each child of a put. For freshly appended opaque objects,
extent leaves and byte leaves, it caches authentication metadata and admits their
decoded payloads on read. Directory and ordered-map pages, extent branches and
publication controls retain immediate read-after-write caching. The first deferred
payload read decompresses it normally, then caches it under the existing byte budget. This keeps streams of newly written
data from displacing decoded tree pages. A writer that reads its new objects back,
as a projection of each flush does, can keep decoded copies of its most
recent payload appends apart from that cache with
`NativeStore::set_appended_payload_budget`. Such a read takes no shared cache
lock, file read, decompression or hash check: the writer framed each object
under the hash that authenticated its content. The copies name exact
occurrences in one file and outlive publications; the budget evicts the oldest
first, payloads over 64 KiB are not copied, and a new file, frame reuse and
`discard_disposable_caches` clear them. The default budget is zero. A closure
copy from the writer reads its sources with `verified_object`, which the copies
serve as well: a copy of an object of 4 KiB or more keeps its frame's
compressed bytes, so a destination that stores frames stores them again, and a
smaller object is encoded again, as after a decoded cache hit.
`writer_read_statistics` counts reads served by the copies, by the shared cache
and by the file. A child with an authenticated occurrence
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

`ObjectStore::visit_verified` exposes authenticated `ObjectView` parts only for
the callback's lifetime. Its default uses the ordinary verified shared read;
arena-backed stores can borrow their immutable slices instead. Resource batch
editing uses this visit when parsing a directory page, preserving the same
frame, decoded-byte and resident-memory charges without requiring an owned
payload copy. Callers needing a pin can still request a shared owned object.

`visit_verified_encoded` can also provide a callback-scoped capability for the
exact raw or Zstandard payload authenticated by decoding. Native readers reuse
bounded frame/decoder workspace. Ordinary role reads and existing decoded entries keep
a full-frame BLAKE3 digest alongside their canonical parts, within
the same byte budget. A later encoded visit checks that digest against the exact
newly read frame before reusing its canonical parts, avoiding another decode and
canonical hash. The proof binds the codec, header and source child locators too;
a decoded cache hit alone never authorizes new encoded bytes. Encoded
visits never force owned cache admission, and no second payload cache is kept.
Proof hashing is lazy: a fully decoded one-pass encoded visit with no matching
resident entry does not compute a digest that would immediately be discarded.
Borrowed cache admission computes the proof only after its payload fits; later certified
hits still hash the newly read complete frame before granting the capability.

Extent namespace checks and range reads also borrow authenticated pages and byte
leaves. They preserve inherited length/height checks, sparse range behavior and
the same frame, source, decoded-byte and edge charges. Callers needing an owned
pin can still request one through the ordinary object API.

Resource closure copies defer extent byte-leaf kind/length checks to the leaf's
ordinary authenticated copy visit. Exact physical completion records retain a
three-byte byte-length fact, so deduplicated occurrences still check later role
requirements. Every declared role retains its ordinary frame, source and
decoded-byte quota charge; invalid roles fail before their leaf is exported.
Content remapping uses 32-byte identity keys, while completion keeps the full
44-byte source reference. Disposable spill records retain only these facts and
pending references, never payloads or ancestor bodies. Output ordering and
default/preserve-source encoding policies are unchanged.
The transient active marker shares a bit with the mapped frame span, whose
valid range leaves that bit unused. Pending and completed byte lengths fit in
three bytes under the existing 8 MiB object bound. These compact records change
only disposable workspace, keeping ordinary cycle detection and exact locators.
Physical validation stores a four-byte direct-role fact: schema-1 kind and
bounded body length/branch height, or an opaque marker that rejects every typed
role. The fact remains keyed by the full expected identity, offset and span.
Incoming extent length requirements remain 64-bit and must match exactly.
Header inventory uses six bytes for the independently bounded frame span and
decoded length. These widths follow admitted wire bounds, and full-width
incoming spans are compared without truncation.
Small physical read windows recycle an evicted buffer under cache pressure;
new bytes still pass the full frame decoder before they gain authority. The CLI
uses a 4 MiB source cache for encoded copies and releases optional source
caches after copying and before output validation.
A generic adapter supplies no encoding and falls back to ordinary encoding. `SealedWriter::set_preserve_source_encoding(true)` and
`SealingOptions::preserve_source_encoding` explicitly opt into this policy;
`pack_commit_with_options` and `pack_verified_commit_with_options` carry it
through full graph and namespace verification. The default still encodes at
the configured level. Preserved encodings can differ from that default for a
source written at another level; canonical IDs, child-role checks and quotas
remain unchanged.

`put_unretained` is a strict write with deferred decoded-cache admission. Native
stores still compute identity, validate the schema and authenticate every child,
but retain only exact type/provenance metadata for a newly appended object.
This lets a publication write final pages from an arena without copying their
bodies and child vectors into the cache. An adapter's default is ordinary `put`.
Duplicate references, stored frame bytes and publication behavior are unchanged;
the first subsequent payload read uses normal authenticated cache admission.

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

## Live flat maps

`LiveMap` and `LiveMapReader` expose the bucketed authenticated delta as a
supported library API. Native callers retain an editor across small updates:

```rust,no_run
# fn example(store: &mut sac::NativeStore) -> sac::Result<()> {
let mut map = store.live_map()?;
map.set(store, b"record-1", b"new bytes")?;
map.publish(store)?; // ordinary native durability barriers
assert_eq!(map.reader(store)?.get(b"record-1")?, Some(b"new bytes".to_vec()));
let exported = map.checkpoint(store)?; // incremental merge, ordinary resource snapshot
// Publish exported explicitly when switching the selected view to ordinary resources.
# Ok(()) }
```

Opening authenticates the complete bounded view. Keep the editor instead of
reopening per edit. Checkpoint and publication cadence are application choices;
`set` alone does not acknowledge durability. A reader holds an immutable view;
use a native pin when the backing generation may be replaced. Reopen the
editor with `store.live_map()` after native compaction or another physical
relocation; the old editor holds references into its original backing store. See
[the live-map profile](../specs/05-live-map-v1.md) for limits and compatibility,
and [the runnable example](../examples/live_map.rs) for native publication,
old-generation pins and ordinary resource export. The separate `MemtableStore`
API retains its own WAL, checkpoint profile, and concurrency semantics.
