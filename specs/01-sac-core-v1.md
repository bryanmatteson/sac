# SAC1 core format and API

SAC1 is a single-file, product-neutral container for named resources and
versioned application records. Sealed and live files share canonical objects,
schemas and snapshot identity. Their locator/publication policies differ.
This prerelease implementation supports the current SAC1 format only.
Earlier section containers and application-private archive layouts are not
production read, write, or migration interfaces.

The owning implementation is [`src/v1`](../src/v1/); the generic tools are
documented in [sac1-cli.md](../docs/sac1-cli.md). This document specifies the
current core wire layout and explains the public APIs. Product profiles define
their own records and semantic validation. Bounds below are wire limits;
operations additionally receive finite work, memory and output limits.

## Physical layout

All fixed-width fields use unsigned little-endian integers. Record starts and
frame spans are multiples of eight. Padding and reserved bytes are zero.
Offsets, lengths and half-open intervals use checked 64-bit arithmetic. A
physical locator is `offset:u64 || frame_span:u32`; span includes its frame
header, stored canonical bytes, physical child locators and padding.

```
sealed:  [128-byte preamble][frames ...][commit][160-byte trailer at exact EOF]
live:    [preamble + zero fill to 4096][slot A][slot B]
         [frames ...][commit][trailer][later frames/commit/trailer ...]
```

Live slots each occupy 4,096 bytes at offsets 4,096 and 8,192. The first live
record is at 12,288. Sealed records begin at 128. A live reader pins the selected
committed end and ignores an unselected suffix. A sealed reader requires the
selected trailer at the exact transport/file boundary. There is no
concatenation convention or ordinary tail-scan admission.

Optional [recovery records](03-recovery-records-v1.md) protect an exact file in a
sidecar or a sealed checkpoint through `sac.recovery.v1`. They do not change
core framing. Ordinary admission does not scan or decode parity.

### Preamble: 128 bytes

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | Magic `53 41 43 31` (`SAC1`) |
| 4 | 4 | Reserved, zero |
| 8 | 1 | Locator policy: 0 sealed, 1 live |
| 9 | 7 | Reserved |
| 16 | 16 | Incarnation: zero for sealed; fresh random nonzero value for a live installation |
| 32 | 64 | Reserved |
| 96 | 32 | `BLAKE3-256("SAC1/preamble\0" || bytes[0:96])` |

The magic is exactly the four ASCII bytes `SAC1`; it has no newline or control-byte
suffix. Bytes 4–7 are reserved zeros, and nonzero reserved bytes reject even when
the preamble digest is valid. The locator policy remains at offset 8 and the
preamble remains 128 bytes. Earlier eight-byte signatures are unsupported.

Unknown locator policies reject. A framing change requires another major wire
version, not a capability bit. Feature declarations belong to the snapshot.

### Object frame

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | `53 4f 31 00` (`SO1\0`) |
| 4 | 1 | Codec: 0 stored, 1 Zstandard |
| 5 | 1 | Frame revision: 1 |
| 6 | 2 | Child count, at most 1,024 |
| 8 | 4 | Stored byte count, at most 8 MiB |
| 12 | 4 | Decoded canonical byte count, 8 through 8 MiB |
| 16 | 32 | Canonical object ID |
| 48 | 4 | CRC32C of all 56 header bytes with this field zero |
| 52 | 4 | Reserved |
| 56 | variable | Stored canonical bytes |
| following | `12*child_count` | Physical child locators, in canonical child order |
| following | 0–7 | Alignment padding |

CRC32C uses the reflected Castagnoli polynomial `0x82f63b78`, all-ones
initialization and final XOR. Header CRC is a framing check, not membership
authority. Object identity is:

```
canonical = kind:u16 || schema:u16 || child_count:u32
            || child_id[0]:32 || ... || child_id[n-1]:32 || body
object_id = BLAKE3-256("SAC1/object\0" || canonical)
frame_span = align8(56 + stored_length + 12*child_count)
```

The canonical count equals the header count. Expected IDs come from the
authenticated parent or admitted root, not just the fetched header. A decoder
checks the expected ID, the frame's ID and the decoded canonical hash. Every
ordinary child locator names a complete earlier frame: the child frame ends
at or before its parent starts. Full physical verification also checks that
reachable locators identify top-level records rather than apparent frames
inside another frame. Repacking rewrites physical locators while retaining
canonical child IDs and body bytes.

Stored encoding has equal stored/decoded lengths. Compressed encoding contains
exactly one ordinary Zstandard frame, with declared decoded size and at most
an 8 MiB history window. It has no external dictionary, concatenated stream or
skippable frame. The decoder consumes its entire stored span. Writers use raw
encoding when compression would grow the object. Kinds 1 and 2 are always raw.
Full readers support both codecs; bounded pure-Rust decoding remains available
without the native/compression writer features.

### Trailer: 160 bytes

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 8 | `SAC1END\0` |
| 8 | 32 | Preamble digest |
| 40 | 8 | Positive generation; sealed files use 1 |
| 48 | 8 | Exclusive committed end, equal to trailer offset + 160 |
| 56 | 8 | Commit frame offset |
| 64 | 8 | Commit frame span |
| 72 | 32 | Expected commit object ID |
| 104 | 24 | Reserved |
| 128 | 32 | `BLAKE3-256("SAC1/trailer\0" || bytes[0:128])` |

The control region is `[max(first_record, committed_end−65536), committed_end)`.
Commit and snapshot frames fit entirely inside it, each with at most 16 KiB of
canonical bytes. The trailer is the last record of that extent. Its commit span
uses an eight-byte field but must fit the ordinary frame span bounds.

### Live slot: 4,096 bytes

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 8 | `SAC1SLOT` |
| 8 | 32 | Preamble digest |
| 40 | 8 | Positive generation, whose modulo 2 equals the slot index |
| 48 | 8 | Selected trailer offset |
| 56 | 32 | Expected trailer digest |
| 88 | 3,976 | Reserved |
| 4,064 | 32 | `BLAKE3-256("SAC1/slot\0" || bytes[0:4064])` |

Zero slots are uncommitted. Checksum-damaged slots yield a degraded read view
when the other slot admits a commit. Checksum-valid slot headers must match
incarnation, positive generation and parity. Select the highest valid
generation, then validate that trailer, commit and snapshot. Corruption or an
unsupported schema at the selected valid generation is an error; it does not
authorize silently opening an older generation.

## Canonical core bodies

Kinds 1–9 require canonical schema 1. Structured bodies use exactly one
definite-length RFC 8949 core deterministic CBOR item, with minimal integers
and lengths and map keys in strictly increasing encoded-byte order. Duplicate
keys, floats, tags, undefined, other simple values, indefinite lengths and
trailing items reject. Allowed values are integers, byte/text strings, arrays,
maps, booleans and null. Text must be UTF-8. The parser permits at most 64 open
containers and 1,048,576 items per object; byte strings remain opaque until an
owning schema parses them. Canonical byte length, item count and nesting depth are portable wire limits.
Reader allocation budgets are operational limits: reaching one means incomplete
verification, not malformed input. The Rust owned-value decoder uses a
16 MiB requested-allocation budget; its in-memory layout is not a wire rule.
Borrowed readers can validate the same items without constructing value trees.

`index` means an unsigned in-bounds child-table index. `version` is 1 through
`2^32−1`. A namespaced `id` is ASCII, 1–128 bytes, matching
`[a-z][a-z0-9]*(?:[._-][a-z0-9]+)+`.

| Kind | Body |
|---:|---|
| 1 Commit | `[snapshot_index, attestations_index_or_null, local_index_or_null]`; children respectively kind 2, optional kind 9, optional kind 8. Local attachment is live-only and outside snapshot identity. |
| 2 Snapshot | `[directory_index, profiles, features]`; directory is kind 3/4. Profiles are unique, ASCII-sorted `[id, version, root_index]`; the kind-8 root has matching namespace/version and type `root`. |
| 3 Directory leaf | Sorted unique entries `[name_bytes, entry_type, metadata, value]`. |
| 4 Directory branch | `[height, [[exact_subtree_max_key, child_index], ...]]`. |
| 5 Extent leaf | Nonempty `[[positive_length, byte_child_index_or_null], ...]`; null means zeros, otherwise kind 7 with exactly that body length. |
| 6 Extent branch | `[height, [[cumulative_end, child_index], ...]]`; ends strictly increase, relative to this subtree's start. |
| 7 Bytes | Raw body bytes, no children; body at most `8 MiB−8`. |
| 8 Profile record | `[namespace, type, version, payload_bytes]`; dependency roles belong to the profile. Type matches `[a-z][a-z0-9_-]*`, at most 128 bytes. |
| 9 Attestation catalogue | At most 256 byte strings of at most 1,024 bytes each; no children; at most 64 KiB canonical bytes. Carries bounded tagged COSE Sign1 values using the recipe below. |

A conforming producer encodes each catalogue entry as CBOR tag 18 containing `[protected_bstr, {},
payload_bstr, signature_bstr]`. Protected bytes are deterministic CBOR `{1: -19}`,
optionally adding key `4` with a key ID of 1 through 128 bytes. Payload bytes are
deterministic CBOR `["sac.snapshot.v1", purpose, snapshot_id_bstr32]`; purpose is
UTF-8 text of 1 through 256 bytes. The Ed25519 signature is exactly 64 bytes and
signs deterministic CBOR `["Signature1", protected_bstr, h'', payload_bstr]`.
Readers assess each entry independently: malformed envelopes, unsupported
algorithms and signed-snapshot mismatches remain visible as invalid or unsupported
trust material while generic content recovery remains available. Outer catalogue
count and byte bounds remain mandatory. Structural parsing and snapshot binding
do not establish publisher trust. `v1::attestation::parse_cose_sign1` exposes the subject and signing input;
with `trust`, `verify_ed25519` checks a caller-selected public key. The caller
also decides allowed purposes, authorized keys, required signatures and freshness.

Known core bodies use every common child index at least once, except kind 8
whose dependency use is profile-defined. Repeated use of an index is allowed.
Null contributes no edge. Canonical child order is retained during repacking.
Unknown kind/schema semantics are explicit unsupported/opaque states rather
than inferred from bytes. Preserving an opaque object's strong closure does
not establish its semantic validity or trust.

Directory leaves have at most 128 KiB canonical bytes, including child IDs,
and at most 144 KiB physical span. Directory branches and extent pages have
at most 64 KiB canonical bytes and at most 80 KiB physical span. Branches have at least two children and
height 1–16; child height decreases exactly by one. Directory fences describe
disjoint inherited intervals and equal each child's exact maximum. Extent
child lengths equal differences between cumulative ends. Leaves have height
zero. Empty directories use an empty leaf; branch children are nonempty.

Directory keys are byte strings of 1–4,096 bytes, excluding slash, NUL, `.` and
`..`. Entry types are 0 file, 1 directory, 2 symlink. File value is
`[length, storage, data]`: storage 0 is inline bytes of exactly `length`, at most
48 KiB; storage 1 is an extent-root child index with matching logical length.
Empty files use empty inline bytes. Directory value is its root child index.
Symlink value is at most 4,096 target bytes; generic extraction records it.

Metadata is a deterministic text-keyed map of at most 16 KiB encoded bytes.
Built-ins are optional `mode` (0–07777), `mtime` ([signed 64-bit seconds,
0–999999999 nanoseconds]), `media_type` (UTF-8 text at most 4,096 bytes), and
`byte_digest` (32-byte whole-file BLAKE3 digest, regular files only). Other
metadata keys must be namespaced IDs and survive lossless repacking.

Features are `[scope, id, version, required_bool]`, sorted uniquely by encoded
`[scope,id]`. Scope is null for core or a declared profile ID. Unknown required
core capabilities block core content admission; unknown required profile
capabilities block that profile operation. Understood core resources remain
recoverable independently of an unsupported profile.

The optional [generic metadata profile](02-generic-metadata-v1.md) provides
container-wide namespaced values using the existing profile and resource kinds.

## Extension ownership, dependencies and identity

Core kinds 1–9 are allocated here; numeric kinds 10–65535 are reserved for future
SAC specifications. Applications MUST use kind 8, canonical schema 1, with their
namespace/type/application version rather than privately assigning numeric kinds.
Known core kinds require schema 1 in every context, including profile and local
closures. An unknown kind may be preserved opaquely beneath a declared profile
or local attachment when its framing, hashes and complete strong closure check.
It cannot satisfy a known core edge role. Preserving it does not establish
profile validity. Copying such a closure is allowed; interpreting, pruning or
transforming its records requires its owning semantics. Unknown required profile
capabilities stop profile operations while understood core resources remain
recoverable. Unknown required core capabilities stop core content operations.

Every dependency needed for a self-contained portable profile MUST be reachable
through the common strong child table. A hash, path or identifier only in an
opaque payload does not retain its target: profiles must explicitly specify any
such weak/external reference and its missing-target behavior. Portable application payloads
MUST NOT depend on physical frame offsets or a particular codec/layout. Local
accelerators belong to the live-only local attachment or must remain valid
when generic tools rewrite locators. Export removes local attachments only with
caller authorization; acceleration owners define rebuilding behavior.

The optional `sac.recovery.v1` profile is an explicit physical repair aid. It
strongly retains its protected canonical Commit, while its parity and discovery
descriptors bind one particular physical checkpoint encoding. These layout
bindings confer no application or publication authority. Generic relocation
preserves profile bytes and canonical content but may invalidate physical repair;
the owning recovery API rejects unusable bindings and requires regeneration.
This exception does not permit application profiles to make offsets authoritative.

Object and snapshot IDs identify the canonical graph, including child order,
chunk/extent boundaries, directory shape, metadata, profile declarations and
inline-versus-extent choices. Equal file bytes do not imply equal snapshot IDs.
`byte_digest` identifies one logical file stream independently of its chunking.
Commit IDs additionally cover attestations/local attachments; a digest of the
physical file identifies one exact encoding. Identity-preserving repacking
preserves canonical objects and changes only physical encoding/locators.
Rebuilding/normalizing a tree is a separate operation and may change its ID.
Reproducible producers must agree on a separately versioned packing recipe
covering input metadata, chunking, tree construction and child ordering; SAC1
core does not mandate one packing policy or unique physical encoding.

## API and verification boundaries

`ReadAt` supplies checked `len()` and exact positional reads. `Reader::open_at`
admits the bounded selected commit/snapshot control region. `PositionalStore`
implements read-only `ObjectStore` over a `ReadAt`. Native file users use
`NativeReader::open`/`open_file` and its pinned snapshot, which survives path
replacement. `ObjectStore::get` authenticates a referenced frame;
`get_shared` allows immutable cache views; `get_verified_shared` authenticates
their expected ID and intrinsic core schema by default. Stores that already
established those checks can return the same verified view directly.
`validate_core_edges` checks required child kinds, schemas and direct role
bindings, including a profile root's namespace, type and version. It receives
an authenticated child-fetch callback. Inherited tree fences and lengths still
belong to full resource validation. `put` appends canonical objects with explicit
ordered dependencies. `MemoryStore` is for bounded
in-memory workloads, not an unbounded-file transport.

`ArchiveReader::lookup_shared` returns a page-pinned entry with borrowed name
and metadata; `None` is an unvalidated route miss, not certified absence.
`open_file` retains an authenticated descriptor for repeated caller-buffer
`read_into` operations. `read_range_into` resolves and reads into caller storage;
`read_to` streams to a writer. Range bounds, extent geometry and dependency
authentication still apply. Caller-retained pages live outside cache residency.
`wire::FrameDecoder` returns authenticated frame views borrowing raw input or
reused decoded output; taking ownership is an explicit copy/transfer operation.
Encoder/output buffers and native codec contexts may be reused within the
canonical/frame limits. Native idle decoder state shares the decoded-cache
budget; live writers own their separate encoder workspace.

Checked persistent-tree mutations may obtain `ObjectStore::rewrite_source(parent)`
and pass its opaque `RewriteSource` to `rewrite`. Generic stores return no source
and use ordinary strict `put`. Native stores authenticate the exact prior parent
occurrence within the current committed incarnation; staged parents fall back to
strict `put`. Every output edge must remain bounded and precede the new parent.
An unchanged edge is the full expected ID, offset and span from that parent;
new or relocated edges retain strict child authentication. Tree callers still
check roles, shape, ordering, fences and lengths at their existing scope.

This operation carries the prior tree's deferred subtree/layout validation. A
parent's canonical hash commits to child IDs, not physical child locators, so
carrying an inherited edge does not certify that child locator or payload.
Poisoned inherited hints may remain deferred until dereference or full closure
verification, which must reject them. The operation neither asserts full graph
validity nor inserts skipped children into the authenticated-child cache. Tokens
from another file or an earlier replaced incarnation reject; ordinary `put`
continues to authenticate all children under its normal cache policy.

For a live database, obtain a fresh 16-byte nonzero incarnation from the host's
secure random source, then use the canonical native constructor:

```rust
use sac::v1::{NativeStore, resources::{ArchiveBuilder, ArchiveReader, Limits}};

// `path` is a new destination; `fresh_incarnation` comes from the host RNG.
let mut store = NativeStore::create_live(path, fresh_incarnation)?;
let mut builder = ArchiveBuilder::bulk(&mut store, Limits::default())?;
builder.add_file(&[b"hello.txt".to_vec()], b"durable content")?;
let snapshot = builder.finish()?;
store.publish(snapshot)?;
let pinned = store.pin()?;
let resources = ArchiveReader::open(&pinned, snapshot, Limits::default())?;
resources.read_to(&[b"hello.txt".to_vec()], &mut output)?;
```

The returned publication is durable only after both barriers complete. A reader
may use the publication's pinned snapshot and exact generation while the writer
continues appending. `Header` remains a transitional source constructor; only
the preamble incarnation, not its source-level lineage field, is persisted.

`resources::ArchiveBuilder::bulk` externally sorts initial archive entries and
encodes directory pages once. `with_limits`/`from_directory` perform persistent
changed-path edits. Builders accept files/readers, directories, symlinks and
sparse extents; `finish` returns a kind-2 snapshot. `pack_snapshot_with_limits`
copies its selected closure to a forward-only `Write`. `pack_commit_with_limits`
also retains attestations and explicitly removes a live-local attachment;
callers must authorize that removal. Both produce a final sealed trailer.

`ArchiveReader` offers streaming enumeration, exact content ranges, full-file
streaming, directory validation, core verification and confined extraction.
An unchecked miss is `NoMatchUnverified`; authoritative absence requires the
source-bound `DirectoryValidated` token. A successful selected route does not
prove consistency of off-path index nodes. `NativeReader::validate_with_limits`
checks physical framing/top-level locators, selected object closure and direct
core child roles;
`ArchiveReader::verify` additionally checks directory/extent invariants and core
resource content starting at its snapshot. Use `verify_commit` with the selected
commit to include its attestation/local dependency closure as well. Profile
semantics and publisher trust remain separate.
A declared whole-file digest is verified against the complete logical stream
during extraction; selective ranges leave that digest unchecked.

All traversals receive finite `resources::Limits` for frames, edges, depth,
source/decoded bytes, memory, time, temporary disk, entries and logical output.
`Limits::max_depth` bounds resource namespace paths, not profile ancestry.
Closure verification and packing use iterative reference frontiers and active
ancestor sets, retaining no decoded ancestor bodies. Memory-only helpers cap
frontier/index memory; native walkers may spill under their disk reservation.
The generic `TraversalLimits` graph depth defaults to one million and remains
separate from the 256-component resource path default. Frame, edge, byte, memory
and elapsed-work limits still apply. Reloading a parent after its children is
charged as another frame/decoded visit. Limits charge logical occurrences in
resource namespaces and expanded sparse bytes. Generic graph verification and
copying deduplicate only completed identical physical `ObjectRef` occurrences;
a different offset/span with the same ID is authenticated separately. Active
ancestors remain tracked until completion, so sharing does not mask cycles.
Directory enumeration and output quotas still charge each logical path.
Exhaustion returns `Error::Limit` with incomplete verification, not a successful
absence result. Native resource verification and packing spill the frontier,
active hashes, completed physical references and hash-to-output remapping under
one `Limits::max_temp_bytes` quota. Their fixed resident prefixes and I/O scratch
reserve 384 KiB against the operation memory limit, in addition to checked object
buffers. Index growth temporarily reserves both old and replacement disk tables
before extending a file. Minimal builds keep a finite resident index and return
a memory limit error when it fills. Store caches and caller-retained objects
have their separately declared budgets.

Native writers hold publication authority over the destination and file,
append changed paths, durably order data/extent before the alternate slot,
then durably order the slot before acknowledging. New named files are exposed
only after their first publication. Writable reopen reconciles/stabilizes
recovered heads; a no-op needs a known durable baseline. A damaged-slot view or
unowned suffix requires explicit recovery; no ordinary writer truncates it
merely because it is outside the selected extent. Publication errors poison a
writer until reconciliation. Compaction copies a pinned closure and fences
installation; older pinned readers retain their original file.

Native compaction prepares and synchronizes its private candidate and an
old-inode recovery link before cutover. The writer-held interval catches up
within explicit byte, time and garbage limits, publishes the candidate through
the ordinary barriers, revalidates identities, then renames and synchronizes the
destination namespace before handing over authority. Uncertain replacement
preserves the recovery link and poisons the writer. After successful replacement,
optional background link removal has separately reported retained-inode bytes
and errors; another candidate is refused until that cleanup is complete.

Foreground readers and the compaction candidate share one native decoded cache
(32 MiB by default). Entries bind file identity, offset, span and expected ID;
decoded buffers, exact LRU metadata, validation keys and forwarding metadata
compete within its budget. Caller-held immutable views can outlive eviction;
the cache budget does not bound arbitrary application retention of those views.
Bounded archive operations separately account their retained buffers. A uniquely owned evicted byte-object buffer
may become the next in-flight read allocation; the new frame is authenticated
again. Reuse never mutates a pinned payload or supplies an identity shortcut.

The optional `http` feature provides `http::HttpSource`, a `ReadAt` source
pinned by a strong ETag and length from HEAD. All GETs send `If-Match`, require
an exact Content-Range and unchanged ETag, and reject redirects, representation
coding and ignored ranges. `HttpLimits` bounds each request, aggregate wire-body
reservations, timeouts and raw cache residency (default 1 MiB). Exact reads are
the default; `HttpLimits::interactive()` permits at most 32 KiB backward
coalescing on small reads. Admission still uses two core reads after the separate
HEAD. Cache hits reuse physical bytes and never skip expected-ID authentication.
Statistics distinguish raw caller bytes, requested spans and consumed response
bodies; protocol headers are outside those body counters. `PositionalStore`
adapts this source to the ordinary resource reader.

`resources::salvage` scans within finite budgets and repairs physical hints
against an explicitly trusted snapshot ID or intact admitted authority. It
writes a new file, preserves original input, and does not promote an orphan
commit from hash validity alone. Product profiles own their record semantics and validation; the generic tool
does not interpret application-private layouts.

## Reproduction

```
cargo test --test sac1_cli --test sac1_attestation
cargo test --features native --test sac1_resources --test sac1_bulk
cargo check --no-default-features --features native --bin sac
```

These exercise real tools and owning behavior. Speed/size thresholds require
their recorded workload and environment; existence of an API or format vector
does not establish them. The public command documentation describes output
layouts, finite quotas, no-clobber installation and each verification scope.


## Native same-file maintenance

Same-file reclamation is an implementation operation and does not change SAC1
magic, object identity, frame layout or publication authority. An implementation
must retain the complete physical closure of both durable heads and every active
cooperating reader before reclaiming storage. Header, locator and padding bytes
of retired frames remain physically framed for older pinned generations. Native
readers retain authenticated root closures; arbitrary retired object locators
are not lifetime pins. Destructive frame reuse and sliding compaction require
durable redo before overwriting source bytes. A pending transaction must block
reader admission until recovery completes. Completed containers remain ordinary
self-contained SAC1; implementation journals are temporary recovery state.

The Rust native API's cooperation, owner-private storage, persistent journal,
limits and filesystem support contract is in
[Same-file native maintenance](../docs/same-file-maintenance.md). Uncoordinated
and cross-host readers require the existing copy and replace operation.
