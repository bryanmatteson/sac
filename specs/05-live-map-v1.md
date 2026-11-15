# Authenticated live map v1

`resources::LiveMap` is a portable flat byte-name map with a standard immutable
resource snapshot as its base and an authenticated bucketed Patricia trie as its
delta. `NativeStore::live_map` opens the selected map or creates an empty editor
for a new live store. Retain the editor across updates. `set` appends immutable
objects and changes the editor root only after successful admission and writes.
`publish` uses the existing native publication protocol, including the chunk
barrier before root-slot installation and the slot synchronization before success.
An unsuccessful publication poisons the writer according to the native protocol.
No sidecar, deferred durability acknowledgment, or auxiliary lookup index is used.
Native compaction preserves canonical identity and old pinned readers. Reopen
the editor after compaction/relocation to use the replacement physical references.

Keys are nonempty resource components of at most 4,096 bytes: no NUL, slash,
`.` or `..`. Values are byte strings of at most `MAX_CHUNK_SIZE - 8` bytes. Empty
values are supported. Nested paths, metadata, deletion and concurrent editor
mutation are outside this profile. Bounds charge the base plus delta, including
shadowed base records: at most 1,000,000 retained records and 512 MiB of logical
key/value bytes. These are logical limits, not a total RSS bound. `checkpoint`
releases the delta's charge. Applications choose checkpoint and publication cadence.

## Snapshot and compatibility

The kind-2/schema-1 snapshot has exactly two common children: an empty standard
kind-3/schema-1 resource directory at index 0 and the live-map root at index 1.
Its sole profile is `["sac.live-map.v1", 1, 1]`; its sole feature is the unscoped
required capability `[null, "sac.live-map", 1, true]`. Readers that do not
understand this capability MUST reject resource interpretation. The empty
outer directory is not the logical map. Unknown profiles, features, nonempty
outer directories, and malformed declarations are rejected by the owner.

The kind-8/schema-1 root is deterministic CBOR:

```
["sac.live-map.v1", "root", 1, payload_bytes]
```

The payload is CBOR `[0, 1]`. The two strong children are the plain base
resource snapshot and the bucket-trie profile root. All dependencies use ordinary
authenticated strong references. Generic core closure copying, validation and
packing preserve these references. Resource-only readers and CLI operations
reject the required capability; they can consume an explicitly exported snapshot.
`checkpoint` returns that ordinary resource snapshot and leaves the editor with
an empty delta. Export publication is explicit: call `store.publish(exported)`
if the selected archive should become a plain resource archive. Publishing the
editor instead retains the live-map profile, even with an empty delta.

Ordinary resource APIs and wire encodings remain unchanged. `LiveMap::open`
imports a fully verified plain flat resource snapshot with no features/profiles
and empty file metadata. It also imports the previously qualified sole
`org.sac.experimental.bucket-dual-map` profile (version 1, no features), whose
root has the same two-child layout. The next live snapshot emits the stable
profile and required capability while retaining exact authenticated delta
references. Other experimental trie/paged profiles are not implicitly converted.

## Bucket encoding

The existing wire namespace `org.sac.experimental.bucket-trie` is deliberately
frozen; the historical spelling does not change on promotion. Each object is
kind 8/schema 1 with CBOR envelope `[namespace, type, 1, payload_bytes]`.
The root's payload is CBOR `[entry_count, 0]` with one node child, or
`[0, null]` with no children for an empty trie.

Node payloads are CBOR byte strings containing bounded little-endian records.
Both begin with a u16 prefix length and the prefix bytes. `bucket` then contains
a u8 row count (1–16), followed by rows of u16 suffix length, suffix bytes and
value encoding. Keys are strictly ordered. Combined suffix bytes are at most
1,024; singleton buckets have an empty suffix and common prefixes are maximal.
`branch` contains a u8 terminal flag, its value encoding when present, then a
u16 edge count and strictly ordered u8 labels. At least two alternatives,
counting the terminal, are required. Each edge consumes one strong node child.

A value tag from 0 to 128 gives an inline byte length followed by those bytes.
Tag 255 is followed by a u32 length and consumes one strong `value` child.
Terminal/row children precede edge children in encounter order. Unused children,
unknown flags/tags, trailing bytes and invalid bounds are rejected. Node canonical
size is at most 16 KiB. Descriptor envelope canonical size is at most 64 KiB.
A `value` payload is CBOR `[length, 0, bytes]` for values of 129–49,152 bytes,
or `[length, 1, 0]` with a single kind-7/schema-1 byte-object child for larger
values. Byte children have no children and their actual length must match.

## Admission and incremental merge

Opening fully verifies the plain base, all trie routes, exact entry counts,
valid complete keys and external value types/lengths. Trie traversal is iterative,
bounded to 1,000,000 node visits and 32 MiB of queued key prefixes; verified
entry materialization is bounded by the logical limits. Reader construction
retains only the two layer handles and does not preload a key index. A miss is
authoritative only for a fully admitted or successfully constructed view.
All subsequent route reads authenticate references through `ObjectStore`.

Edits rewrite the affected trie path and bounded leaf bucket. Checkpoint verifies
and sorts delta entries, then merges batches of at most 512 changed keys through
the ordinary resource builder. Unchanged base pages retain exact references;
large delta byte objects become shared extent references instead of being copied.
The editor selects the replacement base and clears the delta only after every
batch and the replacement snapshot succeeds. An earlier failure leaves the
selected view unchanged, though unreferenced appended objects may remain.
`verify` explicitly materializes the complete logical map; it is not used on
the normal per-edit or point-lookup path.
