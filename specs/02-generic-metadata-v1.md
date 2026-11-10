# Generic container metadata profile, version 1

The optional `sac.metadata.v1` profile adds application-independent metadata to
one SAC1 snapshot. It can coexist with any number of other application profiles.
It changes no core wire schema and has no dependency on an application. An absent profile
means no container metadata; an empty profile is also legal.

## Root and entries

The snapshot declares `["sac.metadata.v1", 1, root_index]`. Its root is a kind-8,
canonical-schema-1 object with exactly one strong child, a core kind-3/4 directory:

```
["sac.metadata.v1", "root", 1, h'8100']
```

The payload bytes are deterministic CBOR `[0]`, naming child slot zero. The
ordinary core directory is flat. Each entry is a regular file, its byte name is
an ASCII namespaced ID from the core grammar (1–128 bytes), and its file content
is exactly one deterministic CBOR value in SAC's core subset. Values support
integers, bytes, text, arrays, maps, booleans and null; tags, floats, indefinite
lengths, nonminimal integers, duplicate or misordered map keys, and trailing
items are rejected. Nested maps may have non-text keys. Values are self-contained
data: bytes that resemble a hash, path or address do not retain another object.
Core file extents provide all strong dependencies needed for large values.

A value has at most 8 MiB encoded bytes and obeys core CBOR depth/item bounds.
There is no fixed whole-map size: resource entry, logical-byte, memory, temporary
storage and elapsed-work limits govern the collection. Reader-local allocation
ceilings may be tighter than wire limits. Unknown entry attributes are legal and
must survive lossless copying; new entries normally have empty entry metadata.

Keys belong to their named namespaces. Version 1 defines no mandatory keys and
no required feature IDs. For example, `org.example.title` may contain text while
`org.example.thumbnail` contains bytes. Unknown keys and nested fields are data,
not unsupported capabilities. An unknown required capability scoped to this
profile prevents its interpretation/editing; generic core recovery remains
available. Unknown profile versions are preserved as opaque strong closures.

## Identity, updates and access

Metadata is committed snapshot content and participates in snapshot identity.
Changing it does not change unchanged file-byte digests, application profile
objects, or the main resource-directory root. Lossless compaction/recovery
preserves the metadata profile's canonical IDs. Local accelerators are not
metadata in this profile.

The Rust writer uses a 4 KiB directory page target and 64 KiB value chunks.
Small values are inline within the page's existing allowance. These are writer
policies, not new wire restrictions. Point reads follow only the selected key's
route and value extents. Key enumeration does not hydrate extent-backed values.
Persistent edits reuse unchanged directory pages and value extents. Writers do
not deserialize or rewrite unrelated keys or other application profiles.

A routed miss alone is not certified absence. The API exposes an unverified-miss
state; its convenience getter checks directory completeness once when needed.
Owned-value decoding is optional: encoded-value APIs preserve canonical bytes
and avoid allocating a structured value tree. Full profile verification checks
flat key grammar, regular-file bounds and every canonical value.

## APIs and commands

`v1::metadata::MetadataReader::open` discovers the optional profile in a snapshot.
`get` returns an owned value, `get_encoded` returns canonical bytes, and
`lookup_encoded` exposes the route-miss distinction. `visit_keys` streams keys
and encoded lengths; `verify` validates the entire profile. `export` writes
canonical CBOR files and the standard reversible extraction report into a new
directory.

`MetadataEditor::open` starts persistent edits against a snapshot. `set`,
`set_encoded` and `remove` affect one namespaced value; `finish` returns the new
snapshot, leaving commit publication to the caller. Setting identical bytes or
removing an absent key is a no-op. `set` replaces the selected whole value;
applications updating nested fields should read/modify that value while keeping
unknown fields. Other keys, profiles and feature declarations are preserved.

The native CLI provides `sac metadata list|get|set|remove|export`; its guide
describes paths, input formats and transaction restrictions. The independent
Python reader's `metadata` command can list, read or export this profile without
any application executable. Exported value bytes are sufficient for lossless
recovery, including unknown and binary fields. Core verification and metadata
validation do not establish the semantics of other profiles or publisher trust.
