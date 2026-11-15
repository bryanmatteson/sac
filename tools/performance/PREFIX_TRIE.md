# Experimental Merkle prefix trie comparison

`src/prefix_trie.rs` is a development prototype of a persistent, bytewise
Patricia trie. It implements a flat byte map. It is outside the library API and
does not change the SAC wire format, resource directory representation or
default writer. It is intended to measure whether rewriting a small trie path
is preferable to rewriting resource directory pages.

Both representations are Merkle structures. The current resource map uses
sorted, bounded B-tree pages. The prototype compresses common byte prefixes,
uses sorted byte labels with up to 256 outgoing edges, and stores one value per
leaf. An edit rewrites the affected leaf and its ancestors. Unchanged subtrees
and old roots remain immutable. Construction is canonical across insertion
order for the same key/value set. There is no deletion API in this prototype.

## Authentication and representation

All trie records use **core kind 8, version 1**, with the application envelope
`["org.sac.experimental.prefix-trie", type, 1, payload_bytes]`. `payload_bytes`
is deterministic CBOR. No reserved core kinds are allocated.

| Type | Payload | Common strong children |
| --- | --- | --- |
| `root` | `[entry_count, root_index_or_null]` | Empty, or the root node at index 0 |
| `leaf` | `[suffix_bytes, storage, data]` | Empty for storage 0 (inline bytes); one kind-7 blob for storage 1 (`data` is its byte length) |
| `branch` | `[prefix_bytes, terminal_index_or_null, [[byte_label, child_index], ...]]` | Optional terminal first, then edges in increasing label order |

A terminal is an empty-suffix leaf. A branch has at least two alternatives;
unary branches are disallowed. Every child-table position is used exactly once
in payload order. Different edge labels may refer to the same immutable object
at different positions, allowing shared suffix subgraphs. Inline values stop
at 48 KiB, matching the resource map's inline threshold. Larger values use a
single authenticated byte object, rather than the resource map's extent tree.

All reads use `ObjectStore::get_verified_shared`; all writes use ordinary
`ObjectStore::put` with exact strong children. There is no caller-supplied hash
admission shortcut. The owning verifier checks record types, namespace and
version, branch ordering/arity/indexes, terminal roles, key limits, blob
kind/length, and declared cardinality. Core closure verification alone cannot
validate opaque application semantics. A missing route is authoritative only
after owning-profile verification, as documented by `get`.

Limits are 4,096 key bytes, `MAX_CHUNK_SIZE - 8` value bytes, 1,000,000 entries
and verification visits, 512 MiB of materialized key/value bytes during
verification, and 32 MiB of queued key prefixes. Traversal and path rewriting
use heap stacks. The verifier returns the complete logical map for comparison.
This deliberately bounded development interface is not a streaming reader.

The root is declared as a snapshot profile alongside an empty core resource
directory. Generic SAC copy/seal operations preserve its complete strong
closure, but resource readers see an empty directory. This is **not** a drop-in
replacement for resource files: resource metadata, hierarchy, range reads,
large extent files, deletion and production profile/API compatibility remain
outside this prototype.

## Durable workload comparison

Build the single executable containing all comparison backends:

```sh
cargo +1.97.1 build --verbose --locked --release \
  --manifest-path tools/performance/Cargo.toml --bin trie_workloads
```

Select the executable actually produced by this build. With a managed Cargo
shim, the verbose rustc invocation's `--out-dir` and `-C extra-filename` identify
the emitted `deps/trie_workloads-<suffix>`; an older convenience path may belong
to another build. The runner records the selected binary's SHA-256.

```sh
python3 tools/performance/run_trie_comparison.py /absolute/path/to/trie_workloads \
  "$HOME/Documents/Developer/sac/prefix-trie/resident"
python3 tools/performance/run_trie_comparison.py /absolute/path/to/trie_workloads \
  "$HOME/Documents/Developer/sac/prefix-trie/spill" --spill \
  --cases updates resize
```

The default is three alternating backend pairs for each of four workloads,
with 8,192 edits and publication either at the end or every 128 edits:

- `updates`: replace 64-byte values across 4,096 keys in permuted order.
- `inserts-ordered`: insert 8,192 odd numbered keys among 8,192 existing even
  numbered keys, in increasing key order.
- `inserts-shuffled`: insert the same odd keys in a fixed permutation.
- `resize`: two passes over 4,096 keys, cycling through 0, 8, 64, 512, 4,096
  and 65,536-byte values, including inline/blob transitions.

These are the same key and payload sequences as `map_workloads`. Fixture
construction happens in a memory store for both backends, followed by a copy
of only the live closure into a fresh native live store. This avoids giving
the trie a historical seed log and append index. Inputs, paths and expected
contents are prepared before timing. Both backends use the same native store,
compression policy, default budgets, publish schedule and executable.

`cpu_ns` and `wall_ns` cover edits. `publication_cpu_ns` and `publication_ns`
cover snapshot construction plus native durable publication, reported
separately. Add edit and publication times for the durable workload cost.
Every new publication checks one chunk barrier and one slot sync. Repeating an
already durable canonical root reuses its existing publication without extra
barriers; the runner records attempts and actual new generations separately.
No sync is removed or amortized differently between backends. A publication cadence of
zero means the whole edit sequence is one durability batch; it does not mean
individual edits are durable before the final publication. For per-edit
durability use `SAC_MAP_PUBLISH_EVERY=1` or runner `--cadences 1`.

Each run reopens the selected native snapshot, authenticates the whole closure,
verifies the owning representation, checks every expected key/value (including
untouched initial keys), validates every old pinned value, and seals the result.
Trie sealed output is reopened and checked through its owner too. Both
backends must produce the same length-delimited logical-content digest.

The runner preserves individual samples, medians and ranges, host load, and
whole-process user/system CPU separately. Whole-process CPU includes seed
construction, checks and sealing; use the in-binary edit CPU for update speed.
Lookup figures cover complete successful reads after structural verification.
`lookup_cpu_ns`/`lookup_ns` measure a warmed sequential traversal;
`random_lookup_cpu_ns`/`random_lookup_ns` measure a fixed key permutation.
`miss_lookup_cpu_ns`/`miss_lookup_ns` measure 4,096 absent keys outside the
record-key range. These are warm reads, not cold-storage latency.
`lookup_prepare_cpu_ns`/`lookup_prepare_ns` separately expose owner reopen and
reader construction, including complete base admission and paged-delta admission.
The map reader is already open for verification; its prepare figure is not a
cold-open comparison. No map payloads are preloaded into the dual reader.

## Checks

```sh
cargo +1.97.1 test --no-default-features --features native \
  --test sac1_prefix_trie --test sac1_live_append \
  --test sac1_resources --test sac1_rewrite
```

Tests cover model equivalence, empty/prefix/binary/long keys, fanout 256,
insertion-order identity, growing/shrinking values and inline/blob transitions,
failed path writes, old roots/pins, spill with no decoded cache, native reopen,
generic sealed relocation, malformed authenticated nodes, hash substitution,
and forged child hashes/locators. Publication fault injection covers a failed
chunk barrier, torn slot, and slot-sync failure, including writer poisoning
and the existing old/new recovery rules.

## Dual representation

`src/dual_map.rs` adds a packed resource B-tree base with a recent-write trie
overlay. Edits update only the overlay. Reads try the overlay and fall back to
the base, so an empty value overrides a base value rather than acting as a
deletion. Deletions/tombstones are not implemented.

The published snapshot declares `org.sac.experimental.dual-map` version 1.
Its kind-8 application root has payload `[0, 1]` and exactly two strong
children: the plain resource base snapshot and the trie profile root. This
binds both layers into the published Merkle closure. Native publication admits
the control objects and applies the same two durability barriers. The generic
outer resource directory is empty, so generic resource
readers cannot accidentally return stale base files. A dual owner supplies the
combined view. The prototype rejects bases containing additional profiles or
features, and its full verifier rejects hierarchy and nonempty file metadata.

Opening a dual map authenticates the complete immutable base and admits its
flat-file shape once. Checkpointing authenticates the delta, checks replacement
lengths against authenticated base routes, and applies sorted batches of at most
512 changed keys through `ArchiveBuilder::set_files_batch`. Untouched directory
pages and file/extent references retain their exact IDs and physical locators.
Large delta values are wrapped in extent descriptors referencing their existing
authenticated kind-7 byte objects; payloads are neither copied nor put again.
Only changed leaves and their ancestors are rewritten. Batches can revisit a
boundary page or ancestor; this is not a global one-write-per-merge promise.
Both in-memory roots and aggregate size/count accounting change only after all
batches and the replacement snapshot succeed.
A failed merge leaves the prior state readable. The next durable publication
selects the completed base and residual overlay together; older published
roots and pinned readers remain immutable. Generic SAC sealing preserves the
dual view without interpreting it. Final resource export checkpoints the
overlay and seals the resulting ordinary resource snapshot, usable by the
existing `ArchiveReader` without a custom profile.

```sh
python3 tools/performance/run_trie_comparison.py /absolute/path/to/trie_workloads \
  "$HOME/Documents/Developer/sac/prefix-trie/dual-resident" \
  --backends map trie dual --cadences 128 --merge-every 1024
```

`SAC_MAP_MERGE_EVERY` (runner `--merge-every`) controls the dual checkpoint
interval in edits; zero disables periodic merges. A final boundary is left
unmerged deliberately, so live lookups and live packed size include a nonempty
overlay. A default 8,192-edit run has seven intermediate merges and a final
1,024-entry overlay, followed by a separately measured final export merge.
This avoids reporting only the favorable empty-overlay read cost.
Using `--merge-every 4096` instead leaves one intermediate merge and a final
4,096-entry overlay for these workloads. Merge cadence does not change the
publication cadence or durability barriers; published snapshots select both
layers even between merges.

`merge_cpu_ns`/`merge_ns` report intermediate merge work separately from hot
edits. `total_cpu_us` and `durable_wall_us` in the summary include edits,
intermediate merges and durable publication. `with_export_cpu_us` also includes
the final native export merge. Sealed encoding itself remains outside these
timers for all backends. `live_sealed_bytes` measures the complete reachable
live representation before final export; `sealed_bytes` measures the final
representation (an ordinary packed resource snapshot for the dual backend).
Appended bytes include intermediate merges/publications and exclude final
export, whose CPU/elapsed cost is reported separately. The benchmark validates
both generic dual packing and the standard resource export, including every
value, after relocation.

Dual tests additionally cover overlay precedence, untouched base values,
checkpoint idempotence, failed-merge atomicity, wrong layer roles, old mixed
roots after checkpointing, durable recovery with both layers present, and
ordinary resource-reader compatibility after final export.

The earlier full-base rebuild remains available only as the `dual-rebuild`
benchmark control. `dual` uses incremental checkpointing. Both controls use the
same delta, base admission, publication schedule, native writer and executable:

```sh
python3 tools/performance/run_trie_comparison.py /absolute/path/to/trie_workloads \
  "$HOME/Documents/Developer/sac/prefix-trie/incremental-resident" \
  --backends map trie dual-rebuild dual --cadences 128 --merge-every 4096
```

Incremental final export retains the persistent base's page grouping and existing
extent/blob boundaries. It does not bulk-normalize files. Equal logical contents
can therefore have different snapshot IDs and packed sizes from the full rebuild
control, including all-zero blobs that the bulk writer turns into sparse holes.
Both outputs are ordinary resource snapshots and are fully verified after packing.
The reachable live graph still includes the residual overlay and is larger than
final exported output.

Tests instrument the merge's store requests: a two-key replacement rewrites one
leaf, retains all other leaf references, does not traverse unrelated base leaves
or file payloads, and reuses the delta blob's exact physical reference. Ordinary
store admission can still authenticate immediate child occurrences; these
algorithm-level counters do not claim that every store performs zero physical
reads of untouched child pages. A multi-batch test
injects failure at every write boundary, including after completed batches and at
the final snapshot, and checks the original roots and values remain selected.

Prototype snapshot admission requires its sole owned profile, an empty outer
resource directory and no extra features. Unsupported required profile
features, additional profiles and nonempty outer resource contents are rejected
rather than being dropped on export. These restrictions are tested.


## Paged dual delta

`dual-paged` compares the same incremental base merge with a small persistent
resource B-tree delta instead of one application object per trie record. Its
separate profile is `org.sac.experimental.paged-dual-map` version 1. The kind-8
root retains payload `[0, 1]`; both strong children are plain resource snapshots
(base, then delta). The outer resource directory remains empty. Generic packing
preserves this closure, and the owner applies delta precedence. The production
resource writer and old `dual` comparison remain unchanged.

The delta writer targets 8 KiB pages. For very long keys it raises that target
to at least `3 * maximum_key_bytes + 256`, permitting legal branch splits for
4,096-byte resource names. Multiple small records share compressed directory
pages. Large values use ordinary authenticated extent trees. A merge reuses
those exact extent roots through `ResourceView::file_contents` and
`ArchiveBuilder::set_files_batch`; it neither reads nor rewrites their payloads.
The same bounded flat-file, empty-metadata, no-extra-profile/feature admission
rules apply to both layers. Full graph and namespace verification precedes
sharing extent references.

Reader construction opens immutable snapshots without materializing either map.
Point reads traverse the delta pages and then the base on a miss. A private
minimum/maximum key pair skips the delta for keys outside its range. Those bounds
are derived from the fully verified namespace on reopen, or from completed
checked writes; they are not untrusted payload hints. Failed writes preserve
both root and bounds, and a checkpoint resets them together. An in-range miss
still traverses the delta, including a miss in a gap. Complete owner admission
remains required before treating any route miss as authoritative absence.

```sh
python3 tools/performance/run_trie_comparison.py /absolute/path/to/trie_workloads \
  "$HOME/Documents/Developer/sac/prefix-trie/paged-dual" \
  --backends map trie dual dual-paged --cadences 128 --merge-every 4096
```

Use the same command with `--merge-every 1024` to exercise frequent merges,
`--spill --cases updates resize` to disable the writer append-index and decoded
caches, keeping the reopened reader decoded cache at zero too,
and `--iterations 64 --cadences 1 --merge-every 16 --cases updates` to exercise
per-edit durability. The final unmerged delta is measured in every variant.
Tests run both layouts through write/merge failures, old roots, native recovery,
packing and shared-reference checks. Additional paged tests reject malformed
layer roles, metadata, hierarchy, extra features and substituted authenticated
pages; check maximum-length keys and failed-write bounds; and bound store reads
to establish that reader construction does not preload the map.

The paged variant is an explicit comparison choice, not a universal replacement.
Small-record warm reads and live packed space can improve substantially, while
write CPU, resize append volume, owner admission and decoded-cache-disabled
lookup costs can regress. Compare those costs together before selecting a delta
layout. Disabling the SAC decoded cache does not disable the OS file cache.

## Bucketed trie delta

`dual-bucket` keeps Patricia routing and the incremental resource base, but
replaces one-record leaves with bounded leaves containing at most 16 records.
The separate dual profile is `org.sac.experimental.bucket-dual-map` version 1;
its kind-8 root retains payload `[0, 1]` with strong children for the plain base
snapshot and the `org.sac.experimental.bucket-trie` version-1 root. The empty
outer directory, ownership restrictions, merge limits and native publication
barriers are the same as the other dual variants. Old profile definitions and
backends remain readable and available as controls.

Bucket-trie records use ordinary kind 8, version 1 application envelopes
`[namespace, type, 1, payload_bytes]`. Root and value-descriptor payload bytes
contain deterministic CBOR arrays. Node payload bytes contain a deterministic
CBOR byte string with the following bounded binary fields. Integers inside that
byte string use little-endian encoding. No caller-provided hash or unchecked
child admission is used.

| Type | Payload | Strong children |
| --- | --- | --- |
| `root` | CBOR `[entry_count, root_index_or_null]` | Empty, or the node at index 0 |
| `value` | CBOR `[byte_length, storage, data]` | Empty for storage 0 (129 bytes through 48 KiB inline); one kind-7/version-1 childless byte object for storage 1 (`data` is child index 0, length exceeds 48 KiB) |
| `bucket` | `u16 prefix_length`, prefix, `u8 row_count`, then rows | Value descriptors, in row order |
| `branch` | `u16 prefix_length`, prefix, `u8 terminal_present`, optional encoded value, `u16 edge_count`, then increasing `u8` labels | Optional terminal descriptor first, then child nodes in label order |

A bucket row is `u16 suffix_length`, suffix, encoded value. An encoded value
starts with a tag: 0–128 is the inline byte length, immediately followed by
those bytes; tag 255 is followed by a `u32` logical byte length and consumes the
next strong child, a separate `value` record. Other tags are invalid. Medium
values live directly in their individual value records, avoiding an extra frame;
large values use small descriptors pointing to byte objects. Bucket rewrites
retain those references and do not copy or recompress neighboring values.
Ordinary store admission authenticates the immediate value records; it does not
traverse their large payload children on each sibling edit. Merges verify the
value records and payloads, then reuse exact large byte-object references.

Prefixes are at most 4,096 bytes, complete keys are at most 4,096 bytes, and a
bucket's suffix bytes total at most 1,024 bytes. Bucket rows are strictly ordered,
number 1–16, and share a maximal prefix (a singleton has an empty suffix). A
branch has at least two alternatives, counting its optional terminal; labels
are strictly increasing and bounded to 256. Every strong-child position is
consumed exactly once. Trailing payload bytes, unused children, malformed value
roles, lengths and bounds are rejected. Routing and bucket records are bounded to
16 KiB of canonical data including their child table; value records are bounded
to 64 KiB, including the individually inline medium value. The existing million-entry
and million-visit limits, 512 MiB logical verification allowance and 32 MiB
queued key-prefix allowance apply. Edits keep their path on the heap; local
bucket splitting handles at most 17 entries with at most 17 recursive frames.
There is no deletion API.

Point reads borrow inline bytes while parsing nodes and copy only the selected
value. They validate the complete local binary node; they do not construct an
owned value map or copy neighboring payloads. Missing routes still require full
owning-profile verification before they prove absence. A failed value write,
bucket split, ancestor rewrite or merge leaves the selected old root and count
unchanged; orphaned append objects can remain unreachable.

```sh
python3 tools/performance/run_trie_comparison.py /absolute/path/to/trie_workloads \
  "$HOME/Documents/Developer/sac/prefix-trie/bucket-resident" \
  --backends map trie dual dual-paged dual-bucket --cadences 128 --merge-every 4096
```

Repeat with `--merge-every 1024` for frequent merges and with
`--spill --cases updates resize` for zero writer append-index/decoded caches and
zero reopened-reader decoded cache. The runner asserts zero decoded residency
after owner verification, preserves all samples and checks equal logical digests.
Both sequential and permuted full-value reads remain separate from reader setup,
verification, edits, merges, publication and final export.

## Public live-map integration

`live-map` runs the public `NativeStore::live_map`, `LiveMap::set`,
`LiveMap::publish`, reader, admission and incremental checkpoint APIs. Its bucket
codec lives in `src/v1/resources/live_map/bucket.rs`; the performance module is
only a re-export, so production and prototype bucket controls share one codec.
`dual-bucket` retains the old experimental owner as a comparison control. The
other trie/paged backends remain development controls.

The production owner fully admits the delta during open, enforces combined
retained-layer limits, and declares a required capability. Its prepare time
therefore includes stronger admission than the experimental owner. Retain the
editor across edits. Publication uses the actual native durable API; checkpoint
returns an ordinary resource snapshot for compatible export. See
[the public profile](../../specs/05-live-map-v1.md) for the complete contract.

To repeat the resident comparison with an explicitly captured release executable:

```sh
python3 tools/performance/run_trie_comparison.py /absolute/path/trie_workloads /fresh/output/resident \
  --repeats 3 --cadences 128 --merge-every 4096 \
  --backends map trie dual dual-paged dual-bucket live-map
```

Use merge cadence 1024 for frequent-merge runs; use `--spill --cases updates resize`
for zero-cache runs; use 64 iterations, cadence 1 and merge cadence 16 for the
per-edit durability diagnostic. Record the actual managed compiler output's
executable and digest rather than assuming a convenience `target` path is current.
