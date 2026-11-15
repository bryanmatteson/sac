# Bounded memtable, immutable checkpoints and WAL

The optional native `MemtableStore` is a byte-key/value write-back layer for a
dedicated SAC live store. It adds no core object kinds or SAC1 wire changes.
Its current portable checkpoint is a `sac.memtable.v2` application profile. The
local write-ahead log uses `.wal` and a prepared successor `.wal.next` beside
the SAC path. Recovery requires the SAC file and every installed WAL segment.
Version 1 stores remain readable and are durably upgraded before new writes;
older v1 writers reject the v2 profile instead of ignoring the successor WAL.

## Public operations and bounds

`MemtableStore::create(path, incarnation, options)` creates a fresh store and
sidecar; `open(path, options)` recovers the archive and installed WAL segments. The caller MUST supply
a fresh nonzero 16-byte incarnation on creation. It also becomes the profile's
stable logical store ID; native compaction may change the physical incarnation
without changing this ID. Both paths retain exclusive native writer locks.
Other native writers MUST NOT edit this dedicated container outside this API.

`get`, `put`, `delete`, `write_batch`, `request_flush`, `flush`, `statistics`
and `close` are thread-safe. A short state lock protects overlay lookup and
handoff; a separate gate serializes WAL appends. The worker exclusively owns
SAC checkpoint construction/publication. Neither SAC I/O nor WAL durability
barriers hold the state lock; base reads use a pinned immutable native reader.
Keys are arbitrary byte strings,
including empty keys, up to 2,047 bytes. Values have a configurable limit no
greater than 8 MiB. A batch contains at most 1,024 mutations. Duplicate keys
within a batch use the last mutation. Deletes are idempotent.

The configurable pending-memory limit charges key and value lengths plus 512
bytes per entry, including tombstones and conservative tree allocation overhead.
The active table, at most one immutable table, and an incoming batch MUST fit
this single combined bound before allocation; duplicate input mutations are charged conservatively before coalescing. The
limit is between 512 bytes and 1 GiB. A batch that cannot fit is rejected.
WAL size is separately bounded, between 173 bytes and 1 TiB. An incoming record
that cannot fit even an empty WAL is rejected. This WAL budget counts retained
record bytes plus one 64-byte header. Two installed segments add one fixed
64-byte header; preparing a successor never copies record payloads. If either
budget would otherwise be exceeded, the writer waits for background retirement
before allocating its batch or accepting its WAL record. Reads continue while
that writer waits. Backpressure is necessary when bounded capacity is exhausted.

These are pending-table and WAL bounds, not a total process RSS limit. Native
caches, encoder workspaces and resource operations have their own finite limits.
WAL output scratch remains bounded by 8 KiB. On Unix, the writer gathers at
most 64 mutations per file write using a fixed 4 KiB framing buffer and a
fixed descriptor array. Prefixes, keys that fit and small values (up to 256
bytes) share that buffer. The arrays total 7,200 bytes on a 64-bit host; larger
payloads are borrowed. Long keys fall back to borrowed slices without reducing
the group size. A typical 64-record batch uses one `writev` call, including
header and digest. Larger batches use successive
bounded groups, and partial writes or interruptions are completed before the
same full-file synchronization and acknowledgment. Other platforms retain the
8 KiB buffered path. Recovery uses at most one payload buffer bounded
by the pending-memory limit in addition to the pending table. Read results are
caller-owned copies outside the table budget. `MemtableOptions::limits` bounds
resource operations, collection entries, logical bytes and per-value reads.

A worker starts a checkpoint when the oldest active mutation reaches
`flush_interval`, even if there are no further API calls. New writes do not
extend that deadline. It also starts at seven-eighths of the combined memory budget,
reserving headroom for writes during publication, or on explicit/admission
pressure requests. Admission independently enforces the full combined bound;
large incoming batches may require backpressure before the proactive threshold.
An admission wait during an in-progress checkpoint waits for that generation's
retirement, then rechecks capacity; it MUST NOT implicitly request a second
checkpoint through newer active writes. Explicit flush watermarks are retained.
At most one immutable generation exists; no queue can grow.
The interval is positive and representable by the monotonic clock. Filesystem
latency and scheduling can delay completion. WAL sync still determines write
acknowledgment latency, and device contention can affect foreground operations.

`request_flush` schedules work and returns the accepted sequence to cover.
`flush` waits until publication and old-segment retirement cover every batch
accepted before the call. It does not exclude later writers: newer active
batches may remain in the WAL when it returns. `close` waits and joins the worker.
Statistics report combined pending entries/bytes (including both versions of a
key present in both tables), active/immutable byte charges, immutable entry
count, checkpoint activity and admission-wait count.

## Portable checkpoint

The snapshot's sole profile declaration is `["sac.memtable.v2", 1, root_index]`.
The feature array is empty. Its kind-8/schema-1 root body is:

```
["sac.memtable.v2", "root", 1, payload_bytes]
```

The root has one common strong child: the resource directory. Its canonical
identity MUST match the snapshot's ordinary resource directory. This makes the
profile's data dependency explicit and retains it in closure copies.
`payload_bytes` is deterministic CBOR encoding
of `[store_id_bytes, checkpoint_sequence_uint]`. Store ID is exactly 16 bytes,
not all zero. Sequence zero denotes the initial empty checkpoint. Each accepted
nonempty mutation batch advances the WAL sequence by one, without wraparound.

The snapshot's ordinary resource directory is flat. Each key is stored as one
regular file named ASCII `k` followed by the key's lowercase hexadecimal encoding.
The empty key has name `k`. File metadata is the empty map. File bytes are the
value; absent keys have no file. Directories, symlinks, noncanonical names,
unknown profile versions and extra profiles/features are rejected by this API.
The directory structure is authenticated and validated on open before routed
misses may be returned as absence. File contents are authenticated when read.

Checkpoint publication selects the new directory and its sequence in the same
authenticated SAC snapshot, using the native ordered durability barriers. This
binding makes replay idempotent across a crash after publication but before WAL
retirement. Only after successful publication may covered records be discarded.

## Local WAL layout

All WAL integer fields are little-endian. Digests use BLAKE3's derive-key mode
with the exact context strings given below. Checksums detect accidental damage;
they do not establish publisher trust or protect against an attacker rewriting
both a record and its checksum.

Both segments use the same record framing as v1. A successor's header base is
the published watermark observed when it was prepared, which can precede its
first record. Its first sequence follows the primary's last complete record.
After promotion, a primary may therefore start above header-base + 1, but every
omitted sequence MUST already be covered by the SAC watermark. All following
records and all cross-segment transitions MUST be contiguous. A complete record
with a sequence gap fails closed; legacy v1 primary logs retain their strict
header-base + 1 initial-sequence rule.

The 64-byte file header is:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 8 | ASCII `SACMTW01` |
| 8 | 16 | Logical store ID |
| 24 | 8 | Base checkpoint sequence |
| 32 | 32 | Digest of bytes 0–31, context `sac.memtable.wal.header.v1` |

Each atomic batch has a 64-byte header, a payload and a 32-byte digest:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 8 | ASCII `SACMTB01` |
| 8 | 8 | Batch sequence |
| 16 | 8 | Payload byte length |
| 24 | 4 | Mutation count |
| 28 | 4 | Zero reserved bytes |
| 32 | 32 | Digest of bytes 0–31, context `sac.memtable.wal.record-header.v1` |
| 64 | Variable | Mutation payload |
| After payload | 32 | Digest of header bytes 0–31 followed by payload, context `sac.memtable.wal.record.v1` |

Payload mutations are unique and sorted by raw key bytes. Each consists of a
one-byte operation (0 delete, 1 put), a four-byte key length, an eight-byte value
length, the key, then the value. Deletes MUST have zero value length. A put may
have an empty value. The mutation count and payload must agree exactly. The
header checksum is checked before trusting lengths, so length-field corruption
does not masquerade as an incomplete final record.

## Acknowledgement, publication and recovery

1. Validate inputs and collection limits. Admit the active/immutable/incoming
   memory sum and retained WAL budget before allocating the coalesced batch.
2. Append and fully synchronize the current WAL segment before acknowledgment
   (`F_FULLFSYNC` on macOS), checking SAC/WAL namespace identities before and
   after. Apply the batch to the active table under the short state lock.
3. Reads consult active, immutable (including tombstones), then the pinned SAC
   checkpoint. A read captures its base pin before releasing the state lock.
4. During the dirty interval, prepare a locked, header-only successor in a private temporary file; sync it,
   install it as `.wal.next` without overwriting an existing segment, then sync
   its parent. Foreground writes continue to the primary during this I/O. Keep
   this empty segment ready until the timer, occupancy or a request triggers
   handoff. A crash or drop before handoff leaves an empty successor alongside
   the primary; recovery validates both and replays the primary normally.
5. Under the WAL gate and state lock, freeze the entire active table at its
   accepted sequence and switch the writer descriptor to the installed successor.
   Release both locks. No values are copied and both tables share the same budget.
6. The worker applies the immutable table to SAC and publishes data plus that
   immutable sequence in the same authenticated snapshot. Newer writes append
   and sync the successor and override immutable values in the active table.
7. Only after publication, rename the successor over the primary and sync the
   parent directory, without the WAL gate or state lock. The active descriptor
   admits either installed name for the same inode across this handoff.
   A crash around this rename sees either both durable segments or the promoted
   successor; the SAC watermark covers the retired prefix in either case.
8. Install the newly pinned checkpoint and remove the immutable overlay under
   the state lock. Drop the retired reader/lease, immutable table and old WAL
   outside that lock, BEFORE returning their charges to the admission budgets. Wake waiting writers and
   flush callers. A failed checkpoint retains recoverable logs and poisons the
   handle without discarding acknowledged active writes.

Recovery refuses a missing WAL, mismatched store ID, WAL base newer than the SAC
checkpoint, sequence gaps, invalid complete headers/payloads/checksums, and any
batch exceeding configured bounds. It validates both complete segments before replay
or WAL replacement. An incomplete primary followed by successor records is an
error; an incomplete final record in the last nonempty segment may be discarded. A short final header or a checksummed header whose final
payload/digest is incomplete is an uncommitted tail; recovery records its byte
count and discards it after replay. A complete invalid record fails closed,
including an invalid final record. Log checksums do not make arbitrary external
truncation distinguishable from an interrupted append.

Records at or below the published watermark are skipped. Later records replay
in order. If a smaller overlay budget cannot hold the accumulated records,
recovery publishes intermediate checkpoints while retaining the original WAL.
After durable replay it first replaces the successor with a synced empty header
at the final watermark and syncs its parent, then promotes that header over the
primary and syncs the parent again. This order also recovers a crash during
normalization without leaving an old prefix followed by an unexplained gap.
Interrupted recovery can therefore be resumed using the same rules. A smaller
configuration unable to admit a single existing batch fails without truncating
the WAL; reopen with sufficient limits.

A torn SAC publication slot has an explicit recovery path for this consumer:
under the native destination fence, validate the admitted checkpoint profile
and complete WAL, then use native replacement compaction to preserve the
admitted snapshot in a fresh live inode. The damaged input is retained under
the native recovery-backup path. Replay then proceeds from that snapshot.
Ordinary `NativeStore::open` continues to require explicit recovery for torn
slots; this consumer's private opt-in does not change that contract.

`statistics().io` contains fixed-size, saturating diagnostic counters since
open. Successful WAL batches report framing, full synchronization and final
verification time separately. Other counters cover write preparation,
WAL-gate/admission waits, successor preparation and checkpoint stages. Native
publication counters share the checkpoint writer's attempted-barrier metrics.
Failed jobs can omit elapsed time from stage totals. Durations on different
threads can overlap; they are neither
process CPU time nor additive end-to-end latency. These counters retain no
per-operation history or payloads and change no WAL, publication or admission
ordering.

Any WAL or checkpoint I/O failure poisons subsequent operations until reopen;
`statistics().failure` retains the first error text, including worker errors.
An error can have an indeterminate commit outcome. A complete unacknowledged
batch may replay after recovery, so applications needing request deduplication
must include their request IDs in the same atomic batch. A successful WAL
acknowledgement establishes durability under the same filesystem and device
sync assumptions as NativeStore; it does not require a subsequent checkpoint.

Drop joins any checkpoint already in progress and stops without requesting a
final checkpoint for active writes. Accepted writes remain in the durable WAL.
`close` performs a final checkpoint and returns errors. Backups and moves MUST
capture the SAC file, `.wal` and any `.wal.next` while the store is
closed/quiescent, or use a completed checkpoint snapshot through SAC APIs.
