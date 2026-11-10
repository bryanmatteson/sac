# Optional SAC recovery records v1

Recovery records add configurable error correction, either externally in a
sidecar (conventionally `<archive>.rr`) or inside the optional `sac.recovery.v1`
profile. Both use the same parity stream. External records protect exact input
file bytes; embedded records protect a sealed checkpoint. Core framing and
sealed exact-EOF admission are unchanged. Normal reads do not scan or decode
parity. Disabled recovery adds no storage or read work. Parity is generated
explicitly; an ordinary save does not regenerate it.

Records cover preamble, live slots, headers, locators, payloads, padding and
trailer. They can protect ciphertext of an age wrapper: generate after
encryption, because parity of plaintext is not encrypted and discloses linear
information about the data. Generate only from immutable or quiescent files.

## Erasure code

Systematic Cauchy Reed–Solomon over GF(256) uses polynomial `0x11d`, generator
`2`. For `k` data blocks and `m` parity blocks the parity coefficient is
`inverse(column XOR (k + row))`. Arithmetic is field multiplication and XOR.
Data indices are `0..k`, parity indices `k..k+m`. Every square Cauchy submatrix
is invertible. No external library's undocumented matrix is implied.

Block size is a power of two from 1 KiB through 1 MiB. Configured data/parity
counts are each `1..=128`, sum at most 256. Defaults: 100 data blocks, 10 parity
blocks, 16 KiB blocks. CLI percentages `1..=100` select parity blocks per 100
data blocks; APIs can configure both counts.

Full stripes use configured counts. Final stripe:
`k = min(configured_data, ceil(remaining_bytes / block_size))`,
`m = ceil(k * configured_parity / configured_data)`. Its coefficients use that
actual `k`. Only the last data block is zero padded. No unused data/parity blocks
are written. Empty sources reject.

BLAKE3 detects damage and turns bad blocks into erasures. Up to `m` corrupt or
missing data/parity blocks **combined in each stripe** can be repaired if stripe
metadata survives. One bad byte consumes a block. Concentrated damage can
exhaust one stripe; this is not a promise to repair any arbitrary percentage of
byte damage. Truncation preserves block positions; insertions/deletions do not.

Storage overhead is parity plus checksums/framing. Each stripe adds
`m * block_size + 64 * (k+m) + 64` bytes; two headers add 256 bytes. Small files
incur block rounding. Smaller blocks localize damage and reduce rounding, with
more checksum overhead.

## Exact wire layout

Unsigned integers are little endian. This separate record format adds no core
locator policy or required profile:

```
[128-byte header]
[stripe 0 checksum table][parity blocks][duplicate checksum table]
[stripe 1 checksum table][parity blocks][duplicate checksum table] ...
[duplicate 128-byte header]
```

| Offset | Bytes | Header field |
|---:|---:|---|
| 0 | 8 | `SAC1REC\0` |
| 8 | 4 | Recovery wire version, 1 |
| 12 | 4 | Header length, 128 |
| 16 | 8 | Protected source length, nonzero |
| 24 | 4 | Block size |
| 28 | 2 | Configured data blocks per stripe |
| 30 | 2 | Configured parity blocks per stripe |
| 32 | 8 | Stripe count, derived from source length/geometry |
| 40 | 8 | Complete record-file length, derived from geometry |
| 48 | 32 | Source digest |
| 80 | 16 | Reserved, zero |
| 96 | 32 | `BLAKE3("SAC1/recovery-header\0" || header[0:96])` |

Source digest: `BLAKE3("SAC1/recovery-source\0" || exact_source_bytes)`.
A checksum table is `k+m` 32-byte block hashes (data then parity), then a
32-byte table hash:

```
block_hash = BLAKE3("SAC1/recovery-block\0" || stripe:u64 || index:u16 || padded_block)
table_hash = BLAKE3("SAC1/recovery-metadata\0" || stripe:u64 || block_hashes)
```

Parity blocks are uncompressed, exactly `block_size` bytes. Either intact
header/table copy suffices. Two checksum-valid copies that disagree reject.
Both table copies lost makes a stripe unrecoverable; both headers lost prevents
admission. A truncated sidecar remains usable if the first header and needed
tables/parity survive. An intact source needs no parity if one table per stripe
survives. Extra trailing record bytes reject.

Checked geometry precedes allocation/output; source/record bytes, output,
resident buffers, stripes and duration have finite limits. One stripe is
resident. Repair checks reconstructed block hashes and the complete output
digest. Output is the original length; extra unprotected source bytes are
omitted. Output remains provisional until all checks succeed.

## APIs and operation

Portable Rust: `sac::recovery::{create, inspect, repair, RecoveryOptions,
RecoveryLimits, RecoveryInfo, RecoveryReport}`. Inputs implement `Read + Seek`;
output implements `Write`. The caller excludes writers, including same-file
maintenance, and stages/discards output on error. Generation checks the source
across two passes, which is not a substitute for writer exclusion.

```
sac recovery create archive.sac archive.sac.rr --redundancy-percent 10
sac recovery inspect archive.sac.rr
sac recovery repair damaged.sac archive.sac.rr repaired.sac
sac verify repaired.sac
sac unpack repaired.sac recovered
```

`--block-size` selects granularity. Common quotas apply; entry limit bounds
stripes. Commands require regular paths, preserve inputs, stage privately and
install without clobbering. The independent Python tool supports the same
commands and `recovery_create`, `recovery_inspect`, `recovery_repair` APIs. It
implements both wire and code independently, invokes no SAC executable and
needs only existing Python dependencies.

Any byte change (including a save or a compaction) makes records stale. Regenerate for
each retained image. Older records may reconstruct an older save if differences
are within capacity. The reported source digest identifies the protected image;
hashes/parity do not establish authenticity, freshness or latest-save authority.
Repair reconstructs bytes, without scanning/promoting orphan commits or choosing
a newer root. Core/profile validation and publisher trust remain separate.

## Embedded recovery profile

```
sac recovery embed archive.sac protected.sac --redundancy-percent 10
sac recovery inspect protected.sac --embedded
sac recovery repair damaged-protected.sac repaired.sac --embedded
```

`embed` creates a new sealed container. Its resource directory and unrelated
profiles remain directly readable; the original file is not wrapped as a nested
resource or duplicated in the output. A packed sealed checkpoint is prepared
first. Its final 160-byte trailer is replaced by ordinary recovery-profile
frames, then a new snapshot, commit and final trailer. The checkpoint trailer
is replicated in the recovery descriptors. Thus there is no parity self-cycle
or non-core suffix after the final trailer.

Recovery restores the **protected checkpoint**, without the subsequently added
recovery profile. In particular its snapshot ID differs from the outer snapshot
that declares recovery. `inspect --embedded` reports the protected snapshot and
byte digest. Existing signatures stay attached to their protected commit; they
do not sign the new outer snapshot. Live inputs are packed as sealed checkpoints;
local attachments require explicit `--strip-local` before removal.

All profile records use core kind 8, canonical schema 1, namespace
`sac.recovery.v1`, profile version 1. Types:

- `root`: two ordered strong children, the protected checkpoint Commit and the
  segment tree. Payload is deterministic CBOR
  `[0,1,source_bytes,source_digest_bstr32,record_bytes,checkpoint_trailer_bstr160]`.
- `segments`: payload is deterministic CBOR `[]`; 1–512 ordered strong children
  are segment leaves or further `segments` nodes in stream order.
- `segment`: no children. Payload is a discovery header, at most 1 MiB of the
  external-format recovery stream, and a duplicate discovery header. Writers
  use stored codec 0 so damaged-frame recovery can find the payload directly.

Each discovery header is 320 bytes:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 8 | `SAC1RSEG` |
| 8 | 4 | Version, 1 |
| 12 | 4 | Header length, 320 |
| 16 | 32 | Protected source digest |
| 48 | 8 | Protected checkpoint byte length |
| 56 | 8 | Complete recovery-stream byte length |
| 64 | 8 | Segment offset in that stream |
| 72 | 4 | Segment byte length, 1 through 1 MiB |
| 76 | 8 | Absolute position of this header |
| 84 | 8 | Absolute position of segment data |
| 92 | 4 | Reserved, zero |
| 96 | 160 | Protected checkpoint trailer |
| 256 | 32 | Protected checkpoint snapshot ID |
| 288 | 32 | `BLAKE3("SAC1/recovery-segment\0" || header[0:288])` |

The two copies identify the same data range and have different self positions
and header digests. Explicit recovery scans for these checked descriptors even
if preamble, frame headers, profile roots or outer publication are damaged. A
descriptor's physical position must match its location, rejecting moved/nested
archive hints. Conflicting checkpoints or overlapping nonidentical segments
reject. Missing segment ranges become erasures in the underlying parity stream.
Each recovered data block and final checkpoint digest still have to validate.
Discovery never grants publisher trust or latest-save authority.

Parity itself is excluded from checkpoint coverage. A damaged parity frame can
still yield usable descriptors/data even if its outer object hash fails. The
profile/root/publication are not required for raw discovery. Loss of both
discovery copies for all usable segments, or of sufficient checksum/parity
material, can prevent recovery.

A save can leave an older protected checkpoint in the profile; it does not cover
later edits. Compaction or repacking relocates frames and invalidates physical discovery
positions. Regenerate with `recovery embed` for the retained image. Re-embedding
removes the previous recovery profile before checkpoint packing, avoiding nested
parity growth and preserving unrelated profiles/features. Re-embedding an outer
snapshot with both an existing recovery profile and an attestation catalogue
rejects rather than silently discarding signed state; use external records or
prepare an explicitly unsigned checkpoint. Signatures on an unchanged protected
checkpoint survive refresh. If newer contents would cause refresh to discard an
older attested checkpoint, refresh rejects rather than silently removing it.

Portable Rust APIs are `sac::recovery::embedded::{inspect,repair,EmbeddedInfo}`.
Native creation uses `embed_file` and `EmbeddedLimits`; it stages, verifies and
installs a fresh file without overwriting a destination. The independent Python
tool supports `recovery inspect ... --embedded` and
`recovery repair ... ... --embedded`, and APIs `recovery_inspect_embedded` and
`recovery_repair_embedded`. Embedded creation is provided by the Rust CLI/API.
