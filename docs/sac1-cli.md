# Generic SAC1 command-line tools

## Build

Build the production tools with `cargo build --release --bin sac`. The default
features include the native file backend and compression. All commands use
current SAC1 archives. `sac inspect` reports selected-root admission without
claiming complete graph or profile verification.

## Command summary

```
sac pack ./files archive.sac
sac pack ./files - | sac unpack - ./received
sac pack ./files live.sac --live
sac list archive.sac
sac verify archive.sac
sac read archive.sac images/program.bin --offset 262130 --length 65536 > range.bin
sac unpack archive.sac ./extracted
sac compact archive.sac compact.sac
sac recover damaged-slots.sac ./recovered-files
sac recover-live damaged-slots.sac recovered-live.sac
sac salvage damaged-locators.sac repaired.sac --snapshot TRUSTED_SNAPSHOT_HEX
sac recovery create archive.sac archive.sac.rr --redundancy-percent 10
sac recovery inspect archive.sac.rr
sac recovery repair damaged.sac archive.sac.rr repaired.sac
sac recovery embed archive.sac protected.sac --redundancy-percent 10
sac recovery inspect protected.sac --embedded
sac recovery repair damaged-protected.sac repaired.sac --embedded
```

## Recovery records

[Recovery records](../specs/03-recovery-records-v1.md) can reconstruct damaged
bytes using previously generated parity. `--redundancy-percent 1..100` sets
parity per 100 data blocks (default 10). `--block-size` selects a power of two
from 1024 through 1048576 (default 16384). Capacity is per stripe and includes
damaged parity blocks; concentrated damage can exhaust it. Hash tables and
block rounding add overhead beyond the percentage. Ordinary reads do no parity
work. Inputs remain untouched; outputs install without clobbering, under common
quotas. Commands require regular paths. Generate records from a quiescent image
and regenerate after each save or compaction. `recovery inspect` reports its source
digest, without asserting freshness or publisher trust. Run `verify` and then
`unpack` on repaired archives for core validation and extraction.

`recovery embed` creates a sealed archive with the optional `sac.recovery.v1`
profile. Resources, metadata and application profiles stay directly readable.
Live local attachments need explicit `--strip-local`. Embedded repair uses a
bounded physical scan and works without normal root admission; it restores the
sealed checkpoint before recovery was attached. The outer snapshot has a new
identity and does not inherit signatures over the protected snapshot, whose
commit/catalogue remain retained. Re-embedding replaces old recovery rather
than accumulating nested parity. Regenerate after later edits or compaction.

## Pack

`pack` stores directory contents relative to the selected source. A single-file
source uses its filename. Empty directories and raw Unix byte names survive;
symbolic-link targets are recorded without following them. Special files reject.
The source is read through confined directory handles. Inputs should be stable
while they are captured; the tool does not claim a filesystem snapshot of a
concurrently changing source tree. The builder's owned temporary directory is
excluded when it falls within the selected source. New archives store minimal
metadata; they do not implicitly grant permission to execute extracted files.
Payload chunks default to 256 KiB. `pack --chunk-size 1048576` selects fixed
1 MiB bulk boundaries; chunk size is checked against the canonical frame cap.

## Streams, staging and output installation

Sealed output uses a forward-only writer and can go to `-`. File input and
individual resource ranges use positional reads. Stdin is spooled to an owned
seekable file under its byte and disk budget, because selected-root verification
and shared object locators can refer to earlier bytes. The pack builder and
closure copier spill indexes to disk; they do not assemble the complete archive
in memory. A failed pipe write may leave an incomplete prefix on stdout, which
has no accepted final trailer.

Named archive outputs use private staging, actual-file verification, atomic
no-clobber installation and a parent-directory durability barrier. Existing
files, symlinks and directories are never overwritten. Live output additionally
uses the backend's publication fence, ordered data/extent and slot barriers,
and a fresh nonzero incarnation. Live output requires a named seekable path.
`compact` copies only the selected strong closure, preserving the snapshot ID
and its attestation catalogue. A commit with a local authority attachment
requires explicit `--strip-local` for sealed compaction or fresh live recovery.
That operation removes the local attachment and can change commit identity;
it retains snapshot identity and the snapshot's profile/optional closures.

## Unpack and recover

`unpack` and `recover` install a new directory containing `content/` and the
tool-owned `report.cbor`. They authenticate content and validate the core
namespace and physical selected extent before publication. Extraction creates
private directories and nonexecutable owner-only files. It records symlinks and
metadata rather than applying their behavior. Lowercase portable names are
preserved; other raw names use deterministic mapped names recorded with their
original components in the report. Archive names cannot select tool-owned report
paths. File operations are relative to confined directory handles, reject link
traversal, and install the completed directory atomically without clobbering an
existing empty directory. Unsupported confinement/publication hosts reject.

## Damaged files: recover, recover-live and salvage

Recovery follows the selected commit. A checksum-damaged live slot can leave
an older admitted commit with explicit diagnostics; recovery preserves the
source and those diagnostics. `recover-live` creates a new incarnation from
that selected snapshot and its attestations. It never promotes an orphan trailer
or guesses an uncommitted head. Corrupt selected roots and invalid locators
produce an explicit integrity failure in ordinary recovery. `salvage` is the
separate repair operation: it scans bounded physical records, authenticates
canonical objects and reconstructs locators into a new sealed file. It requires
a trusted `--snapshot` ID or an intact admitted selected commit. Candidate
objects alone cannot authorize promotion of an orphan commit. Its report states
the authority and preserves the source. Salvage copies the chosen snapshot
closure; it explicitly reports that original commit attestations are not
preserved. Use ordinary `compact` to preserve attestations when the original
commit and locators are intact.

## Verify, list and read

`verify` reports physical and core validation separately from profile semantics,
publisher trust, and whole-resource digest verification. A generic core verifier
does not claim application history replay or trust. Resource extraction checks a
declared whole-resource digest before installing that file. `list` emits one
JSON record per entry, including raw hexadecimal path components, decimal-string
lengths and deterministic CBOR metadata. `read` writes only binary payload to
stdout and fully authenticates boundary chunks; a missing `--length` is allowed
only at offset zero for a complete streamed resource. Buffered range responses
are capped at 16 MiB; use complete streaming reads for larger output.

## HTTP range reads

Build HTTP reading with `cargo build --release --features http --bin sac`:

```
sac read https://example.test/archive.sac images/program.bin --offset 262130 --length 65536 --http-statistics > range.bin
```

HTTP input uses one HEAD to pin a strong ETag and representation length, then
conditional exact byte ranges. Redirects, encoded representations, changed or
ambiguous pin headers, ignored ranges and full-download fallbacks reject. An
observed representation/integrity failure permanently invalidates the source,
including cached payloads. The raw range cache has a 1 MiB resident budget and
at most 256 entries; the CLI coalesces at most 32 KiB of earlier bytes for small
reads to reuse adjacent extent and payload frames. Large control reads remain
exact. Every object read still authenticates its expected ID. The input limit
bounds the pinned representation and aggregate requested response bodies;
conservative overflow-probe reservations may reject before the nominal limit.
`--http-statistics` writes a separate JSON record to stderr: discovery and GET
counts, caller-requested raw bytes, requested range bytes, consumed response-body
bytes, cache hits and residency. These byte counts exclude HTTP/TLS headers and
are distinct from the logical resource bytes emitted on stdout. HTTP requests
have a timeout of at most 30 seconds, bounded by `--max-seconds`.

## Limits

Every command accepts finite limits:

```
--max-input-bytes N   --max-output-bytes N   --max-temp-bytes N
--max-entries N       --max-seconds N        --max-memory-bytes N
```

Values are unsigned decimal bytes/counts/seconds. Defaults are 64 GiB input,
64 GiB logical output/encoded output, 128 GiB temporary storage, one million
entries, one hour and 64 MiB auxiliary resident memory. Temporary budget includes
stdin spooling, private builder data, final staging, and disposable copy/index
files. Unpublished native staging uses one aggregate reservation for the file
extent and its index; sealing also counts simultaneous old and replacement
files and copy/validation scratch. Live packing and recovery install their
final destination only after the private staged archive validates, so a quota
failure leaves that destination absent. JSON listing bytes are also bounded by
`--max-output-bytes`. The native
adapter reserves finite portions for overlapping indexes and
copy work; a conservative reservation may reject a workload before consuming
the entire nominal quota. Raising the finite quota permits retry. Native
commands require at least 48 MiB; lower budgets return `LimitExceeded`.
Elapsed-time checks are cooperative between I/O operations; a blocked caller
pipe still follows the host's I/O cancellation behavior. Quota/integrity failures
do not publish a partial extraction or archive, and cleanup removes only owned
temporary files. Named output installation failure after a durability barrier
can leave the complete output name present and returns an error rather than a
false durable success.

## Diagnostics and exit codes

Diagnostics use `sac.cli-error.v1` JSON on stderr with stable error categories.
Commands return zero on success, two for usage errors and one for failures.
Archive/read binary output has no mixed-in JSON. Earlier prerelease formats are
rejected; the CLI has no migration command. A live recovery status, list,
inspect, verify or extraction status is JSON on stdout. Run
`cargo test --test sac1_cli` for the actual-process pipe,
range, no-clobber, limit, identity and recovery tests.

## Attestations

`verify` reports each optional attestation independently as `valid-structure`,
`invalid`, or `unsupported`, and reports signatures and trust as `unaccepted`.
Malformed optional COSE material and unsupported algorithms remain visible while
ordinary content extraction remains available. The library's bounded attestation
parser and caller-selected-key signature verifier support applications that
require authorized signer and purpose policies; structural CLI verification
alone does not apply such a policy.

## Same-file maintenance

`compact-in-place <live-archive>` slides the current closure into the same inode
with crash recovery. `reclaim <live-archive> [--no-punch]` retains active native
reader roots and durable heads, optionally releases filesystem blocks, and indexes
exact-size reusable byte frames. See [the native maintenance contract](same-file-maintenance.md)
before operating on a live file; raw and remote readers do not register pins.

## Generic container metadata

The optional [generic metadata profile](../specs/02-generic-metadata-v1.md)
coexists with application profiles and requires no application decoder:

```sh
sac metadata list archive.sac
sac metadata get archive.sac org.example.title --json
sac metadata get archive.sac org.example.custom > custom.cbor
sac metadata set archive.sac org.example.custom custom.cbor
sac metadata set archive.sac org.example.title title.json --json
sac metadata remove archive.sac org.example.title
sac metadata export archive.sac new-metadata-directory
```

`list` streams keys and encoded sizes without reading large values. `get` writes
only canonical CBOR to stdout. With `--json`, it emits a lossless typed JSON tree:
`["text","value"]`, `["bytes","hex"]`, `["uint","decimal"]`,
`["nint","decimal argument"]` (the number is `-1-argument`), `["bool",true]`,
`["null"]`, `["array",[...]]`, or `["map",[[key,value],...]]`.

`set` reads one CBOR value from a file or `-` for stdin. Its `--json` option
instead accepts ordinary JSON containing integers, strings, arrays, objects,
booleans and null; floating-point numbers are rejected. Typed JSON from `get`
is a presentation format; use default CBOR output for lossless round trips.
Keys must be namespaced IDs such as `org.example.title`. Unknown keys and nested
fields are preserved when editing another key. Setting a key explicitly replaces
its entire value. Export creates `content/` value files and `report.cbor` with
reversible original-key mappings; an existing destination is never overwritten.

Edits require a live archive. For a sealed archive, first create a new live copy
with `sac recover-live original.sac editable.sac`. Metadata changes snapshot
identity. The CLI refuses edits to attested snapshots; application-managed
transactions can deliberately manage their signatures. A local attachment
requires explicit `--strip-local` before editing. The snapshot API itself never
silently changes a commit's attachments. Ordinary quota options apply to metadata
commands. `verify` checks the known metadata profile and separately reports its
status, while other application-profile semantics remain unchecked.
