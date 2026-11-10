# Independent SAC1 recovery

`sac1_recover.py` is a second implementation of the SAC1 reader. It reads the
wire format directly using Python, the public BLAKE3 and Zstandard libraries,
and its own deterministic CBOR parser. It does not import an application,
invoke Rust, resolve original input paths, or access the network. Installation
needs package access; recovery itself runs offline.

The tool recovers the generic content of a file: resources, generic metadata
and attestation structure. It does not decode application profiles. Objects
below a declared profile root keep their hash, bound and dependency checks;
their meaning remains unverified.

## Install and run

```sh
python3 -m venv /path/to/sac1-env
/path/to/sac1-env/bin/pip install -r tools/sac1-requirements.txt
/path/to/sac1-env/bin/python tools/sac1_recover.py verify archive.sac
/path/to/sac1-env/bin/python tools/sac1_recover.py attestations archive.sac
/path/to/sac1-env/bin/python tools/sac1_recover.py list archive.sac
/path/to/sac1-env/bin/python tools/sac1_recover.py extract archive.sac recovered
/path/to/sac1-env/bin/python tools/sac1_recover.py metadata archive.sac
/path/to/sac1-env/bin/python tools/sac1_recover.py salvage damaged.sac repaired.sac --expected-snapshot HEX
/path/to/sac1-env/bin/python -m unittest discover -s tools -p test_sac1_recover.py
```

The file magic is exactly the four ASCII bytes `SAC1`. Bytes 4–7 of the 128-byte
preamble must be zero, including during independent recovery and salvage output.
Ordinary admission rejects the former eight-byte signature. Discarded
section-format drafts and SACOBJ02 files are unsupported; no conversion is
attempted.

## Live files

Live admission selects the highest intact checksum-valid slot and checks its
exact trailer binding. A damaged slot produces an explicitly degraded view;
an intact slot that binds corrupt content fails rather than falling back.
This standalone tool cannot coordinate with a live writer's publication fence.
Use an immutable retained copy, or arrange external writer exclusion. Its live
admission is integrity-only and always reports durability as uncoordinated.
It never writes a live store or acknowledges a publication.

## Verify

`verify` checks the complete physical record inventory, every reachable
physical frame and child locator, canonical hashes and bounded decoding,
core schemas, directory fences/heights and extent lengths. Opaque object kinds
below declared profile roots retain hash, bound and strong-dependency checks;
their semantics remain unverified. An unknown kind outside a declared profile
or local-data closure fails, and known core edges still require their exact
kind/schema. Signature material
is retained as bytes; publisher trust remains unaccepted. Required unknown
core capabilities fail. Application payload semantics, replay and selected-head
consistency remain explicitly unverified. A successful core check must not be
reported as a validated application profile.

Core directory leaves accept at most 128 KiB complete canonical bytes and
144 KiB complete frames; ordinary inline files are limited to 48 KiB. Directory
branches and extent pages retain 64 KiB canonical and 80 KiB frame bounds.

## Attestations

Optional kind-9 trust entries are independently assessed against the exact
baseline tagged COSE Sign1 grammar and their attached commit's snapshot ID.
`verify` reports counts of valid structures, invalid entries and unsupported
recipes; `attestations` emits each outcome, purpose and binding. Invalid optional
trust material remains visible and does not block generic resource recovery.
The supported structure has protected algorithm -19, optional protected key ID,
empty unprotected headers, embedded public snapshot/purpose payload, and a
64-byte signature. This tool does not perform signature verification or key
lookup: `valid_structure` always retains signature unchecked and trust unaccepted.

## Extract

`extract` performs strict core verification and preflight before writing. It
maps every name to the reserved `sac-<hash>` form, checks generated sibling
collisions, and rejects a collision or path-limit failure during preflight.
The mapping handles arbitrary byte names, Windows aliases, device names and
Unicode aliases without asking the host to interpret those original names.
Files are mode 0600 and directories 0700. Links are recorded in the report and
never instantiated. No permissions, timestamps, ACLs or executable behavior
are restored. Every declared regular-file BLAKE3 digest is checked against the
complete expanded stream. Missing digests remain `DigestUnchecked`; a computed
digest is recorded separately. Output is a fresh directory containing
`content/` and `report.cbor`. Installation uses atomic no-clobber rename on
macOS and Linux; other hosts reject extraction. Creation below the staging
root uses descriptor-relative operations with no-follow checks.

The report is deterministic CBOR `[header, rows]`. Header is
`["sac.extract",1,snapshot_id,verification_states]`. Each row is
`[original_byte_path,mapped_text_path,entry_type,"mapped",metadata,
declared_digest_state,computed_digest_or_null,link_target_or_null]`.
This report format is local to this tool and versioned separately from SAC.

## Salvage

`salvage` scans every aligned candidate independently under limits; a claimed
span cannot skip an embedded candidate. Hash-verified canonical objects are
resolved by expected child IDs and reframed into fresh top-level stored frames.
Damaged physical locators can therefore be repaired. Ordinary root admission,
or an independently trusted `--expected-snapshot`, supplies recovery authority.
Orphan trailers and self-hashed snapshot candidates do not supply authority.
Missing dependencies and limits fail without publishing a partial destination.
The new complete sealed file is checked by the independent reader before
exclusive installation. Commit attachments and local authority are not copied;
the snapshot ID is retained. The JSON result includes the original root-admission
failure and never claims original durability or trust.

## Recovery records

The tool independently implements optional Reed–Solomon
[recovery records](../specs/03-recovery-records-v1.md), using existing dependencies:

```sh
python tools/sac1_recover.py recovery create archive.sac archive.sac.rr --redundancy-percent 10
python tools/sac1_recover.py recovery inspect archive.sac.rr
python tools/sac1_recover.py recovery repair damaged.sac archive.sac.rr repaired.sac
python tools/sac1_recover.py verify repaired.sac
python tools/sac1_recover.py extract repaired.sac recovered
python tools/sac1_recover.py recovery inspect protected.sac --embedded
python tools/sac1_recover.py recovery repair damaged-protected.sac repaired.sac --embedded
```

Records protect exact bytes, including headers, slots and trailers. Generate
them from a quiescent image and regenerate after each save or compaction.
`--block-size` controls damage granularity. Capacity is per stripe and counts
damaged parity; excess damage or loss of both metadata copies rejects. Repair
preserves inputs and never installs partial output. The source digest
identifies the protected image without establishing freshness or publisher
trust. Ordinary reads never consult records. Python APIs are `recovery_create`,
`recovery_inspect`, `recovery_repair` with finite `Limits`.

Embedded protection is created with the Rust `sac recovery embed` command/API.
The Python tool independently discovers checked descriptors and repairs their
protected sealed checkpoint, including when core admission or a profile frame
hash fails. Ordinary resources remain directly readable in healthy protected
archives. Repair excludes the added parity profile and reports the protected
checkpoint identity; it does not assert that the checkpoint is the latest
publication. Python APIs are `recovery_inspect_embedded` and
`recovery_repair_embedded`.

## Limits and errors

All commands have finite source, decoded-byte, frame/edge, entry, path-depth,
elapsed-work, resident-memory, temporary-storage and output limits. Run `--help`
for each override. Holes count as expanded logical and allocated output before
file creation. There is no sparse-hole exemption. Inventories and preflight
maps use a disk-backed SQLite index with a bounded page cache. CBOR
limits are 64 open containers and 1,048,576 items, with conservative per-item
memory charging. Physical caches are bounded; each physical occurrence and each
contextual tree edge is checked. The memory budget is conservative accounting
for reader objects, not a process RSS guarantee including the Python interpreter
and native libraries. Temp accounting reserves staged payloads and index rows;
filesystem allocation amplification is host-dependent. These implementation
limits do not claim the native implementation's performance or its 64 MiB RSS
qualification.

An error exits 2 with a JSON category, exhausted dimension when applicable, and
`complete=false`. A failed operation never supplies an absence result or
overwrites an existing destination. Inputs and unrelated files are preserved.

## Generic metadata without an application

The optional `sac.metadata.v1` profile is independent of all application profiles.
The reader recognizes its public directory/CBOR schema:

```sh
python3 tools/sac1_recover.py metadata archive.sac
python3 tools/sac1_recover.py metadata archive.sac --key org.example.title --json
python3 tools/sac1_recover.py metadata archive.sac --key org.example.custom > custom.cbor
python3 tools/sac1_recover.py metadata archive.sac new-metadata-directory
```

Without a key or destination, the command lists names and encoded sizes. Key
reads write only canonical CBOR; `--json` uses the native CLI's lossless typed
JSON representation. A point read follows the selected directory route and
value extents without scanning unrelated file content. An absent route checks
directory completeness before returning absence. Export uses the standard
confined extraction and reversible `report.cbor` name mapping, and refuses to
overwrite an existing destination. Unknown nested values and binary fields are
preserved exactly. Full `verify` validates this known metadata schema; unknown
versions/capabilities remain reported as unsupported semantics while core
resources remain recoverable. See [the profile specification](../specs/02-generic-metadata-v1.md).
