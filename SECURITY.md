# Security policy

Report a vulnerability privately through the repository's GitHub security
advisories. Include a minimal input, the exact package revision and features,
and the operation and limits used. This implementation is prerelease.

## Boundaries

SAC1 authenticates immutable objects against IDs supplied by an admitted root
or authenticated parent. Physical locators remain checked hints. Bounded root
admission, requested content verification, full physical/core validation,
application-profile validation, publisher trust and coordinated live durability
are distinct outcomes. Only the owning operation may claim its completed scope.

Readers enforce frame size and child-count bounds, checked offset arithmetic,
strict deterministic CBOR limits and single-frame bounded Zstandard decoding.
Archive operations additionally receive finite source, decoded, logical-output,
frame, edge, memory, temporary-disk, depth and elapsed-work limits. A limit error
is incomplete verification. Store cache budgets exclude arbitrary caller-held
immutable views; callers must budget those separately.

Native writes hold exclusive publication authority and acknowledge only after
data and slot durability barriers. Failed or uncertain publication requires
reconciliation. Recovery never promotes an orphan commit from hash validity
alone. Extraction uses confined operations, fresh staging and no-clobber
installation. Contained extraction (`unpack`, `ArchiveReader::extract`) maps
names outside a portable set and applies no links or stored permissions; use it
for untrusted input. Tree extraction (`extract`, `ArchiveReader::extract_tree`)
restores recorded names, symbolic links whose targets can name paths outside
the tree, and permission bits without set-user-ID, set-group-ID or sticky.
Neither writes an entry through a link. `privacy-wrap` keeps its private copy
of the plaintext beside the input, without a name, and never at the wrapper's
destination. Native
writable publication and confined extraction currently require a Unix host.

Optional signature verification uses caller-supplied trust policy. age privacy
requires external identities. Neither content hashes nor included signatures
alone establish publisher authorization, freshness or application correctness.
Unsafe Rust is denied throughout the crate except the small audited native
syscall adapter for effective UID and hole punching. Its synchronous calls do
not expose pointers to callers. Native compression and cryptographic dependencies
retain their own implementation boundaries. Same-file maintenance requires the
cooperating reader and persistent journal contract in
[the maintenance documentation](docs/same-file-maintenance.md).

## Verification

```sh
cargo +1.97.1 test --all-features
cargo +1.97.1 test --no-default-features
python3 -m pip install -r tools/sac1-requirements.txt
python3 tools/test_sac1_recover.py
python3 tools/generate_conformance.py --check
```

See [the wire specification](specs/01-sac-core-v1.md),
[conformance vectors](conformance/README.md) and
[independent recovery](tools/SAC1_RECOVERY.md) for verification scopes.
