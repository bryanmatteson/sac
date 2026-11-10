# Changelog

## Unreleased — 0.2.0 prerelease

Replace the earlier prerelease section format with the current SAC1 immutable
object graph. This is the first format being prepared for stabilization; the
wire version remains 1 and the Rust package version remains 0.2.0.

- Share canonical object identity and public resource/profile schemas between
  sealed archives and live stores, using distinct locator/publication policies.
- Use exactly four ASCII magic bytes `SAC1`, followed by four reserved zero bytes
  in the 128-byte preamble; reject the superseded eight-byte signature.
- Provide bounded resource trees, sparse extents, authenticated range reads,
  identity-preserving packing, durable publication and replacement compaction.
- Expose the current Rust API under `sac::v1` and the crate root, with the `sac`
  CLI and an independent Python reader, extractor and explicit salvage tool.
- Support optional HTTP range reads, COSE/Ed25519 trust and whole-archive age
  privacy without imposing application semantics on generic resource recovery.
- Replace the superseded specifications, fixtures and working plans with the
  current wire specification and independent-reader conformance vectors.
- Separate portable byte/item/depth limits from reader allocation policy; define
  reserved core schemas, opaque extension preservation, profile dependencies and
  the distinction between byte-stream, snapshot, commit and physical identity.
- Align Python and Rust rejection of unsupported schemas for known core kinds,
  including objects beneath profiles; add shared capability/extension vectors.
- Navigate directory and extent pages using borrowed CBOR, expose shared entry
  views and opened-file/caller-buffer reads, and calculate encoded sizes directly.
- Account for extent-frontier sizes incrementally, retaining bounded child
  indexes and avoiding candidate CBOR trees on every appended range.
- Hash newly inserted objects once, reuse writer frame/compression workspaces,
  expose borrowed frame decoding and reuse native decompression contexts.
- Remove ordered-index updates from warm cache hits while retaining exact,
  bounded eviction and physical identity checks. Charge idle decoder state to
  the decoded-cache budget.
- Add crash-safe offline in-place compaction with bounded redo journals and
  automatic recovery before writable admission, preserving inode and root IDs.
- Add background same-file reclamation, native reader pin registration and
  durable exact-span byte-frame reuse while publications continue appending.
- Punch aligned dead-payload ranges on supported macOS and Linux filesystems;
  expose maintenance APIs, CLI commands and disk/allocation/CPU benchmarks.
- Limit the independent Python reader to generic content: resources, generic
  metadata, attestation structure, salvage and recovery records. It no longer
  includes a decoder for an application profile.
- Emit the `report` member of the `unpack`, `recover` and `salvage` results as
  a JSON object. It was a Rust debug string.
- Rewrite the README for new users, move the Rust API notes to
  `docs/api-notes.md`, add section headings to the CLI guide and add
  `CONTRIBUTING.md`. The README now shows a Git dependency, because the crate
  name `sac` on crates.io belongs to a different project.
- Replace the hosted CI workflow with `tools/ci.sh`, which runs the same jobs
  on the local computer, on request.

Earlier prerelease files are unsupported. Re-create them from original inputs;
there is no compatibility reader or migration command. Application-profile
schema versions remain independent of the SAC wire version.
