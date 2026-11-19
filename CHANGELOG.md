# Changelog

## Unreleased — 0.2.0 prerelease

- Add typed snapshot profile discovery, authenticated profile-root access and
  caller-supplied semantic validators. `sac inspect` lists profiles and capabilities,
  and `--validate-profiles` checks generic metadata. Add two complete historical
  section archives to the rejection corpus.

- Added the public authenticated `LiveMap` editor and native live-map entry point,
  with a bucketed trie delta, incremental checkpoints, durable native publication,
  explicit ordinary-resource export and experimental bucket snapshot import.

- Add an experimental bucketed Patricia delta comparison with bounded binary
  node payloads, inline small values and shared authenticated large-value
  descriptors. Preserve incremental merges, exact payload reuse and native
  durability barriers; compare warm and decoded-cache-disabled reads.

- Add a paged-delta dual-map benchmark alongside the trie-delta control, with
  authenticated range routing, small shared directory pages and exact extent
  reuse during incremental merges. Measure reader setup, permuted reads and
  misses separately. Add `ResourceView::file_contents` for borrowed storage
  descriptors without payload materialization; publication barriers are unchanged.

- Borrow authenticated extent pages and byte ranges during namespace checks
  and reads, avoiding temporary owned objects and child vectors. Compute
  full-frame encoding proofs only when a matching decoded entry retains them;
  one-pass encoded copies keep their ordinary frame authentication. Pack
  transient active markers and bounded byte lengths into smaller spill records;
  retain only direct-role decisions in physical validation facts and narrow its
  bounded header inventory to reduce final validation's peak disk usage.

- Share extent byte-leaf role authentication with the sealed-copy visit instead
  of reading each leaf for its role and then again for export. Retain exact
  physical completion facts, all logical quota charges and output order; narrow
  disposable content-map keys and physical-validation facts to reduce spill
  storage.

- Add mixed inline/shared-extent resource batches through `FileContents` and
  `ArchiveBuilder::set_files_batch`. Persistent merges retain untouched page
  and payload references, with bounded batches and atomic root replacement.
  Replace full-base rebuilding in the experimental dual map with delta-only
  merges and retain a matched full-rebuild benchmark control.

- Add explicit `compact --preserve-encoding` and sealed-copy options to reuse
  authenticated raw/compressed payloads through borrowed source visits. Rebuild
  physical child locators without recompression, keep ordinary encoding as the
  default, and retain full validation, installation and resource limits.
  Bind cache reuse to authenticated full-frame digests, recycle bounded read
  windows and unpinned page buffers, and release source caches before final
  output validation.

Replace the earlier prerelease section format with the current SAC1 immutable
object graph. This is the first format being prepared for stabilization; the
wire version remains 1 and the Rust package version remains 0.2.0.

- Add `MemtableStore`, a bounded byte-key/value overlay with atomic synchronous
  WAL batches, overlay reads and tombstones, configurable time/memory/WAL
  checkpoint thresholds, and bounded replay on recovery. Bind checkpoint
  sequences to a snapshot profile before retiring WAL data. Publish one immutable
  generation in the background while active writes sync a successor WAL; charge
  both tables against one budget and preserve pinned base reads. The
  `sac.memtable.v2` profile prevents older writers from ignoring the successor;
  v1 stores are recovered and durably upgraded before acceptance.
  Preserve hot-set coalescing with a seven-eighths proactive watermark, prepare
  the synchronized successor during the dirty interval, and buffer complete WAL
  framing together without changing acknowledgment barriers or admission bounds.
  Expose bounded WAL/checkpoint wall-time attribution and native publication
  barrier counters for separating storage waits from code and admission costs.
  Gather Unix WAL header/payload/digest slices in bounded groups of 64 mutations,
  reducing file-write calls without copying payloads, enlarging the output
  scratch bound or changing full-sync acknowledgements. Retry short/interrupted
  writes before synchronization and preserve the buffered fallback elsewhere.
  Recover torn publication slots through a private validated native recovery
  path while preserving ordinary native admission rules and damaged inputs.

- Reuse exact writer provenance for duplicate appends after cache eviction and
  avoid repeated exact child authentication with a bounded per-put table.
  Expose native compression levels, including raw appends for low latency,
  preserving the selected level through prepared writes and compaction swaps.
- Splice inline-only directory leaves by copying unchanged encoded row ranges,
  avoiding field-by-field reconstruction during small live record updates while
  preserving canonical pages and newly introduced child indices.
- Admit directory leaf fields in one pass and reuse BLAKE3 subtree hashes only
  for exact equal canonical bytes at the same offset. Small live map edits avoid
  rehashing unchanged page regions while retaining standard object identities,
  child authentication and durable publication. Bound and account for the
  encoder's additional comparison and subtree storage.
- Parse schema-known directory scalars directly, and rewrite directory branches
  from borrowed authenticated fences. Preserve first-use child identity order
  with a bounded lookup table instead of repeated linear scans and owned CBOR
  reconstruction during many-key inserts and value resizes.
- Bound persistent directory leaves to 192 rows as well as their selected byte
  target. Dense bulk and older leaves remain readable and split when edited;
  individual inline/metadata limits remain unchanged. New persistent tree
  grouping and snapshot identities can differ, without a wire-format change.

- Pack native append writes across frame boundaries in the existing 64 KiB
  buffer, writing large prefixes directly and preserving exact frame bytes.
- Check destination identity at staging and publication boundaries rather than
  per object; keep append-ID tables resident within a configurable memory
  budget and preserve exact deduplication when pressure spills them.
- Batch rewrite-provenance hashing in fixed stack storage, keep Zstandard's
  compression-level configuration across independent frames, and use compact
  resident append-index values with borrowed, unpadded key lookup.
- Use cached decoded occurrences directly for appended-object type queries,
  without duplicate type metadata; retain shared-reader lookup and exact
  physical authentication. Bound macOS append and spill growth to exact write
  extents, removing speculative headroom and its publication-time trimming;
  coalesce appends in one fixed-capacity 1 MiB buffer.
- Admit opaque extension payloads on demand while keeping exact append/type
  authentication and immediate structural/small byte-leaf caching. Batch cached
  child authentication under one guard, releasing it before a miss reads the
  file. Reuse separate Zstandard contexts for small and large independent
  frames to avoid repeatedly retiring the larger compression workspace.
- Expose authenticated borrowed object visits for bounded staging arenas and
  strict final-page writes with deferred decoded-cache admission. Parse batch
  directory edits through borrowed parts without changing validation charges,
  child authentication, deduplication or stored frame bytes.
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
- Finish in-memory bulk sorts and single-leaf directories without temporary
  files. Size directory branches incrementally and decode only the path during
  external merges.
- Read in-memory positional frames directly from their backing slice, and avoid
  copying native and memory-store writes that already have a stored occurrence.
- Reuse inline probes, skip whole-file hashing when the metadata has no
  `byte_digest`, and skip parallel frame encoding for known native duplicates.
- Export childless objects without a second traversal read and carry native
  read authentication through the CLI's scratch-budget wrapper.
- Verify the portable graph during named sealed compaction, reuse authenticated
  object IDs in the sealed encoder, and buffer staged archive writes.
- Reuse the physical validation decoder and count extent payloads without
  rereading the exact leaf authenticated by the extent role check.
- Coalesce physical inventory reads in a bounded, source-quota-charged window,
  reuse core-parent storage and borrow decoded children for direct role checks.
  Narrow disposable validation/copy tables to their actual state and locator
  widths, reducing sealing work and spill without changing sealed bytes.
- Visit authenticated copy objects through reusable native decoder storage,
  borrow their direct role checks, and reuse the relocation vector. Borrowed
  verified writes preserve destination checks and canonical sealed encoding.
- Reuse intrinsic validation during authenticated role checks and combine copy
  activity/remapping records while retaining exact physical completion state.
- Authenticate ordinary physical child occurrences once per validation walk,
  carrying direct role constraints on the traversal and retaining only exact
  occurrence facts. Keep logical validation charges and profile binding checks.
- Verify resource namespaces through borrowed directory rows, avoiding owned
  CBOR trees and copies of names, metadata and inline file contents.
- Validate extent geometry before sealed export and authenticate the byte
  leaves during the verified copy.
- Hash newly inserted objects once, reuse writer frame/compression workspaces,
  expose borrowed frame decoding and reuse native decompression contexts.
- Assemble compressed objects once in the encoder's existing canonical buffer
  for both BLAKE3 identity and compression. Hash complete contiguous input and
  reuse it only under its authenticated canonical ID; keep raw/control hashing
  on bounded stack scratch and encode current child locators independently.
- Decode compressed frames after the identity domain in the reusable output
  buffer, then authenticate its complete contiguous input without a prefix copy.
- Admit newly appended opaque payloads above 2 KiB on their first read instead
  of eagerly copying them into the decoded cache; retain exact append/type
  authentication and immediate caching for structural pages and smaller data.
- Amortize macOS append extent changes over bounded 1 MiB sparse ranges instead
  of extending writes that may speculatively allocate excess blocks. Clamp
  headroom to file limits, disable it for unreserved staging bytes, and remove
  it before publication returns or a new file limit takes effect.
- Compress complete objects through the direct Zstandard context API, avoiding
  streaming setup while retaining codec allocations across level changes.
  Reuse parsed headers to check single-block compressed frame extents; preserve
  general multi-block parsing and full decompression and identity checks.
- Admit large opaque payloads and child vectors to the decoded cache on read,
  retaining append authentication without eagerly copying data over hot pages.
- Batch canonical headers and child IDs into a fixed stack buffer for BLAKE3
  SIMD, then stream large bodies without allocating or changing cache residency.
  Fuse short hash domains with the first input batch using the same bounded
  stack strategy; decoded buffers and stored bytes retain their existing layout.
- Store append-index hashes once, with compact address values and 60-byte disk
  slots. Keep full rewrite provenance in bounded, buffered side records sharing
  the index's scratch budget; general temporary-table slots omit unused padding.
- Remove ordered-index updates from warm cache hits while retaining exact,
  bounded eviction and physical identity checks. Charge idle decoder state to
  the decoded-cache budget.
- Add crash-safe offline in-place compaction with bounded redo journals and
  automatic recovery before writable admission, preserving inode and root IDs.
- Add background same-file reclamation, native reader pin registration and
  durable exact-span byte-frame reuse while publications continue appending.
- Bind a pending in-place compaction journal and reused-frame record to the
  file before replay. A journal that a restored or replaced file inherits
  through its inode is removed when the file is complete without it, and is an
  integrity error otherwise; it is never applied to a file it does not describe.
- Give each preserved recovery input and each compaction candidate an unused
  name. A live store whose writer was interrupted more than once opens again.
- Add `sac extract` and `ArchiveReader::extract_tree`, which restore the
  recorded tree: names, symbolic links, permission bits and modification times.
  Add `sac pack --preserve` and `ArchiveBuilder::add_directory_with_metadata`
  to record `mode` and `mtime`. `unpack` and its report layout are unchanged.
- Check extraction limits against the expanded namespace before creating any
  file, and use one durability barrier for an extraction instead of two full
  device flushes for each file on macOS.
- Keep the private plaintext copy of `privacy-wrap` beside the input, without a
  name, instead of in the wrapper's destination directory. Report the output
  path of the privacy commands as a string.
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
- Map the temporary-file slots of the native append-ID, closure-copy and
  validation tables into memory on macOS and Linux, instead of one positional
  read or write for each slot. The file blocks are reserved first, so a full
  disk is an error. A filesystem that cannot reserve blocks keeps positional
  I/O. A table that passes its resident prefix moves all its entries to the
  slots. Temporary I/O statistics continue to count each slot read or written.
- Keep the native decoded and authentication caches in hash maps with a linked
  least-recently-used order. A hit, an insert and an eviction take constant
  time; the victims and the byte accounting are the same as before.
- Add `NativeStore::set_encode_threads`, `ObjectStore::prepare`,
  `ObjectStore::put_prepared` and `ExtentAccumulator::push_data_batch`.
  Resource builders hash and compress several file chunks at the same time,
  and the store appends the frames in the order of the puts: the file has the
  same bytes as with one thread. The default is one thread. `sac pack` uses
  the available processors, to a maximum of 16.
- Buffer the temporary sort files of the bulk builder. Each record took two
  writes and two reads of the file.
- Compute the frame header checksum eight bytes at a time from tables. The
  value is the same CRC32C.
- Keep the idle native decoder when the decoded cache is full, within one
  quarter of the cache budget. The cache released it first, so each read of a
  compressed frame made a new codec context.
- Read the name of each directory row during a lookup without a second scan
  of its other fields, and pass over rows without recursion.
- Check the destination before each native write with one lookup of its name
  in the directory that the writer opened, instead of a walk of the complete
  path. A replaced or removed destination file fails the write, as before. A
  replaced ancestor directory fails at the next publication or maintenance
  operation, which examine the complete path.
- Store the Zstandard bytes of a source frame again when a closure copy moves
  an object between native stores, instead of compressing the same canonical
  bytes. The bytes come from the read that authenticated the object; a cache
  hit, a raw frame and a commit or snapshot take the encoder as before. A
  source that this library wrote gives the same destination bytes.
- Keep the row positions of the directory pages that an `ArchiveReader` has
  examined, to a maximum of 1 MiB. A later lookup in a page of 16 rows or
  more is a binary search. A page whose keys are not in order keeps the pass
  over each row.
- Put an entry into a directory leaf from the encoded rows of the page, and
  read a page's height without its rows. An edit decoded each entry of the
  page twice and encoded the page twice. The pages have the same bytes.
- Keep at most 1 MiB of the parents that a closure copy is inside. A parent
  whose children are complete is not read and authenticated a second time. A
  copier with disk-only metadata keeps none.
- Let the threads that read one native store hit its decoded cache at the
  same time. Each hit took the one cache lock, so 18 reader threads gave fewer
  hits in total than one thread. A reader that finds the lock held changes the
  cache to shared hits: a shared lock on one of 256 groups of keys, and a
  record of the hits of each thread that the next exclusive access applies in
  order. One thread, or threads that never meet, use the cache as before, with
  the same victims and byte accounting. Hits that several threads make between
  two exclusive accesses keep the order of each thread, and a thread whose
  record is full while the cache is in use does not record its hit.
- Take the cache lock four times for a read of an object that is not
  resident, instead of six.
- Admit a child of a native put without a read when the writer's append index
  has the complete reference: the writer appended that frame under the hash
  that authenticated it. Before, the writer read and decoded such a child
  again after its entry left the cache. A reference with another offset,
  length or hash is read as before, and so is every child after
  `discard_disposable_caches`, maintenance or a reopen.
- Keep the device and inode of the writer's open file for the check before
  each write, instead of one `fstat` for each put.

Earlier prerelease files are unsupported. Re-create them from original inputs;
there is no compatibility reader or migration command. Application-profile
schema versions remain independent of the SAC wire version.
