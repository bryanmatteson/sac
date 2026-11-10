# Same-file native maintenance

SAC1 retains the four-byte `SAC1` magic and the same canonical object IDs.
These are native storage operations; their recovery journals are not a new wire
format or required archive sidecar.

| Operation | Readers | File length | Allocated filesystem blocks |
| --- | --- | --- | --- |
| `compact_in_place(options)` | Requires no active native pins | Shrinks to the current commit closure | Releases the truncated tail |
| `reclaim_online(options)` | Retains both durable heads and every registered native pin | Preserves length and all record boundaries | Punches dead payload interiors when requested |
| `compact()` | Existing copy and replace implementation | New inode contains current closure | Old inode lives until its readers release it |

Run `sac compact-in-place database.sac` offline, or `sac reclaim database.sac`
with cooperating native readers. `sac reclaim database.sac --no-punch` only
builds the disposable reuse index. JSON output reports logical and allocated
bytes, retained/dead frames, punched bytes, reusable bytes, moved bytes,
a conservative peak journal bound and elapsed time.

## Reader and filesystem contract

Same-file maintenance requires an owner-private regular live file (no group or
other permission bits), the native exclusive writer fence and a local filesystem
with working file locks, atomic rename, fsync and directory fsync. All native
readers must use this implementation and the same persistent `HOME` registry.
`NativeReader::open`, `open_file`, `NativeStore::pin` and read-only native stores
register their root for their lifetime. Registration is keyed by device/inode,
so hard links and independent processes participate. Dead process registrations
are removed after their operating-system lock is released.

An old pin retains its authenticated root closure, rather than arbitrary
unreachable objects in its historical byte range. Raw `File`, `ReadAt`, HTTP,
foreign runtimes and old SAC implementations do not register. Close those
readers before same-file maintenance, or use copy and replace. Copy and replace
remains the choice for uncoordinated readers and cross-host access. Native root
admission and whole-file validation can return `Busy` while maintenance holds
the admission gate; retry them. Existing readers can keep reading reachable
immutable objects during online reclamation. `begin_reclamation` captures the
old prefix and live roots; run `OnlineReclamation::reclaim` on a worker and call
`finish_reclamation` to install the index. Writer publications keep appending
outside that prefix while the worker runs. Old-prefix reuse and other physical
maintenance are excluded until the job ends. Newly admitted roots derive their
old-prefix objects from the captured roots; new objects append outside it.
Dropping the job abandons only its reusable index. The synchronous
`reclaim_online` convenience occupies its caller until the operation completes.
There is no hard latency guarantee for filesystem I/O, admission or publication.

The private persistent registry and active redo journals live under
`$HOME/.sac-native/<device>-<inode>`. Do not remove or relocate that directory
while a transaction is pending. A successful offline operation or reused-frame
write removes its journal. Empty reader-domain directories can remain. Writable
open resumes a pending transaction before admitting a root; read-only native
open returns `RecoveryRequired`. Preserve the registry with a damaged source
when diagnosing recovery. Copying a partially compacted source without its
journal does not produce a recoverable archive. Fully completed SAC files remain
self-contained and independently readable.

A journal is found by device and inode, so a file that is restored or replaced
in place under the same inode inherits a pending journal. Writable open
therefore binds a journal to the file before it changes one byte. Each frame
that the remaining steps read must be where the journal says it is: moved frames
at their destination, the pending batch in its redo record, and all other frames
at their source. Before finalization, the file must also still end at the head
that the plan was made for. If the file does not agree, and the head that it
selects admits with its complete closure intact, the journal is stale: it is
removed and the file is opened unchanged. That is the result of restoring a
backup over an interrupted compaction. If the file does not agree and is not
complete without the journal, open fails with an integrity error, the file and
the journal are unchanged, and `sac salvage` remains available. A reused-frame
record is bound to the preamble and both publication slots in the same way.

The syscall adapter supports macOS `F_PUNCHHOLE` and Linux
`FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE`; filesystem support is required.
It discards only complete 16 KiB allocation units strictly inside dead stored
payloads, preserving frame headers, locators and padding. Small dead frames can
be reusable without being punchable. Unsupported filesystems return an error;
there is no zero-writing fallback presented as disk reclamation. Other Unix
hosts can use compaction and reuse with punching disabled. Windows native
writable publication and these maintenance APIs remain unsupported; the portable
SAC1 reader is separate from that native filesystem capability.

## Recovery and reuse

Offline compaction validates physical frame ownership and the selected closure,
then durably commits a checksummed source-to-destination plan and new file
incarnation. Frames slide in source order, patching physical child locators and
preserving canonical hashes. Before every destructive batch, its complete output
is synchronized to a checked redo record. Data synchronization precedes the
progress checkpoint. Recovery replays that batch and resumes unread source
frames. Both publication slots and trailers are rebuilt and synchronized before
truncation. Removing the manifest after the final sync commits reader admission.
A failed transaction must be resumed; do not continue using the failed writer.

Online reclamation first inventories top-level frames and marks the closure of
the current root, both durable slots and registered pins. Only unmarked payloads
are punched. The writer maintains a bounded set of exact-size free-frame buckets
with offsets spilled to temporary storage. Subsequent kind-7 byte-object writes
can reuse those spans. Metadata and control frames append, preserving the
child-before-parent rule. Each reuse has its own durable full-frame redo record,
so a torn write cannot break the physical framing scanned by old readers. A
publication discards the free index; sweep again to rebuild it. A maintenance
operation rejects unpublished writes, including unpublished reused frames.

Sweep and reused-frame writes retire previously issued physical cache and
deferred rewrite capabilities. Acquire a fresh rewrite source immediately before
rewriting; resource builders do this automatically. Arbitrary retired object
references are outside the lifetime contract after reclamation. Retain a native
reader pin before sweeping if that root must stay usable.

Options enforce graph, source, output, elapsed preparation, memory and temporary
storage bounds. Memory requires at least 64 MiB, with fixed-size resident table
prefixes and a bounded redo/decoder workspace; existing caller-held views and
separate reader caches remain the caller's responsibility. Source accounting
reserves a conservative three passes. Temporary accounting includes plan,
spill tables and simultaneous old/new redo files. Once a durable manifest exists,
recovery takes precedence over elapsed preparation limits. The reported journal
peak is an upper bound, not sampled physical disk use or total scratch I/O.

Allocated-byte statistics sample the open inode. Filesystems can release extra
EOF preallocation when the writer closes; the benchmark also records that state.
