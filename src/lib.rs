//! Sealed Artifact Container: authenticated SAC1 immutable objects, portable
//! resource trees, sealed archives and durable live publication. The wire/API
//! specification is `specs/01-sac-core-v1.md`; application semantics belong to
//! profiles. Content integrity and optional publisher trust are distinct.

#[cfg(feature = "native")]
pub mod cli;
pub mod v1;
#[cfg(feature = "native")]
pub use v1::native::*;
pub use v1::{
    BOOTSTRAP_SIZE, BULK_COMPRESSION_LEVEL, CanonicalObject, ChunkAddress, CompactionLayout,
    CompactionRanges, Error, Header, LocatorPolicy, MAX_CHUNK_SIZE, MemoryStore, ObjectHash,
    ObjectRef, ObjectStore, PAGE_SIZE, PhysicalReadScope, PositionalStore, Preamble,
    PreparedObject, Publication, ReadAt, ReadRequest, ReadStatistics, Reader, Result,
    RewriteSource, SealedWriter, Slot, Trailer, TraversalLimits, ValidationReport, VerifiedObject,
    cbor, copy_closure, copy_closure_with_cache, pack_commit, pack_commit_with_limits,
    pack_snapshot, pack_snapshot_with_limits, recovery, resources, validate_closure,
    validate_core_edges, validate_core_object,
};
