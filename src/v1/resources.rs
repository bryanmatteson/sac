//! Portable byte-name resources over the SAC1 canonical object store.
//!
//! Builders update persistent directory paths. Readers distinguish authenticated
//! routes from validated indexes and never turn an unchecked miss into absence.

use super::cbor::{self, Value};
use super::{CanonicalObject, Error, ObjectHash, ObjectRef, ObjectStore, ObjectView, Result};
use std::time::{Duration, Instant};

mod extract;
mod graph;
mod pages;
mod read;
#[cfg(feature = "native")]
mod salvage;
mod tree;
pub use extract::{ExtractionEntry, ExtractionReport};
pub use read::{
    ArchiveReader, DirectoryValidated, Lookup, OpenedFile, ResourceView, VerificationReport,
};
#[cfg(feature = "native")]
pub use salvage::{SalvageReport, salvage};
pub use tree::{ArchiveBuilder, ExtentAccumulator, PackingStatistics, SparseSegment};

pub type ResourcePath = Vec<Vec<u8>>;
pub const INLINE_LIMIT: usize = 48 * 1024;
pub const DIRECTORY_LEAF_LIMIT: usize = 128 * 1024;
pub const PAGE_LIMIT: usize = 64 * 1024;
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;
pub const BULK_CHUNK_SIZE: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Limits {
    pub max_entries: u64,
    pub max_logical_bytes: u64,
    pub max_file_bytes: u64,
    pub max_decoded_bytes: u64,
    pub max_source_bytes: u64,
    pub max_frames: u64,
    pub max_edges: u64,
    /// Resource path depth; arbitrary profile dependency chains use bounded iterative traversal.
    pub max_depth: usize,
    pub max_memory_bytes: usize,
    pub max_temp_bytes: u64,
    pub max_elapsed: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 1_000_000,
            max_logical_bytes: 64 << 30,
            max_file_bytes: 64 << 30,
            max_decoded_bytes: 256 << 30,
            max_source_bytes: 256 << 30,
            max_frames: 10_000_000,
            max_edges: 10_000_000,
            max_depth: 256,
            max_memory_bytes: 64 << 20,
            max_temp_bytes: 128 << 30,
            max_elapsed: Duration::from_secs(3600),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceEntry {
    pub path: ResourcePath,
    pub kind: EntryKind,
    pub length: u64,
    pub metadata: Value,
    pub link_target: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct Profile {
    pub id: String,
    pub version: u32,
    pub root: ObjectRef,
}
#[derive(Clone, Debug)]
pub struct Feature {
    pub scope: Option<String>,
    pub id: String,
    pub version: u32,
    pub required: bool,
}

pub fn path_from_str(path: &str) -> Result<ResourcePath> {
    let components: ResourcePath = path.split('/').map(|s| s.as_bytes().to_vec()).collect();
    validate_path(&components, &Limits::default())?;
    Ok(components)
}

pub fn snapshot<S: ObjectStore + ?Sized>(
    store: &mut S,
    directory: ObjectRef,
    mut profiles: Vec<Profile>,
    mut features: Vec<Feature>,
) -> Result<ObjectRef> {
    profiles.sort_by(|a, b| a.id.cmp(&b.id));
    let mut children = vec![directory];
    let mut profile_values = Vec::new();
    for profile in profiles {
        let i = child_index(&mut children, profile.root);
        profile_values.push(array(vec![
            Value::Text(profile.id),
            uint(u64::from(profile.version)),
            uint(i),
        ]));
    }
    features.sort_by_key(feature_key);
    let feature_values = features
        .into_iter()
        .map(|f| {
            array(vec![
                f.scope.map(Value::Text).unwrap_or(Value::Null),
                Value::Text(f.id),
                uint(u64::from(f.version)),
                Value::Bool(f.required),
            ])
        })
        .collect();
    put_value(
        store,
        2,
        array(vec![uint(0), array(profile_values), array(feature_values)]),
        &children,
    )
}

fn feature_key(feature: &Feature) -> Vec<u8> {
    cbor::encode(&array(vec![
        feature
            .scope
            .clone()
            .map(Value::Text)
            .unwrap_or(Value::Null),
        Value::Text(feature.id.clone()),
    ]))
}

pub fn commit<S: ObjectStore + ?Sized>(
    store: &mut S,
    root: ObjectRef,
    attestations: Option<ObjectRef>,
    local: Option<ObjectRef>,
) -> Result<ObjectRef> {
    let mut children = vec![root];
    let a = attestations
        .map(|r| uint(child_index(&mut children, r)))
        .unwrap_or(Value::Null);
    let l = local
        .map(|r| uint(child_index(&mut children, r)))
        .unwrap_or(Value::Null);
    put_value(store, 1, array(vec![uint(0), a, l]), &children)
}

/// Copy exactly a snapshot's strong closure, retaining canonical object IDs.
/// Native builds spill exact occurrence state and content remapping under one
/// temporary quota. Minimal builds retain a bounded resident index.
pub fn copy_snapshot<S: ObjectStore + ?Sized, D: ObjectStore + ?Sized>(
    source: &S,
    destination: &mut D,
    root: ObjectRef,
    limits: Limits,
) -> Result<ObjectRef> {
    copy_snapshot_with_verification(source, destination, root, limits, None)
}

pub(super) fn copy_snapshot_with_verification<S: ObjectStore + ?Sized, D: ObjectStore + ?Sized>(
    source: &S,
    destination: &mut D,
    root: ObjectRef,
    limits: Limits,
    mut verification: Option<Budget>,
) -> Result<ObjectRef> {
    let mut budget = Budget::new(limits);
    let mut graph = graph::Workspace::new(&mut budget)?;
    #[cfg(feature = "native")]
    if let Some(verification) = &mut verification {
        verification.reserve_memory(budget.resident_overhead)?;
    }
    // Charge the shared verification reads and edges to both workloads.
    // Reloads and elapsed work in this walk belong to the copy budget.
    // Retain references and traversal state, never ancestor payloads. Reload a
    // parent after its children; immutable stores can serve that from cache.
    graph.push(root, false, &budget)?;
    while let Some((r, expanded)) = graph.pop()? {
        budget.time()?;
        let object = if expanded {
            if graph.mapped(r.hash)?.is_some() {
                graph.complete(r, &budget)?;
                continue;
            }
            budget.get(source, r)?
        } else {
            if graph.completed(r)? {
                continue;
            }
            graph.enter(r, &budget)?;
            let object = budget.get_for_copy(source, r, verification.as_mut())?;
            crate::v1::validate_core_edges(&object, |child| {
                budget.get_for_copy(source, child, verification.as_mut())
            })?;
            for child in &object.children {
                budget.edge()?;
                if let Some(verification) = &mut verification {
                    verification.charge_edge()?;
                }
                budget.check_reference(r, *child)?;
            }
            // Deduplicate only completed identical physical occurrences. A
            // different offset/span with the same ID can carry other locators.
            if !object.children.is_empty() {
                graph.push(r, true, &budget)?;
                for child in object.children.iter().rev() {
                    graph.push(*child, false, &budget)?;
                }
                continue;
            }
            // Leaves need no postorder reload. The authenticated bytes are
            // still in hand and there are no destination locators to resolve.
            object
        };
        graph.complete(r, &budget)?;
        if !expanded && graph.mapped(r.hash)?.is_some() {
            continue;
        }
        let children = object
            .children
            .iter()
            .map(|child| graph.mapped(child.hash)?.ok_or(Error::Missing))
            .collect::<Result<Vec<_>>>()?;
        let verified = super::VerifiedObject {
            hash: r.hash,
            object,
            compressed: None,
        };
        let result = destination.put_verified(&verified, &children)?;
        if result.hash != r.hash {
            return Err(corrupt("copy changed canonical identity"));
        }
        graph.map(result, &budget)?;
    }
    graph.mapped(root.hash)?.ok_or(Error::Missing)
}

pub(crate) fn corrupt(message: impl Into<String>) -> Error {
    Error::Corrupt(message.into())
}
pub(crate) fn array(values: Vec<Value>) -> Value {
    Value::Array(values)
}
pub(crate) fn uint(value: u64) -> Value {
    Value::Uint(value)
}
pub(crate) fn empty_metadata() -> Value {
    Value::Map(Vec::new())
}
pub(crate) fn values(value: &Value) -> Result<&[Value]> {
    match value {
        Value::Array(a) => Ok(a),
        _ => Err(corrupt("expected CBOR array")),
    }
}
pub(crate) fn number(value: &Value) -> Result<u64> {
    match value {
        Value::Uint(n) => Ok(*n),
        _ => Err(corrupt("expected unsigned integer")),
    }
}
pub(crate) fn bytes(value: &Value) -> Result<&[u8]> {
    match value {
        Value::Bytes(b) => Ok(b),
        _ => Err(corrupt("expected byte string")),
    }
}
pub(crate) fn child(object: &CanonicalObject, value: &Value) -> Result<ObjectRef> {
    let i = usize::try_from(number(value)?).map_err(|_| corrupt("child index overflow"))?;
    object
        .children
        .get(i)
        .copied()
        .ok_or_else(|| corrupt("child index out of bounds"))
}
pub(crate) fn child_index(children: &mut Vec<ObjectRef>, reference: ObjectRef) -> u64 {
    if let Some(i) = children.iter().position(|r| r.hash == reference.hash) {
        return i as u64;
    }
    children.push(reference);
    (children.len() - 1) as u64
}
pub(crate) fn put_value<S: ObjectStore + ?Sized>(
    store: &mut S,
    kind: u16,
    value: Value,
    children: &[ObjectRef],
) -> Result<ObjectRef> {
    store.put(kind, 1, &cbor::encode(&value), children)
}
pub(crate) fn canonical_size(value: &Value, children: &[ObjectRef]) -> usize {
    8 + children.len() * 32 + cbor::encoded_len(value)
}
pub(crate) fn check_key(key: &[u8]) -> Result<()> {
    if key.is_empty()
        || key.len() > 4096
        || key == b"."
        || key == b".."
        || key.contains(&0)
        || key.contains(&b'/')
    {
        return Err(corrupt("invalid resource path component"));
    }
    Ok(())
}
pub(crate) fn validate_path(path: &[Vec<u8>], limits: &Limits) -> Result<()> {
    if path.is_empty() {
        return Err(corrupt("empty resource path"));
    }
    if path.len() > limits.max_depth {
        return Err(Error::Limit("path depth"));
    }
    let mut length = 0usize;
    for key in path {
        check_key(key)?;
        length = length
            .checked_add(key.len() + 1)
            .ok_or(Error::Limit("path length"))?;
    }
    if length > limits.max_memory_bytes {
        return Err(Error::Limit("path length"));
    }
    Ok(())
}

pub(crate) struct Budget {
    pub limits: Limits,
    pub directory_write_limit: usize,
    start: Instant,
    frames: u64,
    source: u64,
    decoded: u64,
    edges: u64,
    entries: u64,
    logical: u64,
    resident_overhead: usize,
}
impl Budget {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            directory_write_limit: DIRECTORY_LEAF_LIMIT,
            start: Instant::now(),
            frames: 0,
            source: 0,
            decoded: 0,
            edges: 0,
            entries: 0,
            logical: 0,
            resident_overhead: 0,
        }
    }
    pub fn time(&self) -> Result<()> {
        if self.start.elapsed() > self.limits.max_elapsed {
            Err(Error::Limit("elapsed work"))
        } else {
            Ok(())
        }
    }
    pub fn depth(&self, depth: usize) -> Result<()> {
        self.time()?;
        if depth > self.limits.max_depth {
            Err(Error::Limit("path depth"))
        } else {
            Ok(())
        }
    }
    pub fn memory(&self, bytes: usize) -> Result<()> {
        if bytes
            .checked_add(self.resident_overhead)
            .is_none_or(|bytes| bytes > self.limits.max_memory_bytes)
        {
            Err(Error::Limit("resident memory"))
        } else {
            Ok(())
        }
    }
    #[cfg(feature = "native")]
    pub fn reserve_memory(&mut self, bytes: usize) -> Result<()> {
        self.memory(bytes)?;
        self.resident_overhead += bytes;
        Ok(())
    }
    pub fn edge(&mut self) -> Result<()> {
        self.charge_edge()?;
        self.time()
    }
    fn charge_edge(&mut self) -> Result<()> {
        charge(&mut self.edges, 1, self.limits.max_edges, "logical edges")
    }
    pub fn entry(&mut self, length: u64) -> Result<()> {
        charge(
            &mut self.entries,
            1,
            self.limits.max_entries,
            "output entries",
        )?;
        if length > self.limits.max_file_bytes {
            return Err(Error::Limit("file logical length"));
        }
        charge(
            &mut self.logical,
            length,
            self.limits.max_logical_bytes,
            "logical output bytes",
        )?;
        self.time()
    }
    pub fn get<S: ObjectStore + ?Sized>(
        &mut self,
        store: &S,
        r: ObjectRef,
    ) -> Result<std::sync::Arc<CanonicalObject>> {
        self.get_for_copy(store, r, None)
    }
    pub fn visit<S: ObjectStore + ?Sized>(
        &mut self,
        store: &S,
        reference: ObjectRef,
        visitor: &mut dyn FnMut(ObjectView<'_>) -> Result<()>,
    ) -> Result<()> {
        self.charge_reference(reference)?;
        self.time()?;
        store.visit_verified(reference, &mut |object| {
            self.charge_decoded(object.canonical_len())?;
            visitor(object)
        })
    }
    fn get_for_copy<S: ObjectStore + ?Sized>(
        &mut self,
        store: &S,
        r: ObjectRef,
        verification: Option<&mut Self>,
    ) -> Result<std::sync::Arc<CanonicalObject>> {
        self.charge_reference(r)?;
        self.time()?;
        let object = if let Some(verification) = verification {
            verification.charge_reference(r)?;
            let object = store.get_verified_shared(r)?;
            verification.charge_object(&object)?;
            object
        } else {
            store.get_verified_shared(r)?
        };
        self.charge_object(&object)?;
        Ok(object)
    }
    fn charge_reference(&mut self, r: ObjectRef) -> Result<()> {
        charge(&mut self.frames, 1, self.limits.max_frames, "frame visits")?;
        charge(
            &mut self.source,
            u64::from(r.address.length),
            self.limits.max_source_bytes,
            "source bytes",
        )
    }
    fn charge_object(&mut self, object: &CanonicalObject) -> Result<()> {
        let len = 8usize
            .checked_add(object.children.len() * 32)
            .and_then(|n| n.checked_add(object.bytes.len()))
            .ok_or(Error::Limit("decoded bytes"))?;
        self.charge_decoded(len)
    }
    fn charge_decoded(&mut self, len: usize) -> Result<()> {
        self.memory(len.saturating_mul(3))?;
        charge(
            &mut self.decoded,
            len as u64,
            self.limits.max_decoded_bytes,
            "decoded bytes",
        )
    }
    pub fn check_reference(&self, parent: ObjectRef, child: ObjectRef) -> Result<()> {
        let end = child
            .address
            .offset
            .checked_add(u64::from(child.address.length))
            .ok_or_else(|| corrupt("child extent overflow"))?;
        if end > parent.address.offset {
            return Err(corrupt("child locator is not backward"));
        }
        Ok(())
    }
}
pub(crate) fn charge(
    counter: &mut u64,
    amount: u64,
    limit: u64,
    label: &'static str,
) -> Result<()> {
    let next = counter.checked_add(amount).ok_or(Error::Limit(label))?;
    if next > limit {
        return Err(Error::Limit(label));
    }
    *counter = next;
    Ok(())
}
