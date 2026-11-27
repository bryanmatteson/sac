//! Authenticated flat maps with an immutable resource base and bucketed trie delta.
//! Updates copy only the changed trie path; checkpoint merges only changed keys.
use super::{
    ArchiveBuilder, ArchiveReader, EntryKind, ExtentAccumulator, Feature, FileContents, Limits,
    Profile,
};
use crate::v1::{
    Error, ObjectRef, ObjectStore, Result,
    cbor::{self, Value as V},
    cbor_view, resources,
};
use std::collections::BTreeMap;
#[doc(hidden)]
pub mod bucket;
mod value;
use bucket::BucketTrie;
#[doc(hidden)]
pub use value::Value;
/// Stable live-map snapshot profile and required capability.
pub const PROFILE: &str = "sac.live-map.v1";
pub const CAPABILITY: &str = "sac.live-map";
const LEGACY_PROFILE: &str = "org.sac.experimental.bucket-dual-map";
pub const MAX_KEY: usize = 4096;
pub const MAX_VALUE: usize = crate::v1::MAX_CHUNK_SIZE - 8;
const MAX_ENTRIES: u64 = 1_000_000;
const MAX_BYTES: u64 = 512 * 1024 * 1024;
fn resource_limits() -> Limits {
    Limits {
        max_entries: MAX_ENTRIES,
        max_logical_bytes: MAX_BYTES,
        max_file_bytes: MAX_VALUE as u64,
        ..Limits::default()
    }
}
fn limits(entries: u64, bytes: u64) -> Result<()> {
    if entries > MAX_ENTRIES || bytes > MAX_BYTES {
        return Err(Error::Limit("live map retained layers"));
    }
    Ok(())
}
// Admit the entire owned outer surface, including the exact required capability.
// Generic resource readers must reject the live view instead of reporting an empty map.
fn admit_snapshot<S: ObjectStore + ?Sized>(
    store: &S,
    snapshot: ObjectRef,
    profile: &str,
    required: bool,
) -> Result<ObjectRef> {
    let object = store.get_verified_shared(snapshot)?;
    crate::v1::validate_core_object(&object)?;
    if object.kind != 2 || object.version != 1 || object.children.len() != 2 {
        return Err(bad("snapshot kind/children"));
    }
    let [directory_index, profiles, features] = cbor_view::view(&object.bytes)?.fields()?;
    let mut profiles = profiles.array()?;
    if profiles.len() != 1 {
        return Err(bad("sole profile required"));
    }
    let [id, version, index] = profiles.next().ok_or_else(|| bad("profile"))??.fields()?;
    if id.text()? != profile
        || version.uint()? != 1
        || directory_index.uint()? != 0
        || index.uint()? != 1
    {
        return Err(bad("profile declaration"));
    }
    let expected_features = if required {
        V::Array(vec![V::Array(vec![
            V::Null,
            V::text(CAPABILITY),
            V::Uint(1),
            V::Bool(true),
        ])])
    } else {
        V::Array(vec![])
    };
    if features.encoded() != cbor::encode(&expected_features) {
        return Err(Error::Unsupported("live map capabilities".into()));
    }
    let directory = store.get_verified_shared(object.children[0])?;
    if directory.kind != 3
        || directory.version != 1
        || !directory.children.is_empty()
        || cbor_view::view(&directory.bytes)?.array()?.len() != 0
    {
        return Err(bad("outer directory must be empty"));
    }
    Ok(object.children[1])
}
fn admit_bucket_snapshot<S: ObjectStore + ?Sized>(
    store: &S,
    snapshot: ObjectRef,
    profile: &str,
) -> Result<ObjectRef> {
    admit_snapshot(store, snapshot, profile, false)
}
struct FlatInfo {
    entries: u64,
    bytes: u64,
}
fn admit_flat<S: ObjectStore + ?Sized>(store: &S, root: ObjectRef) -> Result<FlatInfo> {
    let reader = ArchiveReader::open(store, root, resource_limits())?;
    let object = store.get_verified_shared(root)?;
    let [_, profiles, features] = cbor_view::view(&object.bytes)?.fields()?;
    if profiles.array()?.len() != 0 || features.array()?.len() != 0 {
        return Err(bad("layer must be a plain resource snapshot"));
    }
    let report = reader.verify()?;
    let mut retained = 0u64;
    reader.visit_entries(&mut |entry| {
        if entry.kind != EntryKind::File
            || entry.path.len() != 1
            || entry.metadata != V::Map(vec![])
            || !key_valid(&entry.path[0])
            || entry.length > MAX_VALUE as u64
        {
            return Err(bad(
                "layers must contain bounded flat files without metadata",
            ));
        }
        retained = retained
            .checked_add(entry.length + entry.path[0].len() as u64)
            .ok_or(Error::Limit("live map layer bytes"))?;
        if retained > 512 * 1024 * 1024 {
            return Err(Error::Limit("live map layer bytes"));
        }
        Ok(())
    })?;
    Ok(FlatInfo {
        entries: report.files,
        bytes: retained,
    })
}
fn flat_values<S: ObjectStore + ?Sized>(
    store: &S,
    root: ObjectRef,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    admit_flat(store, root)?;
    let reader = ArchiveReader::open(store, root, resource_limits())?;
    let mut values = BTreeMap::new();
    reader.visit_entries(&mut |entry| {
        let value = reader
            .read_file_bounded(&entry.path, MAX_VALUE)?
            .ok_or_else(|| bad("layer file"))?
            .1;
        values.insert(entry.path[0].clone(), value);
        Ok(())
    })?;
    Ok(values)
}

fn bad(message: &str) -> Error {
    Error::Corrupt(format!("live map: {message}"))
}
fn key_valid(key: &[u8]) -> bool {
    !key.is_empty()
        && key.len() <= MAX_KEY
        && key != b"."
        && key != b".."
        && !key.contains(&0)
        && !key.contains(&b'/')
}
/// A retained, authenticated map editor. Keep this handle across edits to avoid
/// repeating full admission. Keys are flat resource names; values are bytes.
/// Limits charge both base and delta, including shadowed base values. Checkpoint
/// releases this retained-layer charge. No metadata, nested paths, or deletion.
#[derive(Clone)]
pub struct LiveMap {
    base: ObjectRef,
    delta: BucketTrie,
    base_entries: u64,
    base_bytes: u64,
    delta_bytes: u64,
}
/// A read handle for one immutable map view. Construction does not preload keys.
pub struct LiveMapReader<'a, S: ObjectStore + ?Sized> {
    store: &'a S,
    base: ArchiveReader<'a, S>,
    delta: BucketTrie,
}
impl<S: ObjectStore + ?Sized> LiveMapReader<'_, S> {
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if !key_valid(key) {
            return Err(bad("resource key"));
        }
        if let Some(value) = self.delta.get(self.store, key)? {
            return Ok(Some(value));
        }
        self.base
            .read_file_bounded(&[key.to_vec()], MAX_VALUE)
            .map(|v| v.map(|(_, bytes)| bytes))
    }
}
impl LiveMap {
    pub fn new<S: ObjectStore + ?Sized>(store: &mut S) -> Result<Self> {
        let base = ArchiveBuilder::new(store).finish()?;
        Self::from_base(store, base)
    }
    /// Import an ordinary flat resource snapshot, fully authenticating its contents.
    pub fn from_base<S: ObjectStore + ?Sized>(store: &S, base: ObjectRef) -> Result<Self> {
        let info = admit_flat(store, base)?;
        limits(info.entries, info.bytes)?;
        Ok(Self {
            base,
            delta: BucketTrie::default(),
            base_entries: info.entries,
            base_bytes: info.bytes,
            delta_bytes: 0,
        })
    }
    /// Authenticate and admit a live snapshot, an ordinary flat snapshot, or the
    /// previously qualified experimental bucket-dual snapshot. Unknown surfaces fail.
    pub fn open<S: ObjectStore + ?Sized>(store: &S, snapshot: ObjectRef) -> Result<Self> {
        let object = store.get_verified_shared(snapshot)?;
        if object.kind != 2 || object.version != 1 {
            return Err(bad("snapshot kind"));
        }
        let [_, profiles, _] = cbor_view::view(&object.bytes)?.fields()?;
        let mut declarations = profiles.array()?;
        if declarations.len() == 0 {
            return Self::from_base(store, snapshot);
        }
        let [id, _, _] = declarations
            .next()
            .ok_or_else(|| bad("profile"))??
            .fields()?;
        let profile = id.text()?;
        if profile != PROFILE && profile != LEGACY_PROFILE {
            return Err(Error::Unsupported("live map profile".into()));
        }
        let root = store.get_verified_shared(admit_snapshot(
            store,
            snapshot,
            profile,
            profile == PROFILE,
        )?)?;
        if root.kind != 8 || root.version != 1 || root.children.len() != 2 {
            return Err(bad("root kind/children"));
        }
        let [namespace, typ, version, payload] = cbor_view::view(&root.bytes)?.fields()?;
        let [base_index, delta_index] = cbor_view::view(payload.bytes()?)?.fields()?;
        if namespace.text()? != profile
            || typ.text()? != "root"
            || version.uint()? != 1
            || base_index.uint()? != 0
            || delta_index.uint()? != 1
        {
            return Err(bad("root fields"));
        }
        let mut map = Self::from_base(store, root.children[0])?;
        map.delta = BucketTrie::from_profile_root(store, root.children[1])?;
        for (key, value) in map.delta.verified_entries(store)? {
            if !key_valid(&key) {
                return Err(bad("delta key"));
            }
            map.delta_bytes = map
                .delta_bytes
                .checked_add((key.len() + value.len()) as u64)
                .ok_or(Error::Limit("live map bytes"))?;
        }
        limits(
            map.base_entries + map.delta.len(),
            map.base_bytes + map.delta_bytes,
        )?;
        Ok(map)
    }
    pub fn overlay_len(&self) -> u64 {
        self.delta.len()
    }
    /// Select the replacement root only after all writes and quota checks succeed.
    pub fn set<S: ObjectStore + ?Sized>(
        &mut self,
        store: &mut S,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        if !key_valid(key) {
            return Err(bad("resource key"));
        }
        let mut next_bytes = self.delta_bytes;
        let entries = self.base_entries + self.delta.len();
        let base_bytes = self.base_bytes;
        self.delta.set_checked(store, key, value, |previous| {
            next_bytes = next_bytes
                .checked_sub(previous.unwrap_or(0) as u64)
                .and_then(|n| {
                    n.checked_add(
                        value.len() as u64
                            + if previous.is_none() {
                                key.len() as u64
                            } else {
                                0
                            },
                    )
                })
                .ok_or(Error::Limit("live map bytes"))?;
            limits(
                entries + u64::from(previous.is_none()),
                base_bytes + next_bytes,
            )
        })?;
        self.delta_bytes = next_bytes;
        Ok(())
    }
    pub fn reader<'a, S: ObjectStore + ?Sized>(
        &self,
        store: &'a S,
    ) -> Result<LiveMapReader<'a, S>> {
        Ok(LiveMapReader {
            store,
            base: ArchiveReader::open(store, self.base, resource_limits())?,
            delta: self.delta.clone(),
        })
    }
    /// Append an authenticated map snapshot. This alone does not publish durably.
    pub fn snapshot<S: ObjectStore + ?Sized>(&self, store: &mut S) -> Result<ObjectRef> {
        let delta = self.delta.profile_root(store)?;
        let root = store.put(
            8,
            1,
            &cbor::encode(&V::Array(vec![
                V::text(PROFILE),
                V::text("root"),
                V::Uint(1),
                V::Bytes(cbor::encode(&V::Array(vec![V::Uint(0), V::Uint(1)]))),
            ])),
            &[self.base, delta],
        )?;
        let directory = ArchiveBuilder::new(store).finish_directory()?;
        resources::snapshot(
            store,
            directory,
            vec![Profile {
                id: PROFILE.into(),
                version: 1,
                root,
            }],
            vec![Feature {
                scope: None,
                id: CAPABILITY.into(),
                version: 1,
                required: true,
            }],
        )
    }
    /// Durably publish through the native store's normal chunk and root-slot barriers.
    #[cfg(feature = "native")]
    pub fn publish(
        &self,
        store: &mut crate::v1::native::NativeStore,
    ) -> Result<crate::v1::Publication> {
        let snapshot = self.snapshot(store)?;
        store.publish(snapshot)
    }
    /// Materialize and verify the complete logical view (bounded by retained limits).
    pub fn verify<S: ObjectStore + ?Sized>(&self, store: &S) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        let mut output = flat_values(store, self.base)?;
        output.extend(self.delta.verify(store)?);
        Ok(output)
    }
    /// Fold only changed keys into the immutable base. Large delta byte objects
    /// become shared extent descriptors; untouched base pages and payloads retain
    /// their exact references. Commit the pair of roots only after all batches
    /// and the replacement snapshot have been written successfully.
    pub fn checkpoint<S: ObjectStore + ?Sized>(&mut self, store: &mut S) -> Result<ObjectRef> {
        if self.delta.is_empty() {
            return Ok(self.base);
        }
        let edits = self.delta.verified_entries(store)?;
        let reader = ArchiveReader::open(store, self.base, resource_limits())?;
        let directory = reader.directory_root();
        let (mut next_entries, mut next_bytes) = (self.base_entries, self.base_bytes);
        for (key, value) in &edits {
            if !key_valid(key) {
                return Err(bad("overlay resource key"));
            }
            if let Some(previous) = reader.lookup_shared(std::slice::from_ref(key))? {
                next_bytes = next_bytes
                    .checked_sub(
                        previous
                            .file_length()
                            .ok_or_else(|| bad("base file role"))?,
                    )
                    .ok_or_else(|| bad("base accounting"))?;
            } else {
                next_entries += 1;
                next_bytes += key.len() as u64;
            }
            next_bytes = next_bytes
                .checked_add(value.len() as u64)
                .ok_or(Error::Limit("dual merge bytes"))?;
        }
        if next_entries > 1_000_000 || next_bytes > 512 * 1024 * 1024 {
            return Err(Error::Limit("dual merge memory"));
        }
        drop(reader);
        let mut root = directory;
        let entries: Vec<_> = edits.into_iter().collect();
        for batch in entries.chunks(512) {
            let mut prepared = Vec::with_capacity(batch.len());
            for (key, value) in batch {
                if !key_valid(key) {
                    return Err(bad("overlay resource key"));
                }
                let contents = match value {
                    Value::Inline(bytes) => FileContents::Inline(bytes),
                    Value::Blob { length, reference } => {
                        let mut extents = ExtentAccumulator::new();
                        extents.push(store, *length as u64, Some(*reference))?;
                        FileContents::Extents {
                            length: *length as u64,
                            root: extents.finish(store)?.ok_or_else(|| bad("empty extent"))?,
                        }
                    }
                };
                prepared.push((vec![key.clone()], contents, V::Map(vec![])));
            }
            let mut builder = ArchiveBuilder::from_directory(store, root, resource_limits());
            builder.set_files_batch(&prepared)?;
            root = builder.finish_directory()?;
        }
        let next = resources::snapshot(store, root, vec![], vec![])?;
        self.delta_bytes = 0;
        self.base = next;
        self.delta = BucketTrie::default();
        self.base_entries = next_entries;
        self.base_bytes = next_bytes;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quota_failures_leave_delta_root_count_and_charge_unchanged() {
        for entry_limit in [false, true] {
            let mut store = crate::v1::MemoryStore::sealed();
            let mut map = LiveMap::new(&mut store).unwrap();
            map.set(&mut store, b"old", b"v").unwrap();
            if entry_limit {
                map.base_entries = MAX_ENTRIES - 1;
            } else {
                map.base_bytes = MAX_BYTES - map.delta_bytes;
            }
            let before = map.snapshot(&mut store).unwrap();
            let charge = map.delta_bytes;
            assert!(map.set(&mut store, b"new", b"v").is_err());
            assert_eq!(map.snapshot(&mut store).unwrap(), before);
            assert_eq!(map.delta_bytes, charge);
            assert_eq!(map.overlay_len(), 1);
        }
    }
}
