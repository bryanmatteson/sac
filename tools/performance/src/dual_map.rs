//! Experimental packed resource base + authenticated trie or paged delta.
use crate::bucket_trie::BucketTrie;
use crate::prefix_trie::{MAX_KEY, MAX_VALUE, PrefixTrie, Value as TrieValue, admit_snapshot};
use sac::cbor::{self, Value as V};
use sac::resources::{
    self, ArchiveBuilder, ArchiveReader, EntryKind, ExtentAccumulator, FileContents, Limits,
    Profile,
};
use sac::v1::cbor_view;
use sac::{Error, ObjectRef, ObjectStore, Result};
use std::collections::BTreeMap;

pub const PROFILE: &str = "org.sac.experimental.dual-map";
pub const BUCKET_PROFILE: &str = "org.sac.experimental.bucket-dual-map";
pub const PAGED_PROFILE: &str = "org.sac.experimental.paged-dual-map";
// Small deltas favor short rewrite paths; the dense base keeps its normal
// grouping. Raise this floor only when long keys require wider branch fences.
const DELTA_PAGE_BYTES: usize = 8192;

#[derive(Clone)]
enum Delta {
    Trie(PrefixTrie),
    Bucket(BucketTrie),
    Paged {
        snapshot: Option<ObjectRef>,
        entries: u64,
        bytes: u64,
        bounds: Option<(Vec<u8>, Vec<u8>)>,
        max_key_bytes: usize,
    },
}
enum MergeValue {
    Inline(Vec<u8>),
    Blob { length: usize, reference: ObjectRef },
    Extents { length: u64, root: ObjectRef },
}
impl MergeValue {
    fn len(&self) -> u64 {
        match self {
            Self::Inline(bytes) => bytes.len() as u64,
            Self::Blob { length, .. } => *length as u64,
            Self::Extents { length, .. } => *length,
        }
    }
}
impl Delta {
    fn len(&self) -> u64 {
        match self {
            Self::Trie(trie) => trie.len(),
            Self::Bucket(trie) => trie.len(),
            Self::Paged { entries, .. } => *entries,
        }
    }
    fn empty(&self) -> Self {
        match self {
            Self::Trie(_) => Self::Trie(PrefixTrie::default()),
            Self::Bucket(_) => Self::Bucket(BucketTrie::default()),
            Self::Paged { .. } => Self::Paged {
                snapshot: None,
                entries: 0,
                bytes: 0,
                bounds: None,
                max_key_bytes: 0,
            },
        }
    }
    fn set<S: ObjectStore + ?Sized>(
        &mut self,
        store: &mut S,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        match self {
            Self::Trie(trie) => trie.set(store, key, value),
            Self::Bucket(trie) => trie.set(store, key, value),
            Self::Paged {
                snapshot,
                entries,
                bytes,
                bounds,
                max_key_bytes,
            } => {
                if value.len() > MAX_VALUE {
                    return Err(Error::Limit("dual value"));
                }
                let path = [key.to_vec()];
                let (directory, previous) = if let Some(root) = *snapshot {
                    let reader = ArchiveReader::open(store, root, Limits::default())?;
                    (
                        Some(reader.directory_root()),
                        reader
                            .lookup_shared(&path)?
                            .map(|entry| entry.file_length().ok_or_else(|| bad("delta file role")))
                            .transpose()?,
                    )
                } else {
                    (None, None)
                };
                let next_entries = *entries + u64::from(previous.is_none());
                let next_bytes = bytes
                    .checked_sub(previous.unwrap_or(0))
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
                    .ok_or(Error::Limit("delta bytes"))?;
                if next_entries > 1_000_000 || next_bytes > 512 * 1024 * 1024 {
                    return Err(Error::Limit("delta memory"));
                }
                let mut builder = match directory {
                    Some(root) => ArchiveBuilder::from_directory(store, root, Limits::default()),
                    None => ArchiveBuilder::new(store),
                };
                // A branch must fit three maximum-size fences so overflow can
                // split into two legal branches with at least two children.
                let next_max_key = (*max_key_bytes).max(key.len());
                builder.set_page_limit(DELTA_PAGE_BYTES.max(3 * next_max_key + 256))?;
                builder.set_file(&path, value, V::Map(vec![]))?;
                let next = builder.finish()?;
                match bounds {
                    Some((low, high)) => {
                        if key < low.as_slice() {
                            *low = key.to_vec();
                        }
                        if key > high.as_slice() {
                            *high = key.to_vec();
                        }
                    }
                    None => *bounds = Some((key.to_vec(), key.to_vec())),
                }
                *max_key_bytes = next_max_key;
                *snapshot = Some(next);
                *entries = next_entries;
                *bytes = next_bytes;
                Ok(())
            }
        }
    }
    fn root<S: ObjectStore + ?Sized>(&self, store: &mut S) -> Result<ObjectRef> {
        match self {
            Self::Trie(trie) => trie.profile_root(store),
            Self::Bucket(trie) => trie.profile_root(store),
            Self::Paged {
                snapshot: Some(root),
                ..
            } => Ok(*root),
            Self::Paged { snapshot: None, .. } => ArchiveBuilder::new(store).finish(),
        }
    }
    fn values<S: ObjectStore + ?Sized>(&self, store: &S) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        match self {
            Self::Trie(trie) => trie.verify(store),
            Self::Bucket(trie) => trie.verify(store),
            Self::Paged { snapshot: None, .. } => Ok(BTreeMap::new()),
            Self::Paged {
                snapshot: Some(root),
                ..
            } => flat_values(store, *root),
        }
    }
    fn entries<S: ObjectStore + ?Sized>(&self, store: &S) -> Result<BTreeMap<Vec<u8>, MergeValue>> {
        match self {
            Self::Trie(trie) => Ok(trie
                .verified_entries(store)?
                .into_iter()
                .map(|(key, value)| {
                    (
                        key,
                        match value {
                            TrieValue::Inline(bytes) => MergeValue::Inline(bytes),
                            TrieValue::Blob { length, reference } => {
                                MergeValue::Blob { length, reference }
                            }
                        },
                    )
                })
                .collect()),
            Self::Bucket(trie) => Ok(trie
                .verified_entries(store)?
                .into_iter()
                .map(|(key, value)| {
                    (
                        key,
                        match value {
                            sac::resources::live_map::Value::Inline(bytes) => MergeValue::Inline(bytes),
                            sac::resources::live_map::Value::Blob { length, reference } => {
                                MergeValue::Blob { length, reference }
                            }
                        },
                    )
                })
                .collect()),
            Self::Paged { snapshot: None, .. } => Ok(BTreeMap::new()),
            Self::Paged {
                snapshot: Some(root),
                ..
            } => {
                admit_flat(store, *root)?;
                let reader = ArchiveReader::open(store, *root, Limits::default())?;
                let mut output = BTreeMap::new();
                reader.visit_entries(&mut |entry| {
                    let view = reader
                        .lookup_shared(&entry.path)?
                        .ok_or_else(|| bad("delta file"))?;
                    let value = match view
                        .file_contents()?
                        .ok_or_else(|| bad("delta file role"))?
                    {
                        FileContents::Inline(bytes) => MergeValue::Inline(bytes.to_vec()),
                        FileContents::Extents { length, root } => {
                            MergeValue::Extents { length, root }
                        }
                    };
                    output.insert(entry.path[0].clone(), value);
                    Ok(())
                })?;
                Ok(output)
            }
        }
    }
}

struct FlatInfo {
    entries: u64,
    bytes: u64,
    bounds: Option<(Vec<u8>, Vec<u8>)>,
    max_key_bytes: usize,
}
fn admit_flat<S: ObjectStore + ?Sized>(store: &S, root: ObjectRef) -> Result<FlatInfo> {
    let reader = ArchiveReader::open(store, root, Limits::default())?;
    let object = store.get_verified_shared(root)?;
    let [_, profiles, features] = cbor_view::view(&object.bytes)?.fields()?;
    if profiles.array()?.len() != 0 || features.array()?.len() != 0 {
        return Err(bad("layer must be a plain resource snapshot"));
    }
    let report = reader.verify()?;
    let mut retained = 0u64;
    let mut bounds: Option<(Vec<u8>, Vec<u8>)> = None;
    let mut max_key_bytes = 0;
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
        max_key_bytes = max_key_bytes.max(entry.path[0].len());
        match &mut bounds {
            Some((_, high)) => *high = entry.path[0].clone(),
            None => bounds = Some((entry.path[0].clone(), entry.path[0].clone())),
        }
        retained = retained
            .checked_add(entry.length + entry.path[0].len() as u64)
            .ok_or(Error::Limit("dual layer bytes"))?;
        if retained > 512 * 1024 * 1024 {
            return Err(Error::Limit("dual layer bytes"));
        }
        Ok(())
    })?;
    Ok(FlatInfo {
        entries: report.files,
        bytes: retained,
        bounds,
        max_key_bytes,
    })
}
fn flat_values<S: ObjectStore + ?Sized>(
    store: &S,
    root: ObjectRef,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    admit_flat(store, root)?;
    let reader = ArchiveReader::open(store, root, Limits::default())?;
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
    Error::Corrupt(format!("experimental dual map: {message}"))
}
fn key_valid(key: &[u8]) -> bool {
    !key.is_empty()
        && key.len() <= MAX_KEY
        && key != b"."
        && key != b".."
        && !key.contains(&0)
        && !key.contains(&b'/')
}
#[derive(Clone)]
pub struct DualMap {
    base: ObjectRef,
    delta: Delta,
    base_entries: u64,
    base_bytes: u64,
}
pub struct DualReader<'a, S: ObjectStore + ?Sized> {
    store: &'a S,
    base: ArchiveReader<'a, S>,
    delta: ReadDelta<'a, S>,
}
// Keep both fixed-size reader handles inline; no extra allocation per reader.
#[allow(clippy::large_enum_variant)]
enum ReadDelta<'a, S: ObjectStore + ?Sized> {
    Trie(PrefixTrie),
    Bucket(BucketTrie),
    Paged {
        reader: Option<ArchiveReader<'a, S>>,
        bounds: Option<(Vec<u8>, Vec<u8>)>,
    },
}
impl<S: ObjectStore + ?Sized> DualReader<'_, S> {
    /// Missing routes are authoritative after DualMap::verify.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if !key_valid(key) {
            return Err(bad("resource key"));
        }
        match &self.delta {
            ReadDelta::Trie(trie) => {
                if let Some(value) = trie.get(self.store, key)? {
                    return Ok(Some(value));
                }
                self.base
                    .read_file_bounded(&[key.to_vec()], MAX_VALUE)
                    .map(|v| v.map(|(_, bytes)| bytes))
            }
            ReadDelta::Bucket(trie) => {
                if let Some(value) = trie.get(self.store, key)? {
                    return Ok(Some(value));
                }
                self.base
                    .read_file_bounded(&[key.to_vec()], MAX_VALUE)
                    .map(|v| v.map(|(_, bytes)| bytes))
            }
            ReadDelta::Paged { reader, bounds } => {
                let path = [key.to_vec()];
                // Bounds come only from a complete layer admission or successful
                // writes to this immutable root; an unchecked hint cannot skip it.
                if let (Some(reader), Some((low, high))) = (reader, bounds)
                    && low.as_slice() <= key
                    && key <= high.as_slice()
                    && let Some((_, bytes)) = reader.read_file_bounded(&path, MAX_VALUE)?
                {
                    return Ok(Some(bytes));
                }
                self.base
                    .read_file_bounded(&path, MAX_VALUE)
                    .map(|v| v.map(|(_, bytes)| bytes))
            }
        }
    }
}
impl DualMap {
    pub fn from_base<S: ObjectStore + ?Sized>(store: &S, base: ObjectRef) -> Result<Self> {
        let FlatInfo {
            entries: base_entries,
            bytes: base_bytes,
            ..
        } = admit_flat(store, base)?;
        Ok(Self {
            base,
            delta: Delta::Trie(PrefixTrie::default()),
            base_entries,
            base_bytes,
        })
    }
    pub fn from_base_bucket<S: ObjectStore + ?Sized>(store: &S, base: ObjectRef) -> Result<Self> {
        let mut map = Self::from_base(store, base)?;
        map.delta = Delta::Bucket(BucketTrie::default());
        Ok(map)
    }
    pub fn from_base_paged<S: ObjectStore + ?Sized>(store: &S, base: ObjectRef) -> Result<Self> {
        let mut map = Self::from_base(store, base)?;
        map.delta = Delta::Paged {
            snapshot: None,
            entries: 0,
            bytes: 0,
            bounds: None,
            max_key_bytes: 0,
        };
        Ok(map)
    }
    fn profile(&self) -> &'static str {
        match self.delta {
            Delta::Trie(_) => PROFILE,
            Delta::Bucket(_) => BUCKET_PROFILE,
            Delta::Paged { .. } => PAGED_PROFILE,
        }
    }
    pub fn overlay_len(&self) -> u64 {
        self.delta.len()
    }
    pub fn set<S: ObjectStore + ?Sized>(
        &mut self,
        store: &mut S,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        if !key_valid(key) {
            return Err(bad("resource key"));
        }
        self.delta.set(store, key, value)
    }
    pub fn reader<'a, S: ObjectStore + ?Sized>(&self, store: &'a S) -> Result<DualReader<'a, S>> {
        Ok(DualReader {
            store,
            base: ArchiveReader::open(store, self.base, Limits::default())?,
            delta: match &self.delta {
                Delta::Trie(trie) => ReadDelta::Trie(trie.clone()),
                Delta::Bucket(trie) => ReadDelta::Bucket(trie.clone()),
                Delta::Paged {
                    snapshot, bounds, ..
                } => ReadDelta::Paged {
                    reader: snapshot
                        .map(|root| ArchiveReader::open(store, root, Limits::default()))
                        .transpose()?,
                    bounds: bounds.clone(),
                },
            },
        })
    }
    pub fn snapshot<S: ObjectStore + ?Sized>(&self, store: &mut S) -> Result<ObjectRef> {
        let delta = self.delta.root(store)?;
        let root = store.put(
            8,
            1,
            &cbor::encode(&V::Array(vec![
                V::text(self.profile()),
                V::text("root"),
                V::Uint(1),
                V::Bytes(cbor::encode(&V::Array(vec![V::Uint(0), V::Uint(1)]))),
            ])),
            &[self.base, delta],
        )?;
        // Never expose a stale resource directory to a generic resource reader.
        let directory = ArchiveBuilder::new(store).finish_directory()?;
        resources::snapshot(
            store,
            directory,
            vec![Profile {
                id: self.profile().into(),
                version: 1,
                root,
            }],
            vec![],
        )
    }
    pub fn open<S: ObjectStore + ?Sized>(store: &S, snapshot: ObjectRef) -> Result<Self> {
        let object = store.get_verified_shared(snapshot)?;
        let [_, profiles, _] = cbor_view::view(&object.bytes)?.fields()?;
        let declaration = profiles.array()?.next().ok_or_else(|| bad("profile"))??;
        let [id, _, _] = declaration.fields()?;
        let profile = match id.text()? {
            PROFILE => PROFILE,
            BUCKET_PROFILE => BUCKET_PROFILE,
            PAGED_PROFILE => PAGED_PROFILE,
            _ => return Err(bad("profile namespace")),
        };
        let root = store.get_verified_shared(admit_snapshot(store, snapshot, profile)?)?;
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
        map.delta = if profile == PROFILE {
            Delta::Trie(PrefixTrie::from_profile_root(store, root.children[1])?)
        } else if profile == BUCKET_PROFILE {
            Delta::Bucket(BucketTrie::from_profile_root(store, root.children[1])?)
        } else {
            let FlatInfo {
                entries,
                bytes,
                bounds,
                max_key_bytes,
            } = admit_flat(store, root.children[1])?;
            Delta::Paged {
                snapshot: Some(root.children[1]),
                entries,
                bytes,
                bounds,
                max_key_bytes,
            }
        };
        Ok(map)
    }
    pub fn verify<S: ObjectStore + ?Sized>(&self, store: &S) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        let mut output = flat_values(store, self.base)?;
        let mut retained: usize = output
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum();
        for (key, value) in self.delta.values(store)? {
            if !key_valid(&key) {
                return Err(bad("overlay resource key"));
            }
            retained += key.len() + value.len();
            if let Some(prior) = output.insert(key.clone(), value) {
                retained -= key.len() + prior.len();
            }
            if retained > 512 * 1024 * 1024 || output.len() > 1_000_000 {
                return Err(Error::Limit("dual verification memory"));
            }
        }
        Ok(output)
    }
    /// Fold only changed keys into the immutable base. Large delta byte objects
    /// become shared extent descriptors; untouched base pages and payloads retain
    /// their exact references. Commit the pair of roots only after all batches
    /// and the replacement snapshot have been written successfully.
    pub fn checkpoint<S: ObjectStore + ?Sized>(&mut self, store: &mut S) -> Result<ObjectRef> {
        if self.delta.len() == 0 {
            return Ok(self.base);
        }
        let edits = self.delta.entries(store)?;
        let reader = ArchiveReader::open(store, self.base, Limits::default())?;
        let directory = reader.directory_root();
        let (mut next_entries, mut next_bytes) = (self.base_entries, self.base_bytes);
        for (key, value) in &edits {
            if !key_valid(key) {
                return Err(bad("overlay resource key"));
            }
            if let Some(previous) = reader.lookup_shared(&[key.clone()])? {
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
                .checked_add(value.len())
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
                    MergeValue::Inline(bytes) => FileContents::Inline(bytes),
                    MergeValue::Blob { length, reference } => {
                        let mut extents = ExtentAccumulator::new();
                        extents.push(store, *length as u64, Some(*reference))?;
                        FileContents::Extents {
                            length: *length as u64,
                            root: extents.finish(store)?.ok_or_else(|| bad("empty extent"))?,
                        }
                    }
                    MergeValue::Extents { length, root } => FileContents::Extents {
                        length: *length,
                        root: *root,
                    },
                };
                prepared.push((vec![key.clone()], contents, V::Map(vec![])));
            }
            let mut builder = ArchiveBuilder::from_directory(store, root, Limits::default());
            builder.set_files_batch(&prepared)?;
            root = builder.finish_directory()?;
        }
        let next = resources::snapshot(store, root, vec![], vec![])?;
        self.base = next;
        self.delta = self.delta.empty();
        self.base_entries = next_entries;
        self.base_bytes = next_bytes;
        Ok(next)
    }

    /// Full rebuild control, retained only for paired performance comparisons.
    pub fn checkpoint_rebuild<S: ObjectStore + ?Sized>(
        &mut self,
        store: &mut S,
    ) -> Result<ObjectRef> {
        if self.delta.len() == 0 {
            return Ok(self.base);
        }
        let values = self.verify(store)?;
        let next_entries = values.len() as u64;
        let next_bytes = values
            .iter()
            .map(|(key, value)| (key.len() + value.len()) as u64)
            .sum();
        let mut builder = ArchiveBuilder::bulk(store, Limits::default())?;
        for (key, value) in values {
            if value.len() > resources::INLINE_LIMIT {
                // Bytes are already materialized. Avoid the streaming reader's
                // chunk-batch scratch buffer for each individual large value.
                // This uses the same chunk boundaries and extent admission.
                builder.add_sparse(&[key], vec![resources::SparseSegment::Data(value)])?;
            } else {
                builder.add_file(&[key], &value)?;
            }
        }
        let next = builder.finish()?;
        self.base = next;
        self.base_entries = next_entries;
        self.base_bytes = next_bytes;
        self.delta = self.delta.empty();
        Ok(next)
    }
}
