use super::*;
use std::io::Read;
mod batch;
#[cfg(feature = "native")]
mod bulk;

/// Successful packing I/O from private external-sort spools. Counts include
/// repeated merge passes; peak includes simultaneously retained input/output runs.
#[derive(Clone, Copy, Default, Debug)]
pub struct PackingStatistics {
    pub temporary_peak_bytes: u64,
    pub temporary_read_bytes: u64,
    pub temporary_write_bytes: u64,
}

#[derive(Clone, Debug)]
pub enum SparseSegment {
    Data(Vec<u8>),
    Hole(u64),
}

#[derive(Clone, Debug)]
pub(crate) enum FileData {
    Inline(Vec<u8>),
    Extents(ObjectRef),
}
#[derive(Clone, Debug)]
pub(crate) enum EntryData {
    File { length: u64, data: FileData },
    Directory(ObjectRef),
    Symlink(Vec<u8>),
}
#[derive(Clone, Debug)]
pub(crate) struct Entry {
    pub name: Vec<u8>,
    pub metadata: Value,
    pub data: EntryData,
}
impl Entry {
    pub fn public(&self, path: ResourcePath) -> ResourceEntry {
        let (kind, length, link_target) = match &self.data {
            EntryData::File { length, .. } => (EntryKind::File, *length, None),
            EntryData::Directory(_) => (EntryKind::Directory, 0, None),
            EntryData::Symlink(target) => (
                EntryKind::Symlink,
                target.len() as u64,
                Some(target.clone()),
            ),
        };
        ResourceEntry {
            path,
            kind,
            length,
            metadata: self.metadata.clone(),
            link_target,
        }
    }
}

pub(crate) enum DirectoryNode {
    Leaf(Vec<Entry>),
    Branch {
        height: u64,
        fences: Vec<(Vec<u8>, ObjectRef)>,
    },
}
pub(crate) fn directory(object: &CanonicalObject) -> Result<DirectoryNode> {
    if object.version != 1 {
        return Err(Error::Unsupported("directory schema".into()));
    }
    if object.canonical_len()
        > if object.kind == 3 {
            DIRECTORY_LEAF_LIMIT
        } else {
            PAGE_LIMIT
        }
    {
        return Err(Error::Limit("directory page bytes"));
    }
    let body = cbor::decode(&object.bytes)?;
    match object.kind {
        3 => {
            let mut entries = Vec::new();
            let mut previous: Option<&[u8]> = None;
            for value in values(&body)? {
                let row = values(value)?;
                if row.len() != 4 {
                    return Err(corrupt("directory entry arity"));
                }
                let name = bytes(&row[0])?;
                check_key(name)?;
                if previous.is_some_and(|p| p >= name) {
                    return Err(corrupt("directory keys unordered"));
                }
                previous = Some(name);
                let data = match number(&row[1])? {
                    0 => {
                        let v = values(&row[3])?;
                        if v.len() != 3 {
                            return Err(corrupt("file descriptor arity"));
                        }
                        let length = number(&v[0])?;
                        let data = match number(&v[1])? {
                            0 => {
                                let b = bytes(&v[2])?;
                                if b.len() > INLINE_LIMIT || b.len() as u64 != length {
                                    return Err(corrupt("inline length mismatch"));
                                }
                                FileData::Inline(b.to_vec())
                            }
                            1 => {
                                if length == 0 {
                                    return Err(corrupt("zero file must be inline"));
                                }
                                FileData::Extents(child(object, &v[2])?)
                            }
                            _ => return Err(corrupt("unknown file storage")),
                        };
                        EntryData::File { length, data }
                    }
                    1 => EntryData::Directory(child(object, &row[3])?),
                    2 => {
                        let target = bytes(&row[3])?;
                        if target.len() > 4096 {
                            return Err(corrupt("symlink target length"));
                        }
                        EntryData::Symlink(target.to_vec())
                    }
                    _ => return Err(corrupt("unknown directory entry type")),
                };
                entries.push(Entry {
                    name: name.to_vec(),
                    metadata: row[2].clone(),
                    data,
                });
            }
            Ok(DirectoryNode::Leaf(entries))
        }
        4 => {
            let v = values(&body)?;
            if v.len() != 2 {
                return Err(corrupt("directory branch arity"));
            }
            let height = number(&v[0])?;
            if !(1..=16).contains(&height) {
                return Err(corrupt("directory branch height"));
            }
            let mut fences: Vec<(Vec<u8>, ObjectRef)> = Vec::new();
            for pair in values(&v[1])? {
                let pair = values(pair)?;
                if pair.len() != 2 {
                    return Err(corrupt("directory fence arity"));
                }
                let key = bytes(&pair[0])?;
                check_key(key)?;
                if fences.last().is_some_and(|(k, _)| k.as_slice() >= key) {
                    return Err(corrupt("directory fence ordering"));
                }
                fences.push((key.to_vec(), child(object, &pair[1])?));
            }
            if fences.len() < 2 {
                return Err(corrupt("single-child directory branch"));
            }
            Ok(DirectoryNode::Branch { height, fences })
        }
        _ => Err(corrupt("expected directory node")),
    }
}

pub(crate) fn encode_leaf(entries: &[Entry]) -> (Value, Vec<ObjectRef>) {
    let mut children = Vec::new();
    let rows = entries
        .iter()
        .map(|entry| {
            let (kind, value) = match &entry.data {
                EntryData::File { length, data } => {
                    let (storage, value) = match data {
                        FileData::Inline(b) => (0, Value::Bytes(b.clone())),
                        FileData::Extents(r) => (1, uint(child_index(&mut children, *r))),
                    };
                    (0, array(vec![uint(*length), uint(storage), value]))
                }
                EntryData::Directory(r) => (1, uint(child_index(&mut children, *r))),
                EntryData::Symlink(target) => (2, Value::Bytes(target.clone())),
            };
            array(vec![
                Value::Bytes(entry.name.clone()),
                uint(kind),
                entry.metadata.clone(),
                value,
            ])
        })
        .collect();
    (array(rows), children)
}
fn encode_branch(height: u64, fences: &[(Vec<u8>, ObjectRef)]) -> (Value, Vec<ObjectRef>) {
    let mut children = Vec::new();
    let rows = fences
        .iter()
        .map(|(k, r)| {
            array(vec![
                Value::Bytes(k.clone()),
                uint(child_index(&mut children, *r)),
            ])
        })
        .collect();
    (array(vec![uint(height), array(rows)]), children)
}
fn fits(value: &Value, children: &[ObjectRef]) -> bool {
    children.len() <= 1024 && canonical_size(value, children) <= PAGE_LIMIT
}
fn fits_leaf(value: &Value, children: &[ObjectRef]) -> bool {
    children.len() <= 1024 && canonical_size(value, children) <= DIRECTORY_LEAF_LIMIT
}
fn store_leaf<S: ObjectStore + ?Sized>(
    store: &mut S,
    entries: &[Entry],
) -> Result<(Vec<u8>, ObjectRef)> {
    store_leaf_after(store, entries, None)
}
fn store_leaf_after<S: ObjectStore + ?Sized>(
    store: &mut S,
    entries: &[Entry],
    prior: Option<ObjectRef>,
) -> Result<(Vec<u8>, ObjectRef)> {
    let (value, children) = encode_leaf(entries);
    if !fits_leaf(&value, &children) {
        return Err(Error::Limit("directory entry too large"));
    }
    let r = put_tree_value(store, prior, 3, value, &children)?;
    Ok((
        entries.last().map(|e| e.name.clone()).unwrap_or_default(),
        r,
    ))
}
#[cfg(feature = "native")]
fn store_branch<S: ObjectStore + ?Sized>(
    store: &mut S,
    height: u64,
    fences: &[(Vec<u8>, ObjectRef)],
) -> Result<(Vec<u8>, ObjectRef)> {
    store_branch_after(store, height, fences, None)
}
fn store_branch_after<S: ObjectStore + ?Sized>(
    store: &mut S,
    height: u64,
    fences: &[(Vec<u8>, ObjectRef)],
    prior: Option<ObjectRef>,
) -> Result<(Vec<u8>, ObjectRef)> {
    if height > 16 || fences.len() < 2 {
        return Err(Error::Limit("directory tree height"));
    }
    let (value, children) = encode_branch(height, fences);
    if !fits(&value, &children) {
        return Err(Error::Limit("directory branch bytes"));
    }
    let r = put_tree_value(store, prior, 4, value, &children)?;
    Ok((fences.last().unwrap().0.clone(), r))
}

fn put_tree_value<S: ObjectStore + ?Sized>(
    store: &mut S,
    prior: Option<ObjectRef>,
    kind: u16,
    value: Value,
    children: &[ObjectRef],
) -> Result<ObjectRef> {
    if let Some(source) = prior
        .map(|r| store.rewrite_source(r))
        .transpose()?
        .flatten()
    {
        store.rewrite(&source, kind, 1, &cbor::encode(&value), children)
    } else {
        put_value(store, kind, value, children)
    }
}

pub struct ArchiveBuilder<'a, S: ObjectStore + ?Sized> {
    store: &'a mut S,
    root: Option<ObjectRef>,
    limits: Limits,
    chunk_size: usize,
    page_limit: usize,
    entries: u64,
    logical: u64,
    #[cfg(feature = "native")]
    bulk: Option<bulk::Bulk>,
}
impl<'a, S: ObjectStore + ?Sized> ArchiveBuilder<'a, S> {
    pub fn new(store: &'a mut S) -> Self {
        Self {
            store,
            root: None,
            limits: Limits::default(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            page_limit: DIRECTORY_LEAF_LIMIT,
            entries: 0,
            logical: 0,
            #[cfg(feature = "native")]
            bulk: None,
        }
    }
    pub fn with_limits(store: &'a mut S, limits: Limits) -> Self {
        let mut b = Self::new(store);
        b.limits = limits;
        b
    }
    /// Initial archive packing with bounded external sorting and bottom-up
    /// directory pages. Unlike checked persistent edits, this mode materializes
    /// its directory root only in `finish`; arbitrary input ordering is allowed.
    #[cfg(feature = "native")]
    pub fn bulk(store: &'a mut S, limits: Limits) -> Result<Self> {
        let staged = bulk::Bulk::new(limits.clone())?;
        let mut builder = Self::with_limits(store, limits);
        builder.bulk = Some(staged);
        Ok(builder)
    }
    pub fn set_chunk_size(&mut self, size: usize) -> Result<()> {
        if size == 0
            || size > 8 * 1024 * 1024 - 8
            || size.saturating_mul(3) > self.limits.max_memory_bytes
        {
            return Err(Error::Limit("chunk size"));
        }
        self.chunk_size = size;
        Ok(())
    }
    /// Bound pages rewritten by this persistent writer independently of the
    /// generic core admission cap. Existing indivisible inline/metadata rows
    /// retain their legal size when a later writer selects a smaller target.
    pub fn set_page_limit(&mut self, bytes: usize) -> Result<()> {
        if !(1024..=DIRECTORY_LEAF_LIMIT).contains(&bytes) {
            return Err(Error::Limit("directory writer page target"));
        }
        #[cfg(feature = "native")]
        if self.bulk.is_some() {
            return Err(Error::Unsupported(
                "bulk builder uses the generic normalization page target".into(),
            ));
        }
        self.page_limit = bytes;
        Ok(())
    }
    fn inline_limit(&self) -> usize {
        INLINE_LIMIT.min(self.page_limit / 2)
    }
    pub fn directory_root(&self) -> Option<ObjectRef> {
        self.root
    }
    /// Start checked edits from a directory root validated by the caller.
    pub fn from_directory(store: &'a mut S, root: ObjectRef, limits: Limits) -> Self {
        Self {
            store,
            root: Some(root),
            limits,
            chunk_size: DEFAULT_CHUNK_SIZE,
            page_limit: DIRECTORY_LEAF_LIMIT,
            entries: 0,
            logical: 0,
            #[cfg(feature = "native")]
            bulk: None,
        }
    }
    pub fn add_file(&mut self, path: &[Vec<u8>], bytes: &[u8]) -> Result<()> {
        self.add_file_with_metadata(path, bytes, empty_metadata())
    }
    pub fn add_file_with_metadata(
        &mut self,
        path: &[Vec<u8>],
        bytes: &[u8],
        metadata: Value,
    ) -> Result<()> {
        self.add_reader_with_metadata(path, std::io::Cursor::new(bytes), metadata)
    }
    pub fn add_reader<R: Read>(&mut self, path: &[Vec<u8>], reader: R) -> Result<()> {
        self.add_reader_with_metadata(path, reader, empty_metadata())
    }
    pub fn add_reader_with_metadata<R: Read>(
        &mut self,
        path: &[Vec<u8>],
        mut reader: R,
        metadata: Value,
    ) -> Result<()> {
        validate_path(path, &self.limits)?;
        let work = Budget::new(self.limits.clone());
        work.memory(
            self.chunk_size
                .max(self.inline_limit() + 1)
                .saturating_mul(3)
                .saturating_add(self.inline_limit() + 1),
        )?;
        // Most archive entries are small. Determine inline eligibility without
        // allocating and clearing a full interactive/bulk chunk for every file.
        let mut prefix = vec![0; self.inline_limit() + 1];
        let mut filled = 0;
        while filled < prefix.len() {
            work.time()?;
            match reader.read(&mut prefix[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        prefix.truncate(filled);
        if filled <= self.inline_limit() {
            // Retained inline data must not keep the full probe allocation.
            // Bulk runs may hold thousands of these small files at once.
            prefix = prefix.as_slice().to_vec();
            check_declared_digest(&metadata, blake3::hash(&prefix).as_bytes())?;
            return self.insert(
                path,
                metadata,
                EntryData::File {
                    length: filled as u64,
                    data: FileData::Inline(prefix),
                },
                false,
            );
        }
        let mut reader = std::io::Cursor::new(prefix).chain(reader);
        let mut bytes = vec![0u8; self.chunk_size.max(self.inline_limit() + 1)];
        let mut first = Vec::new();
        let mut length = 0u64;
        let mut accumulator = ExtentAccumulator::new();
        let mut hasher = blake3::Hasher::new();
        loop {
            work.time()?;
            let mut filled = 0;
            while filled < self.chunk_size {
                work.time()?;
                match reader.read(&mut bytes[filled..self.chunk_size]) {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e.into()),
                }
            }
            if filled == 0 {
                break;
            }
            length = length
                .checked_add(filled as u64)
                .ok_or(Error::Limit("file length"))?;
            if length > self.limits.max_file_bytes
                || length > self.limits.max_logical_bytes.saturating_sub(self.logical)
            {
                return Err(Error::Limit("logical input bytes"));
            }
            hasher.update(&bytes[..filled]);
            if length <= self.inline_limit() as u64 {
                first.extend_from_slice(&bytes[..filled]);
            } else {
                if !first.is_empty() {
                    accumulator.push_data(self.store, &first)?;
                    first.clear();
                }
                accumulator.push_data(self.store, &bytes[..filled])?;
            }
            if filled < self.chunk_size {
                break;
            }
        }
        let data = if length <= self.inline_limit() as u64 {
            FileData::Inline(first)
        } else {
            FileData::Extents(
                accumulator
                    .finish(self.store)?
                    .ok_or_else(|| corrupt("missing file extents"))?,
            )
        };
        check_declared_digest(&metadata, hasher.finalize().as_bytes())?;
        self.insert(path, metadata, EntryData::File { length, data }, false)
    }
    pub fn add_sparse(&mut self, path: &[Vec<u8>], segments: Vec<SparseSegment>) -> Result<()> {
        validate_path(path, &self.limits)?;
        let mut accumulator = ExtentAccumulator::new();
        let mut length = 0u64;
        for segment in segments {
            let n = match &segment {
                SparseSegment::Data(b) => b.len() as u64,
                SparseSegment::Hole(n) => *n,
            };
            length = length
                .checked_add(n)
                .ok_or(Error::Limit("sparse file length"))?;
            if length > self.limits.max_file_bytes
                || length > self.limits.max_logical_bytes.saturating_sub(self.logical)
            {
                return Err(Error::Limit("logical input bytes"));
            }
            match segment {
                SparseSegment::Data(b) => {
                    for chunk in b.chunks(self.chunk_size) {
                        accumulator.push_data(self.store, chunk)?;
                    }
                }
                SparseSegment::Hole(n) => accumulator.push(self.store, n, None)?,
            }
        }
        let data = match accumulator.finish(self.store)? {
            Some(r) => FileData::Extents(r),
            None => FileData::Inline(Vec::new()),
        };
        self.insert(
            path,
            empty_metadata(),
            EntryData::File { length, data },
            false,
        )
    }
    pub fn add_directory(&mut self, path: &[Vec<u8>]) -> Result<()> {
        let root = store_leaf(self.store, &[])?.1;
        self.insert(path, empty_metadata(), EntryData::Directory(root), false)
    }
    pub fn add_symlink(&mut self, path: &[Vec<u8>], target: &[u8]) -> Result<()> {
        if target.len() > 4096 {
            return Err(Error::Limit("symlink target"));
        }
        self.insert(
            path,
            empty_metadata(),
            EntryData::Symlink(target.to_vec()),
            false,
        )
    }
    pub fn set_file(&mut self, path: &[Vec<u8>], bytes: &[u8], metadata: Value) -> Result<()> {
        check_declared_digest(&metadata, blake3::hash(bytes).as_bytes())?;
        // Construct the file first, then atomically substitute its directory path.
        let data = if bytes.len() <= self.inline_limit() {
            FileData::Inline(bytes.to_vec())
        } else {
            let mut a = ExtentAccumulator::new();
            for b in bytes.chunks(self.chunk_size) {
                a.push_data(self.store, b)?;
            }
            FileData::Extents(a.finish(self.store)?.unwrap())
        };
        self.insert(
            path,
            metadata,
            EntryData::File {
                length: bytes.len() as u64,
                data,
            },
            true,
        )
    }
    /// Install a checked shared extent descriptor without copying its payload.
    /// The caller must validate the full extent graph before publication.
    pub fn set_extent_file(
        &mut self,
        path: &[Vec<u8>],
        length: u64,
        extent: ObjectRef,
        metadata: Value,
    ) -> Result<()> {
        if length == 0 {
            return Err(corrupt("extent file must be nonempty"));
        }
        let object = self.store.get(extent)?;
        if object.version != 1 || !matches!(object.kind, 5 | 6) {
            return Err(corrupt("expected extent tree"));
        }
        self.insert(
            path,
            metadata,
            EntryData::File {
                length,
                data: FileData::Extents(extent),
            },
            true,
        )
    }
    pub fn remove_file(&mut self, path: &[Vec<u8>]) -> Result<()> {
        #[cfg(feature = "native")]
        if self.bulk.is_some() {
            return Err(Error::Unsupported(
                "bulk construction does not remove existing files".into(),
            ));
        }
        validate_path(path, &self.limits)?;
        let root = self.root.ok_or(Error::Missing)?;
        let mut budget = Budget::new(self.limits.clone());
        budget.directory_write_limit = self.page_limit;
        self.root = Some(remove_path(self.store, root, path, &mut budget, 0)?);
        Ok(())
    }
    fn insert(
        &mut self,
        path: &[Vec<u8>],
        metadata: Value,
        mut data: EntryData,
        replace: bool,
    ) -> Result<()> {
        validate_path(path, &self.limits)?;
        let length = match &data {
            EntryData::File { length, .. } => *length,
            _ => 0,
        };
        let next_entries = self
            .entries
            .checked_add(1)
            .ok_or(Error::Limit("input entries"))?;
        if next_entries > self.limits.max_entries {
            return Err(Error::Limit("input entries"));
        }
        let next_logical = self
            .logical
            .checked_add(length)
            .ok_or(Error::Limit("logical input bytes"))?;
        if length > self.limits.max_file_bytes || next_logical > self.limits.max_logical_bytes {
            return Err(Error::Limit("logical input bytes"));
        }
        // A small payload may fit its inline byte cap while the complete
        // entry exceeds this writer's page target because of metadata/name
        // bytes. Fall back to an extent before building directory pages.
        if let EntryData::File {
            length,
            data: FileData::Inline(bytes),
        } = &data
        {
            let name = path.last().unwrap();
            if bytes
                .len()
                .saturating_add(16384)
                .saturating_add(name.len())
                .saturating_add(64)
                > self.page_limit
            {
                let metadata_bytes = cbor::encode(&metadata).len();
                if bytes
                    .len()
                    .saturating_add(metadata_bytes)
                    .saturating_add(name.len())
                    .saturating_add(64)
                    > self.page_limit
                {
                    let candidate = Entry {
                        name: name.clone(),
                        metadata: metadata.clone(),
                        data: data.clone(),
                    };
                    let (value, children) = encode_leaf(&[candidate]);
                    if canonical_size(&value, &children) > self.page_limit && *length != 0 {
                        let length = *length;
                        let mut extents = ExtentAccumulator::new();
                        extents.push_data(self.store, bytes)?;
                        data = EntryData::File {
                            length,
                            data: FileData::Extents(extents.finish(self.store)?.unwrap()),
                        };
                    }
                }
            }
        }
        let (value, children) = encode_leaf(&[Entry {
            name: path.last().unwrap().clone(),
            metadata: metadata.clone(),
            data: data.clone(),
        }]);
        if canonical_size(&value, &children) > self.page_limit {
            return Err(Error::Limit("directory entry too large for writer target"));
        }
        #[cfg(feature = "native")]
        if let Some(bulk) = &mut self.bulk {
            if replace {
                return Err(Error::Unsupported(
                    "bulk construction requires unique initial resources".into(),
                ));
            }
            bulk.push(path, metadata, data)?;
            self.entries = next_entries;
            self.logical = next_logical;
            return Ok(());
        }
        let root = match self.root {
            Some(r) => r,
            None => store_leaf(self.store, &[])?.1,
        };
        let mut budget = Budget::new(self.limits.clone());
        budget.directory_write_limit = self.page_limit;
        let root = update_directory(
            self.store,
            root,
            path,
            metadata,
            data,
            replace,
            &mut budget,
            0,
        )?;
        self.root = Some(root);
        self.entries = next_entries;
        self.logical = next_logical;
        Ok(())
    }
    pub fn finish(self) -> Result<ObjectRef> {
        self.finish_with_statistics().map(|(root, _)| root)
    }
    /// Finish only the resource directory, for embedding in an application profile.
    pub fn finish_directory(self) -> Result<ObjectRef> {
        #[cfg(feature = "native")]
        if let Some(bulk) = self.bulk {
            return bulk.finish(self.store).map(|(root, _)| root);
        }
        match self.root {
            Some(root) => Ok(root),
            None => store_leaf(self.store, &[]).map(|(_, root)| root),
        }
    }
    /// Finish the same production path and report external-sort temporary I/O.
    /// Persistent incremental builders have no sort spools and report zeroes.
    pub fn finish_with_statistics(self) -> Result<(ObjectRef, PackingStatistics)> {
        #[cfg(feature = "native")]
        if let Some(bulk) = self.bulk {
            let (root, statistics) = bulk.finish(self.store)?;
            return Ok((
                snapshot(self.store, root, Vec::new(), Vec::new())?,
                statistics,
            ));
        }
        let root = match self.root {
            Some(r) => r,
            None => store_leaf(self.store, &[])?.1,
        };
        Ok((
            snapshot(self.store, root, Vec::new(), Vec::new())?,
            PackingStatistics::default(),
        ))
    }
}

fn remove_path<S: ObjectStore + ?Sized>(
    store: &mut S,
    root: ObjectRef,
    path: &[Vec<u8>],
    budget: &mut Budget,
    depth: usize,
) -> Result<ObjectRef> {
    budget.depth(depth)?;
    let existing = lookup_entry(store, root, &path[0], budget)?.ok_or(Error::Missing)?;
    if path.len() > 1 {
        let EntryData::Directory(child) = existing.data else {
            return Err(corrupt("path parent is not directory"));
        };
        let replacement = remove_path(store, child, &path[1..], budget, depth + 1)?;
        let entry = Entry {
            name: existing.name,
            metadata: existing.metadata,
            data: EntryData::Directory(replacement),
        };
        let updated = insert_page(store, root, entry, true, budget, depth)?;
        let height = match directory(budget.get(store, root)?.as_ref())? {
            DirectoryNode::Leaf(_) => 0,
            DirectoryNode::Branch { height, .. } => height,
        };
        return finish_directory_pages(store, height, updated, budget);
    }
    if matches!(existing.data, EntryData::Directory(_)) {
        return Err(corrupt("remove_file requires file or symlink"));
    }
    match remove_page(store, root, &path[0], budget, depth)? {
        Some((_, reference, _)) => Ok(reference),
        None => Ok(store_leaf(store, &[])?.1),
    }
}
fn remove_page<S: ObjectStore + ?Sized>(
    store: &mut S,
    root: ObjectRef,
    name: &[u8],
    budget: &mut Budget,
    depth: usize,
) -> Result<Option<(Vec<u8>, ObjectRef, u64)>> {
    budget.depth(depth)?;
    let node = directory(budget.get(store, root)?.as_ref())?;
    match node {
        DirectoryNode::Leaf(mut entries) => {
            let i = entries
                .binary_search_by(|e| e.name.as_slice().cmp(name))
                .map_err(|_| Error::Missing)?;
            entries.remove(i);
            if entries.is_empty() {
                Ok(None)
            } else {
                let (k, r) = store_leaf_after(store, &entries, Some(root))?;
                Ok(Some((k, r, 0)))
            }
        }
        DirectoryNode::Branch { height, mut fences } => {
            let i = fences.partition_point(|(k, _)| k.as_slice() < name);
            if i == fences.len() {
                return Err(Error::Missing);
            }
            let changed = remove_page(store, fences[i].1, name, budget, depth + 1)?;
            match changed {
                None => {
                    fences.remove(i);
                }
                Some((key, reference, child_height)) if child_height == height - 1 => {
                    fences[i] = (key, reference)
                }
                Some((key, reference, child_height)) => {
                    if child_height + 2 != height {
                        return Err(corrupt("deletion height mismatch"));
                    }
                    let sibling_index = if i > 0 { i - 1 } else { i + 1 };
                    let sibling = directory(budget.get(store, fences[sibling_index].1)?.as_ref())?;
                    let DirectoryNode::Branch {
                        height: sibling_height,
                        fences: mut children,
                    } = sibling
                    else {
                        return Err(corrupt("expected sibling branch"));
                    };
                    if sibling_height != height - 1 {
                        return Err(corrupt("sibling height mismatch"));
                    }
                    let position = children.partition_point(|(k, _)| k < &key);
                    children.insert(position, (key, reference));
                    let (v, c) = encode_branch(sibling_height, &children);
                    let replacements = if fits(&v, &c)
                        && canonical_size(&v, &c) <= budget.directory_write_limit
                    {
                        vec![store_branch_after(
                            store,
                            sibling_height,
                            &children,
                            Some(fences[sibling_index].1),
                        )?]
                    } else {
                        let pivot =
                            split_branch(sibling_height, &children, budget.directory_write_limit)?;
                        vec![
                            store_branch_after(
                                store,
                                sibling_height,
                                &children[..pivot],
                                Some(fences[sibling_index].1),
                            )?,
                            store_branch_after(
                                store,
                                sibling_height,
                                &children[pivot..],
                                Some(fences[sibling_index].1),
                            )?,
                        ]
                    };
                    let first = i.min(sibling_index);
                    let last = i.max(sibling_index);
                    fences.splice(first..=last, replacements);
                }
            }
            match fences.len() {
                0 => Ok(None),
                1 => {
                    let (k, r) = fences.pop().unwrap();
                    Ok(Some((k, r, height - 1)))
                }
                _ => {
                    let (k, r) = store_branch_after(store, height, &fences, Some(root))?;
                    Ok(Some((k, r, height)))
                }
            }
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "persistent path updates carry entry data, inherited depth and the shared operation budget"
)]
fn update_directory<S: ObjectStore + ?Sized>(
    store: &mut S,
    root: ObjectRef,
    path: &[Vec<u8>],
    metadata: Value,
    data: EntryData,
    replace: bool,
    budget: &mut Budget,
    depth: usize,
) -> Result<ObjectRef> {
    budget.depth(depth)?;
    let entry = if path.len() == 1 {
        Entry {
            name: path[0].clone(),
            metadata,
            data,
        }
    } else {
        let old = lookup_entry(store, root, &path[0], budget)?;
        let (child, parent_metadata) = match old {
            Some(Entry {
                data: EntryData::Directory(r),
                metadata,
                ..
            }) => (r, metadata),
            Some(_) => return Err(corrupt("path parent is not a directory")),
            None => (store_leaf(store, &[])?.1, empty_metadata()),
        };
        let r = update_directory(
            store,
            child,
            &path[1..],
            metadata,
            data,
            replace,
            budget,
            depth + 1,
        )?;
        Entry {
            name: path[0].clone(),
            metadata: parent_metadata,
            data: EntryData::Directory(r),
        }
    };
    let object = budget.get(store, root)?;
    let height = match directory(&object)? {
        DirectoryNode::Leaf(_) => 0,
        DirectoryNode::Branch { height, .. } => height,
    };
    let changes = insert_page(store, root, entry, replace || path.len() > 1, budget, depth)?;
    finish_directory_pages(store, height, changes, budget)
}

fn finish_directory_pages<S: ObjectStore + ?Sized>(
    store: &mut S,
    mut height: u64,
    mut pages: Vec<(Vec<u8>, ObjectRef)>,
    budget: &mut Budget,
) -> Result<ObjectRef> {
    while pages.len() > 1 {
        height += 1;
        if height > 16 {
            return Err(Error::Limit("directory tree height"));
        }
        pages = batch::emit_branches(store, height, &pages, budget, None)?;
    }
    Ok(pages
        .pop()
        .ok_or_else(|| corrupt("empty directory result"))?
        .1)
}

pub(crate) fn lookup_entry<S: ObjectStore + ?Sized>(
    store: &S,
    root: ObjectRef,
    name: &[u8],
    budget: &mut Budget,
) -> Result<Option<Entry>> {
    super::pages::lookup(store, root, name, budget)?
        .map(|entry| entry.owned())
        .transpose()
}

pub(crate) fn check_interval(
    entries: &[Entry],
    lower: Option<&[u8]>,
    upper: Option<&[u8]>,
) -> Result<()> {
    if lower.is_some() || upper.is_some() {
        let first = entries
            .first()
            .ok_or_else(|| corrupt("empty branch child"))?;
        let last = entries.last().unwrap();
        if lower.is_some_and(|l| first.name.as_slice() <= l)
            || upper.is_some_and(|u| last.name.as_slice() != u)
        {
            return Err(corrupt("directory leaf interval mismatch"));
        }
    }
    Ok(())
}
fn insert_page<S: ObjectStore + ?Sized>(
    store: &mut S,
    root: ObjectRef,
    entry: Entry,
    replace: bool,
    budget: &mut Budget,
    depth: usize,
) -> Result<Vec<(Vec<u8>, ObjectRef)>> {
    budget.depth(depth)?;
    let object = budget.get(store, root)?;
    match directory(&object)? {
        DirectoryNode::Leaf(mut entries) => {
            let write_limit = if object.canonical_len() > budget.directory_write_limit {
                leaf_write_limit(&entries, budget.directory_write_limit)
            } else {
                budget.directory_write_limit
            };
            match entries.binary_search_by(|e| e.name.cmp(&entry.name)) {
                Ok(i) => {
                    if !replace {
                        if matches!(
                            (&entries[i].data, &entry.data),
                            (EntryData::Directory(_), EntryData::Directory(_))
                        ) {
                            return Ok(vec![(entries.last().unwrap().name.clone(), root)]);
                        }
                        return Err(corrupt("duplicate resource path"));
                    }
                    entries[i] = entry;
                }
                Err(i) => entries.insert(i, entry),
            }
            let (v, c) = encode_leaf(&entries);
            if fits_leaf(&v, &c) && canonical_size(&v, &c) <= budget.directory_write_limit {
                return Ok(vec![store_leaf_after(store, &entries, Some(root))?]);
            }
            batch::emit_leaves(store, &entries, budget, Some(root), write_limit)
        }
        DirectoryNode::Branch { height, mut fences } => {
            let i = fences
                .partition_point(|(key, _)| key < &entry.name)
                .min(fences.len() - 1);
            let changes = insert_page(store, fences[i].1, entry, replace, budget, depth + 1)?;
            fences.splice(i..i + 1, changes);
            let (v, c) = encode_branch(height, &fences);
            if fits(&v, &c) && canonical_size(&v, &c) <= budget.directory_write_limit {
                return Ok(vec![store_branch_after(
                    store,
                    height,
                    &fences,
                    Some(root),
                )?]);
            }
            batch::emit_branches(store, height, &fences, budget, Some(root))
        }
    }
}
fn split_branch(height: u64, fences: &[(Vec<u8>, ObjectRef)], page_limit: usize) -> Result<usize> {
    let limit = page_limit.min(PAGE_LIMIT);
    // Variable-length names make a split by row count insufficient for a
    // smaller hot-page target. Select a pivot whose two encoded pages fit.
    let center = fences.len() / 2;
    for distance in 0..fences.len() {
        let pivot = if distance % 2 == 0 {
            center.saturating_add(distance / 2)
        } else {
            center.saturating_sub(distance.div_ceil(2))
        };
        if pivot < 2 || fences.len().saturating_sub(pivot) < 2 {
            continue;
        }
        let (a, ac) = encode_branch(height, &fences[..pivot]);
        let (b, bc) = encode_branch(height, &fences[pivot..]);
        if fits(&a, &ac)
            && fits(&b, &bc)
            && canonical_size(&a, &ac) <= limit
            && canonical_size(&b, &bc) <= limit
        {
            return Ok(pivot);
        }
    }
    Err(Error::Limit("directory branch cannot fit writer target"))
}
#[cfg(test)]
#[test]
fn variable_name_branches_respect_smaller_writer_target() {
    let fences: Vec<_> = (0..7u8)
        .map(|ordinal| {
            let name = vec![b'a' + ordinal; if ordinal < 3 { 4 } else { 255 }];
            (
                name,
                ObjectRef {
                    hash: ObjectHash([ordinal; 32]),
                    address: Default::default(),
                },
            )
        })
        .collect();
    let (old_count_half, old_children) = encode_branch(1, &fences[3..]);
    assert!(canonical_size(&old_count_half, &old_children) > 1024);
    let pivot = split_branch(1, &fences, 1024).unwrap();
    for half in [&fences[..pivot], &fences[pivot..]] {
        let (value, children) = encode_branch(1, half);
        assert!(half.len() >= 2 && canonical_size(&value, &children) <= 1024);
    }
}
// A new writer target must not invalidate inherited descriptors. Inline bytes
// and metadata are indivisible and authenticated by the directory row; preserve
// their representation while splitting a previously wider page into as many
// balanced pages as needed. New rows still obey the selected target.
fn leaf_write_limit(entries: &[Entry], target: usize) -> usize {
    entries.iter().fold(target, |limit, entry| {
        let (value, children) = encode_leaf(std::slice::from_ref(entry));
        limit.max(canonical_size(&value, &children))
    })
}

#[derive(Clone, Copy)]
struct ExtentInfo {
    reference: ObjectRef,
    length: u64,
    height: u64,
}
/// Bounded persistent extent-tree frontier for shared or streamed byte objects.
pub struct ExtentAccumulator {
    rows: Vec<(u64, Option<ObjectRef>)>,
    sizing: ExtentSizing,
    levels: Vec<ExtentLevel>,
}
#[derive(Default)]
struct ExtentLevel {
    nodes: Vec<ExtentInfo>,
    sizing: ExtentSizing,
}
#[derive(Default)]
struct ExtentSizing {
    row_bytes: usize,
    length: u64,
    children: std::collections::HashMap<ObjectHash, u64>,
}
fn integer_size(value: u64) -> usize {
    cbor::encoded_len(&uint(value))
}
impl ExtentSizing {
    fn clear(&mut self) {
        self.row_bytes = 0;
        self.length = 0;
        self.children.clear();
    }
    fn row(
        &self,
        length: u64,
        reference: Option<ObjectRef>,
        branch: bool,
    ) -> Result<(usize, usize, u64)> {
        let end = self
            .length
            .checked_add(length)
            .ok_or(Error::Limit("extent total"))?;
        let index = reference.and_then(|r| self.children.get(&r.hash).copied());
        let children = self.children.len() + usize::from(reference.is_some() && index.is_none());
        let row_bytes = 1
            + integer_size(if branch { end } else { length })
            + reference.map_or(1, |_| {
                integer_size(index.unwrap_or(self.children.len() as u64))
            });
        Ok((row_bytes, children, end))
    }
    fn fits(
        &self,
        rows: usize,
        length: u64,
        reference: Option<ObjectRef>,
        height: Option<u64>,
    ) -> Result<bool> {
        let (row_bytes, children, _) = self.row(length, reference, height.is_some())?;
        let body = integer_size((rows + 1) as u64)
            + self.row_bytes
            + row_bytes
            + height.map_or(0, |h| 1 + integer_size(h));
        Ok(children <= 1024 && 8 + 32 * children + body <= PAGE_LIMIT)
    }
    fn push(&mut self, length: u64, reference: Option<ObjectRef>, branch: bool) -> Result<()> {
        let (row_bytes, _, end) = self.row(length, reference, branch)?;
        if let Some(reference) = reference {
            let next = self.children.len() as u64;
            self.children.entry(reference.hash).or_insert(next);
        }
        self.row_bytes += row_bytes;
        self.length = end;
        Ok(())
    }
}
impl Default for ExtentAccumulator {
    fn default() -> Self {
        Self::new()
    }
}
impl ExtentAccumulator {
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            sizing: ExtentSizing::default(),
            levels: Vec::new(),
        }
    }
    pub fn push_data<S: ObjectStore + ?Sized>(
        &mut self,
        store: &mut S,
        bytes: &[u8],
    ) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let r = if bytes.iter().all(|b| *b == 0) {
            None
        } else {
            Some(store.put(7, 1, bytes, &[])?)
        };
        self.push(store, bytes.len() as u64, r)
    }
    pub fn push<S: ObjectStore + ?Sized>(
        &mut self,
        store: &mut S,
        length: u64,
        reference: Option<ObjectRef>,
    ) -> Result<()> {
        if length == 0 {
            return Ok(());
        }
        if reference.is_none()
            && let Some(&(n, None)) = self.rows.last()
        {
            let merged = n
                .checked_add(length)
                .ok_or(Error::Limit("zero run length"))?;
            let growth = integer_size(merged) - integer_size(n);
            if 8 + 32 * self.sizing.children.len()
                + integer_size(self.rows.len() as u64)
                + self.sizing.row_bytes
                + growth
                <= PAGE_LIMIT
            {
                self.sizing.length = self
                    .sizing
                    .length
                    .checked_add(length)
                    .ok_or(Error::Limit("extent total"))?;
                self.sizing.row_bytes += growth;
                self.rows.last_mut().unwrap().0 = merged;
                return Ok(());
            }
            self.flush_leaf(store)?;
        }
        if !self.sizing.fits(self.rows.len(), length, reference, None)? {
            self.flush_leaf(store)?;
        }
        self.sizing.push(length, reference, false)?;
        self.rows.push((length, reference));
        Ok(())
    }
    fn flush_leaf<S: ObjectStore + ?Sized>(&mut self, store: &mut S) -> Result<()> {
        if self.rows.is_empty() {
            return Ok(());
        }
        let (v, c) = encode_extents(&self.rows);
        let length = self.rows.iter().try_fold(0u64, |n, (len, _)| {
            n.checked_add(*len).ok_or(Error::Limit("extent total"))
        })?;
        let reference = put_value(store, 5, v, &c)?;
        self.rows.clear();
        self.sizing.clear();
        self.promote(
            store,
            ExtentInfo {
                reference,
                length,
                height: 0,
            },
        )
    }
    fn promote<S: ObjectStore + ?Sized>(&mut self, store: &mut S, node: ExtentInfo) -> Result<()> {
        let level = node.height as usize;
        if level >= 16 {
            return Err(Error::Limit("extent tree height"));
        }
        while self.levels.len() <= level {
            self.levels.push(ExtentLevel::default());
        }
        if !self.levels[level].sizing.fits(
            self.levels[level].nodes.len(),
            node.length,
            Some(node.reference),
            Some(node.height + 1),
        )? {
            let mut nodes = std::mem::take(&mut self.levels[level].nodes);
            let parent = store_extent_branch(store, &nodes)?;
            nodes.clear();
            self.levels[level].nodes = nodes;
            self.levels[level].sizing.clear();
            self.promote(store, parent)?;
        }
        self.levels[level]
            .sizing
            .push(node.length, Some(node.reference), true)?;
        self.levels[level].nodes.push(node);
        Ok(())
    }
    pub fn finish<S: ObjectStore + ?Sized>(mut self, store: &mut S) -> Result<Option<ObjectRef>> {
        self.flush_leaf(store)?;
        // Finish the lowest frontier first. A singleton is promoted unchanged;
        // a taller sibling is flattened one level when needed to avoid unary nodes.
        let mut pending: Option<ExtentInfo> = None;
        for level in 0..self.levels.len() {
            let mut nodes = std::mem::take(&mut self.levels[level].nodes);
            if let Some(node) = pending.take() {
                if node.height == level as u64 {
                    nodes.push(node);
                } else {
                    if nodes.is_empty() {
                        pending = Some(node);
                        continue;
                    }
                    let previous = nodes.pop().unwrap();
                    nodes.extend(append_extent_tail(store, previous, node)?);
                }
            }
            pending = match nodes.len() {
                0 => None,
                1 => Some(nodes[0]),
                _ => Some(store_extent_branch(store, &nodes)?),
            };
        }
        Ok(pending.map(|n| n.reference))
    }
}
fn append_extent_tail<S: ObjectStore + ?Sized>(
    store: &mut S,
    left: ExtentInfo,
    right: ExtentInfo,
) -> Result<Vec<ExtentInfo>> {
    if left.height == right.height {
        return Ok(vec![left, right]);
    }
    if left.height < right.height {
        return Err(corrupt("extent frontier order"));
    }
    let object = store.get(left.reference)?;
    let body = cbor::decode(&object.bytes)?;
    let fields = values(&body)?;
    let mut prior = 0;
    let mut children = Vec::new();
    for row in values(&fields[1])? {
        let row = values(row)?;
        let end = number(&row[0])?;
        children.push(ExtentInfo {
            reference: child(&object, &row[1])?,
            length: end - prior,
            height: left.height - 1,
        });
        prior = end;
    }
    let last = children
        .pop()
        .ok_or_else(|| corrupt("empty extent frontier"))?;
    children.extend(append_extent_tail(store, last, right)?);
    let (v, c) = encode_extent_branch(left.height, &children)?;
    if fits(&v, &c) {
        Ok(vec![store_extent_branch(store, &children)?])
    } else {
        let middle = children.len() / 2;
        Ok(vec![
            store_extent_branch(store, &children[..middle])?,
            store_extent_branch(store, &children[middle..])?,
        ])
    }
}
fn encode_extents(rows: &[(u64, Option<ObjectRef>)]) -> (Value, Vec<ObjectRef>) {
    let mut children = Vec::new();
    let value = array(
        rows.iter()
            .map(|(len, r)| {
                array(vec![
                    uint(*len),
                    r.map(|r| uint(child_index(&mut children, r)))
                        .unwrap_or(Value::Null),
                ])
            })
            .collect(),
    );
    (value, children)
}
fn encode_extent_branch(height: u64, nodes: &[ExtentInfo]) -> Result<(Value, Vec<ObjectRef>)> {
    let mut children = Vec::new();
    let mut end = 0u64;
    let mut rows = Vec::new();
    for node in nodes {
        end = end
            .checked_add(node.length)
            .ok_or(Error::Limit("extent total"))?;
        rows.push(array(vec![
            uint(end),
            uint(child_index(&mut children, node.reference)),
        ]));
    }
    Ok((array(vec![uint(height), array(rows)]), children))
}
fn store_extent_branch<S: ObjectStore + ?Sized>(
    store: &mut S,
    nodes: &[ExtentInfo],
) -> Result<ExtentInfo> {
    if nodes.len() < 2 {
        return Err(corrupt("unary extent branch"));
    }
    let height = nodes[0].height + 1;
    let (v, c) = encode_extent_branch(height, nodes)?;
    if !fits(&v, &c) {
        return Err(Error::Limit("extent branch bytes"));
    }
    let length = nodes.iter().try_fold(0u64, |sum, n| {
        sum.checked_add(n.length)
            .ok_or(Error::Limit("extent length"))
    })?;
    Ok(ExtentInfo {
        reference: put_value(store, 6, v, &c)?,
        length,
        height,
    })
}
pub(crate) fn check_declared_digest(metadata: &Value, actual: &[u8; 32]) -> Result<()> {
    if let Value::Map(entries) = metadata {
        for entry in entries {
            if entry.key == Value::Text("byte_digest".into()) && bytes(&entry.value)? != actual {
                return Err(corrupt("whole-resource digest mismatch"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod extent_sizing_tests {
    use super::*;
    #[test]
    fn incremental_sizes_match_canonical_encoding_across_boundaries_and_duplicate_children() {
        for branch in [false, true] {
            let mut sizing = ExtentSizing::default();
            let mut rows = Vec::new();
            let mut nodes = Vec::new();
            for i in 0..1400u64 {
                let child = ObjectRef {
                    hash: ObjectHash::digest(&(if i % 17 == 0 { 0 } else { i }).to_le_bytes()),
                    address: crate::v1::ChunkAddress {
                        offset: 128,
                        length: 64,
                    },
                };
                let reference = (branch || i % 5 != 0).then_some(child);
                let length = [1, 23, 24, 255, 256, 65535, 65536, 1u64 << 32][i as usize % 8];
                let node = ExtentInfo {
                    reference: child,
                    length,
                    height: 0,
                };
                let expected = if branch {
                    nodes.push(node);
                    let (body, children) = encode_extent_branch(1, &nodes).unwrap();
                    let fits = fits(&body, &children);
                    nodes.pop();
                    fits
                } else {
                    rows.push((length, reference));
                    let (body, children) = encode_extents(&rows);
                    let fits = fits(&body, &children);
                    rows.pop();
                    fits
                };
                let count = if branch { nodes.len() } else { rows.len() };
                assert_eq!(
                    sizing
                        .fits(count, length, reference, branch.then_some(1))
                        .unwrap(),
                    expected
                );
                if !expected {
                    sizing.clear();
                    rows.clear();
                    nodes.clear();
                }
                sizing.push(length, reference, branch).unwrap();
                if branch {
                    nodes.push(node);
                } else {
                    rows.push((length, reference));
                }
            }
        }
        // Repeated children hit the byte-size boundary before the child-count
        // boundary. Check both sides without rebuilding a page on each step.
        for branch in [false, true] {
            let child = ObjectRef {
                hash: ObjectHash([9; 32]),
                address: crate::v1::ChunkAddress {
                    offset: 128,
                    length: 64,
                },
            };
            let mut sizing = ExtentSizing::default();
            let mut split = false;
            for count in 0..10_000 {
                if !sizing
                    .fits(count, 1 << 32, Some(child), branch.then_some(1))
                    .unwrap()
                {
                    assert!(count > 5000);
                    for (rows, expected) in [(count, true), (count + 1, false)] {
                        let (body, children) = if branch {
                            encode_extent_branch(
                                1,
                                &vec![
                                    ExtentInfo {
                                        reference: child,
                                        length: 1 << 32,
                                        height: 0
                                    };
                                    rows
                                ],
                            )
                            .unwrap()
                        } else {
                            encode_extents(&vec![(1 << 32, Some(child)); rows])
                        };
                        assert_eq!(fits(&body, &children), expected);
                    }
                    split = true;
                    break;
                }
                sizing.push(1 << 32, Some(child), branch).unwrap();
            }
            assert!(split);
        }
        let mut store = crate::v1::MemoryStore::sealed();
        let child = store.put(7, 1, b"abc", &[]).unwrap();
        let mut accumulator = ExtentAccumulator::new();
        accumulator.push(&mut store, 23, None).unwrap();
        accumulator.push(&mut store, 1, None).unwrap();
        accumulator.push(&mut store, 3, Some(child)).unwrap();
        accumulator.push(&mut store, 65535, None).unwrap();
        accumulator.push(&mut store, 1, None).unwrap();
        assert!(accumulator.push(&mut store, u64::MAX, None).is_err());
        let root = accumulator.finish(&mut store).unwrap().unwrap();
        let (expected, children) = encode_extents(&[(24, None), (3, Some(child)), (65536, None)]);
        assert_eq!(store.get(root).unwrap().bytes, cbor::encode(&expected));
        assert_eq!(store.get(root).unwrap().children, children);
    }
}
