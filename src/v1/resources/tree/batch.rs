use super::*;
use crate::v1::validate_core_object;

/// An incremental batch is deliberately small: callers flush between batches.
const MAX_FILE_BATCH: usize = 512;
type Edit = (ResourcePath, u64, ObjectRef, Value);
type Pages = Vec<(Vec<u8>, ObjectRef)>;

// Metadata can encode compactly while owning many Value slots. Account those
// capacities before cloning a batch; serialized byte counts alone cannot bound
// arrays of small integers or cached map-key encodings.
fn metadata_memory(value: &Value, depth: usize, maximum: usize) -> Result<usize> {
    if depth > cbor::MAX_DEPTH {
        return Err(Error::Limit("CBOR depth"));
    }
    let mut bytes = match value {
        Value::Bytes(bytes) => bytes.capacity(),
        Value::Text(text) => text.capacity(),
        Value::Array(values) => values
            .capacity()
            .checked_mul(std::mem::size_of::<Value>())
            .ok_or(Error::Limit("resident memory"))?,
        Value::Map(entries) => entries
            .capacity()
            .checked_mul(std::mem::size_of::<cbor::MapEntry>())
            .ok_or(Error::Limit("resident memory"))?,
        _ => 0,
    };
    if bytes > maximum {
        return Err(Error::Limit("resident memory"));
    }
    match value {
        Value::Array(values) => {
            for value in values {
                bytes += metadata_memory(value, depth + 1, maximum - bytes)?;
            }
        }
        Value::Map(entries) => {
            for entry in entries {
                bytes = bytes
                    .checked_add(entry.key_bytes.capacity())
                    .filter(|n| *n <= maximum)
                    .ok_or(Error::Limit("resident memory"))?;
                bytes += metadata_memory(&entry.key, depth + 1, maximum - bytes)?;
                bytes += metadata_memory(&entry.value, depth + 1, maximum - bytes)?;
            }
        }
        _ => {}
    }
    Ok(bytes)
}

impl<S: ObjectStore + ?Sized> ArchiveBuilder<'_, S> {
    /// Apply at most 512 sorted, unique extent-file replacements together.
    ///
    /// Paths use bytewise component order. A file path cannot be an ancestor of
    /// another edit. Missing parent directories are created; existing parent
    /// metadata is retained. Extent roots receive the same checks as
    /// `set_extent_file`; callers still validate their complete extent graphs.
    /// Each touched directory page is written at most once, and untouched pages
    /// retain their physical references. Pages that split may have a different
    /// valid grouping from repeated single-file updates. Without splits the
    /// resulting canonical root is identical. The builder root and accounting
    /// change only on success; failed writes can leave unreachable objects in
    /// the append-only store, just like the other incremental editing methods.
    pub fn set_extent_files_batch(&mut self, edits: &[Edit]) -> Result<()> {
        #[cfg(feature = "native")]
        if self.bulk.is_some() {
            return Err(Error::Unsupported(
                "bulk construction cannot replace files".into(),
            ));
        }
        if edits.len() > MAX_FILE_BATCH {
            return Err(Error::Limit("file batch entries"));
        }
        if edits.is_empty() {
            return Ok(());
        }
        let mut budget = Budget::new(self.limits.clone());
        budget.directory_write_limit = self.page_limit;
        let mut retained = 0usize;
        let mut next_entries = self.entries;
        let mut next_logical = self.logical;
        for (i, (path, length, extent, metadata)) in edits.iter().enumerate() {
            validate_path(path, &self.limits)?;
            if i > 0 && (edits[i - 1].0 >= *path || path.starts_with(&edits[i - 1].0)) {
                return Err(corrupt(
                    "file batch paths must be sorted, unique and nonoverlapping",
                ));
            }
            if *length == 0 {
                return Err(corrupt("extent file must be nonempty"));
            }
            next_entries = next_entries
                .checked_add(1)
                .ok_or(Error::Limit("input entries"))?;
            next_logical = next_logical
                .checked_add(*length)
                .ok_or(Error::Limit("logical input bytes"))?;
            if next_entries > self.limits.max_entries
                || *length > self.limits.max_file_bytes
                || next_logical > self.limits.max_logical_bytes
            {
                return Err(Error::Limit("logical input bytes"));
            }
            let metadata_bytes = metadata_memory(
                metadata,
                0,
                self.limits.max_memory_bytes.saturating_sub(retained) / 3,
            )?;
            retained = retained
                .checked_add(
                    metadata_bytes
                        .checked_mul(3)
                        .ok_or(Error::Limit("resident memory"))?,
                )
                .ok_or(Error::Limit("resident memory"))?;
            budget.memory(retained)?;
            let object = batch_get(self.store, *extent, &mut budget, retained)?;
            if object.version != 1 || !matches!(object.kind, 5 | 6) {
                return Err(corrupt("expected extent tree"));
            }
            validate_core_object(&object)?;
            let entry = Entry {
                name: path.last().unwrap().clone(),
                metadata: metadata.clone(),
                data: EntryData::File {
                    length: *length,
                    data: FileData::Extents(*extent),
                },
            };
            let (value, children) = encode_leaf(&[entry]);
            let encoded = cbor::encode(&value);
            let checked = CanonicalObject {
                kind: 3,
                version: 1,
                bytes: encoded,
                children,
            };
            validate_core_object(&checked)?;
            if checked.canonical_len() > self.page_limit {
                return Err(Error::Limit("directory entry too large for writer target"));
            }
            retained = retained
                .checked_add(checked.canonical_len().saturating_mul(3))
                .and_then(|n| n.checked_add(path.iter().map(|p| p.len() + 32).sum::<usize>()))
                .ok_or(Error::Limit("resident memory"))?;
            budget.memory(retained)?;
        }
        let root = batch_directory(self.store, self.root, edits, 0, &mut budget, retained)?;
        self.root = Some(root);
        self.entries = next_entries;
        self.logical = next_logical;
        Ok(())
    }
}

fn batch_get<S: ObjectStore + ?Sized>(
    store: &S,
    root: ObjectRef,
    budget: &mut Budget,
    retained: usize,
) -> Result<std::sync::Arc<CanonicalObject>> {
    budget.memory(retained)?;
    let previous = budget.resident_overhead;
    budget.resident_overhead = previous
        .checked_add(retained)
        .ok_or(Error::Limit("resident memory"))?;
    let result = budget.get(store, root);
    budget.resident_overhead = previous;
    result
}

fn batch_directory<S: ObjectStore + ?Sized>(
    store: &mut S,
    root: Option<ObjectRef>,
    edits: &[Edit],
    at: usize,
    budget: &mut Budget,
    retained: usize,
) -> Result<ObjectRef> {
    budget.depth(at)?;
    let (mut height, mut pages) =
        batch_page(store, root, edits, at, None, None, None, budget, retained)?;
    while pages.len() > 1 {
        height = height
            .checked_add(1)
            .ok_or(Error::Limit("directory tree height"))?;
        pages = emit_branches(store, height, &pages, budget, None)?;
    }
    Ok(pages
        .pop()
        .ok_or_else(|| corrupt("empty file batch result"))?
        .1)
}

#[allow(clippy::too_many_arguments)]
fn batch_page<S: ObjectStore + ?Sized>(
    store: &mut S,
    root: Option<ObjectRef>,
    edits: &[Edit],
    at: usize,
    expected: Option<u64>,
    lower: Option<&[u8]>,
    upper: Option<&[u8]>,
    budget: &mut Budget,
    retained: usize,
) -> Result<(u64, Pages)> {
    budget.edge()?;
    let object = root
        .map(|r| batch_get(store, r, budget, retained))
        .transpose()?;
    let node = object
        .as_ref()
        .map(|o| directory(o))
        .transpose()?
        .unwrap_or(DirectoryNode::Leaf(Vec::new()));
    let retained = retained
        .checked_add(
            object
                .as_ref()
                .map_or(0, |o| o.canonical_len().saturating_mul(3)),
        )
        .ok_or(Error::Limit("resident memory"))?;
    budget.memory(retained)?;
    match node {
        DirectoryNode::Leaf(mut entries) => {
            let write_limit = if object
                .as_ref()
                .is_some_and(|o| o.canonical_len() > budget.directory_write_limit)
            {
                leaf_write_limit(&entries, budget.directory_write_limit)
            } else {
                budget.directory_write_limit
            };
            if expected.is_some_and(|h| h != 0) {
                return Err(corrupt("directory height mismatch"));
            }
            check_interval(&entries, lower, upper)?;
            let mut start = 0;
            while start < edits.len() {
                let name = &edits[start].0[at];
                let mut end = start + 1;
                while end < edits.len() && edits[end].0[at] == *name {
                    end += 1;
                }
                let found = entries.binary_search_by(|e| e.name.cmp(name));
                let entry = if edits[start].0.len() == at + 1 {
                    let (_, length, extent, metadata) = &edits[start];
                    Entry {
                        name: name.clone(),
                        metadata: metadata.clone(),
                        data: EntryData::File {
                            length: *length,
                            data: FileData::Extents(*extent),
                        },
                    }
                } else {
                    let (child, metadata) = match found {
                        Ok(i) => match entries[i].data {
                            EntryData::Directory(r) => {
                                budget.check_reference(root.unwrap(), r)?;
                                (Some(r), entries[i].metadata.clone())
                            }
                            _ => return Err(corrupt("path parent is not a directory")),
                        },
                        Err(_) => (None, empty_metadata()),
                    };
                    let child = batch_directory(
                        store,
                        child,
                        &edits[start..end],
                        at + 1,
                        budget,
                        retained,
                    )?;
                    Entry {
                        name: name.clone(),
                        metadata,
                        data: EntryData::Directory(child),
                    }
                };
                match found {
                    Ok(i) => entries[i] = entry,
                    Err(i) => entries.insert(i, entry),
                }
                start = end;
            }
            let (value, children) = encode_leaf(&entries);
            let hash = CanonicalObject {
                kind: 3,
                version: 1,
                bytes: cbor::encode(&value),
                children,
            }
            .hash();
            if let Some(root) = root.filter(|r| r.hash == hash) {
                return Ok((
                    0,
                    vec![(
                        entries.last().map_or_else(Vec::new, |e| e.name.clone()),
                        root,
                    )],
                ));
            }
            Ok((0, emit_leaves(store, &entries, budget, root, write_limit)?))
        }
        DirectoryNode::Branch { height, fences } => {
            if expected.is_some_and(|h| h != height) {
                return Err(corrupt("directory height mismatch"));
            }
            if upper.is_some_and(|u| fences.last().unwrap().0.as_slice() != u)
                || lower.is_some_and(|l| fences[0].0.as_slice() <= l)
            {
                return Err(corrupt("directory interval mismatch"));
            }
            let mut result = Vec::with_capacity(fences.len() + edits.len());
            let mut start = 0;
            for (i, (key, child)) in fences.iter().enumerate() {
                let end = if i + 1 == fences.len() {
                    edits.len()
                } else {
                    start
                        + edits[start..]
                            .partition_point(|edit| edit.0[at].as_slice() <= key.as_slice())
                };
                if end == start {
                    result.push((key.clone(), *child));
                    continue;
                }
                budget.check_reference(root.unwrap(), *child)?;
                let child_lower = if i == 0 {
                    lower
                } else {
                    Some(fences[i - 1].0.as_slice())
                };
                let (_, changed) = batch_page(
                    store,
                    Some(*child),
                    &edits[start..end],
                    at,
                    Some(height - 1),
                    child_lower,
                    Some(key),
                    budget,
                    retained,
                )?;
                result.extend(changed);
                start = end;
            }
            if result == fences {
                return Ok((
                    height,
                    vec![(fences.last().unwrap().0.clone(), root.unwrap())],
                ));
            }
            Ok((height, emit_branches(store, height, &result, budget, root)?))
        }
    }
}

// Incremental splits leave room on both sides. Greedily filling one page and
// emitting a single-row tail makes random subsequent inserts repeatedly rewrite
// full pages, even though every page individually respects the writer target.
fn balanced_pivot(weights: &[usize], minimum: usize) -> Result<usize> {
    if weights.len() < 2 * minimum {
        return Err(Error::Limit("directory branch cannot fit writer target"));
    }
    let total = weights.iter().try_fold(0usize, |sum, &weight| {
        sum.checked_add(weight)
            .ok_or(Error::Limit("directory split weights"))
    })?;
    let mut left = weights[..minimum].iter().sum::<usize>();
    let mut best = minimum;
    let mut distance = left.abs_diff(total - left);
    for pivot in minimum + 1..=weights.len() - minimum {
        left += weights[pivot - 1];
        let next = left.abs_diff(total - left);
        if next < distance {
            best = pivot;
            distance = next;
        }
    }
    Ok(best)
}

pub(super) fn emit_leaves<S: ObjectStore + ?Sized>(
    store: &mut S,
    entries: &[Entry],
    budget: &mut Budget,
    prior: Option<ObjectRef>,
    write_limit: usize,
) -> Result<Pages> {
    let mut result = Vec::new();
    let mut pending = Vec::new();
    pending.push(0..entries.len());
    while let Some(range) = pending.pop() {
        budget.time()?;
        let rows = &entries[range.clone()];
        let fits = {
            let (value, children) = encode_leaf(rows);
            fits_leaf(&value, &children) && canonical_size(&value, &children) <= write_limit
        };
        if fits {
            result.push(store_leaf_after(store, rows, prior)?);
            continue;
        }
        if rows.len() < 2 {
            return Err(Error::Limit("directory entry too large for writer target"));
        }
        let weights: Vec<_> = rows
            .iter()
            .map(|entry| {
                let (value, children) = encode_leaf(std::slice::from_ref(entry));
                canonical_size(&value, &children)
            })
            .collect();
        let pivot = range.start + balanced_pivot(&weights, 1)?;
        pending.push(pivot..range.end);
        pending.push(range.start..pivot);
    }
    Ok(result)
}

pub(super) fn emit_branches<S: ObjectStore + ?Sized>(
    store: &mut S,
    height: u64,
    fences: &[(Vec<u8>, ObjectRef)],
    budget: &mut Budget,
    prior: Option<ObjectRef>,
) -> Result<Pages> {
    let mut result = Vec::new();
    let mut pending = Vec::new();
    pending.push(0..fences.len());
    let limit = budget.directory_write_limit.min(PAGE_LIMIT);
    while let Some(range) = pending.pop() {
        budget.time()?;
        let rows = &fences[range.clone()];
        let fits = {
            let (value, children) = encode_branch(height, rows);
            fits(&value, &children) && canonical_size(&value, &children) <= limit
        };
        if fits {
            result.push(store_branch_after(store, height, rows, prior)?);
            continue;
        }
        let weights: Vec<_> = rows
            .iter()
            .map(|row| {
                let (value, children) = encode_branch(height, std::slice::from_ref(row));
                canonical_size(&value, &children)
            })
            .collect();
        let pivot = range.start + balanced_pivot(&weights, 2)?;
        pending.push(pivot..range.end);
        pending.push(range.start..pivot);
    }
    Ok(result)
}
