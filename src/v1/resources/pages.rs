//! Read-only directory navigation retaining just the selected authenticated page.
use super::tree::{Entry, EntryData, FileData};
use super::*;
use crate::v1::cbor_view::{self, Item};
use std::{ops::Range, sync::Arc};
pub(crate) struct SharedEntry {
    pub object: Arc<CanonicalObject>,
    pub row: Range<usize>,
}
impl SharedEntry {
    pub fn fields(&self) -> Result<[Item<'_>; 4]> {
        cbor_view::admitted(&self.object.bytes[self.row.clone()])?.fields()
    }
    pub fn child(&self, item: Item<'_>) -> Result<ObjectRef> {
        self.object
            .children
            .get(usize::try_from(item.uint()?).map_err(|_| corrupt("child index"))?)
            .copied()
            .ok_or_else(|| corrupt("child index"))
    }
    pub fn owned(&self) -> Result<Entry> {
        let [n, k, m, v] = self.fields()?;
        let data = match k.uint()? {
            0 => {
                let [l, s, d] = v.fields()?;
                EntryData::File {
                    length: l.uint()?,
                    data: if s.uint()? == 0 {
                        FileData::Inline(d.bytes()?.to_vec())
                    } else {
                        FileData::Extents(self.child(d)?)
                    },
                }
            }
            1 => EntryData::Directory(self.child(v)?),
            2 => EntryData::Symlink(v.bytes()?.to_vec()),
            _ => return Err(corrupt("directory type")),
        };
        Ok(Entry {
            name: n.bytes()?.to_vec(),
            metadata: cbor::decode(m.encoded())?,
            data,
        })
    }
}
struct Bound {
    bytes: [u8; 4096],
    len: usize,
}
impl Bound {
    fn new() -> Self {
        Self {
            bytes: [0; 4096],
            len: 0,
        }
    }
    fn set(&mut self, key: &[u8]) -> Result<()> {
        if key.len() > self.bytes.len() {
            return Err(Error::Limit("directory key"));
        }
        self.bytes[..key.len()].copy_from_slice(key);
        self.len = key.len();
        Ok(())
    }
    fn get(&self) -> Option<&[u8]> {
        (self.len > 0).then_some(&self.bytes[..self.len])
    }
}
/// Row positions of directory pages, so that a later lookup in the same page
/// is a binary search instead of a pass over each row. A reader owns one.
/// The positions take at most [`ROW_INDEX_BYTES`]; a full index starts again.
#[derive(Default)]
pub(crate) struct RowIndexes {
    // The start of each row and the end of the last row. None for a page
    // whose keys are not in strictly increasing order: a lookup in it passes
    // over each row, as it does without an index.
    pages: std::collections::HashMap<ObjectRef, Option<Arc<Vec<u32>>>>,
    bytes: usize,
}
const ROW_INDEX_BYTES: usize = 1024 * 1024;
// A pass over fewer rows costs less than an index lookup.
const INDEXED_ROWS: usize = 16;

fn row_index(
    indexes: Option<&std::sync::Mutex<RowIndexes>>,
    page: ObjectRef,
    object: &CanonicalObject,
    rows: cbor_view::Items<'_>,
    fields: usize,
) -> Result<Option<Arc<Vec<u32>>>> {
    let Some(indexes) = indexes else {
        return Ok(None);
    };
    if rows.len() < INDEXED_ROWS {
        return Ok(None);
    }
    if let Some(known) = indexes.lock().unwrap().pages.get(&page) {
        return Ok(known.clone());
    }
    let base = object.bytes.as_ptr() as usize;
    let mut offsets = Vec::with_capacity(rows.len().min(object.bytes.len()) + 1);
    let mut previous: Option<&[u8]> = None;
    let mut sorted = true;
    let mut end = 0;
    for row in rows {
        let row = row?;
        let key = row.first_field(fields)?.bytes()?;
        sorted &= previous.is_none_or(|previous| previous < key);
        previous = Some(key);
        let start = row.encoded().as_ptr() as usize - base;
        offsets.push(start as u32);
        end = start + row.encoded().len();
    }
    offsets.push(end as u32);
    let built = sorted.then(|| Arc::new(offsets));
    let size = built.as_ref().map_or(0, |offsets| offsets.len() * 4) + 64;
    let mut indexes = indexes.lock().unwrap();
    if indexes.bytes + size > ROW_INDEX_BYTES {
        indexes.pages.clear();
        indexes.bytes = 0;
    }
    indexes.bytes += size;
    indexes.pages.insert(page, built.clone());
    Ok(built)
}
fn indexed_row<'a>(object: &'a CanonicalObject, offsets: &[u32], row: usize) -> Result<Item<'a>> {
    cbor_view::admitted(
        object
            .bytes
            .get(offsets[row] as usize..offsets[row + 1] as usize)
            .ok_or_else(|| corrupt("directory row index"))?,
    )
}
// The first row whose key is not less than `name`, in a page with keys in
// strictly increasing order.
fn indexed_position(
    object: &CanonicalObject,
    offsets: &[u32],
    fields: usize,
    name: &[u8],
) -> Result<usize> {
    let (mut low, mut high) = (0, offsets.len() - 1);
    while low < high {
        let middle = low + (high - low) / 2;
        if indexed_row(object, offsets, middle)?
            .first_field(fields)?
            .bytes()?
            < name
        {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    Ok(low)
}

pub(crate) fn lookup<S: ObjectStore + ?Sized>(
    store: &S,
    mut root: ObjectRef,
    name: &[u8],
    budget: &mut Budget,
    indexes: Option<&std::sync::Mutex<RowIndexes>>,
) -> Result<Option<SharedEntry>> {
    let mut expected_height = None;
    let mut lower = Bound::new();
    let mut upper = Bound::new();
    loop {
        budget.edge()?;
        let object = budget.get(store, root)?;
        if object.version != 1 {
            return Err(Error::Unsupported("directory schema".into()));
        }
        let body = cbor_view::admitted(&object.bytes)?;
        match object.kind {
            3 => {
                if expected_height.is_some_and(|h| h != 0) {
                    return Err(corrupt("directory height mismatch"));
                }
                let mut first = None;
                let mut last = None;
                let mut selected = None;
                if let Some(offsets) = row_index(indexes, root, &object, body.array()?, 4)? {
                    let rows = offsets.len() - 1;
                    let key = |row| indexed_row(&object, &offsets, row)?.first_field(4)?.bytes();
                    first = Some(key(0)?);
                    last = Some(key(rows - 1)?);
                    let position = indexed_position(&object, &offsets, 4, name)?;
                    if position < rows && key(position)? == name {
                        selected = Some(offsets[position] as usize..offsets[position + 1] as usize);
                    }
                } else {
                    for row in body.array()? {
                        let row = row?;
                        let key = row.first_field(4)?.bytes()?;
                        first = first.or(Some(key));
                        last = Some(key);
                        if key == name {
                            let start =
                                row.encoded().as_ptr() as usize - object.bytes.as_ptr() as usize;
                            selected = Some(start..start + row.encoded().len());
                        }
                    }
                }
                if lower.get().is_some() || upper.get().is_some() {
                    let first = first.ok_or_else(|| corrupt("empty branch child"))?;
                    let last = last.unwrap();
                    if lower.get().is_some_and(|l| first <= l)
                        || upper.get().is_some_and(|u| last != u)
                    {
                        return Err(corrupt("directory leaf interval mismatch"));
                    }
                }
                return Ok(selected.map(|row| SharedEntry { object, row }));
            }
            4 => {
                let [h, rows] = body.fields()?;
                let h = h.uint()?;
                if expected_height.is_some_and(|e| e != h) {
                    return Err(corrupt("directory height mismatch"));
                }
                let mut first = None;
                let mut last = None;
                let mut selected = None;
                if let Some(offsets) = row_index(indexes, root, &object, rows.array()?, 2)? {
                    let count = offsets.len() - 1;
                    let key = |row| indexed_row(&object, &offsets, row)?.first_field(2)?.bytes();
                    first = Some(key(0)?);
                    last = Some(key(count - 1)?);
                    let position = indexed_position(&object, &offsets, 2, name)?;
                    if position < count {
                        let [k, r] = indexed_row(&object, &offsets, position)?.fields()?;
                        let prior = match position {
                            0 => None,
                            position => Some(key(position - 1)?),
                        };
                        selected = Some((prior, k.bytes()?, r.uint()?));
                    }
                } else {
                    let mut prior = None;
                    for row in rows.array()? {
                        let [k, r] = row?.fields()?;
                        let key = k.bytes()?;
                        first = first.or(Some(key));
                        last = Some(key);
                        if selected.is_none() && key >= name {
                            selected = Some((prior, key, r.uint()?));
                        }
                        prior = Some(key);
                    }
                }
                let first = first.ok_or_else(|| corrupt("empty directory branch"))?;
                if upper.get().is_some_and(|u| Some(u) != last)
                    || lower.get().is_some_and(|l| first <= l)
                {
                    return Err(corrupt("directory interval mismatch"));
                }
                let Some((prior, key, index)) = selected else {
                    return Ok(None);
                };
                let next = *object
                    .children
                    .get(index as usize)
                    .ok_or_else(|| corrupt("child index"))?;
                budget.check_reference(root, next)?;
                if let Some(prior) = prior {
                    lower.set(prior)?;
                }
                upper.set(key)?;
                root = next;
                expected_height = Some(h - 1);
            }
            _ => return Err(corrupt("expected directory node")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::MemoryStore;
    use crate::v1::resources::ArchiveBuilder;

    #[test]
    fn indexed_lookup_agrees_with_a_pass_over_each_row() {
        let mut store = MemoryStore::sealed();
        let root = {
            let mut builder = ArchiveBuilder::new(&mut store);
            // Small pages give the directory several branch levels.
            builder.set_page_limit(4096).unwrap();
            for ordinal in (0..3000u32).step_by(2) {
                builder
                    .add_file(&[format!("f{ordinal:05}").into_bytes()], b"x")
                    .unwrap();
            }
            builder.finish_directory().unwrap()
        };
        let indexes = std::sync::Mutex::new(RowIndexes::default());
        let mut names: Vec<Vec<u8>> = (0..3001u32)
            .map(|ordinal| format!("f{ordinal:05}").into_bytes())
            .collect();
        names.extend([
            b"a".to_vec(),
            b"f".to_vec(),
            b"f00000\0".to_vec(),
            b"z".to_vec(),
        ]);
        // The second pass finds each page in the index.
        for _ in 0..2 {
            for name in &names {
                let mut budget = Budget::new(Limits::default());
                let expected = lookup(&store, root, name, &mut budget, None).unwrap();
                let mut budget = Budget::new(Limits::default());
                let actual = lookup(&store, root, name, &mut budget, Some(&indexes)).unwrap();
                assert_eq!(expected.is_some(), actual.is_some(), "{name:?}");
                if let (Some(expected), Some(actual)) = (expected, actual) {
                    assert_eq!(expected.row, actual.row);
                    assert_eq!(expected.object.bytes, actual.object.bytes);
                }
            }
        }
        let indexes = indexes.lock().unwrap();
        assert!(indexes.pages.len() > 2);
        assert!(indexes.pages.values().all(Option::is_some));
        assert!(indexes.bytes <= ROW_INDEX_BYTES);
    }
}
