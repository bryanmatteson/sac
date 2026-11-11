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
pub(crate) fn lookup<S: ObjectStore + ?Sized>(
    store: &S,
    mut root: ObjectRef,
    name: &[u8],
    budget: &mut Budget,
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
                let mut prior = None;
                let mut selected = None;
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
