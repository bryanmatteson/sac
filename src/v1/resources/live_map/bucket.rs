//! Bounded Patricia leaf buckets: small shared records, external large values.
use super::{MAX_KEY, MAX_VALUE, Value, admit_bucket_snapshot};
use crate::v1::cbor::{self, Value as V};
use crate::v1::cbor_view;
use crate::v1::{CanonicalObject, Error, ObjectRef, ObjectStore, Result, resources};
use std::collections::BTreeMap;

// Frozen wire identifier: promotion preserves references from the qualified prototype.
pub const PROFILE: &str = "org.sac.experimental.bucket-trie";
const INLINE: usize = 128;
const VALUE_INLINE: usize = 48 * 1024;
const ROWS: usize = 16;
const KEY_BYTES: usize = 1024;
const VISITS: usize = 1_000_000;
fn bad(s: &str) -> Error {
    Error::Corrupt(format!("experimental bucket trie: {s}"))
}
fn record<S: ObjectStore + ?Sized>(
    store: &mut S,
    typ: &str,
    payload: V,
    children: &[ObjectRef],
) -> Result<ObjectRef> {
    store.put(
        8,
        1,
        &cbor::encode(&V::Array(vec![
            V::text(PROFILE),
            V::text(typ),
            V::Uint(1),
            V::Bytes(cbor::encode(&payload)),
        ])),
        children,
    )
}
fn body<'a>(object: &'a CanonicalObject, typ: &str) -> Result<cbor_view::Item<'a>> {
    if object.kind != 8 || object.version != 1 || object.canonical_len() > 65536 {
        return Err(bad("record kind/size"));
    }
    let [namespace, actual, version, payload] = cbor_view::view(&object.bytes)?.fields()?;
    if namespace.text()? != PROFILE || actual.text()? != typ || version.uint()? != 1 {
        return Err(bad("record envelope"));
    }
    cbor_view::view(payload.bytes()?)
}
#[derive(Clone, Copy)]
enum ValueView<'a> {
    Inline(&'a [u8]),
    Blob { length: usize, reference: ObjectRef },
}
impl ValueView<'_> {
    fn owned(self) -> Value {
        match self {
            Self::Inline(v) => Value::Inline(v.to_vec()),
            Self::Blob { length, reference } => Value::Blob { length, reference },
        }
    }
    fn read<S: ObjectStore + ?Sized>(self, store: &S) -> Result<Vec<u8>> {
        match self {
            Self::Inline(v) => Ok(v.to_vec()),
            Self::Blob { length, reference } => {
                let object = store.get_verified_shared(reference)?;
                match resolve_view(&object, length)? {
                    ValueView::Inline(bytes) => Ok(bytes.to_vec()),
                    ValueView::Blob { length, reference } => {
                        Value::Blob { length, reference }.read(store)
                    }
                }
            }
        }
    }
}
// Buckets point to separate value records. Medium values live individually
// inline; large values use small descriptors. Ordinary put admission checks
// those immediate records without repeatedly reading their large byte children.
fn resolve_view(object: &CanonicalObject, length: usize) -> Result<ValueView<'_>> {
    let [declared, storage, data] = body(object, "value")?.fields()?;
    if declared.uint()? != length as u64 {
        return Err(bad("value length"));
    }
    match storage.uint()? {
        0 if length <= VALUE_INLINE && object.children.is_empty() => {
            let bytes = data.bytes()?;
            if bytes.len() != length {
                return Err(bad("inline value length"));
            }
            Ok(ValueView::Inline(bytes))
        }
        1 if length > VALUE_INLINE && data.uint()? == 0 && object.children.len() == 1 => {
            Ok(ValueView::Blob {
                length,
                reference: object.children[0],
            })
        }
        _ => Err(bad("value storage/children")),
    }
}
fn resolve<S: ObjectStore + ?Sized>(store: &S, value: Value) -> Result<Value> {
    match value {
        Value::Inline(_) => Ok(value),
        Value::Blob { length, reference } => {
            let object = store.get_verified_shared(reference)?;
            Ok(resolve_view(&object, length)?.owned())
        }
    }
}
struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.0.len() {
            return Err(bad("truncated node"));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<usize> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as usize)
    }
    fn value(&mut self, children: &[ObjectRef], used: &mut usize) -> Result<ValueView<'a>> {
        match self.byte()? {
            n @ 0..=128 => Ok(ValueView::Inline(self.take(n as usize)?)),
            255 => {
                let length = u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize;
                if !(INLINE + 1..=MAX_VALUE).contains(&length) {
                    return Err(bad("blob length"));
                }
                let reference = *children.get(*used).ok_or_else(|| bad("value child"))?;
                *used += 1;
                Ok(ValueView::Blob { length, reference })
            }
            _ => Err(bad("value tag")),
        }
    }
}
fn encode_value(value: &Value, bytes: &mut Vec<u8>, children: &mut Vec<ObjectRef>) {
    match value {
        Value::Inline(v) => {
            bytes.push(v.len() as u8);
            bytes.extend(v);
        }
        Value::Blob { length, reference } => {
            bytes.push(255);
            bytes.extend((*length as u32).to_le_bytes());
            children.push(*reference);
        }
    }
}
enum View<'a> {
    Bucket {
        prefix: &'a [u8],
        rows: Vec<(&'a [u8], ValueView<'a>)>,
    },
    Branch {
        prefix: &'a [u8],
        terminal: Option<ValueView<'a>>,
        edges: Vec<(u8, ObjectRef)>,
    },
}
impl<'a> View<'a> {
    fn parse(object: &'a CanonicalObject) -> Result<Self> {
        if object.kind != 8 || object.version != 1 || object.canonical_len() > 16384 {
            return Err(bad("node kind/size"));
        }
        let [namespace, typ, version, payload] = cbor_view::view(&object.bytes)?.fields()?;
        if namespace.text()? != PROFILE || version.uint()? != 1 {
            return Err(bad("node envelope"));
        }
        let mut cursor = Cursor(cbor_view::view(payload.bytes()?)?.bytes()?);
        let prefix_len = cursor.u16()?;
        let prefix = cursor.take(prefix_len)?;
        if prefix.len() > MAX_KEY {
            return Err(bad("node prefix"));
        }
        let mut used = 0;
        let result = match typ.text()? {
            "bucket" => {
                let count = cursor.byte()? as usize;
                if count == 0 || count > ROWS {
                    return Err(bad("bucket bounds"));
                }
                let mut rows = Vec::with_capacity(count);
                let mut key_bytes = 0;
                for _ in 0..count {
                    let n = cursor.u16()?;
                    let suffix = cursor.take(n)?;
                    key_bytes += n;
                    if prefix.len() + n > MAX_KEY
                        || key_bytes > KEY_BYTES
                        || rows.last().is_some_and(|(p, _)| *p >= suffix)
                    {
                        return Err(bad("bucket keys"));
                    }
                    rows.push((suffix, cursor.value(&object.children, &mut used)?));
                }
                if rows.len() == 1 && !rows[0].0.is_empty()
                    || rows.len() > 1
                        && !rows[0].0.is_empty()
                        && rows[0].0.first() == rows.last().unwrap().0.first()
                {
                    return Err(bad("bucket prefix"));
                }
                Self::Bucket { prefix, rows }
            }
            "branch" => {
                let terminal = match cursor.byte()? {
                    0 => None,
                    1 => Some(cursor.value(&object.children, &mut used)?),
                    _ => return Err(bad("terminal flag")),
                };
                let count = cursor.u16()?;
                if count > 256 || count + usize::from(terminal.is_some()) < 2 {
                    return Err(bad("branch arity"));
                }
                let mut edges = Vec::with_capacity(count);
                for _ in 0..count {
                    let label = cursor.byte()?;
                    if edges.last().is_some_and(|(p, _)| *p >= label) {
                        return Err(bad("branch order"));
                    }
                    let child = *object
                        .children
                        .get(used)
                        .ok_or_else(|| bad("branch child"))?;
                    used += 1;
                    edges.push((label, child));
                }
                Self::Branch {
                    prefix,
                    terminal,
                    edges,
                }
            }
            _ => return Err(bad("node type")),
        };
        if !cursor.0.is_empty() || used != object.children.len() {
            return Err(bad("trailing bytes/unused children"));
        }
        Ok(result)
    }
    fn owned(self) -> Node {
        match self {
            Self::Bucket { prefix, rows } => Node::Bucket {
                prefix: prefix.to_vec(),
                rows: rows
                    .into_iter()
                    .map(|(k, v)| (k.to_vec(), v.owned()))
                    .collect(),
            },
            Self::Branch {
                prefix,
                terminal,
                edges,
            } => Node::Branch {
                prefix: prefix.to_vec(),
                terminal: terminal.map(ValueView::owned),
                edges,
            },
        }
    }
}
#[derive(Clone)]
enum Node {
    Bucket {
        prefix: Vec<u8>,
        rows: Vec<(Vec<u8>, Value)>,
    },
    Branch {
        prefix: Vec<u8>,
        terminal: Option<Value>,
        edges: Vec<(u8, ObjectRef)>,
    },
}
impl Node {
    fn read<S: ObjectStore + ?Sized>(store: &S, reference: ObjectRef) -> Result<Self> {
        let object = store.get_verified_shared(reference)?;
        Ok(View::parse(&object)?.owned())
    }
    fn write<S: ObjectStore + ?Sized>(&self, store: &mut S) -> Result<ObjectRef> {
        let mut children = Vec::new();
        let mut bytes = Vec::new();
        let (prefix, typ) = match self {
            Self::Bucket { prefix, .. } => (prefix, "bucket"),
            Self::Branch { prefix, .. } => (prefix, "branch"),
        };
        bytes.extend((prefix.len() as u16).to_le_bytes());
        bytes.extend(prefix);
        match self {
            Self::Bucket { rows, .. } => {
                bytes.push(rows.len() as u8);
                for (key, value) in rows {
                    bytes.extend((key.len() as u16).to_le_bytes());
                    bytes.extend(key);
                    encode_value(value, &mut bytes, &mut children);
                }
            }
            Self::Branch {
                terminal, edges, ..
            } => {
                bytes.push(u8::from(terminal.is_some()));
                if let Some(value) = terminal {
                    encode_value(value, &mut bytes, &mut children);
                }
                bytes.extend((edges.len() as u16).to_le_bytes());
                for (label, reference) in edges {
                    bytes.push(*label);
                    children.push(*reference);
                }
            }
        }
        record(store, typ, V::Bytes(bytes), &children)
    }
}
// A split handles at most ROWS+1 entries. Each recursive branch reduces that
// number, so this local construction has at most ROWS+1 stack frames.
fn build<S: ObjectStore + ?Sized>(
    store: &mut S,
    entries: Vec<(Vec<u8>, Value)>,
) -> Result<ObjectRef> {
    let first = &entries.first().ok_or_else(|| bad("empty build"))?.0;
    let last = &entries.last().unwrap().0;
    let n = first.iter().zip(last).take_while(|(a, b)| a == b).count();
    let prefix = first[..n].to_vec();
    let key_bytes: usize = entries.iter().map(|(k, _)| k.len() - n).sum();
    if entries.len() <= ROWS && key_bytes <= KEY_BYTES {
        return Node::Bucket {
            prefix,
            rows: entries
                .into_iter()
                .map(|(k, v)| (k[n..].to_vec(), v))
                .collect(),
        }
        .write(store);
    }
    let mut terminal = None;
    let mut groups: BTreeMap<u8, Vec<(Vec<u8>, Value)>> = BTreeMap::new();
    for (key, value) in entries {
        if key.len() == n {
            terminal = Some(value);
        } else {
            groups
                .entry(key[n])
                .or_default()
                .push((key[n + 1..].to_vec(), value));
        }
    }
    let mut edges = Vec::with_capacity(groups.len());
    for (label, entries) in groups {
        edges.push((label, build(store, entries)?));
    }
    Node::Branch {
        prefix,
        terminal,
        edges,
    }
    .write(store)
}
#[derive(Clone, Default)]
pub struct BucketTrie {
    root: Option<ObjectRef>,
    len: u64,
}
impl BucketTrie {
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn len(&self) -> u64 {
        self.len
    }
    pub fn set<S: ObjectStore + ?Sized>(
        &mut self,
        store: &mut S,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<()> {
        self.set_checked(store, key, bytes, |_| Ok(()))
    }
    pub(super) fn set_checked<S: ObjectStore + ?Sized>(
        &mut self,
        store: &mut S,
        key: &[u8],
        bytes: &[u8],
        check: impl FnOnce(Option<usize>) -> Result<()>,
    ) -> Result<()> {
        if key.len() > MAX_KEY || bytes.len() > MAX_VALUE {
            return Err(Error::Limit("bucket key/value"));
        }
        let value = if bytes.len() <= INLINE {
            Value::Inline(bytes.to_vec())
        } else {
            let descriptor = if bytes.len() <= VALUE_INLINE {
                record(
                    store,
                    "value",
                    V::Array(vec![
                        V::Uint(bytes.len() as u64),
                        V::Uint(0),
                        V::Bytes(bytes.to_vec()),
                    ]),
                    &[],
                )?
            } else {
                let blob = store.put(7, 1, bytes, &[])?;
                record(
                    store,
                    "value",
                    V::Array(vec![V::Uint(bytes.len() as u64), V::Uint(1), V::Uint(0)]),
                    &[blob],
                )?
            };
            Value::Blob {
                length: bytes.len(),
                reference: descriptor,
            }
        };
        let mut remaining = key;
        let mut next = self.root;
        let mut path = Vec::new();
        let mut inserted = true;
        let mut previous = None;
        let mut replacement = loop {
            let Some(reference) = next else {
                break build(store, vec![(remaining.to_vec(), value)])?;
            };
            match Node::read(store, reference)? {
                Node::Bucket { prefix, rows } => {
                    let mut entries: BTreeMap<_, _> = rows
                        .into_iter()
                        .map(|(suffix, v)| {
                            let mut k = prefix.clone();
                            k.extend(suffix);
                            (k, v)
                        })
                        .collect();
                    previous = entries.insert(remaining.to_vec(), value).map(|v| v.len());
                    inserted = previous.is_none();
                    break build(store, entries.into_iter().collect())?;
                }
                Node::Branch {
                    mut prefix,
                    mut terminal,
                    mut edges,
                } => {
                    let common = prefix
                        .iter()
                        .zip(remaining)
                        .take_while(|(a, b)| a == b)
                        .count();
                    if common < prefix.len() {
                        let shared = prefix[..common].to_vec();
                        let label = prefix[common];
                        prefix.drain(..common + 1);
                        let old = Node::Branch {
                            prefix,
                            terminal,
                            edges,
                        }
                        .write(store)?;
                        let mut edges = vec![(label, old)];
                        let terminal = if common == remaining.len() {
                            Some(value)
                        } else {
                            let new =
                                build(store, vec![(remaining[common + 1..].to_vec(), value)])?;
                            edges.push((remaining[common], new));
                            edges.sort_unstable_by_key(|(b, _)| *b);
                            None
                        };
                        break Node::Branch {
                            prefix: shared,
                            terminal,
                            edges,
                        }
                        .write(store)?;
                    }
                    remaining = &remaining[common..];
                    if remaining.is_empty() {
                        previous = terminal.replace(value).map(|v| v.len());
                        inserted = previous.is_none();
                        break Node::Branch {
                            prefix,
                            terminal,
                            edges,
                        }
                        .write(store)?;
                    }
                    let label = remaining[0];
                    remaining = &remaining[1..];
                    next = edges
                        .binary_search_by_key(&label, |(b, _)| *b)
                        .ok()
                        .map(|i| edges[i].1);
                    path.push((prefix, terminal, std::mem::take(&mut edges), label));
                }
            }
        };
        for (prefix, terminal, mut edges, label) in path.into_iter().rev() {
            match edges.binary_search_by_key(&label, |(b, _)| *b) {
                Ok(i) => edges[i].1 = replacement,
                Err(i) => edges.insert(i, (label, replacement)),
            }
            replacement = Node::Branch {
                prefix,
                terminal,
                edges,
            }
            .write(store)?;
        }
        if inserted && self.len >= VISITS as u64 {
            return Err(Error::Limit("bucket entries"));
        }
        check(previous)?;
        self.root = Some(replacement);
        self.len += u64::from(inserted);
        Ok(())
    }
    /// Route misses are authoritative only after full owning verification.
    pub fn get<S: ObjectStore + ?Sized>(&self, store: &S, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if key.len() > MAX_KEY {
            return Err(Error::Limit("bucket key"));
        }
        let mut remaining = key;
        let mut next = self.root;
        for _ in 0..=MAX_KEY + 1 {
            let Some(reference) = next else {
                return Ok(None);
            };
            let object = store.get_verified_shared(reference)?;
            match View::parse(&object)? {
                View::Bucket { prefix, rows } => {
                    let Some(suffix) = remaining.strip_prefix(prefix) else {
                        return Ok(None);
                    };
                    return rows
                        .binary_search_by_key(&suffix, |(k, _)| *k)
                        .ok()
                        .map(|i| rows[i].1.read(store))
                        .transpose();
                }
                View::Branch {
                    prefix,
                    terminal,
                    edges,
                } => {
                    let Some(rest) = remaining.strip_prefix(prefix) else {
                        return Ok(None);
                    };
                    remaining = rest;
                    if remaining.is_empty() {
                        return terminal.map(|v| v.read(store)).transpose();
                    }
                    let label = remaining[0];
                    remaining = &remaining[1..];
                    next = edges
                        .binary_search_by_key(&label, |(b, _)| *b)
                        .ok()
                        .map(|i| edges[i].1);
                }
            }
        }
        Err(Error::Limit("bucket depth"))
    }
    pub fn profile_root<S: ObjectStore + ?Sized>(&self, store: &mut S) -> Result<ObjectRef> {
        record(
            store,
            "root",
            V::Array(vec![
                V::Uint(self.len),
                if self.root.is_some() {
                    V::Uint(0)
                } else {
                    V::Null
                },
            ]),
            &self.root.into_iter().collect::<Vec<_>>(),
        )
    }
    pub fn from_profile_root<S: ObjectStore + ?Sized>(store: &S, root: ObjectRef) -> Result<Self> {
        let object = store.get_verified_shared(root)?;
        let [len, index] = body(&object, "root")?.fields()?;
        let len = len.uint()?;
        if len > VISITS as u64 {
            return Err(Error::Limit("bucket entries"));
        }
        let root = match (len, index.is_null(), object.children.as_slice()) {
            (0, true, []) => None,
            (1.., false, [r]) if index.uint()? == 0 => Some(*r),
            _ => return Err(bad("root count/children")),
        };
        Ok(Self { root, len })
    }
    pub fn snapshot<S: ObjectStore + ?Sized>(&self, store: &mut S) -> Result<ObjectRef> {
        let root = self.profile_root(store)?;
        let directory = resources::ArchiveBuilder::new(store).finish_directory()?;
        resources::snapshot(
            store,
            directory,
            vec![resources::Profile {
                id: PROFILE.into(),
                version: 1,
                root,
            }],
            vec![],
        )
    }
    pub fn open<S: ObjectStore + ?Sized>(store: &S, snapshot: ObjectRef) -> Result<Self> {
        Self::from_profile_root(store, admit_bucket_snapshot(store, snapshot, PROFILE)?)
    }
    #[doc(hidden)]
    pub fn verified_entries<S: ObjectStore + ?Sized>(
        &self,
        store: &S,
    ) -> Result<BTreeMap<Vec<u8>, Value>> {
        let mut output = BTreeMap::new();
        let mut stack: Vec<_> = self.root.map(|r| (r, Vec::new())).into_iter().collect();
        let mut visits = 0;
        let mut bytes = 0usize;
        let mut queued = 0;
        let mut emit = |key: Vec<u8>, value: Value| -> Result<()> {
            if key.len() > MAX_KEY {
                return Err(Error::Limit("bucket key"));
            }
            let value = resolve(store, value)?;
            value.validate(store)?;
            bytes = bytes
                .checked_add(key.len() + value.len())
                .ok_or(Error::Limit("bucket bytes"))?;
            if bytes > 512 * 1024 * 1024 || output.len() >= VISITS {
                return Err(Error::Limit("bucket bytes/entries"));
            }
            if output.insert(key, value).is_some() {
                return Err(bad("duplicate key"));
            }
            Ok(())
        };
        while let Some((reference, mut key)) = stack.pop() {
            queued -= key.len();
            visits += 1;
            if visits > VISITS {
                return Err(Error::Limit("bucket visits"));
            }
            match Node::read(store, reference)? {
                Node::Bucket { prefix, rows } => {
                    key.extend(prefix);
                    for (suffix, value) in rows {
                        let mut k = key.clone();
                        k.extend(suffix);
                        emit(k, value)?;
                    }
                }
                Node::Branch {
                    prefix,
                    terminal,
                    edges,
                } => {
                    key.extend(prefix);
                    if key.len() > MAX_KEY {
                        return Err(Error::Limit("bucket key"));
                    }
                    if let Some(value) = terminal {
                        emit(key.clone(), value)?;
                    }
                    for (label, r) in edges.into_iter().rev() {
                        let mut k = key.clone();
                        k.push(label);
                        if k.len() > MAX_KEY {
                            return Err(Error::Limit("bucket key"));
                        }
                        queued += k.len();
                        stack.push((r, k));
                    }
                    if queued > 32 * 1024 * 1024 {
                        return Err(Error::Limit("bucket queued keys"));
                    }
                }
            }
        }
        if output.len() as u64 != self.len {
            return Err(bad("entry count"));
        }
        Ok(output)
    }
    pub fn verify<S: ObjectStore + ?Sized>(&self, store: &S) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        self.verified_entries(store)?
            .into_iter()
            .map(|(k, v)| Ok((k, v.read(store)?)))
            .collect()
    }
}
