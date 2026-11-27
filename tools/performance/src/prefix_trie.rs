//! Experimental persistent bytewise Patricia trie, deliberately outside the public API.
//! Uses core kind 8 application records and ordinary authenticated strong children.
//! This flat byte map does not implement the resource profile's metadata or hierarchy.
use sac::cbor::{self, Value as V};
use sac::v1::cbor_view;
use sac::{CanonicalObject, Error, ObjectRef, ObjectStore, Result, resources};
use std::collections::BTreeMap;

pub const PROFILE: &str = "org.sac.experimental.prefix-trie";
pub const MAX_KEY: usize = 4096;
pub const MAX_VALUE: usize = sac::MAX_CHUNK_SIZE - 8;
const INLINE: usize = 48 * 1024;
const MAX_VISITS: usize = 1_000_000;

fn bad(message: &str) -> Error {
    Error::Corrupt(format!("experimental prefix trie: {message}"))
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
    if object.kind != 8 || object.version != 1 {
        return Err(bad("record type"));
    }
    let [namespace, actual, version, payload] = cbor_view::view(&object.bytes)?.fields()?;
    if namespace.text()? != PROFILE || actual.text()? != typ || version.uint()? != 1 {
        return Err(bad("record namespace/type/version"));
    }
    cbor_view::view(payload.bytes()?)
}

/// This prototype owns the entire snapshot view; refuse surfaces it cannot retain.
pub(crate) fn admit_snapshot<S: ObjectStore + ?Sized>(
    store: &S,
    snapshot: ObjectRef,
    profile: &str,
) -> Result<ObjectRef> {
    let archive = resources::ArchiveReader::open(store, snapshot, resources::Limits::default())?;
    let object = store.get_verified_shared(snapshot)?;
    let [_, profiles, features] = cbor_view::view(&object.bytes)?.fields()?;
    let mut profiles = profiles.array()?;
    if profiles.len() != 1 || features.array()?.len() != 0 || object.children.len() != 2 {
        return Err(Error::Unsupported(
            "experimental map requires its sole profile and no additional features".into(),
        ));
    }
    let directory = store.get_verified_shared(archive.directory_root())?;
    if directory.kind != 3
        || directory.version != 1
        || !directory.children.is_empty()
        || cbor_view::view(&directory.bytes)?.array()?.len() != 0
    {
        return Err(bad("outer resource directory must be empty"));
    }
    let [id, version, index] = profiles.next().ok_or_else(|| bad("profile"))??.fields()?;
    if id.text()? != profile || version.uint()? != 1 {
        return Err(bad("profile declaration"));
    }
    let index = usize::try_from(index.uint()?).map_err(|_| bad("profile index"))?;
    object
        .children
        .get(index)
        .copied()
        .ok_or_else(|| bad("profile index"))
}

#[derive(Clone)]
pub(crate) enum Value {
    Inline(Vec<u8>),
    Blob { length: usize, reference: ObjectRef },
}
impl Value {
    fn write<S: ObjectStore + ?Sized>(store: &mut S, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_VALUE {
            return Err(Error::Limit("trie value"));
        }
        Ok(if bytes.len() <= INLINE {
            Self::Inline(bytes.to_vec())
        } else {
            Self::Blob {
                length: bytes.len(),
                reference: store.put(7, 1, bytes, &[])?,
            }
        })
    }
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Inline(bytes) => bytes.len(),
            Self::Blob { length, .. } => *length,
        }
    }
    pub(crate) fn validate<S: ObjectStore + ?Sized>(&self, store: &S) -> Result<()> {
        if let Self::Blob { length, reference } = self {
            let object = store.get_verified_shared(*reference)?;
            if object.kind != 7
                || object.version != 1
                || !object.children.is_empty()
                || object.bytes.len() != *length
            {
                return Err(bad("blob type/length"));
            }
        }
        Ok(())
    }
    pub(crate) fn read<S: ObjectStore + ?Sized>(&self, store: &S) -> Result<Vec<u8>> {
        match self {
            Self::Inline(bytes) => Ok(bytes.clone()),
            Self::Blob { length, reference } => {
                let object = store.get_verified_shared(*reference)?;
                if object.kind != 7
                    || object.version != 1
                    || !object.children.is_empty()
                    || object.bytes.len() != *length
                {
                    return Err(bad("blob type/length"));
                }
                Ok(object.bytes.clone())
            }
        }
    }
}
#[derive(Clone)]
enum Node {
    Leaf {
        suffix: Vec<u8>,
        value: Value,
    },
    Branch {
        prefix: Vec<u8>,
        terminal: Option<ObjectRef>,
        edges: Vec<(u8, ObjectRef)>,
    },
}
impl Node {
    fn write<S: ObjectStore + ?Sized>(&self, store: &mut S) -> Result<ObjectRef> {
        match self {
            Self::Leaf { suffix, value } => {
                let (storage, data, children) = match value {
                    Value::Inline(bytes) => (0, V::Bytes(bytes.clone()), vec![]),
                    Value::Blob { length, reference } => {
                        (1, V::Uint(*length as u64), vec![*reference])
                    }
                };
                record(
                    store,
                    "leaf",
                    V::Array(vec![V::Bytes(suffix.clone()), V::Uint(storage), data]),
                    &children,
                )
            }
            Self::Branch {
                prefix,
                terminal,
                edges,
            } => {
                let mut children: Vec<_> = terminal.iter().copied().collect();
                let rows = edges
                    .iter()
                    .map(|(label, child)| {
                        let index = children.len();
                        children.push(*child);
                        V::Array(vec![V::Uint(u64::from(*label)), V::Uint(index as u64)])
                    })
                    .collect();
                record(
                    store,
                    "branch",
                    V::Array(vec![
                        V::Bytes(prefix.clone()),
                        if terminal.is_some() {
                            V::Uint(0)
                        } else {
                            V::Null
                        },
                        V::Array(rows),
                    ]),
                    &children,
                )
            }
        }
    }
    fn read<S: ObjectStore + ?Sized>(store: &S, reference: ObjectRef) -> Result<Self> {
        let object = store.get_verified_shared(reference)?;
        if object.kind != 8 || object.version != 1 {
            return Err(bad("node kind"));
        }
        let [_, typ, _, _] = cbor_view::view(&object.bytes)?.fields()?;
        match typ.text()? {
            "leaf" => {
                let [suffix, storage, data] = body(&object, "leaf")?.fields()?;
                let suffix = suffix.bytes()?.to_vec();
                if suffix.len() > MAX_KEY {
                    return Err(Error::Limit("trie key"));
                }
                let value = match (storage.uint()?, object.children.as_slice()) {
                    (0, []) => {
                        let bytes = data.bytes()?;
                        if bytes.len() > INLINE {
                            return Err(bad("oversized inline value"));
                        }
                        Value::Inline(bytes.to_vec())
                    }
                    (1, [reference]) => {
                        let length =
                            usize::try_from(data.uint()?).map_err(|_| bad("blob length"))?;
                        if !(INLINE + 1..=MAX_VALUE).contains(&length) {
                            return Err(bad("blob length"));
                        }
                        Value::Blob {
                            length,
                            reference: *reference,
                        }
                    }
                    _ => return Err(bad("leaf storage/children")),
                };
                Ok(Self::Leaf { suffix, value })
            }
            "branch" => {
                let [prefix, terminal, rows] = body(&object, "branch")?.fields()?;
                let prefix = prefix.bytes()?.to_vec();
                if prefix.len() > MAX_KEY {
                    return Err(Error::Limit("trie prefix"));
                }
                let terminal = if terminal.is_null() {
                    None
                } else {
                    if terminal.uint()? != 0 {
                        return Err(bad("terminal index"));
                    }
                    Some(
                        *object
                            .children
                            .first()
                            .ok_or_else(|| bad("terminal child"))?,
                    )
                };
                let rows = rows.array()?;
                if rows.len() > 256
                    || rows.len() + usize::from(terminal.is_some()) != object.children.len()
                    || object.children.len() < 2
                {
                    return Err(bad("branch arity"));
                }
                let mut edges = Vec::with_capacity(rows.len());
                for row in rows {
                    let [label, index] = row?.fields()?;
                    let label = u8::try_from(label.uint()?).map_err(|_| bad("edge label"))?;
                    if edges.last().is_some_and(|(previous, _)| *previous >= label) {
                        return Err(bad("edge ordering"));
                    }
                    let expected = edges.len() + usize::from(terminal.is_some());
                    if index.uint()? != expected as u64 {
                        return Err(bad("edge index"));
                    }
                    edges.push((label, object.children[expected]));
                }
                Ok(Self::Branch {
                    prefix,
                    terminal,
                    edges,
                })
            }
            _ => Err(bad("node type")),
        }
    }
}

#[derive(Clone, Default)]
pub struct PrefixTrie {
    root: Option<ObjectRef>,
    len: u64,
}
impl PrefixTrie {
    pub fn len(&self) -> u64 {
        self.len
    }
    pub fn set<S: ObjectStore + ?Sized>(
        &mut self,
        store: &mut S,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<()> {
        if key.len() > MAX_KEY {
            return Err(Error::Limit("trie key"));
        }
        // Heap path, bounded by key length: each branch consumes at least one byte.
        let value = Value::write(store, bytes)?;
        let mut path = Vec::new();
        let mut remaining = key;
        let mut next = self.root;
        let mut inserted = true;
        let mut replacement = loop {
            let Some(reference) = next else {
                break Node::Leaf {
                    suffix: remaining.to_vec(),
                    value,
                }
                .write(store)?;
            };
            let node = Node::read(store, reference)?;
            let prefix = match &node {
                Node::Leaf { suffix, .. } => suffix.clone(),
                Node::Branch { prefix, .. } => prefix.clone(),
            };
            let common = prefix
                .iter()
                .zip(remaining)
                .take_while(|(a, b)| a == b)
                .count();
            if common < prefix.len() {
                let mut old = node.clone();
                match &mut old {
                    Node::Leaf { suffix, .. } => {
                        suffix.drain(..common + 1);
                    }
                    Node::Branch { prefix, .. } => {
                        prefix.drain(..common + 1);
                    }
                }
                let old_ref = old.write(store)?;
                let mut edges = vec![(prefix[common], old_ref)];
                let terminal = if common == remaining.len() {
                    Some(
                        Node::Leaf {
                            suffix: vec![],
                            value,
                        }
                        .write(store)?,
                    )
                } else {
                    let new_ref = Node::Leaf {
                        suffix: remaining[common + 1..].to_vec(),
                        value,
                    }
                    .write(store)?;
                    edges.push((remaining[common], new_ref));
                    edges.sort_unstable_by_key(|(label, _)| *label);
                    None
                };
                break Node::Branch {
                    prefix: prefix[..common].to_vec(),
                    terminal,
                    edges,
                }
                .write(store)?;
            }
            remaining = &remaining[common..];
            match node {
                Node::Leaf {
                    value: old_value, ..
                } => {
                    if remaining.is_empty() {
                        inserted = false;
                        break Node::Leaf {
                            suffix: prefix.clone(),
                            value,
                        }
                        .write(store)?;
                    }
                    let terminal = Some(
                        Node::Leaf {
                            suffix: vec![],
                            value: old_value,
                        }
                        .write(store)?,
                    );
                    let child = Node::Leaf {
                        suffix: remaining[1..].to_vec(),
                        value,
                    }
                    .write(store)?;
                    break Node::Branch {
                        prefix: prefix.clone(),
                        terminal,
                        edges: vec![(remaining[0], child)],
                    }
                    .write(store)?;
                }
                Node::Branch {
                    prefix,
                    terminal,
                    edges,
                } => {
                    let selected = remaining.first().copied();
                    next = match selected {
                        None => terminal,
                        Some(label) => edges
                            .binary_search_by_key(&label, |(b, _)| *b)
                            .ok()
                            .map(|i| edges[i].1),
                    };
                    path.push((prefix, terminal, edges, selected));
                    if selected.is_some() {
                        remaining = &remaining[1..];
                    }
                    // A terminal must be an empty-suffix leaf, never another branch.
                    if selected.is_none()
                        && let Some(reference) = next
                        && !matches!(Node::read(store, reference)?, Node::Leaf { suffix, .. } if suffix.is_empty())
                    {
                        return Err(bad("terminal must be an empty leaf"));
                    }
                }
            }
        };
        for (prefix, mut terminal, mut edges, selected) in path.into_iter().rev() {
            match selected {
                None => terminal = Some(replacement),
                Some(label) => match edges.binary_search_by_key(&label, |(b, _)| *b) {
                    Ok(i) => edges[i].1 = replacement,
                    Err(i) => edges.insert(i, (label, replacement)),
                },
            }
            replacement = Node::Branch {
                prefix,
                terminal,
                edges,
            }
            .write(store)?;
        }
        if inserted && self.len >= MAX_VISITS as u64 {
            return Err(Error::Limit("trie entries"));
        }
        self.root = Some(replacement);
        self.len += u64::from(inserted);
        Ok(())
    }
    /// A missing route is only authoritative after owning-profile verification.
    pub fn get<S: ObjectStore + ?Sized>(&self, store: &S, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if key.len() > MAX_KEY {
            return Err(Error::Limit("trie key"));
        }
        let mut remaining = key;
        let mut next = self.root;
        let mut terminal_route = false;
        for _ in 0..=MAX_KEY + 1 {
            let Some(reference) = next else {
                return Ok(None);
            };
            match Node::read(store, reference)? {
                Node::Leaf { suffix, value } => {
                    if terminal_route && !suffix.is_empty() {
                        return Err(bad("terminal suffix"));
                    }
                    return if suffix == remaining {
                        value.read(store).map(Some)
                    } else {
                        Ok(None)
                    };
                }
                Node::Branch {
                    prefix,
                    terminal,
                    edges,
                } => {
                    if terminal_route {
                        return Err(bad("terminal branch"));
                    }
                    let Some(rest) = remaining.strip_prefix(prefix.as_slice()) else {
                        return Ok(None);
                    };
                    remaining = rest;
                    terminal_route = remaining.is_empty();
                    next = if terminal_route {
                        terminal
                    } else {
                        let label = remaining[0];
                        remaining = &remaining[1..];
                        edges
                            .binary_search_by_key(&label, |(b, _)| *b)
                            .ok()
                            .map(|i| edges[i].1)
                    };
                }
            }
        }
        Err(Error::Limit("trie depth"))
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
        Self::from_profile_root(store, admit_snapshot(store, snapshot, PROFILE)?)
    }
    pub fn from_profile_root<S: ObjectStore + ?Sized>(store: &S, root: ObjectRef) -> Result<Self> {
        let object = store.get_verified_shared(root)?;
        let [len, index] = body(&object, "root")?.fields()?;
        let len = len.uint()?;
        if len > MAX_VISITS as u64 {
            return Err(Error::Limit("trie entries"));
        }
        let root = match (len, index.is_null(), object.children.as_slice()) {
            (0, true, []) => None,
            (1.., false, [reference]) if index.uint()? == 0 => Some(*reference),
            _ => return Err(bad("root count/children")),
        };
        Ok(Self { root, len })
    }
    /// Verify every route and value, including exact declared cardinality.
    /// Work and memory are explicitly bounded for this development prototype.
    pub fn verify<S: ObjectStore + ?Sized>(&self, store: &S) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        self.entries(store, false)?
            .into_iter()
            .map(|(key, value)| Ok((key, value.read(store)?)))
            .collect()
    }
    /// Authenticate the delta while retaining large values as exact shared
    /// byte-object references. Bounds include logical bytes, not only descriptors.
    pub(crate) fn verified_entries<S: ObjectStore + ?Sized>(
        &self,
        store: &S,
    ) -> Result<BTreeMap<Vec<u8>, Value>> {
        self.entries(store, true)
    }
    fn entries<S: ObjectStore + ?Sized>(
        &self,
        store: &S,
        validate_blobs: bool,
    ) -> Result<BTreeMap<Vec<u8>, Value>> {
        let mut output = BTreeMap::new();
        let mut stack: Vec<_> = self
            .root
            .map(|r| (r, Vec::new(), false))
            .into_iter()
            .collect();
        let mut visits = 0;
        let mut value_bytes = 0usize;
        let mut queued_key_bytes = 0usize;
        while let Some((reference, mut key, terminal_route)) = stack.pop() {
            queued_key_bytes -= key.len();
            visits += 1;
            if visits > MAX_VISITS {
                return Err(Error::Limit("trie verification visits"));
            }
            match Node::read(store, reference)? {
                Node::Leaf { suffix, value } => {
                    if terminal_route && !suffix.is_empty() {
                        return Err(bad("terminal suffix"));
                    }
                    key.extend(suffix);
                    if key.len() > MAX_KEY {
                        return Err(Error::Limit("trie key"));
                    }
                    if validate_blobs {
                        value.validate(store)?;
                    }
                    value_bytes = value_bytes
                        .checked_add(value.len() + key.len())
                        .ok_or(Error::Limit("trie verification bytes"))?;
                    if value_bytes > 512 * 1024 * 1024 {
                        return Err(Error::Limit("trie verification bytes"));
                    }
                    if output.insert(key, value).is_some() {
                        return Err(bad("duplicate key"));
                    }
                }
                Node::Branch {
                    prefix,
                    terminal,
                    edges,
                } => {
                    if terminal_route {
                        return Err(bad("terminal branch"));
                    }
                    key.extend(prefix);
                    if key.len() > MAX_KEY {
                        return Err(Error::Limit("trie key"));
                    }
                    if let Some(child) = terminal {
                        queued_key_bytes += key.len();
                        stack.push((child, key.clone(), true));
                    }
                    for (label, child) in edges.into_iter().rev() {
                        let mut next = key.clone();
                        next.push(label);
                        if next.len() > MAX_KEY {
                            return Err(Error::Limit("trie key"));
                        }
                        queued_key_bytes += next.len();
                        stack.push((child, next, false));
                    }
                    if queued_key_bytes > 32 * 1024 * 1024 {
                        return Err(Error::Limit("trie queued key bytes"));
                    }
                }
            }
        }
        if output.len() as u64 != self.len {
            return Err(bad("entry count"));
        }
        Ok(output)
    }
}
