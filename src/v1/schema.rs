//! Intrinsic and direct-edge validation over borrowed canonical bytes.
use super::{
    CanonicalObject, Error, Result,
    cbor::Value,
    cbor_view::{self, Item},
    corrupt,
};
pub(crate) fn array(value: &Value, length: usize) -> Result<&[Value]> {
    match value {
        Value::Array(values) if values.len() == length => Ok(values),
        _ => Err(corrupt("core array shape")),
    }
}
pub(crate) fn uint(value: &Value) -> Result<u64> {
    match value {
        Value::Uint(n) => Ok(*n),
        _ => Err(corrupt("expected unsigned integer")),
    }
}
pub fn valid_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let mut separator = false;
    let mut component = false;
    for byte in bytes {
        if matches!(*byte, b'.' | b'_' | b'-') {
            if !component {
                return false;
            }
            separator = true;
            component = false;
        } else if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            component = true;
        } else {
            return false;
        }
    }
    separator && component
}

fn id(item: Item<'_>) -> Result<&str> {
    let text = item.text()?;
    if !valid_id(text) {
        return Err(corrupt("namespaced ID"));
    }
    Ok(text)
}
fn version(item: Item<'_>) -> Result<u64> {
    let n = item.uint()?;
    if n == 0 || n > u32::MAX as u64 {
        return Err(corrupt("version range"));
    }
    Ok(n)
}
fn key(item: Item<'_>) -> Result<&[u8]> {
    key_bytes(item.bytes()?)
}
fn key_bytes(key: &[u8]) -> Result<&[u8]> {
    if key.is_empty()
        || key.len() > 4096
        || matches!(key, b"." | b"..")
        || key.iter().any(|b| matches!(*b, 0 | b'/'))
    {
        return Err(corrupt("directory key"));
    }
    Ok(key)
}
fn metadata(item: Item<'_>, kind: u64) -> Result<()> {
    if item.encoded().len() > 16384 {
        return Err(Error::Limit("metadata"));
    }
    for pair in item.map()? {
        let (k, v) = pair?;
        match k.text()? {
            "mode" => {
                if v.uint()? > 0o7777 {
                    return Err(corrupt("mode range"));
                }
            }
            "mtime" => {
                let [s, n] = v.fields()?;
                if s.integer()?.1 > i64::MAX as u64 || n.uint()? > 999999999 {
                    return Err(corrupt("mtime range"));
                }
            }
            "media_type" => {
                if v.text()?.len() > 4096 {
                    return Err(Error::Limit("media type"));
                }
            }
            "byte_digest" => {
                if kind != 0 || v.bytes()?.len() != 32 {
                    return Err(corrupt("file byte digest"));
                }
            }
            name => {
                if !valid_id(name) {
                    return Err(corrupt("unknown unnamespaced metadata"));
                }
            }
        }
    }
    Ok(())
}
pub fn validate_core_object(object: &CanonicalObject) -> Result<()> {
    validate_core_shape(
        object.kind,
        object.version,
        &object.bytes,
        object.children.len(),
    )
}
pub(crate) fn validate_core_shape(
    kind: u16,
    version_number: u16,
    bytes: &[u8],
    child_count: usize,
) -> Result<()> {
    let canonical_len = child_count
        .checked_mul(32)
        .and_then(|n| n.checked_add(8))
        .and_then(|n| n.checked_add(bytes.len()))
        .ok_or(Error::Limit("canonical object"))?;
    if child_count > super::MAX_CHILDREN || canonical_len > super::MAX_CHUNK_SIZE {
        return Err(Error::Limit("canonical object"));
    }
    if !(1..=9).contains(&kind) {
        return Ok(());
    }
    if version_number != 1 {
        return Err(Error::Unsupported(format!(
            "core kind {} schema {}",
            kind, version_number
        )));
    }
    let cap = match kind {
        1 | 2 => 16384,
        3 => 128 * 1024,
        4..=6 | 9 => 65536,
        _ => super::MAX_CHUNK_SIZE,
    };
    if canonical_len > cap {
        return Err(Error::Limit("core canonical bytes"));
    }
    if kind == 7 {
        return if child_count == 0 {
            Ok(())
        } else {
            Err(corrupt("byte object children"))
        };
    }
    if kind == 3 {
        return validate_directory_leaf(bytes, child_count);
    }
    let body = cbor_view::view(bytes)?;
    let mut used = [false; super::MAX_CHILDREN];
    let mut index = |item: Item<'_>| -> Result<usize> {
        let n = usize::try_from(item.uint()?).map_err(|_| corrupt("child index"))?;
        if n >= child_count {
            return Err(corrupt("child index out of bounds"));
        }
        used[n] = true;
        Ok(n)
    };
    match kind {
        1 => {
            let [s, a, l] = body.fields()?;
            index(s)?;
            if !a.is_null() {
                index(a)?;
            }
            if !l.is_null() {
                index(l)?;
            }
        }
        2 => {
            let [d, profiles, features] = body.fields()?;
            index(d)?;
            let mut previous = None;
            for profile in profiles.array()? {
                let [n, v, r] = profile?.fields()?;
                let name = id(n)?;
                if previous.is_some_and(|p| p >= name) {
                    return Err(corrupt("profile order"));
                }
                previous = Some(name);
                version(v)?;
                index(r)?;
            }
            let mut previous = None;
            for feature in features.array()? {
                let [s, n, v, r] = feature?.fields()?;
                if !s.is_null() {
                    let name = id(s)?;
                    let mut found = false;
                    for profile in profiles.array()? {
                        if profile?.fields::<3>()?[0].text()? == name {
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        return Err(corrupt("feature profile scope"));
                    }
                }
                id(n)?;
                version(v)?;
                r.boolean()?;
                let key = (s.encoded(), n.encoded());
                if previous.is_some_and(|p| p >= key) {
                    return Err(corrupt("feature order or duplicate"));
                }
                previous = Some(key);
            }
        }
        4 | 6 => {
            let [h, rows] = body.fields()?;
            if !(1..=16).contains(&h.uint()?) || rows.array()?.len() < 2 {
                return Err(corrupt("branch shape"));
            }
            let mut prior_key = None;
            let mut prior_end = 0;
            for row in rows.array()? {
                let [k, r] = row?.fields()?;
                if kind == 4 {
                    let k = key(k)?;
                    if prior_key.is_some_and(|p| p >= k) {
                        return Err(corrupt("fence order"));
                    }
                    prior_key = Some(k);
                } else {
                    let n = k.uint()?;
                    if n <= prior_end {
                        return Err(corrupt("extent end order"));
                    }
                    prior_end = n;
                }
                index(r)?;
            }
        }
        5 => {
            if body.array()?.len() == 0 {
                return Err(corrupt("empty extent leaf"));
            }
            let mut length = 0u64;
            for row in body.array()? {
                let [n, r] = row?.fields()?;
                let n = n.uint()?;
                if n == 0 {
                    return Err(corrupt("empty extent"));
                }
                length = length.checked_add(n).ok_or(Error::Limit("extent length"))?;
                if !r.is_null() {
                    index(r)?;
                }
            }
        }
        8 => {
            let [n, t, v, p] = body.fields()?;
            id(n)?;
            let t = t.text()?;
            let mut chars = t.bytes();
            if t.len() > 128
                || !chars.next().is_some_and(|b| b.is_ascii_lowercase())
                || !chars.all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-')
                })
            {
                return Err(corrupt("profile type"));
            }
            version(v)?;
            p.bytes()?;
            return Ok(());
        }
        9 => {
            if body.array()?.len() > 256 {
                return Err(Error::Limit("attestations"));
            }
            for entry in body.array()? {
                if entry?.bytes()?.len() > 1024 {
                    return Err(Error::Limit("signature bytes"));
                }
            }
        }
        _ => unreachable!(),
    }
    if used[..child_count].iter().any(|used| !*used) {
        return Err(corrupt("unused canonical child index"));
    }
    Ok(())
}
// Consume each directory field once instead of validating the whole CBOR tree,
// rediscovering every row boundary and walking its nested fields again. This is
// still intrinsic admission, including canonical CBOR and all child-index uses.
fn validate_directory_leaf(bytes: &[u8], child_count: usize) -> Result<()> {
    let mut cursor = cbor_view::CheckedCursor::new(bytes);
    let mut used = [false; super::MAX_CHILDREN];
    let mut index = |value: u64| -> Result<()> {
        let n = usize::try_from(value).map_err(|_| corrupt("child index"))?;
        let slot = used
            .get_mut(..child_count)
            .and_then(|used| used.get_mut(n))
            .ok_or_else(|| corrupt("child index out of bounds"))?;
        *slot = true;
        Ok(())
    };
    let mut previous = None;
    for _ in 0..cursor.array(0)? {
        if cursor.array(1)? != 4 {
            return Err(corrupt("core array shape"));
        }
        let name = key_bytes(cursor.bytes()?)?;
        if previous.is_some_and(|prior| prior >= name) {
            return Err(corrupt("directory order"));
        }
        previous = Some(name);
        let kind = cursor.uint()?;
        let attributes = cursor.item(2)?;
        if attributes.encoded() != [0xa0] {
            metadata(attributes, kind)?;
        }
        match kind {
            0 => {
                if cursor.array(2)? != 3 {
                    return Err(corrupt("core array shape"));
                }
                let length = cursor.uint()?;
                let storage = cursor.uint()?;
                match storage {
                    0 => {
                        let bytes = cursor.bytes()?;
                        if bytes.len() > 48 * 1024 || bytes.len() as u64 != length {
                            return Err(corrupt("inline file length"));
                        }
                    }
                    1 => {
                        if length == 0 {
                            return Err(corrupt("zero-length extent file"));
                        }
                        index(cursor.uint()?)?;
                    }
                    _ => return Err(corrupt("file storage discriminant")),
                }
            }
            1 => index(cursor.uint()?)?,
            2 => {
                if cursor.bytes()?.len() > 4096 {
                    return Err(Error::Limit("symlink target"));
                }
            }
            _ => return Err(corrupt("directory type discriminant")),
        }
    }
    cursor.finish()?;
    if used[..child_count].iter().any(|used| !*used) {
        return Err(corrupt("unused canonical child index"));
    }
    Ok(())
}

/// Check direct strong-edge roles; inherited tree geometry belongs to resources.
pub fn validate_core_edges(
    parent: &CanonicalObject,
    mut fetch: impl FnMut(super::ObjectRef) -> Result<std::sync::Arc<CanonicalObject>>,
) -> Result<()> {
    validate_core_edges_impl::<true>(parent.into(), |reference, check| {
        let child = fetch(reference)?;
        check(CoreShape {
            kind: child.kind,
            version: child.version,
            bytes: &child.bytes,
            child_count: child.children.len(),
        })
    })
}

/// Borrow a fetched child's authenticated canonical parts only while its role
/// is checked. Physical validators can reuse their decoder without allocating
/// an owned body, child vector and Arc for every edge.
pub(crate) struct CoreShape<'a> {
    pub kind: u16,
    pub version: u16,
    pub bytes: &'a [u8],
    pub child_count: usize,
}

pub(crate) fn validate_core_edges_with(
    parent: super::ObjectView<'_>,
    fetch: impl FnMut(super::ObjectRef, &mut dyn FnMut(CoreShape<'_>) -> Result<()>) -> Result<()>,
) -> Result<()> {
    // Both the parent and fetched child parts must already have passed intrinsic
    // validation, as required by ObjectStore::visit_verified and FrameDecoder.
    validate_core_edges_impl::<false>(parent, fetch)
}

fn validate_core_edges_impl<const VALIDATE_SHAPES: bool>(
    parent: super::ObjectView<'_>,
    mut fetch: impl FnMut(super::ObjectRef, &mut dyn FnMut(CoreShape<'_>) -> Result<()>) -> Result<()>,
) -> Result<()> {
    if VALIDATE_SHAPES {
        parent.validate()?;
    }
    visit_core_roles(parent, |index, role| {
        fetch(parent.children[index], &mut |child| {
            role.check::<VALIDATE_SHAPES>(child)
        })
    })
}

/// Direct constraints supplied by an intrinsically admitted parent. Keeping
/// them separate from fetching lets physical validation check a child during
/// its ordinary graph visit instead of decoding it once for each role edge.
#[derive(Clone, Copy)]
pub(crate) enum CoreRole<'a> {
    Kinds(u16, u16),
    Profile { namespace: &'a str, version: u64 },
    Branch { kind: u16, height: u64 },
    Bytes(u64),
}
impl CoreRole<'_> {
    pub(crate) fn check<const VALIDATE_SHAPES: bool>(self, child: CoreShape<'_>) -> Result<()> {
        let (first, second) = match self {
            Self::Kinds(first, second) => (first, second),
            Self::Profile { .. } => (8, 8),
            Self::Branch { kind, .. } => (kind, kind),
            Self::Bytes(_) => (7, 7),
        };
        if child.version != 1 || (child.kind != first && child.kind != second) {
            return Err(corrupt("core child role kind or schema"));
        }
        if VALIDATE_SHAPES {
            validate_core_shape(child.kind, child.version, child.bytes, child.child_count)?;
        }
        match self {
            Self::Kinds(..) => {}
            Self::Profile { namespace, version } => {
                let [n, t, v, _] = cbor_view::admitted(child.bytes)?.fields()?;
                if n.text()? != namespace || t.text()? != "root" || v.uint()? != version {
                    return Err(corrupt("profile declaration root binding mismatch"));
                }
            }
            Self::Branch { height, .. } => {
                if cbor_view::admitted(child.bytes)?.fields::<2>()?[0].uint()? != height {
                    return Err(corrupt("core branch child height"));
                }
            }
            Self::Bytes(length) => {
                if child.bytes.len() as u64 != length {
                    return Err(corrupt("extent byte length"));
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn visit_core_roles(
    parent: super::ObjectView<'_>,
    mut visit: impl FnMut(usize, CoreRole<'_>) -> Result<()>,
) -> Result<()> {
    if !matches!(parent.kind, 1..=6) {
        return Ok(());
    }
    let body = cbor_view::admitted(parent.bytes)?;
    let mut load = |i: Item<'_>, role| -> Result<()> {
        let n = usize::try_from(i.uint()?).map_err(|_| corrupt("core child index"))?;
        if n >= parent.children.len() {
            return Err(corrupt("core child index"));
        }
        visit(n, role)
    };
    match parent.kind {
        1 => {
            let [s, a, l] = body.fields()?;
            load(s, CoreRole::Kinds(2, 2))?;
            if !a.is_null() {
                load(a, CoreRole::Kinds(9, 9))?;
            }
            if !l.is_null() {
                load(l, CoreRole::Kinds(8, 8))?;
            }
        }
        2 => {
            let [d, p, _] = body.fields()?;
            load(d, CoreRole::Kinds(3, 4))?;
            for p in p.array()? {
                let [n, v, r] = p?.fields()?;
                load(
                    r,
                    CoreRole::Profile {
                        namespace: n.text()?,
                        version: v.uint()?,
                    },
                )?;
            }
        }
        3 => {
            for entry in body.array()? {
                let [_, kind, _, v] = entry?.fields()?;
                match kind.uint()? {
                    0 => {
                        let [_, s, d] = v.fields()?;
                        if s.uint()? == 1 {
                            load(d, CoreRole::Kinds(5, 6))?;
                        }
                    }
                    1 => {
                        load(v, CoreRole::Kinds(3, 4))?;
                    }
                    _ => {}
                }
            }
        }
        4 | 6 => {
            let [h, rows] = body.fields()?;
            let h = h.uint()?;
            let leaf = if parent.kind == 4 { 3 } else { 5 };
            for row in rows.array()? {
                let [_, r] = row?.fields()?;
                load(
                    r,
                    if h == 1 {
                        CoreRole::Kinds(leaf, leaf)
                    } else {
                        CoreRole::Branch {
                            kind: parent.kind,
                            height: h - 1,
                        }
                    },
                )?;
            }
        }
        5 => {
            for row in body.array()? {
                let [n, r] = row?.fields()?;
                if !r.is_null() {
                    load(r, CoreRole::Bytes(n.uint()?))?;
                }
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

#[cfg(test)]
mod directory_tests {
    use super::*;
    use crate::v1::cbor::{self, Value as V};

    // The preceding whole-value admission path is an independent boundary
    // oracle for the streaming cursor: full CBOR validation, then row views.
    fn full_scan(bytes: &[u8], child_count: usize) -> Result<()> {
        if child_count > super::super::MAX_CHILDREN
            || 8 + 32 * child_count + bytes.len() > 128 * 1024
        {
            return Err(Error::Limit("core canonical bytes"));
        }
        let body = cbor_view::view(bytes)?;
        let mut used = [false; super::super::MAX_CHILDREN];
        let mut index = |item: Item<'_>| -> Result<()> {
            let n = usize::try_from(item.uint()?).map_err(|_| corrupt("child index"))?;
            if n >= child_count {
                return Err(corrupt("child index out of bounds"));
            }
            used[n] = true;
            Ok(())
        };
        let mut previous = None;
        for row in body.array()? {
            let [n, k, m, v] = row?.fields()?;
            let name = key(n)?;
            if previous.is_some_and(|prior| prior >= name) {
                return Err(corrupt("directory order"));
            }
            previous = Some(name);
            let kind = k.uint()?;
            metadata(m, kind)?;
            match kind {
                0 => {
                    let [l, s, d] = v.fields()?;
                    let length = l.uint()?;
                    match s.uint()? {
                        0 => {
                            if d.bytes()?.len() > 48 * 1024 || d.bytes()?.len() as u64 != length {
                                return Err(corrupt("inline file length"));
                            }
                        }
                        1 => {
                            if length == 0 {
                                return Err(corrupt("zero-length extent file"));
                            }
                            index(d)?;
                        }
                        _ => return Err(corrupt("file storage discriminant")),
                    }
                }
                1 => index(v)?,
                2 => {
                    if v.bytes()?.len() > 4096 {
                        return Err(Error::Limit("symlink target"));
                    }
                }
                _ => return Err(corrupt("directory type discriminant")),
            }
        }
        if used[..child_count].iter().any(|used| !*used) {
            return Err(corrupt("unused canonical child index"));
        }
        Ok(())
    }
    fn compare(bytes: &[u8], child_count: usize) {
        assert_eq!(
            validate_core_shape(3, 1, bytes, child_count).is_ok(),
            full_scan(bytes, child_count).is_ok(),
            "child_count={child_count} bytes={bytes:02x?}"
        );
    }
    fn row(name: Vec<u8>, kind: u64, metadata: V, value: V) -> V {
        V::Array(vec![V::Bytes(name), V::Uint(kind), metadata, value])
    }
    #[test]
    fn streaming_directory_admission_matches_full_scan_for_mutated_pages() {
        for count in [0, 1, 23, 24, 25, 128] {
            for variant in 0..3 {
                let entries = (0..count)
                    .map(|index| {
                        let metadata = cbor::text_map(vec![(
                            "org.example.data",
                            V::Array(vec![V::text("é"), V::Uint(index as u64)]),
                        )]);
                        let value = match variant {
                            0 => V::Array(vec![
                                V::Uint(8),
                                V::Uint(0),
                                V::Bytes((index as u64).to_le_bytes().to_vec()),
                            ]),
                            1 => V::Uint(index as u64),
                            _ => V::Bytes(b"target".to_vec()),
                        };
                        row(
                            format!("k{index:04}").into_bytes(),
                            variant,
                            metadata,
                            value,
                        )
                    })
                    .collect();
                let bytes = cbor::encode(&V::Array(entries));
                let children = if variant == 1 { count } else { 0 };
                assert!(full_scan(&bytes, children).is_ok());
                compare(&bytes, children);
                for at in (0..bytes.len()).step_by((bytes.len() / 128).max(1)) {
                    for byte in [0, 0x18, 0x1f, 0x61, 0x80, 0x84, 0xa2, 0xff] {
                        let mut changed = bytes.clone();
                        changed[at] = byte;
                        compare(&changed, children);
                    }
                    compare(&bytes[..at], children);
                }
                let mut trailing = bytes.clone();
                trailing.push(0);
                compare(&trailing, children);
                for children in [0, 1, 2, 1024, 1025] {
                    compare(&bytes, children);
                }
            }
        }
    }
    #[test]
    fn streaming_directory_admission_keeps_nested_metadata_limits_and_child_uses() {
        for depth in 0..=66 {
            let mut nested = V::Null;
            for _ in 0..depth {
                nested = V::Array(vec![nested]);
            }
            let metadata = cbor::text_map(vec![("org.example.data", nested)]);
            let bytes = cbor::encode(&V::Array(vec![row(
                b"a".to_vec(),
                0,
                metadata,
                V::Array(vec![V::Uint(0), V::Uint(0), V::Bytes(Vec::new())]),
            )]));
            compare(&bytes, 0);
        }
        let bytes = cbor::encode(&V::Array(vec![
            row(
                b"a".to_vec(),
                0,
                V::Map(Vec::new()),
                V::Array(vec![V::Uint(9), V::Uint(1), V::Uint(0)]),
            ),
            row(b"b".to_vec(), 1, V::Map(Vec::new()), V::Uint(1)),
            row(
                b"c".to_vec(),
                2,
                V::Map(Vec::new()),
                V::Bytes(b"target".to_vec()),
            ),
        ]));
        for children in 0..4 {
            compare(&bytes, children);
        }
        assert!(validate_core_shape(3, 1, &bytes, 2).is_ok());
    }
}
