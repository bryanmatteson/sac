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
    let key = item.bytes()?;
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
        3 => {
            let mut previous = None;
            for entry in body.array()? {
                let [n, k, m, v] = entry?.fields()?;
                let name = key(n)?;
                if previous.is_some_and(|p| p >= name) {
                    return Err(corrupt("directory order"));
                }
                previous = Some(name);
                let k = k.uint()?;
                metadata(m, k)?;
                match k {
                    0 => {
                        let [l, s, d] = v.fields()?;
                        let l = l.uint()?;
                        match s.uint()? {
                            0 => {
                                if d.bytes()?.len() > 48 * 1024 || d.bytes()?.len() as u64 != l {
                                    return Err(corrupt("inline file length"));
                                }
                            }
                            1 => {
                                if l == 0 {
                                    return Err(corrupt("zero-length extent file"));
                                }
                                index(d)?;
                            }
                            _ => return Err(corrupt("file storage discriminant")),
                        }
                    }
                    1 => {
                        index(v)?;
                    }
                    2 => {
                        if v.bytes()?.len() > 4096 {
                            return Err(Error::Limit("symlink target"));
                        }
                    }
                    _ => return Err(corrupt("directory type discriminant")),
                }
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
/// Check direct strong-edge roles; inherited tree geometry belongs to resources.
pub fn validate_core_edges(
    parent: &CanonicalObject,
    mut fetch: impl FnMut(super::ObjectRef) -> Result<std::sync::Arc<CanonicalObject>>,
) -> Result<()> {
    validate_core_object(parent)?;
    if !matches!(parent.kind, 1..=6) {
        return Ok(());
    }
    let body = cbor_view::view(&parent.bytes)?;
    let mut load = |i: Item<'_>, kinds: &[u16]| -> Result<std::sync::Arc<CanonicalObject>> {
        let n = usize::try_from(i.uint()?).map_err(|_| corrupt("core child index"))?;
        let r = *parent
            .children
            .get(n)
            .ok_or_else(|| corrupt("core child index"))?;
        let child = fetch(r)?;
        if child.version != 1 || !kinds.contains(&child.kind) {
            return Err(corrupt("core child role kind or schema"));
        }
        validate_core_object(&child)?;
        Ok(child)
    };
    match parent.kind {
        1 => {
            let [s, a, l] = body.fields()?;
            load(s, &[2])?;
            if !a.is_null() {
                load(a, &[9])?;
            }
            if !l.is_null() {
                load(l, &[8])?;
            }
        }
        2 => {
            let [d, p, _] = body.fields()?;
            load(d, &[3, 4])?;
            for p in p.array()? {
                let [n, v, r] = p?.fields()?;
                let child = load(r, &[8])?;
                let [cn, ct, cv, _] = cbor_view::view(&child.bytes)?.fields()?;
                if cn.text()? != n.text()? || ct.text()? != "root" || cv.uint()? != v.uint()? {
                    return Err(corrupt("profile declaration root binding mismatch"));
                }
            }
        }
        3 => {
            for entry in body.array()? {
                let [_, kind, _, v] = entry?.fields()?;
                match kind.uint()? {
                    0 => {
                        let [_, s, d] = v.fields()?;
                        if s.uint()? == 1 {
                            load(d, &[5, 6])?;
                        }
                    }
                    1 => {
                        load(v, &[3, 4])?;
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
                let child = load(r, &[if h == 1 { leaf } else { parent.kind }])?;
                if h > 1 && cbor_view::view(&child.bytes)?.fields::<2>()?[0].uint()? != h - 1 {
                    return Err(corrupt("core branch child height"));
                }
            }
        }
        5 => {
            for row in body.array()? {
                let [n, r] = row?.fields()?;
                if !r.is_null() && load(r, &[7])?.bytes.len() as u64 != n.uint()? {
                    return Err(corrupt("extent byte length"));
                }
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}
