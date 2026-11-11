//! Borrowed deterministic CBOR; no heap allocation or owned value tree.
use super::cbor::{MAX_DEPTH, MAX_ITEMS};
use super::{Error, Result, corrupt};
#[derive(Clone, Copy, Debug)]
pub struct Item<'a> {
    encoded: &'a [u8],
    head: usize,
    major: u8,
    argument: u64,
}
pub fn view(bytes: &[u8]) -> Result<Item<'_>> {
    let mut remaining = MAX_ITEMS;
    if scan(bytes, 0, &mut remaining, true)? != bytes.len() {
        return Err(corrupt("trailing CBOR items"));
    }
    admitted(bytes)
}
/// The header of a well-formed item, for navigation. `None` means that
/// `header` gives the reason; this function makes no error value.
#[inline(always)]
fn valid_header(bytes: &[u8]) -> Option<(u8, u64, usize)> {
    let first = *bytes.first()?;
    let major = first >> 5;
    let ai = first & 31;
    if major == 7 {
        return matches!(ai, 20..=22).then_some((major, u64::from(ai), 1));
    }
    if major > 5 || ai > 27 {
        return None;
    }
    if ai < 24 {
        return Some((major, u64::from(ai), 1));
    }
    let width = 1usize << (ai - 24);
    let data = bytes.get(1..1 + width)?;
    let mut n = 0u64;
    for b in data {
        n = (n << 8) | u64::from(*b);
    }
    let minimum = match width {
        1 => 24,
        2 => 256,
        4 => 65536,
        _ => 1u64 << 32,
    };
    (n >= minimum).then_some((major, n, 1 + width))
}
#[inline]
fn header(bytes: &[u8]) -> Result<(u8, u64, usize)> {
    let first = *bytes.first().ok_or_else(|| corrupt("truncated CBOR"))?;
    let major = first >> 5;
    let ai = first & 31;
    if major == 7 {
        return if matches!(ai, 20..=22) {
            Ok((major, u64::from(ai), 1))
        } else {
            Err(corrupt("unsupported CBOR simple value"))
        };
    }
    if major > 5 || ai > 27 {
        return Err(corrupt("indefinite, tagged or reserved CBOR"));
    }
    if ai < 24 {
        return Ok((major, u64::from(ai), 1));
    }
    let width = 1usize << (ai - 24);
    let data = bytes
        .get(1..1 + width)
        .ok_or_else(|| corrupt("truncated CBOR argument"))?;
    let mut n = 0u64;
    for b in data {
        n = (n << 8) | u64::from(*b);
    }
    if n < match width {
        1 => 24,
        2 => 256,
        4 => 65536,
        _ => 1u64 << 32,
    } {
        return Err(corrupt("nonminimal CBOR"));
    }
    Ok((major, n, 1 + width))
}
fn scan(bytes: &[u8], depth: usize, remaining: &mut usize, validate: bool) -> Result<usize> {
    *remaining = remaining.checked_sub(1).ok_or(Error::Limit("CBOR items"))?;
    let (major, n, head) = header(bytes)?;
    match major {
        0 | 1 | 7 => Ok(head),
        2 | 3 => {
            let end = head
                .checked_add(usize::try_from(n).map_err(|_| Error::Limit("CBOR string"))?)
                .ok_or(Error::Limit("CBOR string"))?;
            let data = bytes
                .get(head..end)
                .ok_or_else(|| corrupt("truncated CBOR string"))?;
            if validate && major == 3 {
                std::str::from_utf8(data).map_err(|_| corrupt("CBOR UTF-8"))?;
            }
            Ok(end)
        }
        4 | 5 => {
            if depth >= MAX_DEPTH {
                return Err(Error::Limit("CBOR nesting"));
            }
            let count = usize::try_from(n)
                .map_err(|_| Error::Limit("CBOR items"))?
                .checked_mul(if major == 5 { 2 } else { 1 })
                .filter(|n| *n <= *remaining)
                .ok_or(Error::Limit("CBOR items"))?;
            let mut at = head;
            let mut previous: Option<&[u8]> = None;
            for i in 0..count {
                let length = scan(
                    bytes.get(at..).ok_or_else(|| corrupt("truncated CBOR"))?,
                    depth + 1,
                    remaining,
                    validate,
                )?;
                if validate && major == 5 && i % 2 == 0 {
                    let key = &bytes[at..at + length];
                    if previous.is_some_and(|p| p >= key) {
                        return Err(corrupt("CBOR map order or duplicate key"));
                    }
                    previous = Some(key);
                }
                at += length;
            }
            Ok(at)
        }
        _ => Err(corrupt("CBOR major type")),
    }
}
/// The encoded length of the first item. This has the structure, depth and
/// item-count checks of `scan` without its text and map-order checks, and it
/// does not recurse: navigation calls it for each row of a page.
fn skip(bytes: &[u8], remaining: &mut usize) -> Result<usize> {
    // The items that remain in each open array or map. Rows nest a few
    // levels; the recursive scan takes an item that nests more.
    const INLINE_DEPTH: usize = 8;
    let limit = *remaining;
    let mut open = [0usize; INLINE_DEPTH];
    let mut depth = 0;
    let mut at = 0usize;
    loop {
        *remaining = remaining.checked_sub(1).ok_or(Error::Limit("CBOR items"))?;
        let rest = bytes.get(at..).unwrap_or_default();
        let (major, n, head) = match valid_header(rest) {
            Some(header) => header,
            None => header(rest)?,
        };
        match major {
            0 | 1 | 7 => at += head,
            2 | 3 => {
                let end = at
                    .checked_add(head)
                    .and_then(|start| start.checked_add(usize::try_from(n).ok()?))
                    .ok_or(Error::Limit("CBOR string"))?;
                if end > bytes.len() {
                    return Err(corrupt("truncated CBOR string"));
                }
                at = end;
            }
            4 | 5 => {
                if depth >= INLINE_DEPTH {
                    *remaining = limit;
                    return scan(bytes, 0, remaining, false);
                }
                let count = usize::try_from(n)
                    .map_err(|_| Error::Limit("CBOR items"))?
                    .checked_mul(if major == 5 { 2 } else { 1 })
                    .filter(|n| *n <= *remaining)
                    .ok_or(Error::Limit("CBOR items"))?;
                at += head;
                if count > 0 {
                    open[depth] = count;
                    depth += 1;
                    continue;
                }
            }
            _ => return Err(corrupt("CBOR major type")),
        }
        // One item is complete. It can complete its containers.
        loop {
            if depth == 0 {
                return Ok(at);
            }
            open[depth - 1] -= 1;
            if open[depth - 1] > 0 {
                break;
            }
            depth -= 1;
        }
    }
}
fn prefix(bytes: &[u8]) -> Result<Item<'_>> {
    let (major, argument, head) = match valid_header(bytes) {
        Some(header) => header,
        None => header(bytes)?,
    };
    // An integer, a simple value or a string ends where its header says.
    let len = match major {
        0 | 1 | 7 => head,
        2 | 3 => {
            let end = head
                .checked_add(usize::try_from(argument).map_err(|_| Error::Limit("CBOR string"))?)
                .ok_or(Error::Limit("CBOR string"))?;
            if end > bytes.len() {
                return Err(corrupt("truncated CBOR string"));
            }
            end
        }
        _ => {
            let mut remaining = MAX_ITEMS;
            skip(bytes, &mut remaining)?
        }
    };
    Ok(Item {
        encoded: &bytes[..len],
        head,
        major,
        argument,
    })
}
impl<'a> Item<'a> {
    pub fn encoded(self) -> &'a [u8] {
        self.encoded
    }
    pub fn uint(self) -> Result<u64> {
        if self.major == 0 {
            Ok(self.argument)
        } else {
            Err(corrupt("expected unsigned integer"))
        }
    }
    pub fn integer(self) -> Result<(bool, u64)> {
        if self.major <= 1 {
            Ok((self.major == 1, self.argument))
        } else {
            Err(corrupt("expected integer"))
        }
    }
    pub fn bytes(self) -> Result<&'a [u8]> {
        if self.major == 2 {
            Ok(&self.encoded[self.head..])
        } else {
            Err(corrupt("expected byte string"))
        }
    }
    pub fn text(self) -> Result<&'a str> {
        if self.major != 3 {
            return Err(corrupt("expected text"));
        }
        std::str::from_utf8(&self.encoded[self.head..]).map_err(|_| corrupt("CBOR UTF-8"))
    }
    pub fn is_null(self) -> bool {
        self.major == 7 && self.argument == 22
    }
    pub fn boolean(self) -> Result<bool> {
        match (self.major, self.argument) {
            (7, 20) => Ok(false),
            (7, 21) => Ok(true),
            _ => Err(corrupt("expected boolean")),
        }
    }
    pub fn array(self) -> Result<Items<'a>> {
        if self.major != 4 {
            return Err(corrupt("expected array"));
        }
        Ok(Items {
            bytes: &self.encoded[self.head..],
            remaining: self.argument as usize,
        })
    }
    /// The first field of an array of exactly `count` fields. The other
    /// fields are not examined.
    pub fn first_field(self, count: usize) -> Result<Item<'a>> {
        let mut iter = self.array()?;
        if iter.len() != count {
            return Err(corrupt("core array shape"));
        }
        iter.next().ok_or_else(|| corrupt("core array shape"))?
    }
    pub fn fields<const N: usize>(self) -> Result<[Item<'a>; N]> {
        let mut iter = self.array()?;
        if iter.len() != N {
            return Err(corrupt("core array shape"));
        }
        let mut fields = [self; N];
        for field in &mut fields {
            *field = iter.next().unwrap()?;
        }
        Ok(fields)
    }
    pub fn map(self) -> Result<Pairs<'a>> {
        if self.major != 5 {
            return Err(corrupt("expected map"));
        }
        Ok(Pairs(Items {
            bytes: &self.encoded[self.head..],
            remaining: self.argument as usize * 2,
        }))
    }
}
pub struct Items<'a> {
    bytes: &'a [u8],
    remaining: usize,
}
impl<'a> Iterator for Items<'a> {
    type Item = Result<Item<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        match prefix(self.bytes) {
            Ok(item) => {
                self.bytes = &self.bytes[item.encoded.len()..];
                Some(Ok(item))
            }
            Err(error) => {
                self.remaining = 0;
                Some(Err(error))
            }
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}
impl ExactSizeIterator for Items<'_> {}
pub struct Pairs<'a>(Items<'a>);
impl<'a> Iterator for Pairs<'a> {
    type Item = Result<(Item<'a>, Item<'a>)>;
    fn next(&mut self) -> Option<Self::Item> {
        let key = self.0.next()?;
        Some(key.and_then(|key| Ok((key, self.0.next().ok_or_else(|| corrupt("map value"))??))))
    }
}

pub(crate) fn admitted(bytes: &[u8]) -> Result<Item<'_>> {
    let (major, argument, head) = header(bytes)?;
    Ok(Item {
        encoded: bytes,
        head,
        major,
        argument,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::cbor::{self, Value};

    // A small deterministic generator: nested arrays and maps, strings of
    // several header widths, integers and simple values.
    fn value(seed: &mut u64, depth: usize) -> Value {
        *seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let choice = (*seed >> 33) % if depth < 5 { 8 } else { 5 };
        let size = ((*seed >> 20) % 300) as usize;
        match choice {
            0 => Value::Uint(*seed >> 40),
            1 => Value::NInt(*seed >> 50),
            2 => Value::Bytes(vec![7; size]),
            3 => Value::Text("x".repeat(size % 40)),
            4 => Value::Null,
            5 => Value::Array((0..size % 5).map(|_| value(seed, depth + 1)).collect()),
            6 => Value::Array(Vec::new()),
            _ => cbor::text_map(
                [
                    ("alpha", value(seed, depth + 1)),
                    ("beta", value(seed, depth + 1)),
                ]
                .into_iter()
                .take(size % 3)
                .collect(),
            ),
        }
    }
    #[test]
    fn flat_skip_agrees_with_the_recursive_scan() {
        let mut seed = 1;
        for _ in 0..2000 {
            let encoded = cbor::encode(&value(&mut seed, 0));
            // The complete item, each truncation of it, and trailing bytes.
            let mut inputs: Vec<Vec<u8>> = (0..=encoded.len().min(48))
                .map(|cut| encoded[..encoded.len() - cut].to_vec())
                .collect();
            inputs.push([&encoded[..], &[0xff, 0x00]].concat());
            for input in inputs {
                for limit in [MAX_ITEMS, 3] {
                    let (mut left, mut right) = (limit, limit);
                    let expected = scan(&input, 0, &mut left, false);
                    let actual = skip(&input, &mut right);
                    assert_eq!(format!("{expected:?}"), format!("{actual:?}"));
                    if expected.is_ok() {
                        assert_eq!(left, right);
                    }
                }
            }
        }
        // Nesting to the limit, and one level more.
        for levels in [MAX_DEPTH, MAX_DEPTH + 1] {
            let mut input = vec![0x81; levels];
            input.push(0x00);
            let (mut left, mut right) = (MAX_ITEMS, MAX_ITEMS);
            assert_eq!(
                format!("{:?}", scan(&input, 0, &mut left, false)),
                format!("{:?}", skip(&input, &mut right))
            );
        }
    }
}
