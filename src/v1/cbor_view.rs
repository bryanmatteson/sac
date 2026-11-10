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
fn prefix(bytes: &[u8]) -> Result<Item<'_>> {
    let (major, argument, head) = header(bytes)?;
    let mut remaining = MAX_ITEMS;
    let len = scan(bytes, 0, &mut remaining, false)?;
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
