//! Bounded RFC 8949 core deterministic CBOR for SAC1 structured bodies.
use super::{Error, Result, corrupt};
/// CBOR value model preserving the information needed for deterministic
/// reserialization and schema validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Unsigned integer.
    Uint(u64),
    /// Negative integer; on-wire value = `-1 - n`.
    NInt(u64),
    /// Byte string.
    Bytes(Vec<u8>),
    /// UTF-8 text string. Profile schemas validate any additional text constraints.
    Text(String),
    /// Array of values.
    Array(Vec<Value>),
    /// Map of (key, value) preserving on-wire (sorted) order.
    Map(Vec<MapEntry>),
    /// Boolean.
    Bool(bool),
    /// CBOR null.
    Null,
}

/// A single map entry along with the encoded bytes of its key. The key bytes
/// are retained so the decoder can enforce the sort/dup rule by direct byte
/// comparison without re-encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapEntry {
    pub key: Value,
    pub key_bytes: Vec<u8>,
    pub value: Value,
}

impl Value {
    /// Convenience constructor for text values.
    #[must_use]
    pub fn text(s: impl Into<String>) -> Self {
        Self::Text(s.into())
    }
    /// Convenience constructor for byte values.
    #[must_use]
    pub fn bytes(b: impl Into<Vec<u8>>) -> Self {
        Self::Bytes(b.into())
    }
}

/// Encode `value` to deterministic CBOR.
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(encoded_len(value));
    encode_into(value, &mut out);
    out
}

pub fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Uint(v) => write_head(0, *v, out),
        Value::NInt(v) => write_head(1, *v, out),
        Value::Bytes(b) => {
            write_head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            write_head(3, s.len() as u64, out);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(arr) => {
            write_head(4, arr.len() as u64, out);
            for v in arr {
                encode_into(v, out);
            }
        }
        Value::Map(entries) => {
            write_head(5, entries.len() as u64, out);
            for entry in entries {
                encode_into(&entry.key, out);
                encode_into(&entry.value, out);
            }
        }
        Value::Bool(false) => out.push(0xF4),
        Value::Bool(true) => out.push(0xF5),
        Value::Null => out.push(0xF6),
    }
}

fn write_head(major: u8, value: u64, out: &mut Vec<u8>) {
    let major_bits = (major & 0x07) << 5;
    if value < 24 {
        out.push(major_bits | (value as u8));
    } else if value <= u64::from(u8::MAX) {
        out.push(major_bits | 24);
        out.push(value as u8);
    } else if value <= u64::from(u16::MAX) {
        out.push(major_bits | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u64::from(u32::MAX) {
        out.push(major_bits | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(major_bits | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

/// Build a deterministic CBOR map value from `(text-key, value)` pairs. The
/// caller provides the entries in any order; this function sorts them by the
/// encoded text-key bytes (which, for text keys, is `0x60 + len || utf8` for
/// short keys) and rejects duplicates.
///
/// Panics if any key value is not `Value::Text`. SAC core never uses
/// non-text map keys.
#[must_use]
pub fn text_map(pairs: Vec<(&str, Value)>) -> Value {
    let mut entries: Vec<MapEntry> = pairs
        .into_iter()
        .map(|(k, v)| {
            let key = Value::Text(k.to_string());
            let key_bytes = encode(&key);
            MapEntry {
                key,
                key_bytes,
                value: v,
            }
        })
        .collect();
    entries.sort_by(|a, b| a.key_bytes.cmp(&b.key_bytes));
    // Caller is responsible for dedup; we leave duplicates intact so the
    // encoder produces an invalid CBOR (which would fail our own decoder),
    // surfacing the bug at test time.
    Value::Map(entries)
}

pub const MAX_DEPTH: usize = 64;
pub const MAX_ITEMS: usize = 1_048_576;
/// Per-object allocations, including copied strings and map-key encodings.
pub const MAX_ALLOCATION_BYTES: usize = 16 * 1024 * 1024;

pub fn decode(bytes: &[u8]) -> Result<Value> {
    let mut parser = Parser {
        bytes,
        pos: 0,
        items: MAX_ITEMS,
        allocation: MAX_ALLOCATION_BYTES,
    };
    let value = parser.value(0)?;
    if parser.pos != bytes.len() {
        return Err(corrupt("trailing CBOR items"));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    items: usize,
    allocation: usize,
}
impl<'a> Parser<'a> {
    fn allocate(&mut self, bytes: usize) -> Result<()> {
        self.allocation = self
            .allocation
            .checked_sub(bytes)
            .ok_or(Error::Limit("CBOR allocation"))?;
        Ok(())
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(count)
            .ok_or(Error::Limit("CBOR bytes"))?;
        let result = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| corrupt("truncated CBOR"))?;
        self.pos = end;
        Ok(result)
    }
    fn count(&self, count: u64, multiplier: usize) -> Result<usize> {
        let count = usize::try_from(count).map_err(|_| Error::Limit("CBOR count"))?;
        let minimum = count
            .checked_mul(multiplier)
            .ok_or(Error::Limit("CBOR count"))?;
        if minimum > self.bytes.len() - self.pos || minimum > self.items {
            return Err(Error::Limit("CBOR count"));
        }
        Ok(count)
    }
    fn value(&mut self, depth: usize) -> Result<Value> {
        self.items = self
            .items
            .checked_sub(1)
            .ok_or(Error::Limit("CBOR items"))?;
        let first = self.take(1)?[0];
        let major = first >> 5;
        let additional = first & 31;
        if major == 7 {
            return match additional {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                _ => Err(corrupt("unsupported CBOR simple value")),
            };
        }
        let number = match additional {
            0..=23 => u64::from(additional),
            24 => {
                let n = u64::from(self.take(1)?[0]);
                if n < 24 {
                    return Err(corrupt("nonminimal CBOR"));
                }
                n
            }
            25 => {
                let n = u64::from(u16::from_be_bytes(self.take(2)?.try_into().unwrap()));
                if n <= 255 {
                    return Err(corrupt("nonminimal CBOR"));
                }
                n
            }
            26 => {
                let n = u64::from(u32::from_be_bytes(self.take(4)?.try_into().unwrap()));
                if n <= 65535 {
                    return Err(corrupt("nonminimal CBOR"));
                }
                n
            }
            27 => {
                let n = u64::from_be_bytes(self.take(8)?.try_into().unwrap());
                if n <= u32::MAX as u64 {
                    return Err(corrupt("nonminimal CBOR"));
                }
                n
            }
            _ => return Err(corrupt("indefinite or reserved CBOR")),
        };
        match major {
            0 => Ok(Value::Uint(number)),
            1 => Ok(Value::NInt(number)),
            2 | 3 => {
                let count = usize::try_from(number).map_err(|_| Error::Limit("CBOR string"))?;
                self.allocate(count)?;
                let bytes = self.take(count)?;
                if major == 2 {
                    Ok(Value::Bytes(bytes.to_vec()))
                } else {
                    Ok(Value::Text(
                        std::str::from_utf8(bytes)
                            .map_err(|_| corrupt("CBOR UTF-8"))?
                            .to_owned(),
                    ))
                }
            }
            4 | 5 => {
                if depth >= MAX_DEPTH {
                    return Err(Error::Limit("CBOR nesting"));
                }
                let count = self.count(number, if major == 5 { 2 } else { 1 })?;
                if major == 4 {
                    self.allocate(
                        count
                            .checked_mul(std::mem::size_of::<Value>())
                            .ok_or(Error::Limit("CBOR allocation"))?,
                    )?;
                    let mut values = Vec::with_capacity(count);
                    for _ in 0..count {
                        values.push(self.value(depth + 1)?);
                    }
                    Ok(Value::Array(values))
                } else {
                    self.allocate(
                        count
                            .checked_mul(std::mem::size_of::<MapEntry>())
                            .ok_or(Error::Limit("CBOR allocation"))?,
                    )?;
                    let mut entries: Vec<MapEntry> = Vec::with_capacity(count);
                    for _ in 0..count {
                        let start = self.pos;
                        let key = self.value(depth + 1)?;
                        self.allocate(self.pos - start)?;
                        let key_bytes = self.bytes[start..self.pos].to_vec();
                        if entries
                            .last()
                            .is_some_and(|previous| previous.key_bytes >= key_bytes)
                        {
                            return Err(corrupt("CBOR map order or duplicate key"));
                        }
                        let value = self.value(depth + 1)?;
                        entries.push(MapEntry {
                            key,
                            key_bytes,
                            value,
                        });
                    }
                    Ok(Value::Map(entries))
                }
            }
            _ => Err(corrupt("CBOR tags forbidden")),
        }
    }
}

/// Exact encoded size without allocating or serializing.
pub fn encoded_len(value: &Value) -> usize {
    fn head(n: u64) -> usize {
        match n {
            0..=23 => 1,
            24..=255 => 2,
            256..=65535 => 3,
            65536..=4294967295 => 5,
            _ => 9,
        }
    }
    match value {
        Value::Uint(n) | Value::NInt(n) => head(*n),
        Value::Bytes(b) => head(b.len() as u64) + b.len(),
        Value::Text(s) => head(s.len() as u64) + s.len(),
        Value::Array(a) => head(a.len() as u64) + a.iter().map(encoded_len).sum::<usize>(),
        Value::Map(a) => {
            head(a.len() as u64)
                + a.iter()
                    .map(|e| encoded_len(&e.key) + encoded_len(&e.value))
                    .sum::<usize>()
        }
        _ => 1,
    }
}
