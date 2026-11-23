//! RFC 8949 core deterministic CBOR for SAC1 structured bodies and profiles.
//!
//! Decoding is bounded by its input: every item occupies at least one encoded
//! byte, and a declared count or length is checked against the bytes that
//! remain, so no fixed item or allocation cap refuses a large well-formed
//! value. Nesting is limited to [`MAX_DEPTH`] for stack safety.
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

impl MapEntry {
    /// An entry whose key bytes are the key's deterministic encoding.
    #[must_use]
    pub fn new(key: Value, value: Value) -> Self {
        let key_bytes = encode(&key);
        Self {
            key,
            key_bytes,
            value,
        }
    }
    /// An entry with a text key.
    #[must_use]
    pub fn text(key: &str, value: Value) -> Self {
        Self::new(Value::text(key), value)
    }
    fn has_text_key(&self, key: &str) -> bool {
        matches!(&self.key, Value::Text(text) if text == key)
    }
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
    /// An array of `values`.
    #[must_use]
    pub fn array(values: impl IntoIterator<Item = Value>) -> Self {
        Self::Array(values.into_iter().collect())
    }
    /// A text-keyed map in deterministic key order. A repeated key is
    /// rejected when the map is written with [`Value::encode`].
    #[must_use]
    pub fn map<'a>(pairs: impl IntoIterator<Item = (&'a str, Value)>) -> Self {
        text_map(pairs.into_iter().collect())
    }
    /// A map of arbitrary keys in deterministic key order. A repeated key is
    /// rejected when the map is written with [`Value::encode`].
    #[must_use]
    pub fn map_of(pairs: impl IntoIterator<Item = (Value, Value)>) -> Self {
        let mut entries: Vec<MapEntry> = pairs
            .into_iter()
            .map(|(key, value)| MapEntry::new(key, value))
            .collect();
        entries.sort_by(|a, b| a.key_bytes.cmp(&b.key_bytes));
        Self::Map(entries)
    }
    pub fn as_array(&self) -> Result<&[Value]> {
        match self {
            Self::Array(values) => Ok(values),
            _ => Err(corrupt("expected CBOR array")),
        }
    }
    pub fn as_map(&self) -> Result<&[MapEntry]> {
        match self {
            Self::Map(entries) => Ok(entries),
            _ => Err(corrupt("expected CBOR map")),
        }
    }
    pub fn as_bytes(&self) -> Result<&[u8]> {
        match self {
            Self::Bytes(bytes) => Ok(bytes),
            _ => Err(corrupt("expected CBOR bytes")),
        }
    }
    pub fn as_text(&self) -> Result<&str> {
        match self {
            Self::Text(text) => Ok(text),
            _ => Err(corrupt("expected CBOR text")),
        }
    }
    pub fn as_uint(&self) -> Result<u64> {
        match self {
            Self::Uint(value) => Ok(*value),
            _ => Err(corrupt("expected CBOR unsigned integer")),
        }
    }
    /// The value of text key `key` in this map.
    pub fn field(&self, key: &str) -> Result<&Value> {
        match self {
            Self::Map(entries) => entries
                .iter()
                .find(|entry| entry.has_text_key(key))
                .map(|entry| &entry.value)
                .ok_or_else(|| Error::Corrupt(format!("missing field {key}"))),
            _ => Err(corrupt("expected CBOR map")),
        }
    }
    /// The deterministic encoding, with map keys sorted as they are written.
    /// A repeated map key or nesting past [`MAX_DEPTH`] is rejected; a value
    /// this process holds is never refused for its size.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(encoded_len(self));
        self.write(&mut out, 0)?;
        Ok(out)
    }
    /// [`Value::encode`] into `out` for a value that sits `depth` levels inside
    /// an enclosing value, so the whole encoding keeps the decoder's nesting
    /// bound.
    pub fn write(&self, out: &mut Vec<u8>, depth: usize) -> Result<()> {
        match self {
            Self::Array(values) => {
                nesting(depth)?;
                write_head(4, values.len() as u64, out);
                for value in values {
                    value.write(out, depth + 1)?;
                }
                Ok(())
            }
            Self::Map(_) => self.write_map(out, depth, None),
            scalar => {
                encode_into(scalar, out);
                Ok(())
            }
        }
    }
    /// Write this map with the value of text key `key` replaced by `raw`. The
    /// caller has checked `raw` as one item at `depth + 1` with
    /// [`item_end_nested`], as [`decode`] would check it in place; the value
    /// this map holds for that key is not written.
    pub fn write_with_raw(
        &self,
        out: &mut Vec<u8>,
        depth: usize,
        key: &str,
        raw: &[u8],
    ) -> Result<()> {
        match self {
            Self::Map(entries) if entries.iter().any(|entry| entry.has_text_key(key)) => {
                self.write_map(out, depth, Some((key, raw)))
            }
            _ => Err(corrupt("raw CBOR map field")),
        }
    }
    fn write_map(&self, out: &mut Vec<u8>, depth: usize, raw: Option<(&str, &[u8])>) -> Result<()> {
        let Self::Map(entries) = self else {
            return Err(corrupt("expected CBOR map"));
        };
        nesting(depth)?;
        // Decoded and built maps are already in key order; entries a caller
        // pushed take their place here.
        let mut ordered: Vec<&MapEntry> = entries.iter().collect();
        ordered.sort_by(|a, b| a.key_bytes.cmp(&b.key_bytes));
        if ordered.windows(2).any(|w| w[0].key_bytes == w[1].key_bytes) {
            return Err(corrupt("duplicate CBOR map key"));
        }
        write_head(5, ordered.len() as u64, out);
        for entry in ordered {
            out.extend_from_slice(&entry.key_bytes);
            match raw {
                Some((key, raw)) if entry.has_text_key(key) => out.extend_from_slice(raw),
                _ => entry.value.write(out, depth + 1)?,
            }
        }
        Ok(())
    }
}

fn nesting(depth: usize) -> Result<()> {
    if depth >= MAX_DEPTH {
        return Err(Error::Limit("CBOR nesting"));
    }
    Ok(())
}

/// Encode `value` to deterministic CBOR, writing map entries in the order the
/// value holds them. [`Value::encode`] also sorts and checks them.
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

/// Write the minimal head of an item of major type `major` with argument
/// `value`: a count, length or integer.
pub fn write_head(major: u8, value: u64, out: &mut Vec<u8>) {
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
/// short keys). A repeated key is left in place, so the plain [`encode`]
/// produces CBOR that SAC's own decoder rejects, and [`Value::encode`] fails.
#[must_use]
pub fn text_map(pairs: Vec<(&str, Value)>) -> Value {
    let mut entries: Vec<MapEntry> = pairs
        .into_iter()
        .map(|(key, value)| MapEntry::text(key, value))
        .collect();
    entries.sort_by(|a, b| a.key_bytes.cmp(&b.key_bytes));
    Value::Map(entries)
}

pub const MAX_DEPTH: usize = 64;

/// Decode one item; see the module documentation for its bounds.
pub fn decode(bytes: &[u8]) -> Result<Value> {
    decode_nested(bytes, 0)
}

/// [`decode`] for an item that sits `depth` levels inside an enclosing value,
/// so the whole encoding keeps the decoder's nesting bound.
pub fn decode_nested(bytes: &[u8], depth: usize) -> Result<Value> {
    let mut parser = Parser { bytes, pos: 0 };
    let value = parser.value(depth)?;
    if parser.pos != bytes.len() {
        return Err(corrupt("trailing CBOR items"));
    }
    Ok(value)
}

/// Where the one item at `offset` ends. Checks the item as [`decode`] does
/// (minimal arguments, UTF-8 text, map key order and uniqueness, nesting) but
/// builds no values, for callers that keep canonical bytes as they are.
pub fn item_end(bytes: &[u8], offset: usize) -> Result<usize> {
    item_end_nested(bytes, offset, 0)
}

/// [`item_end`] for an item that sits `depth` levels inside an enclosing
/// value, so the whole encoding keeps the decoder's nesting bound.
pub fn item_end_nested(bytes: &[u8], offset: usize, depth: usize) -> Result<usize> {
    let item = bytes
        .get(offset..)
        .ok_or_else(|| corrupt("truncated CBOR"))?;
    // Each item occupies at least one byte, so the input bounds the count.
    let mut remaining = item.len();
    Ok(offset + super::cbor_view::scan(item, depth, &mut remaining, true)?)
}

/// The major type, minimal argument and content start of the head at
/// `offset`. Simple values have no argument and are rejected.
pub fn head_at(bytes: &[u8], offset: usize) -> Result<(u8, u64, usize)> {
    let item = bytes
        .get(offset..)
        .ok_or_else(|| corrupt("truncated CBOR"))?;
    let (major, argument, head) = super::cbor_view::header(item)?;
    if major == 7 {
        return Err(corrupt("unexpected CBOR simple value"));
    }
    Ok((major, argument, offset + head))
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Parser<'a> {
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
    /// A declared count can never exceed the bytes that remain, since each
    /// item occupies at least one; this also bounds what the count reserves.
    fn count(&self, count: u64, multiplier: usize) -> Result<usize> {
        let count = usize::try_from(count).map_err(|_| corrupt("impossible CBOR count"))?;
        let minimum = count
            .checked_mul(multiplier)
            .ok_or_else(|| corrupt("impossible CBOR count"))?;
        if minimum > self.bytes.len() - self.pos {
            return Err(corrupt("impossible CBOR count"));
        }
        Ok(count)
    }
    fn value(&mut self, depth: usize) -> Result<Value> {
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
                let count = usize::try_from(number).map_err(|_| corrupt("truncated CBOR"))?;
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
                nesting(depth)?;
                let count = self.count(number, if major == 5 { 2 } else { 1 })?;
                if major == 4 {
                    let mut values = Vec::with_capacity(count);
                    for _ in 0..count {
                        values.push(self.value(depth + 1)?);
                    }
                    Ok(Value::Array(values))
                } else {
                    let mut entries: Vec<MapEntry> = Vec::with_capacity(count);
                    for _ in 0..count {
                        let start = self.pos;
                        let key = self.value(depth + 1)?;
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
    match value {
        Value::Uint(n) | Value::NInt(n) => head_len(*n),
        Value::Bytes(b) => head_len(b.len() as u64) + b.len(),
        Value::Text(s) => head_len(s.len() as u64) + s.len(),
        Value::Array(a) => head_len(a.len() as u64) + a.iter().map(encoded_len).sum::<usize>(),
        Value::Map(a) => {
            head_len(a.len() as u64)
                + a.iter()
                    .map(|e| encoded_len(&e.key) + encoded_len(&e.value))
                    .sum::<usize>()
        }
        _ => 1,
    }
}

pub(crate) fn head_len(n: u64) -> usize {
    match n {
        0..=23 => 1,
        24..=255 => 2,
        256..=65535 => 3,
        65536..=4294967295 => 5,
        _ => 9,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_declared_count_past_the_remaining_bytes_is_rejected_before_allocation() {
        let mut encoded = Vec::new();
        write_head(4, 1 << 40, &mut encoded);
        encoded.extend([0xf6; 16]);
        assert!(
            decode(&encoded)
                .unwrap_err()
                .to_string()
                .contains("impossible CBOR count")
        );
        let mut map = Vec::new();
        write_head(5, 9, &mut map);
        map.extend([0xf6; 17]);
        assert!(decode(&map).is_err());
    }

    #[test]
    fn values_past_former_fixed_counts_and_sizes_roundtrip() {
        // More values than one million, and more slot storage than 16 MiB.
        let many = Value::Array(vec![Value::Null; 1_200_000]);
        assert_eq!(decode(&many.encode().unwrap()).unwrap(), many);
        // More byte storage than 16 MiB in aggregate.
        let wide = Value::Array(vec![Value::Bytes(vec![0; 9 * 1024 * 1024]); 2]);
        assert_eq!(decode(&wide.encode().unwrap()).unwrap(), wide);
        let encoded = many.encode().unwrap();
        assert_eq!(item_end(&encoded, 0).unwrap(), encoded.len());
    }

    #[test]
    fn canonicality_checks_do_not_need_an_allocated_second_encoding() {
        assert!(decode(&[0x18, 0]).is_err());
        assert!(decode(&[0xa2, 0x01, 0, 0, 0]).is_err());
        assert!(decode(&[0xa2, 0, 0, 0, 0]).is_err());
        let value = Value::map([
            ("hello", Value::Uint(24)),
            ("world", Value::array([Value::Null])),
        ]);
        assert_eq!(decode(&value.encode().unwrap()).unwrap(), value);
    }

    #[test]
    fn checked_writes_sort_pushed_entries_and_reject_repeats() {
        let mut fields = Value::map([("b", Value::Uint(2))]);
        let Value::Map(entries) = &mut fields else {
            unreachable!()
        };
        entries.push(MapEntry::text("a", Value::Uint(1)));
        let encoded = fields.encode().unwrap();
        assert_eq!(
            decode(&encoded).unwrap(),
            Value::map([("a", Value::Uint(1)), ("b", Value::Uint(2))])
        );
        let Value::Map(entries) = &mut fields else {
            unreachable!()
        };
        entries.push(MapEntry::text("b", Value::Null));
        assert!(fields.encode().is_err());
        assert_eq!(fields.field("a").unwrap(), &Value::Uint(1));
        assert!(fields.field("missing").is_err());
        assert!(Value::Null.field("a").is_err());
        let keyed = Value::map_of([(Value::Uint(2), Value::Null), (Value::Uint(1), Value::Null)]);
        assert_eq!(decode(&keyed.encode().unwrap()).unwrap(), keyed);
    }

    #[test]
    fn a_raw_map_field_writes_the_bytes_its_value_would() {
        let fields = Value::map([
            ("b", Value::array([Value::Uint(7), Value::text("x")])),
            ("a", Value::Null),
        ]);
        let raw = fields.encode().unwrap();
        let mut expected = Vec::new();
        Value::map([
            ("kind", Value::Uint(1)),
            ("fields", fields),
            ("z", Value::Bool(true)),
        ])
        .write(&mut expected, 3)
        .unwrap();
        let payload = Value::map([
            ("kind", Value::Uint(1)),
            ("fields", Value::Null),
            ("z", Value::Bool(true)),
        ]);
        assert_eq!(item_end_nested(&raw, 0, 4).unwrap(), raw.len());
        let mut actual = Vec::new();
        payload
            .write_with_raw(&mut actual, 3, "fields", &raw)
            .unwrap();
        assert_eq!(actual, expected);
        assert!(
            payload
                .write_with_raw(&mut Vec::new(), 3, "missing", &raw)
                .is_err()
        );
        // Nesting counts from the enclosing value, as a decoder of the whole
        // encoding counts it.
        let mut deep = Value::Null;
        for _ in 0..61 {
            deep = Value::array([deep]);
        }
        let deep = deep.encode().unwrap();
        assert!(item_end_nested(&deep, 0, 0).is_ok());
        assert!(item_end_nested(&deep, 0, 4).is_err());
        assert!(decode_nested(&deep, 0).is_ok());
        assert!(decode_nested(&deep, 4).is_err());
    }

    #[test]
    fn item_end_checks_what_decode_checks_without_building_values() {
        let value = Value::map([
            ("hello", Value::Uint(24)),
            (
                "world",
                Value::array([Value::Null, Value::text("x"), Value::bytes([1, 2])]),
            ),
        ]);
        let mut encoded = value.encode().unwrap();
        let end = encoded.len();
        encoded.push(0xf6);
        assert_eq!(item_end(&encoded, 0).unwrap(), end);
        assert_eq!(item_end(&encoded, end).unwrap(), end + 1);
        for damaged in [
            &[0x18, 0][..],
            &[0xa2, 0x01, 0, 0, 0],
            &[0xa2, 0, 0, 0, 0],
            &[0x62, 0xff, 0xfe],
            &[0x82, 0xf6],
        ] {
            assert!(decode(damaged).is_err());
            assert!(item_end(damaged, 0).is_err());
        }
        assert_eq!(head_at(&[0x19, 1, 0], 0).unwrap(), (0, 256, 3));
        assert!(head_at(&[0x19, 0, 1], 0).is_err());
        assert!(head_at(&[0xf6], 0).is_err());
    }
}
