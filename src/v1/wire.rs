//! SAC1 fixed wire structures and bounded frame codec.
use super::*;
#[cfg(not(feature = "compression"))]
use std::io::Read;

pub const PREAMBLE_SIZE: usize = 128;
pub const TRAILER_SIZE: usize = 160;
pub const FRAME: usize = 56;
pub const CONTROL_SIZE: u64 = 65536;
pub const MAGIC: [u8; 4] = *b"SAC1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocatorPolicy {
    Sealed,
    Live,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Preamble {
    pub policy: LocatorPolicy,
    pub incarnation: [u8; 16],
}
impl Preamble {
    pub fn sealed() -> Self {
        Self {
            policy: LocatorPolicy::Sealed,
            incarnation: [0; 16],
        }
    }
    pub fn live(incarnation: [u8; 16]) -> Result<Self> {
        if incarnation == [0; 16] {
            return Err(corrupt("zero live incarnation"));
        }
        Ok(Self {
            policy: LocatorPolicy::Live,
            incarnation,
        })
    }
    pub fn first_record_offset(self) -> u64 {
        match self.policy {
            LocatorPolicy::Sealed => 128,
            LocatorPolicy::Live => BOOTSTRAP_SIZE as u64,
        }
    }
    pub fn encode(self) -> [u8; PREAMBLE_SIZE] {
        let mut bytes = [0; PREAMBLE_SIZE];
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[8] = u8::from(self.policy == LocatorPolicy::Live);
        bytes[16..32].copy_from_slice(&self.incarnation);
        let digest = domain_hash(b"SAC1/preamble\0", &bytes[..96]);
        bytes[96..].copy_from_slice(&digest.0);
        bytes
    }
    pub fn digest(self) -> ObjectHash {
        ObjectHash(self.encode()[96..].try_into().unwrap())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PREAMBLE_SIZE {
            return Err(corrupt("preamble length"));
        }
        if bytes[..4] != MAGIC {
            return Err(Error::Unsupported("container magic".into()));
        }
        if bytes[4..8]
            .iter()
            .chain(&bytes[9..16])
            .chain(&bytes[32..96])
            .any(|b| *b != 0)
        {
            return Err(corrupt("preamble reserved"));
        }
        if domain_hash(b"SAC1/preamble\0", &bytes[..96]).0 != bytes[96..] {
            return Err(corrupt("preamble checksum"));
        }
        let incarnation = bytes[16..32].try_into().unwrap();
        match bytes[8] {
            0 if incarnation == [0; 16] => Ok(Self::sealed()),
            0 => Err(corrupt("sealed incarnation")),
            1 => Self::live(incarnation),
            _ => Err(Error::Unsupported("locator policy".into())),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Trailer {
    pub preamble_digest: ObjectHash,
    pub generation: u64,
    pub committed_end: u64,
    pub commit: ObjectRef,
}
impl Trailer {
    pub fn encode(self) -> [u8; TRAILER_SIZE] {
        let mut bytes = [0; TRAILER_SIZE];
        bytes[..8].copy_from_slice(b"SAC1END\0");
        bytes[8..40].copy_from_slice(&self.preamble_digest.0);
        bytes[40..48].copy_from_slice(&self.generation.to_le_bytes());
        bytes[48..56].copy_from_slice(&self.committed_end.to_le_bytes());
        bytes[56..64].copy_from_slice(&self.commit.address.offset.to_le_bytes());
        bytes[64..72].copy_from_slice(&u64::from(self.commit.address.length).to_le_bytes());
        bytes[72..104].copy_from_slice(&self.commit.hash.0);
        let digest = domain_hash(b"SAC1/trailer\0", &bytes[..128]);
        bytes[128..].copy_from_slice(&digest.0);
        bytes
    }
    pub fn digest(self) -> ObjectHash {
        ObjectHash(self.encode()[128..].try_into().unwrap())
    }
    pub fn decode(bytes: &[u8], preamble: &Preamble, offset: u64, file_len: u64) -> Result<Self> {
        if bytes.len() != TRAILER_SIZE || &bytes[..8] != b"SAC1END\0" {
            return Err(corrupt("trailer framing"));
        }
        if !offset.is_multiple_of(8) || bytes[104..128].iter().any(|b| *b != 0) {
            return Err(corrupt("trailer reserved or alignment"));
        }
        if domain_hash(b"SAC1/trailer\0", &bytes[..128]).0 != bytes[128..] {
            return Err(corrupt("trailer checksum"));
        }
        let trailer = Self {
            preamble_digest: ObjectHash(bytes[8..40].try_into().unwrap()),
            generation: le64(bytes, 40),
            committed_end: le64(bytes, 48),
            commit: ObjectRef {
                hash: ObjectHash(bytes[72..104].try_into().unwrap()),
                address: ChunkAddress {
                    offset: le64(bytes, 56),
                    length: u32::try_from(le64(bytes, 64)).map_err(|_| corrupt("commit span"))?,
                },
            },
        };
        if trailer.preamble_digest != preamble.digest()
            || trailer.generation == 0
            || trailer.committed_end
                != offset
                    .checked_add(TRAILER_SIZE as u64)
                    .ok_or_else(|| corrupt("trailer overflow"))?
            || trailer.committed_end > file_len
            || (preamble.policy == LocatorPolicy::Sealed
                && (trailer.generation != 1 || trailer.committed_end != file_len))
        {
            return Err(corrupt("trailer publication binding"));
        }
        let start = control_start(preamble.first_record_offset(), trailer.committed_end)?;
        validate_address(trailer.commit.address, start, offset)?;
        Ok(trailer)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    pub preamble_digest: ObjectHash,
    pub generation: u64,
    pub trailer_offset: u64,
    pub trailer_digest: ObjectHash,
}
impl Slot {
    pub fn encode(self) -> [u8; PAGE_SIZE] {
        let mut bytes = [0; PAGE_SIZE];
        bytes[..8].copy_from_slice(b"SAC1SLOT");
        bytes[8..40].copy_from_slice(&self.preamble_digest.0);
        bytes[40..48].copy_from_slice(&self.generation.to_le_bytes());
        bytes[48..56].copy_from_slice(&self.trailer_offset.to_le_bytes());
        bytes[56..88].copy_from_slice(&self.trailer_digest.0);
        let digest = domain_hash(b"SAC1/slot\0", &bytes[..4064]);
        bytes[4064..].copy_from_slice(&digest.0);
        bytes
    }
    pub fn decode(bytes: &[u8], preamble: &Preamble, index: usize) -> Result<Option<Self>> {
        if bytes.len() != PAGE_SIZE {
            return Err(corrupt("slot length"));
        }
        if bytes.iter().all(|b| *b == 0) {
            return Ok(None);
        }
        if domain_hash(b"SAC1/slot\0", &bytes[..4064]).0 != bytes[4064..] {
            return Err(corrupt("slot checksum"));
        }
        let slot = Self {
            preamble_digest: ObjectHash(bytes[8..40].try_into().unwrap()),
            generation: le64(bytes, 40),
            trailer_offset: le64(bytes, 48),
            trailer_digest: ObjectHash(bytes[56..88].try_into().unwrap()),
        };
        if &bytes[..8] != b"SAC1SLOT"
            || bytes[88..4064].iter().any(|b| *b != 0)
            || preamble.policy != LocatorPolicy::Live
            || slot.preamble_digest != preamble.digest()
            || slot.generation == 0
            || slot.generation % 2 != index as u64
            || !slot.trailer_offset.is_multiple_of(8)
        {
            return Err(corrupt("slot header"));
        }
        Ok(Some(slot))
    }
}

pub fn control_start(first: u64, end: u64) -> Result<u64> {
    let data = end
        .checked_sub(first)
        .filter(|n| *n >= TRAILER_SIZE as u64)
        .ok_or_else(|| corrupt("short committed extent"))?;
    Ok(end - data.min(CONTROL_SIZE))
}
pub fn validate_address(address: ChunkAddress, first: u64, end: u64) -> Result<()> {
    if address.offset < first
        || !address.offset.is_multiple_of(8)
        || address.length < 64
        || !address.length.is_multiple_of(8)
        || address.length as usize > MAX_CHUNK_SIZE + FRAME + MAX_CHILDREN * 12 + 7
        || address
            .offset
            .checked_add(u64::from(address.length))
            .is_none_or(|n| n > end)
    {
        return Err(corrupt("frame address outside pinned bounds"));
    }
    Ok(())
}
pub fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
pub fn le64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
// Table `n` advances the checksum of one byte through `n` more zero bytes, so
// eight lookups consume eight input bytes.
const fn crc32c_tables() -> [[u32; 256]; 8] {
    let mut tables = [[0u32; 256]; 8];
    let mut byte = 0;
    while byte < 256 {
        let mut crc = byte as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = (crc >> 1) ^ (0x82f63b78u32 & 0u32.wrapping_sub(crc & 1));
            bit += 1;
        }
        tables[0][byte] = crc;
        byte += 1;
    }
    let mut table = 1;
    while table < 8 {
        let mut byte = 0;
        while byte < 256 {
            let previous = tables[table - 1][byte];
            tables[table][byte] = (previous >> 8) ^ tables[0][(previous & 0xff) as usize];
            byte += 1;
        }
        table += 1;
    }
    tables
}
static CRC32C: [[u32; 256]; 8] = crc32c_tables();
fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    let mut words = bytes.chunks_exact(8);
    for word in &mut words {
        let low = u32::from_le_bytes(word[..4].try_into().unwrap()) ^ crc;
        let high = u32::from_le_bytes(word[4..].try_into().unwrap());
        crc = CRC32C[7][(low & 0xff) as usize]
            ^ CRC32C[6][((low >> 8) & 0xff) as usize]
            ^ CRC32C[5][((low >> 16) & 0xff) as usize]
            ^ CRC32C[4][(low >> 24) as usize]
            ^ CRC32C[3][(high & 0xff) as usize]
            ^ CRC32C[2][((high >> 8) & 0xff) as usize]
            ^ CRC32C[1][((high >> 16) & 0xff) as usize]
            ^ CRC32C[0][(high >> 24) as usize];
    }
    for byte in words.remainder() {
        crc = (crc >> 8) ^ CRC32C[0][((crc ^ u32::from(*byte)) & 0xff) as usize];
    }
    !crc
}
#[cfg(test)]
#[test]
fn table_checksum_agrees_with_the_bitwise_definition() {
    fn bitwise(bytes: &[u8]) -> u32 {
        let mut crc = !0u32;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0x82f63b78u32 & 0u32.wrapping_sub(crc & 1));
            }
        }
        !crc
    }
    assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    let mut bytes = [0u8; 257];
    blake3::Hasher::new().finalize_xof().fill(&mut bytes);
    for length in 0..=bytes.len() {
        assert_eq!(crc32c(&bytes[..length]), bitwise(&bytes[..length]));
    }
}

pub fn frame_span(header: &[u8]) -> Result<usize> {
    if header.len() < FRAME || header[..4] != *b"SO1\0" {
        return Err(corrupt("frame header"));
    }
    let mut checked: [u8; FRAME] = header[..FRAME].try_into().unwrap();
    checked[48..52].fill(0);
    if crc32c(&checked) != le32(header, 48) {
        return Err(corrupt("frame header checksum"));
    }
    if header[5] != 1 || header[52..56].iter().any(|b| *b != 0) {
        return Err(Error::Unsupported("frame revision or reserved bits".into()));
    }
    let children = usize::from(u16::from_le_bytes(header[6..8].try_into().unwrap()));
    let stored = le32(header, 8) as usize;
    let decoded = le32(header, 12) as usize;
    if children > MAX_CHILDREN
        || stored > MAX_CHUNK_SIZE
        || !(8..=MAX_CHUNK_SIZE).contains(&decoded)
    {
        return Err(Error::Limit("frame bounds"));
    }
    if header[4] > 1 {
        return Err(Error::Unsupported("frame codec".into()));
    }
    Ok((FRAME + stored + 12 * children + 7) & !7)
}

/// Reusable frame encoder. Buffers and the optional codec context belong to
/// the writer; canonical identity is independent of their physical encoding.
#[derive(Default)]
pub struct FrameEncoder {
    frame: Vec<u8>,
    #[cfg(feature = "compression")]
    canonical: Vec<u8>,
    #[cfg(feature = "compression")]
    compressor: Option<(i32, zstd::bulk::Compressor<'static>)>,
}
// Cloning a store clones content, never codec state or scratch reservations.
impl Clone for FrameEncoder {
    fn clone(&self) -> Self {
        Self::default()
    }
}
impl FrameEncoder {
    pub fn encode(&mut self, object: &CanonicalObject, level: i32) -> Result<&[u8]> {
        self.encode_hashed(object, level, object.hash())
    }
    pub fn buffer_capacity(&self) -> usize {
        let bytes = self.frame.capacity();
        #[cfg(feature = "compression")]
        let bytes = bytes + self.canonical.capacity();
        bytes
    }
    pub(crate) fn encode_hashed(
        &mut self,
        object: &CanonicalObject,
        level: i32,
        hash: ObjectHash,
    ) -> Result<&[u8]> {
        check_input(&object.bytes, &object.children)?;
        validate_core_object(object)?;
        self.frame.clear();
        self.frame.resize(FRAME, 0);
        #[cfg(feature = "compression")]
        let mut codec = 0u8;
        #[cfg(not(feature = "compression"))]
        let codec = 0u8;
        #[cfg(feature = "compression")]
        if !matches!(object.kind, 1 | 2) && level != 0 {
            self.canonical.clear();
            object.write_canonical(&mut self.canonical);
            if self
                .compressor
                .as_ref()
                .is_none_or(|(old, _)| *old != level)
            {
                self.compressor = Some((level, zstd::bulk::Compressor::new(level)?));
            }
            let bound = zstd::zstd_safe::compress_bound(self.canonical.len());
            self.frame.resize(FRAME + bound, 0);
            let written = self
                .compressor
                .as_mut()
                .unwrap()
                .1
                .compress_to_buffer(&self.canonical, &mut self.frame[FRAME..])?;
            if written < self.canonical.len() {
                self.frame.truncate(FRAME + written);
                codec = 1;
            } else {
                self.frame.truncate(FRAME);
                self.frame.extend_from_slice(&self.canonical);
            }
        } else {
            object.write_canonical(&mut self.frame);
        }
        #[cfg(not(feature = "compression"))]
        {
            let _ = level;
            object.write_canonical(&mut self.frame);
        }
        self.finish(object, hash, codec)
    }
    /// A frame for `object` from the Zstandard bytes of another frame. A
    /// decoder authenticated those bytes as the canonical bytes of this
    /// object; only the child locators differ.
    #[cfg(feature = "compression")]
    pub(crate) fn encode_stored(
        &mut self,
        object: &CanonicalObject,
        hash: ObjectHash,
        compressed: &[u8],
    ) -> Result<&[u8]> {
        check_input(&object.bytes, &object.children)?;
        validate_core_object(object)?;
        self.frame.clear();
        self.frame.resize(FRAME, 0);
        self.frame.extend_from_slice(compressed);
        self.finish(object, hash, 1)
    }
    // The stored bytes are in the frame. Add the child locators, the padding
    // and the header.
    fn finish(&mut self, object: &CanonicalObject, hash: ObjectHash, codec: u8) -> Result<&[u8]> {
        let stored = self.frame.len() - FRAME;
        for child in &object.children {
            self.frame
                .extend_from_slice(&child.address.offset.to_le_bytes());
            self.frame
                .extend_from_slice(&child.address.length.to_le_bytes());
        }
        let span = (self.frame.len() + 7) & !7;
        let maximum = match object.kind {
            3 => Some(144 * 1024),
            4..=6 | 9 => Some(80 * 1024),
            _ => None,
        };
        if maximum.is_some_and(|max| span > max) {
            return Err(Error::Limit("core page wire span"));
        }
        self.frame.resize(span, 0);
        self.frame[..4].copy_from_slice(b"SO1\0");
        self.frame[4] = codec;
        self.frame[5] = 1;
        self.frame[6..8].copy_from_slice(&(object.children.len() as u16).to_le_bytes());
        self.frame[8..12].copy_from_slice(&(stored as u32).to_le_bytes());
        self.frame[12..16].copy_from_slice(&(object.canonical_len() as u32).to_le_bytes());
        self.frame[16..48].copy_from_slice(&hash.0);
        let crc = crc32c(&self.frame[..FRAME]);
        self.frame[48..52].copy_from_slice(&crc.to_le_bytes());
        Ok(&self.frame)
    }
}
pub fn encode_frame(object: &CanonicalObject, level: i32) -> Result<Vec<u8>> {
    let mut encoder = FrameEncoder::default();
    encoder.encode(object, level)?;
    Ok(encoder.frame)
}

fn zstd_bounds(payload: &[u8], decoded: usize) -> Result<()> {
    if payload.len() < 6 || payload[..4] != [0x28, 0xb5, 0x2f, 0xfd] {
        return Err(corrupt("zstd magic"));
    }
    let descriptor = payload[4];
    if descriptor & 0x1b != 0 {
        return Err(corrupt("zstd reserved flags or dictionary"));
    }
    let single = descriptor & 0x20 != 0;
    let flag = descriptor >> 6;
    if !single && flag == 0 {
        return Err(corrupt("zstd content size required"));
    }
    let mut at = 5;
    if !single {
        let window = payload[at];
        at += 1;
        let base = 1u64
            .checked_shl(10 + u32::from(window >> 3))
            .ok_or(Error::Limit("zstd window"))?;
        if base + base / 8 * u64::from(window & 7) > MAX_CHUNK_SIZE as u64 {
            return Err(Error::Limit("zstd window"));
        }
    }
    let count = match flag {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let size_bytes = payload
        .get(at..at + count)
        .ok_or_else(|| corrupt("zstd content size"))?;
    let mut size = 0u64;
    for (i, byte) in size_bytes.iter().enumerate() {
        size |= u64::from(*byte) << (i * 8);
    }
    if flag == 1 {
        size += 256;
    }
    if size != decoded as u64 {
        return Err(corrupt("zstd content size mismatch"));
    }
    Ok(())
}

pub fn decode_frame(
    reference: ObjectRef,
    bytes: &[u8],
    first: u64,
    end: u64,
) -> Result<CanonicalObject> {
    validate_address(reference.address, first, end)?;
    decode_frame_inner(reference, bytes, Some(first))
}

/// Native callers can transfer the read buffer. The ordinary stored byte-object
/// path authenticates the complete frame and reuses that allocation for output.
/// Other shapes retain the common decoder and all of its validation rules.
pub fn decode_frame_owned(
    reference: ObjectRef,
    bytes: Vec<u8>,
    first: u64,
    end: u64,
) -> Result<CanonicalObject> {
    FrameDecoder::default().decode_owned(reference, bytes, first, end)
}

/// Verify canonical content independently of damaged physical hints.
/// Returned child addresses are untrusted and must be resolved by verified ID
/// before publication; this function grants no ordinary read admission.
pub fn decode_frame_salvage(reference: ObjectRef, bytes: &[u8]) -> Result<CanonicalObject> {
    decode_frame_inner(reference, bytes, None)
}
fn decode_frame_inner(
    reference: ObjectRef,
    bytes: &[u8],
    first: Option<u64>,
) -> Result<CanonicalObject> {
    let span = frame_span(bytes)?;
    if span != bytes.len() || span != reference.address.length as usize {
        return Err(corrupt("frame span"));
    }
    if bytes[16..48] != reference.hash.0 {
        return Err(corrupt("frame expected ID"));
    }
    let count = usize::from(u16::from_le_bytes(bytes[6..8].try_into().unwrap()));
    let stored = le32(bytes, 8) as usize;
    let decoded = le32(bytes, 12) as usize;
    let payload = &bytes[FRAME..FRAME + stored];
    let canonical = if bytes[4] == 0 {
        if stored != decoded {
            return Err(corrupt("stored decoded length"));
        }
        std::borrow::Cow::Borrowed(payload)
    } else {
        zstd_bounds(payload, decoded)?;
        #[cfg(feature = "compression")]
        let out = {
            let frame_size = zstd::zstd_safe::find_frame_compressed_size(payload)
                .map_err(|_| corrupt("zstd frame"))?;
            if frame_size != payload.len() {
                return Err(corrupt("zstd trailing bytes"));
            }
            zstd::bulk::decompress(payload, decoded).map_err(|_| corrupt("zstd payload"))?
        };
        #[cfg(not(feature = "compression"))]
        let out = {
            let mut decoder = ruzstd::decoding::StreamingDecoder::new(payload)
                .map_err(|_| corrupt("zstd header"))?;
            let mut out = Vec::with_capacity(decoded);
            (&mut decoder)
                .take(decoded as u64 + 1)
                .read_to_end(&mut out)
                .map_err(|_| corrupt("zstd payload"))?;
            if <[u8]>::len(decoder.get_ref()) != 0 {
                return Err(corrupt("zstd trailing bytes"));
            }
            out
        };
        std::borrow::Cow::Owned(out)
    };
    if canonical.len() != decoded || domain_hash(b"SAC1/object\0", &canonical) != reference.hash {
        return Err(corrupt("object identity or decoded length"));
    }
    if canonical.len() < 8
        || le32(&canonical, 4) as usize != count
        || 8 + 32 * count > canonical.len()
    {
        return Err(corrupt("canonical child table"));
    }
    let mut children = Vec::with_capacity(count);
    for i in 0..count {
        let at = FRAME + stored + 12 * i;
        let child = ObjectRef {
            hash: ObjectHash(canonical[8 + 32 * i..40 + 32 * i].try_into().unwrap()),
            address: ChunkAddress {
                offset: le64(bytes, at),
                length: le32(bytes, at + 8),
            },
        };
        if let Some(first) = first {
            validate_address(child.address, first, reference.address.offset)?;
        }
        children.push(child);
    }
    if bytes[FRAME + stored + 12 * count..].iter().any(|b| *b != 0) {
        return Err(corrupt("frame padding"));
    }
    let kind = u16::from_le_bytes(canonical[..2].try_into().unwrap());
    let version = u16::from_le_bytes(canonical[2..4].try_into().unwrap());
    let body_offset = 8 + 32 * count;
    let body = match canonical {
        std::borrow::Cow::Borrowed(data) => data[body_offset..].to_vec(),
        std::borrow::Cow::Owned(mut data) => {
            let length = data.len() - body_offset;
            data.copy_within(body_offset.., 0);
            data.truncate(length);
            data
        }
    };
    let object = CanonicalObject {
        kind,
        version,
        bytes: body,
        children,
    };
    if (object.kind == 1 || object.kind == 2) && bytes[4] != 0 {
        return Err(corrupt("compressed control object"));
    }
    validate_core_object(&object)?;
    let maximum = match object.kind {
        3 => Some(144 * 1024),
        4..=6 | 9 => Some(80 * 1024),
        _ => None,
    };
    if maximum.is_some_and(|max| bytes.len() > max) {
        return Err(Error::Limit("core page wire span"));
    }
    Ok(object)
}

/// Authenticated view retaining canonical and physical backing separately.
/// Child access assembles one reference by value; no child vector is allocated.
pub struct FrameView<'a> {
    pub kind: u16,
    pub version: u16,
    pub body: &'a [u8],
    canonical: &'a [u8],
    locators: &'a [u8],
    count: usize,
}
impl FrameView<'_> {
    pub fn child_count(&self) -> usize {
        self.count
    }
    pub fn child(&self, index: usize) -> Option<ObjectRef> {
        if index >= self.count {
            return None;
        }
        Some(ObjectRef {
            hash: ObjectHash(
                self.canonical[8 + 32 * index..40 + 32 * index]
                    .try_into()
                    .unwrap(),
            ),
            address: ChunkAddress {
                offset: le64(self.locators, 12 * index),
                length: le32(self.locators, 12 * index + 8),
            },
        })
    }
    pub fn to_owned(&self) -> CanonicalObject {
        CanonicalObject {
            kind: self.kind,
            version: self.version,
            bytes: self.body.to_vec(),
            children: (0..self.count).map(|i| self.child(i).unwrap()).collect(),
        }
    }
}
/// Caller-owned decode workspace. Stored frames borrow input directly;
/// compressed frames reuse bounded output and native codec state.
#[derive(Default)]
pub struct FrameDecoder {
    decoded: Vec<u8>,
    #[cfg(feature = "compression")]
    decompressor: Option<zstd::zstd_safe::DCtx<'static>>,
}
impl FrameDecoder {
    pub fn retained_bytes(&self) -> usize {
        let bytes = self.decoded.capacity();
        #[cfg(feature = "compression")]
        let bytes = bytes + self.decompressor.as_ref().map_or(0, |d| d.sizeof());
        bytes
    }
    pub fn decode_owned(
        &mut self,
        reference: ObjectRef,
        frame: Vec<u8>,
        first: u64,
        end: u64,
    ) -> Result<CanonicalObject> {
        let view = self.decode(reference, &frame, first, end)?;
        let kind = view.kind;
        let version = view.version;
        let children = (0..view.count).map(|i| view.child(i).unwrap()).collect();
        let body_offset = view.body.as_ptr() as usize - view.canonical.as_ptr() as usize;
        let length = view.body.len();
        let stored = frame[4] == 0;
        let mut bytes = if stored {
            frame
        } else {
            std::mem::take(&mut self.decoded)
        };
        let start = body_offset + if stored { FRAME } else { 0 };
        bytes.copy_within(start..start + length, 0);
        bytes.truncate(length);
        Ok(CanonicalObject {
            kind,
            version,
            bytes,
            children,
        })
    }

    pub fn buffer_capacity(&self) -> usize {
        self.decoded.capacity()
    }
    pub fn decode<'a>(
        &'a mut self,
        reference: ObjectRef,
        frame: &'a [u8],
        first: u64,
        end: u64,
    ) -> Result<FrameView<'a>> {
        validate_address(reference.address, first, end)?;
        let span = frame_span(frame)?;
        if span != frame.len() || span != reference.address.length as usize {
            return Err(corrupt("frame span"));
        }
        if frame[16..48] != reference.hash.0 {
            return Err(corrupt("frame expected ID"));
        }
        let stored = le32(frame, 8) as usize;
        let decoded = le32(frame, 12) as usize;
        let count = usize::from(u16::from_le_bytes(frame[6..8].try_into().unwrap()));
        let payload = &frame[FRAME..FRAME + stored];
        let canonical = if frame[4] == 0 {
            if stored != decoded {
                return Err(corrupt("stored decoded length"));
            }
            payload
        } else {
            zstd_bounds(payload, decoded)?;
            #[cfg(feature = "compression")]
            {
                let size = zstd::zstd_safe::find_frame_compressed_size(payload)
                    .map_err(|_| corrupt("zstd frame"))?;
                if size != payload.len() {
                    return Err(corrupt("zstd trailing bytes"));
                }
                if self.decompressor.is_none() {
                    self.decompressor = Some(zstd::zstd_safe::DCtx::create());
                }
                self.decoded.resize(decoded, 0);
                let n = self
                    .decompressor
                    .as_mut()
                    .unwrap()
                    .decompress(&mut self.decoded[..], payload)
                    .map_err(|_| corrupt("zstd payload"))?;
                if n != decoded {
                    return Err(corrupt("object decoded length"));
                }
            }
            #[cfg(not(feature = "compression"))]
            {
                let mut decoder = ruzstd::decoding::StreamingDecoder::new(payload)
                    .map_err(|_| corrupt("zstd header"))?;
                self.decoded.clear();
                self.decoded.reserve(decoded);
                (&mut decoder)
                    .take(decoded as u64 + 1)
                    .read_to_end(&mut self.decoded)
                    .map_err(|_| corrupt("zstd payload"))?;
                if <[u8]>::len(decoder.get_ref()) != 0 || self.decoded.len() != decoded {
                    return Err(corrupt("zstd trailing bytes or decoded length"));
                }
            }
            &self.decoded
        };
        if domain_hash(b"SAC1/object\0", canonical) != reference.hash {
            return Err(corrupt("object identity or decoded length"));
        }
        if le32(canonical, 4) as usize != count || 8 + 32 * count > canonical.len() {
            return Err(corrupt("canonical child table"));
        }
        let locators = &frame[FRAME + stored..FRAME + stored + 12 * count];
        if frame[FRAME + stored + 12 * count..].iter().any(|b| *b != 0) {
            return Err(corrupt("frame padding"));
        }
        let kind = u16::from_le_bytes(canonical[..2].try_into().unwrap());
        let version = u16::from_le_bytes(canonical[2..4].try_into().unwrap());
        if matches!(kind, 1 | 2) && frame[4] != 0 {
            return Err(corrupt("compressed control object"));
        }
        let body = &canonical[8 + 32 * count..];
        super::schema::validate_core_shape(kind, version, body, count)?;
        let max = match kind {
            3 => Some(144 * 1024),
            4..=6 | 9 => Some(80 * 1024),
            _ => None,
        };
        if max.is_some_and(|max| frame.len() > max) {
            return Err(Error::Limit("core page wire span"));
        }
        let view = FrameView {
            kind,
            version,
            body,
            canonical,
            locators,
            count,
        };
        for i in 0..count {
            validate_address(
                view.child(i).unwrap().address,
                first,
                reference.address.offset,
            )?;
        }
        Ok(view)
    }
}
