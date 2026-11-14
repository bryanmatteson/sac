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
    canonical_hash: Option<ObjectHash>,
    #[cfg(feature = "compression")]
    compressors: [Option<zstd::zstd_safe::CCtx<'static>>; 2],
    #[cfg(feature = "compression")]
    compression_levels: [Option<i32>; 2],
}
// Cloning a store clones content, never codec state or scratch reservations.
impl Clone for FrameEncoder {
    fn clone(&self) -> Self {
        Self::default()
    }
}
impl FrameEncoder {
    pub fn encode(&mut self, object: &CanonicalObject, level: i32) -> Result<&[u8]> {
        let hash = self.prepare_hash(
            object.kind,
            object.version,
            &object.bytes,
            &object.children,
            level,
        );
        self.encode_hashed(object, level, hash)
    }
    /// Assemble canonical bytes once for both identity and compression. Raw
    /// frames retain bounded stack hashing without allocating codec scratch.
    pub(crate) fn prepare_hash(
        &mut self,
        kind: u16,
        version: u16,
        bytes: &[u8],
        children: &[ObjectRef],
        level: i32,
    ) -> ObjectHash {
        #[cfg(feature = "compression")]
        {
            self.canonical_hash = None;
            if !matches!(kind, 1 | 2) && level != 0 {
                self.prepare_canonical(kind, version, bytes, children);
                let hash = ObjectHash::digest(&self.canonical);
                self.canonical_hash = Some(hash);
                return hash;
            }
        }
        let _ = level;
        CanonicalObject::hash_parts(kind, version, bytes, children)
    }
    #[cfg(feature = "compression")]
    fn prepare_canonical(&mut self, kind: u16, version: u16, bytes: &[u8], children: &[ObjectRef]) {
        self.canonical.clear();
        self.canonical
            .reserve(super::OBJECT_HASH_DOMAIN.len() + 8 + 32 * children.len() + bytes.len());
        self.canonical.extend_from_slice(super::OBJECT_HASH_DOMAIN);
        CanonicalObject::write_parts(kind, version, bytes, children, &mut self.canonical);
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
        self.encode_parts(
            object.kind,
            object.version,
            &object.bytes,
            &object.children,
            level,
            hash,
        )
    }
    pub(crate) fn encode_parts(
        &mut self,
        kind: u16,
        version: u16,
        bytes: &[u8],
        children: &[ObjectRef],
        level: i32,
        hash: ObjectHash,
    ) -> Result<&[u8]> {
        super::schema::validate_core_shape(kind, version, bytes, children.len())?;
        self.frame.clear();
        self.frame.resize(FRAME, 0);
        #[cfg(feature = "compression")]
        let mut codec = 0u8;
        #[cfg(not(feature = "compression"))]
        let codec = 0u8;
        #[cfg(feature = "compression")]
        if !matches!(kind, 1 | 2) && level != 0 {
            // A known hash authenticates canonical bytes, independently of
            // child locators. Consume only a matching prepared representation;
            // authenticated copies and other callers can still encode normally.
            if self.canonical_hash.take() != Some(hash) {
                self.prepare_canonical(kind, version, bytes, children);
            }
            let canonical = &self.canonical[super::OBJECT_HASH_DOMAIN.len()..];
            let bound = zstd::zstd_safe::compress_bound(canonical.len());
            // Zstandard initializes the part of the spare capacity it writes.
            // The cursor starts after the already initialized frame header.
            self.frame.reserve(bound);
            let mut output = std::io::Cursor::new(&mut self.frame);
            output.set_position(FRAME as u64);
            // Keep the selected level across complete independent frames.
            // compress2 starts a fresh session without rebuilding the same
            // parameter configuration for each object.
            // Zstd shrinks an oversized workspace after repeated small frames.
            // Keep small and large frames separate so interleaved writes do not
            // repeatedly discard and rebuild the larger workspace.
            let slot = usize::from(canonical.len() > 4096);
            let compressor =
                self.compressors[slot].get_or_insert_with(zstd::zstd_safe::CCtx::create);
            if self.compression_levels[slot] != Some(level) {
                compressor
                    .set_parameter(zstd::zstd_safe::CParameter::CompressionLevel(level))
                    .map_err(|code| std::io::Error::other(zstd::zstd_safe::get_error_name(code)))?;
                self.compression_levels[slot] = Some(level);
            }
            let result = compressor.compress2(&mut output, canonical);
            if result.is_err() {
                compressor
                    .reset(zstd::zstd_safe::ResetDirective::SessionOnly)
                    .map_err(|code| std::io::Error::other(zstd::zstd_safe::get_error_name(code)))?;
            }
            let written = result
                .map_err(|code| std::io::Error::other(zstd::zstd_safe::get_error_name(code)))?;
            if written < canonical.len() {
                codec = 1;
            } else {
                self.frame.truncate(FRAME);
                self.frame.extend_from_slice(canonical);
            }
        } else {
            CanonicalObject::write_parts(kind, version, bytes, children, &mut self.frame);
        }
        #[cfg(not(feature = "compression"))]
        {
            let _ = level;
            CanonicalObject::write_parts(kind, version, bytes, children, &mut self.frame);
        }
        self.finish(
            kind,
            8 + children.len() * 32 + bytes.len(),
            children,
            hash,
            codec,
        )
    }
    /// A frame from the Zstandard bytes of another frame. A
    /// decoder authenticated those bytes as the canonical bytes of this
    /// object; only the child locators differ.
    #[cfg(feature = "compression")]
    pub(crate) fn encode_stored(
        &mut self,
        kind: u16,
        version: u16,
        bytes: &[u8],
        children: &[ObjectRef],
        hash: ObjectHash,
        compressed: &[u8],
    ) -> Result<&[u8]> {
        super::schema::validate_core_shape(kind, version, bytes, children.len())?;
        self.frame.clear();
        self.frame.resize(FRAME, 0);
        self.frame.extend_from_slice(compressed);
        self.finish(
            kind,
            8 + children.len() * 32 + bytes.len(),
            children,
            hash,
            1,
        )
    }
    // The stored bytes are in the frame. Add the child locators, the padding
    // and the header.
    fn finish(
        &mut self,
        kind: u16,
        canonical_len: usize,
        children: &[ObjectRef],
        hash: ObjectHash,
        codec: u8,
    ) -> Result<&[u8]> {
        let stored = self.frame.len() - FRAME;
        for child in children {
            self.frame
                .extend_from_slice(&child.address.offset.to_le_bytes());
            self.frame
                .extend_from_slice(&child.address.length.to_le_bytes());
        }
        let span = (self.frame.len() + 7) & !7;
        let maximum = match kind {
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
        self.frame[6..8].copy_from_slice(&(children.len() as u16).to_le_bytes());
        self.frame[8..12].copy_from_slice(&(stored as u32).to_le_bytes());
        self.frame[12..16].copy_from_slice(&(canonical_len as u32).to_le_bytes());
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
    #[cfg(feature = "compression")]
    {
        // Most object frames have one block. We already parsed its frame
        // header, so validate the stored extent here instead of asking Zstd
        // to parse that header again before the actual decompression.
        let block_at = at + count;
        let header = payload
            .get(block_at..block_at + 3)
            .ok_or_else(|| corrupt("zstd block header"))?;
        let block = u32::from_le_bytes([header[0], header[1], header[2], 0]);
        if block & 1 != 0 {
            if block >> 3 > 128 * 1024 {
                return Err(corrupt("zstd block size"));
            }
            let stored = match (block >> 1) & 3 {
                0 | 2 => (block >> 3) as usize,
                1 => 1, // RLE stores one byte, regardless of decoded size.
                _ => return Err(corrupt("zstd block type")),
            };
            let checksum = if descriptor & 4 != 0 { 4 } else { 0 };
            if block_at + 3 + stored + checksum != payload.len() {
                return Err(corrupt("zstd frame extent"));
            }
        } else {
            let size = zstd::zstd_safe::find_frame_compressed_size(payload)
                .map_err(|_| corrupt("zstd frame"))?;
            if size != payload.len() {
                return Err(corrupt("zstd trailing bytes"));
            }
        }
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
        let out =
            { zstd::bulk::decompress(payload, decoded).map_err(|_| corrupt("zstd payload"))? };
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
    #[cfg(feature = "native")]
    pub(crate) fn trim_buffer(&mut self, max_capacity: usize) {
        if self.decoded.capacity() > max_capacity {
            self.decoded = Vec::new();
        }
    }

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
        let start = body_offset
            + if stored {
                FRAME
            } else {
                super::OBJECT_HASH_DOMAIN.len()
            };
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
            self.decoded.clear();
            self.decoded
                .reserve(super::OBJECT_HASH_DOMAIN.len() + decoded);
            self.decoded.extend_from_slice(super::OBJECT_HASH_DOMAIN);
            #[cfg(feature = "compression")]
            {
                if self.decompressor.is_none() {
                    self.decompressor = Some(zstd::zstd_safe::DCtx::create());
                }
                // Decode after the identity domain so authentication can hash
                // one contiguous input without a second prefix copy.
                let mut output = std::io::Cursor::new(&mut self.decoded);
                output.set_position(super::OBJECT_HASH_DOMAIN.len() as u64);
                let n = self
                    .decompressor
                    .as_mut()
                    .unwrap()
                    .decompress(&mut output, payload)
                    .map_err(|_| corrupt("zstd payload"))?;
                if n != decoded {
                    return Err(corrupt("object decoded length"));
                }
            }
            #[cfg(not(feature = "compression"))]
            {
                let mut decoder = ruzstd::decoding::StreamingDecoder::new(payload)
                    .map_err(|_| corrupt("zstd header"))?;
                (&mut decoder)
                    .take(decoded as u64 + 1)
                    .read_to_end(&mut self.decoded)
                    .map_err(|_| corrupt("zstd payload"))?;
                if <[u8]>::len(decoder.get_ref()) != 0
                    || self.decoded.len() != super::OBJECT_HASH_DOMAIN.len() + decoded
                {
                    return Err(corrupt("zstd trailing bytes or decoded length"));
                }
            }
            &self.decoded[super::OBJECT_HASH_DOMAIN.len()..]
        };
        let hash = if frame[4] == 0 {
            domain_hash(super::OBJECT_HASH_DOMAIN, canonical)
        } else {
            ObjectHash::digest(&self.decoded)
        };
        if hash != reference.hash {
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

#[cfg(all(test, feature = "compression"))]
mod codec_tests {
    use super::*;

    #[test]
    fn compressor_reuse_preserves_frames_across_sizes_and_levels() {
        let mut encoder = FrameEncoder::default();
        let mut object = CanonicalObject {
            kind: 42000,
            version: 9,
            bytes: Vec::new(),
            children: Vec::new(),
        };
        for round in 0..4 {
            for (length, level) in [(65536, 1), (4089, 3), (4096, 3), (127, -3)] {
                object.bytes = (0..length).map(|i| ((i + round) % 251) as u8).collect();
                let expected = encode_frame(&object, level).unwrap();
                assert_eq!(encoder.encode(&object, level).unwrap(), expected);
                // Enough small frames to exercise Zstd's workspace retirement
                // policy before the next larger independent frame.
                object.bytes.truncate(63);
                for _ in 0..130 {
                    let expected = encode_frame(&object, level).unwrap();
                    assert_eq!(encoder.encode(&object, level).unwrap(), expected);
                }
            }
        }
    }

    #[test]
    fn prepared_canonical_hash_handles_relocation_and_unprepared_interleaving() {
        let mut encoder = FrameEncoder::default();
        for length in [0, 63, 1005, 2029, 4076, 4077, 4096, 65536, 131072] {
            for count in [0, 1, 127, 128, 255] {
                let mut object = CanonicalObject {
                    kind: 42000,
                    version: 9,
                    bytes: (0..length).map(|i| (i % 251) as u8).collect(),
                    children: (0..count)
                        .map(|i| ObjectRef {
                            hash: ObjectHash::digest(&(i as u64).to_le_bytes()),
                            address: ChunkAddress {
                                offset: 128 + i as u64 * 64,
                                length: 64,
                            },
                        })
                        .collect(),
                };
                for level in [1, 0, 3, -3, 1] {
                    let hash = encoder.prepare_hash(
                        object.kind,
                        object.version,
                        &object.bytes,
                        &object.children,
                        level,
                    );
                    assert_eq!(hash, object.hash());
                    assert_eq!(encoder.canonical_hash, (level != 0).then_some(hash));
                    // Physical hints are outside canonical identity. Reusing
                    // canonical bytes must still encode the current locators.
                    for child in &mut object.children {
                        child.address.offset += 64;
                    }
                    let frame = encoder.encode_hashed(&object, level, hash).unwrap();
                    let reference = ObjectRef {
                        hash,
                        address: ChunkAddress {
                            offset: 65536,
                            length: frame.len() as u32,
                        },
                    };
                    assert_eq!(
                        decode_frame(reference, frame, 128, 65536 + frame.len() as u64).unwrap(),
                        object
                    );
                }
                // A duplicate put may leave preparation unused. An unrelated
                // authenticated write must rebuild rather than use those bytes.
                encoder.prepare_hash(
                    object.kind,
                    object.version,
                    &object.bytes,
                    &object.children,
                    1,
                );
                object.version += 1;
                object.bytes.push(19);
                let hash = object.hash();
                let frame = encoder.encode_hashed(&object, 1, hash).unwrap();
                let reference = ObjectRef {
                    hash,
                    address: ChunkAddress {
                        offset: 65536,
                        length: frame.len() as u32,
                    },
                };
                assert_eq!(
                    decode_frame(reference, frame, 128, 65536 + frame.len() as u64).unwrap(),
                    object
                );
                assert_eq!(encoder.canonical_hash, None);
            }
        }
    }

    #[test]
    fn zstd_extent_checks_cover_block_types_checksums_and_trailing_frames() {
        let mut frames = Vec::new();
        for block_type in [0, 1] {
            let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0x20, 32];
            let block = 1u32 | (block_type << 1) | (32 << 3);
            frame.extend_from_slice(&block.to_le_bytes()[..3]);
            frame.resize(frame.len() + if block_type == 1 { 1 } else { 32 }, 71);
            frames.push((frame, 32));
        }
        let mut multiple = vec![0x28, 0xb5, 0x2f, 0xfd, 0x20, 32];
        for last in [0u32, 1] {
            multiple.extend_from_slice(&(last | (16 << 3)).to_le_bytes()[..3]);
            multiple.extend_from_slice(&[71; 16]);
        }
        frames.push((multiple, 32));
        for length in [8, 255, 256, 65536, 131072, 131073, 262144] {
            for checksum in [false, true] {
                let bytes: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
                let mut compressor = zstd::bulk::Compressor::new(1).unwrap();
                compressor
                    .set_parameter(zstd::zstd_safe::CParameter::ChecksumFlag(checksum))
                    .unwrap();
                frames.push((compressor.compress(&bytes).unwrap(), length));
            }
        }
        for (frame, decoded) in frames {
            zstd_bounds(&frame, decoded).unwrap();
            assert_eq!(
                zstd::zstd_safe::find_frame_compressed_size(&frame).unwrap(),
                frame.len()
            );
            assert_eq!(
                zstd::bulk::decompress(&frame, decoded).unwrap().len(),
                decoded
            );
            assert!(zstd_bounds(&frame, decoded + 1).is_err());
            for missing in 1..=frame.len().min(12) {
                assert!(zstd_bounds(&frame[..frame.len() - missing], decoded).is_err());
            }
            for trailing in [
                vec![0],
                zstd::bulk::compress(&[], 1).unwrap(),
                frame.clone(),
            ] {
                let mut bad = frame.clone();
                bad.extend_from_slice(&trailing);
                assert!(zstd_bounds(&bad, decoded).is_err());
            }
            // Structural mutations accepted by our fast extent check must
            // agree with Zstd's general frame-size parser. Payload integrity
            // remains the decompressor's and canonical hash's responsibility.
            for index in 0..frame.len().min(64) {
                for bit in 0..8 {
                    let mut bad = frame.clone();
                    bad[index] ^= 1 << bit;
                    if zstd_bounds(&bad, decoded).is_ok() {
                        assert_eq!(
                            zstd::zstd_safe::find_frame_compressed_size(&bad).unwrap(),
                            bad.len()
                        );
                    }
                }
            }
        }
        let mut reserved = vec![0x28, 0xb5, 0x2f, 0xfd, 0x20, 32, 7, 0, 0];
        assert!(zstd_bounds(&reserved, 32).is_err());
        reserved[6..9].copy_from_slice(&(3u32 | (131073 << 3)).to_le_bytes()[..3]);
        reserved.push(71);
        assert!(zstd_bounds(&reserved, 32).is_err());
    }
}
