//! Optional byte-exact recovery records. Ordinary SAC readers never consult them.
//!
//! Records can be a portable sidecar or an optional embedded recovery profile.
//! Checksums turn damaged blocks into erasures; a systematic Cauchy Reed-Solomon
//! code repairs them. Neither hashes nor parity establish publisher authority.
use super::{Error, Result, corrupt, domain_hash};
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::{Duration, Instant};

pub mod embedded;

const HEADER: usize = 128;
const MAGIC: &[u8; 8] = b"SAC1REC\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryOptions {
    /// Power of two, 1 KiB through 1 MiB. Smaller blocks localize damage.
    pub block_size: u32,
    pub data_shards: u16,
    pub parity_shards: u16,
}
impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            block_size: 16 * 1024,
            data_shards: 100,
            parity_shards: 10,
        }
    }
}
impl RecoveryOptions {
    /// Percentage of data blocks, rounded up; checksums/framing are additional.
    pub fn with_percent(percent: u16) -> Result<Self> {
        if !(1..=100).contains(&percent) {
            return Err(corrupt("recovery percentage must be 1 through 100"));
        }
        Ok(Self {
            parity_shards: percent,
            ..Self::default()
        })
    }
    fn validate(self) -> Result<()> {
        if !(1024..=1024 * 1024).contains(&self.block_size)
            || !self.block_size.is_power_of_two()
            || !(1..=128).contains(&self.data_shards)
            || !(1..=128).contains(&self.parity_shards)
            || self.data_shards + self.parity_shards > 256
        {
            return Err(corrupt("recovery block/code geometry"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct RecoveryLimits {
    pub max_source_bytes: u64,
    pub max_record_bytes: u64,
    pub max_output_bytes: u64,
    pub max_memory_bytes: u64,
    pub max_stripes: u64,
    pub max_duration: Duration,
}
impl Default for RecoveryLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 64 << 30,
            max_record_bytes: 128 << 30,
            max_output_bytes: 128 << 30,
            max_memory_bytes: 64 << 20,
            max_stripes: 1_000_000,
            max_duration: Duration::from_secs(3600),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryInfo {
    pub options: RecoveryOptions,
    pub source_bytes: u64,
    pub source_digest: [u8; 32],
    pub stripes: u64,
    pub record_bytes: u64,
}
impl RecoveryInfo {
    fn new(options: RecoveryOptions, source_bytes: u64, source_digest: [u8; 32]) -> Result<Self> {
        options.validate()?;
        if source_bytes == 0 {
            return Err(corrupt("empty recovery source"));
        }
        let stripes =
            source_bytes.div_ceil(u64::from(options.block_size) * u64::from(options.data_shards));
        let mut info = Self {
            options,
            source_bytes,
            source_digest,
            stripes,
            record_bytes: 0,
        };
        let (k, m) = info.geometry(stripes - 1);
        info.record_bytes = (HEADER as u64 * 2)
            .checked_add(
                (stripes - 1)
                    .checked_mul(info.stripe_span(
                        usize::from(options.data_shards),
                        usize::from(options.parity_shards),
                    ))
                    .ok_or(Error::Limit("recovery record size"))?,
            )
            .and_then(|n| n.checked_add(info.stripe_span(k, m)))
            .ok_or(Error::Limit("recovery record size"))?;
        Ok(info)
    }
    fn geometry(self, stripe: u64) -> (usize, usize) {
        let o = self.options;
        let remaining =
            self.source_bytes - stripe * u64::from(o.block_size) * u64::from(o.data_shards);
        let k = remaining
            .div_ceil(u64::from(o.block_size))
            .min(u64::from(o.data_shards)) as usize;
        let m = (k * usize::from(o.parity_shards)).div_ceil(usize::from(o.data_shards));
        (k, m)
    }
    fn stripe_span(self, k: usize, m: usize) -> u64 {
        (2 * ((k + m) * 32 + 32) + m * self.options.block_size as usize) as u64
    }
    fn encode(self) -> [u8; HEADER] {
        let mut b = [0; HEADER];
        b[..8].copy_from_slice(MAGIC);
        b[8..12].copy_from_slice(&1u32.to_le_bytes());
        b[12..16].copy_from_slice(&(HEADER as u32).to_le_bytes());
        b[16..24].copy_from_slice(&self.source_bytes.to_le_bytes());
        b[24..28].copy_from_slice(&self.options.block_size.to_le_bytes());
        b[28..30].copy_from_slice(&self.options.data_shards.to_le_bytes());
        b[30..32].copy_from_slice(&self.options.parity_shards.to_le_bytes());
        b[32..40].copy_from_slice(&self.stripes.to_le_bytes());
        b[40..48].copy_from_slice(&self.record_bytes.to_le_bytes());
        b[48..80].copy_from_slice(&self.source_digest);
        let hash = domain_hash(b"SAC1/recovery-header\0", &b[..96]);
        b[96..].copy_from_slice(&hash.0);
        b
    }
    fn decode(b: &[u8; HEADER]) -> Result<Self> {
        if &b[..8] != MAGIC
            || b[8..12] != 1u32.to_le_bytes()
            || b[12..16] != (HEADER as u32).to_le_bytes()
            || b[80..96] != [0; 16]
            || domain_hash(b"SAC1/recovery-header\0", &b[..96]).0 != b[96..]
        {
            return Err(corrupt("recovery header"));
        }
        let info = Self::new(
            RecoveryOptions {
                block_size: u32::from_le_bytes(b[24..28].try_into().unwrap()),
                data_shards: u16::from_le_bytes(b[28..30].try_into().unwrap()),
                parity_shards: u16::from_le_bytes(b[30..32].try_into().unwrap()),
            },
            u64::from_le_bytes(b[16..24].try_into().unwrap()),
            b[48..80].try_into().unwrap(),
        )?;
        if info.stripes != u64::from_le_bytes(b[32..40].try_into().unwrap())
            || info.record_bytes != u64::from_le_bytes(b[40..48].try_into().unwrap())
        {
            return Err(corrupt("recovery length/stripe count"));
        }
        Ok(info)
    }
    fn check(self, limits: &RecoveryLimits) -> Result<()> {
        // Account blocks, equations, reconstructed output and bounded metadata.
        let o = self.options;
        let memory = (u64::from(o.data_shards) + 2 * u64::from(o.parity_shards) + 2)
            * u64::from(o.block_size)
            + 256 * 1024;
        if self.source_bytes > limits.max_source_bytes
            || self.record_bytes > limits.max_record_bytes
            || self.stripes > limits.max_stripes
            || memory > limits.max_memory_bytes
        {
            return Err(Error::Limit("recovery input, stripes or memory"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryReport {
    pub info: RecoveryInfo,
    pub repaired_data_shards: u64,
    pub damaged_parity_shards: u64,
    pub degraded_metadata_copies: u64,
}

fn time_check(start: Instant, limits: &RecoveryLimits) -> Result<()> {
    if start.elapsed() > limits.max_duration {
        return Err(Error::Limit("recovery duration"));
    }
    Ok(())
}
fn read_at<R: Read + Seek>(input: &mut R, offset: u64, bytes: &mut [u8]) -> Result<usize> {
    input.seek(SeekFrom::Start(offset))?;
    let mut n = 0;
    while n < bytes.len() {
        match input.read(&mut bytes[n..]) {
            Ok(0) => break,
            Ok(count) => n += count,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(n)
}
fn read_header<R: Read + Seek>(input: &mut R, at: u64) -> Result<Option<RecoveryInfo>> {
    let mut b = [0; HEADER];
    if read_at(input, at, &mut b)? != HEADER {
        return Ok(None);
    }
    Ok(RecoveryInfo::decode(&b).ok())
}
/// Admit either intact header copy, rejecting conflicting valid copies.
pub fn inspect<R: Read + Seek>(records: &mut R, limits: &RecoveryLimits) -> Result<RecoveryInfo> {
    let len = records.seek(SeekFrom::End(0))?;
    if len > limits.max_record_bytes {
        return Err(Error::Limit("recovery record input"));
    }
    let first = read_header(records, 0)?;
    let last = if len >= HEADER as u64 * 2 {
        read_header(records, len - HEADER as u64)?
    } else {
        None
    };
    if first.zip(last).is_some_and(|(a, b)| a != b) {
        return Err(corrupt("conflicting recovery headers"));
    }
    let info = first
        .or(last)
        .ok_or_else(|| corrupt("no intact recovery header"))?;
    info.check(limits)?;
    if len > info.record_bytes {
        return Err(corrupt("recovery record trailing bytes"));
    }
    Ok(info)
}
fn source_hasher() -> blake3::Hasher {
    let mut h = blake3::Hasher::new();
    h.update(b"SAC1/recovery-source\0");
    h
}
fn source_hash<R: Read + Seek>(
    source: &mut R,
    len: u64,
    start: Instant,
    limits: &RecoveryLimits,
) -> Result<[u8; 32]> {
    source.seek(SeekFrom::Start(0))?;
    let mut left = len;
    let mut buffer = vec![0; 64 * 1024];
    let mut hash = source_hasher();
    while left > 0 {
        time_check(start, limits)?;
        let n = left.min(buffer.len() as u64) as usize;
        source.read_exact(&mut buffer[..n])?;
        hash.update(&buffer[..n]);
        left -= n as u64;
    }
    Ok(*hash.finalize().as_bytes())
}
fn block_hash(stripe: u64, index: usize, block: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"SAC1/recovery-block\0");
    h.update(&stripe.to_le_bytes());
    h.update(&(index as u16).to_le_bytes());
    h.update(block);
    *h.finalize().as_bytes()
}
fn metadata_hash(stripe: u64, bytes: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"SAC1/recovery-metadata\0");
    h.update(&stripe.to_le_bytes());
    h.update(bytes);
    *h.finalize().as_bytes()
}

/// Generate records for exact source bytes. The caller must exclude writers.
/// Output is provisional until success; the source is checked across both passes.
pub fn create<R: Read + Seek, W: Write>(
    source: &mut R,
    output: &mut W,
    options: RecoveryOptions,
    limits: &RecoveryLimits,
) -> Result<RecoveryInfo> {
    let start = Instant::now();
    let len = source.seek(SeekFrom::End(0))?;
    let mut info = RecoveryInfo::new(options, len, [0; 32])?;
    info.check(limits)?;
    if info.record_bytes > limits.max_output_bytes {
        return Err(Error::Limit("recovery output"));
    }
    info.source_digest = source_hash(source, len, start, limits)?;
    output.write_all(&info.encode())?;
    source.seek(SeekFrom::Start(0))?;
    let gf = Galois::new();
    let mut second = source_hasher();
    let mut left = len;
    for stripe in 0..info.stripes {
        time_check(start, limits)?;
        let (k, m) = info.geometry(stripe);
        let mut data = vec![vec![0; options.block_size as usize]; k];
        for block in &mut data {
            let n = left.min(u64::from(options.block_size)) as usize;
            source.read_exact(&mut block[..n])?;
            second.update(&block[..n]);
            left -= n as u64;
        }
        let mut parity = vec![vec![0; options.block_size as usize]; m];
        for (row, block) in parity.iter_mut().enumerate() {
            time_check(start, limits)?;
            for (col, input) in data.iter().enumerate() {
                gf.add_scaled(block, input, gf.inv((col ^ (k + row)) as u8));
            }
        }
        let mut metadata = Vec::with_capacity((k + m) * 32 + 32);
        for (i, block) in data.iter().chain(&parity).enumerate() {
            metadata.extend_from_slice(&block_hash(stripe, i, block));
        }
        metadata.extend_from_slice(&metadata_hash(stripe, &metadata));
        output.write_all(&metadata)?;
        for block in parity {
            output.write_all(&block)?;
        }
        output.write_all(&metadata)?;
    }
    if *second.finalize().as_bytes() != info.source_digest || source.seek(SeekFrom::End(0))? != len
    {
        return Err(corrupt("recovery source changed during generation"));
    }
    output.write_all(&info.encode())?;
    Ok(info)
}

fn metadata_at<R: Read + Seek>(
    records: &mut R,
    offset: u64,
    stripe: u64,
    size: usize,
) -> Result<Option<Vec<u8>>> {
    let mut b = vec![0; size];
    if read_at(records, offset, &mut b)? != size
        || metadata_hash(stripe, &b[..size - 32]) != b[size - 32..]
    {
        return Ok(None);
    }
    Ok(Some(b))
}

/// Reconstruct exact protected bytes, including preamble/slots/trailer. Does not
/// interpret or promote commits. Output MUST be staged and discarded on error.
/// Corrupt/missing blocks consume one erasure each; excess damage rejects.
pub fn repair<R: Read + Seek, P: Read + Seek, W: Write>(
    source: &mut R,
    records: &mut P,
    output: &mut W,
    limits: &RecoveryLimits,
) -> Result<RecoveryReport> {
    let start = Instant::now();
    let info = inspect(records, limits)?;
    if info.source_bytes > limits.max_output_bytes
        || source.seek(SeekFrom::End(0))? > limits.max_source_bytes
    {
        return Err(Error::Limit("recovery source/output"));
    }
    let mut report = RecoveryReport {
        info,
        repaired_data_shards: 0,
        damaged_parity_shards: 0,
        degraded_metadata_copies: 0,
    };
    let gf = Galois::new();
    let mut offset = HEADER as u64;
    let mut position = 0u64;
    let mut hash = source_hasher();
    for stripe in 0..info.stripes {
        time_check(start, limits)?;
        let (k, m) = info.geometry(stripe);
        let b = info.options.block_size as usize;
        let metadata_size = (k + m) * 32 + 32;
        let a = metadata_at(records, offset, stripe, metadata_size)?;
        let z = metadata_at(
            records,
            offset + metadata_size as u64 + (m * b) as u64,
            stripe,
            metadata_size,
        )?;
        if a.as_ref().zip(z.as_ref()).is_some_and(|(a, z)| a != z) {
            return Err(corrupt("conflicting recovery metadata"));
        }
        report.degraded_metadata_copies += u64::from(a.is_none()) + u64::from(z.is_none());
        let metadata = a
            .or(z)
            .ok_or_else(|| corrupt("no intact recovery stripe metadata"))?;
        let mut data = Vec::with_capacity(k);
        let mut missing = Vec::new();
        for col in 0..k {
            let mut block = vec![0; b];
            let at = position + (col * b) as u64;
            let n = (info.source_bytes - at).min(b as u64) as usize;
            let read = read_at(source, at, &mut block[..n])?;
            if read != n || block_hash(stripe, col, &block) != metadata[col * 32..(col + 1) * 32] {
                missing.push(col);
            }
            data.push(block);
        }
        let mut equations = Vec::new();
        let mut rows = Vec::new();
        for row in 0..m {
            let mut block = vec![0; b];
            let read = read_at(
                records,
                offset + metadata_size as u64 + (row * b) as u64,
                &mut block,
            )?;
            if read != b
                || block_hash(stripe, k + row, &block)
                    != metadata[(k + row) * 32..(k + row + 1) * 32]
            {
                report.damaged_parity_shards += 1;
            } else if rows.len() < missing.len() {
                rows.push(row);
                equations.push(block);
            }
        }
        if rows.len() < missing.len() {
            return Err(corrupt("recovery redundancy exhausted in stripe"));
        }
        if !missing.is_empty() {
            let matrix: Vec<Vec<u8>> = rows
                .iter()
                .map(|row| {
                    missing
                        .iter()
                        .map(|col| gf.inv((col ^ (k + row)) as u8))
                        .collect()
                })
                .collect();
            let inverse = gf.invert(matrix)?;
            for (row, equation) in rows.iter().zip(&mut equations) {
                time_check(start, limits)?;
                for (col, block) in data.iter().enumerate() {
                    if !missing.contains(&col) {
                        gf.add_scaled(equation, block, gf.inv((col ^ (k + row)) as u8));
                    }
                }
            }
            for (i, col) in missing.iter().enumerate() {
                time_check(start, limits)?;
                data[*col].fill(0);
                for (j, equation) in equations.iter().enumerate() {
                    gf.add_scaled(&mut data[*col], equation, inverse[i][j]);
                }
                if block_hash(stripe, *col, &data[*col]) != metadata[col * 32..(col + 1) * 32] {
                    return Err(corrupt("reconstructed recovery block digest"));
                }
            }
            report.repaired_data_shards += missing.len() as u64;
        }
        for block in data {
            let n = (info.source_bytes - position).min(b as u64) as usize;
            output.write_all(&block[..n])?;
            hash.update(&block[..n]);
            position += n as u64;
        }
        offset += info.stripe_span(k, m);
    }
    if *hash.finalize().as_bytes() != info.source_digest {
        return Err(corrupt(
            "recovered source digest mismatch (wrong or stale records)",
        ));
    }
    time_check(start, limits)?;
    Ok(report)
}

// GF(256), polynomial x^8+x^4+x^3+x^2+1 (0x11d), generator 2.
// Cauchy parity coefficient inv(column XOR (data_count + parity_row)).
struct Galois {
    exp: [u8; 512],
    log: [usize; 256],
}
impl Galois {
    fn new() -> Self {
        let mut g = Self {
            exp: [0; 512],
            log: [0; 256],
        };
        let mut x = 1u16;
        for i in 0..255 {
            g.exp[i] = x as u8;
            g.log[x as usize] = i;
            x <<= 1;
            if x & 256 != 0 {
                x ^= 0x11d;
            }
        }
        for i in 255..512 {
            g.exp[i] = g.exp[i - 255];
        }
        g
    }
    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            self.exp[self.log[a as usize] + self.log[b as usize]]
        }
    }
    fn inv(&self, a: u8) -> u8 {
        debug_assert_ne!(a, 0);
        self.exp[255 - self.log[a as usize]]
    }
    fn add_scaled(&self, dst: &mut [u8], src: &[u8], factor: u8) {
        let table: [u8; 256] = std::array::from_fn(|i| self.mul(i as u8, factor));
        for (a, b) in dst.iter_mut().zip(src) {
            *a ^= table[*b as usize];
        }
    }
    fn invert(&self, mut a: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>> {
        let n = a.len();
        let mut inverse = vec![vec![0; n]; n];
        for (i, row) in inverse.iter_mut().enumerate() {
            row[i] = 1;
        }
        for col in 0..n {
            let pivot = (col..n)
                .find(|&r| a[r][col] != 0)
                .ok_or_else(|| corrupt("singular recovery matrix"))?;
            a.swap(col, pivot);
            inverse.swap(col, pivot);
            let scale = self.inv(a[col][col]);
            for j in 0..n {
                a[col][j] = self.mul(a[col][j], scale);
                inverse[col][j] = self.mul(inverse[col][j], scale);
            }
            for row in 0..n {
                if row != col {
                    let scale = a[row][col];
                    for j in 0..n {
                        a[row][j] ^= self.mul(scale, a[col][j]);
                        inverse[row][j] ^= self.mul(scale, inverse[col][j]);
                    }
                }
            }
        }
        Ok(inverse)
    }
}
