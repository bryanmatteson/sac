//! Experimental raw publication journal. It deliberately does not implement
//! ObjectStore: local sequence IDs are not canonical object hashes.
use sac::{ChunkAddress, ObjectHash, ObjectRef};
use std::{
    fs::{File, OpenOptions},
    hash::{BuildHasher, Hash, Hasher},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

const HEADER: usize = 32;
const REF_BYTES: usize = 8;
const FILE_HEADER: usize = 128;
const MAX_RECORD: usize = sac::v1::MAX_CHUNK_SIZE + sac::v1::MAX_CHILDREN * 12 + HEADER;
const BUFFER: usize = 64 * 1024;
const MAX_RECORDS: usize = 100_000;
#[derive(Default)]
struct Seen(Vec<u64>);
impl Seen {
    fn new(records: usize) -> Self {
        Self(vec![0; records.div_ceil(64)])
    }
    fn get(&self, index: usize) -> bool {
        self.0
            .get(index / 64)
            .is_some_and(|word| word & (1 << (index % 64)) != 0)
    }
    fn insert(&mut self, index: usize) {
        self.0[index / 64] |= 1 << (index % 64);
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RecordId {
    scope: [u8; 16],
    sequence: u64,
}
impl RecordId {
    pub fn sequence(self) -> u64 {
        self.sequence
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Reference {
    /// Producer-supplied identity hint in the admitted immutable base. Native
    /// materialization authenticates the payload before accepting this identity.
    Base(ObjectRef),
    Local(RecordId),
}
#[derive(Default, Clone, Copy, Debug)]
pub struct Statistics {
    pub appended: u64,
    pub reused: u64,
    pub candidates: u64,
    pub compared_bytes: u64,
}
#[derive(Clone, Copy, Default)]
struct Candidate {
    fingerprint: u64,
    sequence: u64,
    offset: u64,
    length: u32,
    kind: u16,
    version: u16,
    children: u32,
    body: u32,
}

pub struct Journal {
    base: Base,
    file: File,
    scope: [u8; 16],
    length: u64,
    buffer_offset: u64,
    buffer: Vec<u8>,
    frame: Vec<u8>,
    records: u64,
    seen: Seen,
    max_records: usize,
    candidates: Vec<Candidate>,
    hasher: std::hash::RandomState,
    pub statistics: Statistics,
}
/// Eight-byte wire handles: aligned base offset (low bit zero) or local ID
/// shifted left one with its low bit set. Scope belongs to the journal header.
fn encoded_reference(reference: Reference, scope: [u8; 16]) -> io::Result<[u8; 8]> {
    let value = match reference {
        Reference::Base(reference) => reference.address.offset,
        Reference::Local(id) => {
            if id.scope != scope || id.sequence == 0 || id.sequence > u64::MAX / 2 {
                return Err(invalid("foreign journal reference"));
            }
            return Ok(((id.sequence << 1) | 1).to_le_bytes());
        }
    };
    if value == 0 || value & 7 != 0 {
        return Err(invalid("unaligned base handle"));
    }
    Ok(value.to_le_bytes())
}
fn decoded_reference(
    bytes: &[u8],
    hints: &mut &[u8],
    scope: [u8; 16],
    records: u64,
) -> io::Result<Reference> {
    let value = u64::from_le_bytes(bytes.try_into().map_err(|_| invalid("journal reference"))?);
    if value & 1 == 0 {
        if value == 0 || value & 7 != 0 {
            return Err(invalid("unaligned base handle"));
        }
        let hint = hints
            .get(..36)
            .ok_or_else(|| invalid("base identity hint"))?;
        let reference = ObjectRef {
            hash: ObjectHash(hint[..32].try_into().unwrap()),
            address: ChunkAddress {
                offset: value,
                length: u32::from_le_bytes(hint[32..].try_into().unwrap()),
            },
        };
        *hints = &hints[36..];
        Ok(Reference::Base(reference))
    } else {
        let sequence = value >> 1;
        if sequence == 0 || sequence > records {
            return Err(invalid("journal forward reference"));
        }
        Ok(Reference::Local(RecordId { scope, sequence }))
    }
}

fn append_hints(bytes: &mut Vec<u8>, children: &[Reference]) {
    for child in children {
        if let Reference::Base(reference) = child {
            bytes.extend_from_slice(&reference.hash.0);
            bytes.extend_from_slice(&reference.address.length.to_le_bytes());
        }
    }
}

/// Bound base metadata; each eight-byte handle resolves within this exact
/// selected publication. Header reads recover full IDs; NativeStore still
/// authenticates canonical bytes when materializing those references.
pub struct Base {
    file: File,
    _pin: sac::NativeReader,
    binding: [u8; 92],
    first: u64,
    end: u64,
    reads: u64,
}
impl Base {
    pub fn open(path: &Path) -> io::Result<Self> {
        use sac::ObjectStore;
        let mut file = File::open(path)?;
        let reader = sac::NativeReader::open_file(file.try_clone()?).map_err(io::Error::other)?;
        let publication = reader
            .root()
            .ok_or_else(|| invalid("base has no publication"))?;
        let bounds = reader
            .physical_read_scope()
            .ok_or_else(|| invalid("base scope"))?;
        let mut header = [0; 128];
        file.read_exact(&mut header)?;
        let preamble = sac::Preamble::decode(&header).map_err(io::Error::other)?;
        let mut binding = [0; 92];
        binding[..32].copy_from_slice(&preamble.digest().0);
        binding[32..40].copy_from_slice(&bounds.end.to_le_bytes());
        binding[40..48].copy_from_slice(&publication.generation.to_le_bytes());
        binding[48..80].copy_from_slice(&publication.root.hash.0);
        binding[80..88].copy_from_slice(&publication.root.address.offset.to_le_bytes());
        binding[88..92].copy_from_slice(&publication.root.address.length.to_le_bytes());
        Ok(Self {
            file,
            binding,
            _pin: reader,
            first: bounds.first,
            end: bounds.end,
            reads: 0,
        })
    }
    fn check_offset(&self, offset: u64) -> io::Result<()> {
        if offset < self.first
            || offset & 7 != 0
            || offset.checked_add(56).is_none_or(|n| n > self.end)
        {
            return Err(invalid("base handle bounds"));
        }
        Ok(())
    }
    fn check_hint(&self, reference: ObjectRef) -> io::Result<()> {
        self.check_offset(reference.address.offset)?;
        if reference.address.length < 56
            || !reference.address.length.is_multiple_of(8)
            || reference
                .address
                .offset
                .checked_add(u64::from(reference.address.length))
                .is_none_or(|end| end > self.end)
        {
            return Err(invalid("base hint span"));
        }
        Ok(())
    }
    fn reference_from_header(&self, offset: u64, header: &[u8]) -> io::Result<ObjectRef> {
        let length = sac::v1::wire::frame_span(header).map_err(io::Error::other)?;
        if offset
            .checked_add(length as u64)
            .is_none_or(|n| n > self.end)
        {
            return Err(invalid("base frame bounds"));
        }
        Ok(ObjectRef {
            hash: ObjectHash(header[16..48].try_into().unwrap()),
            address: ChunkAddress {
                offset,
                length: length as u32,
            },
        })
    }
    fn reference(&mut self, offset: u64) -> io::Result<ObjectRef> {
        self.check_offset(offset)?;
        let mut header = [0; 56];
        use std::os::unix::fs::FileExt;
        self.file.read_exact_at(&mut header, offset)?;
        self.reads += 1;
        self.reference_from_header(offset, &header)
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "crc"))]
fn checksum(mut crc: u32, bytes: &[u8]) -> u32 {
    use core::arch::aarch64::{__crc32cb, __crc32cd};
    let mut words = bytes.chunks_exact(8);
    // Target guarantees CRC. These intrinsics accept values, not pointers.
    unsafe {
        for word in &mut words {
            crc = __crc32cd(crc, u64::from_le_bytes(word.try_into().unwrap()));
        }
        for byte in words.remainder() {
            crc = __crc32cb(crc, *byte);
        }
    }
    crc
}
#[cfg(not(all(target_arch = "aarch64", target_feature = "crc")))]
fn checksum(mut crc: u32, bytes: &[u8]) -> u32 {
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f63b78u32 & 0u32.wrapping_sub(crc & 1));
        }
    }
    crc
}
fn seal_frame(frame: &mut [u8]) {
    frame[28..32].fill(0);
    let crc = !checksum(!0, frame);
    frame[28..32].copy_from_slice(&crc.to_le_bytes());
}
fn check_frame(frame: &mut [u8]) -> io::Result<()> {
    let expected = u32::from_le_bytes(frame[28..32].try_into().unwrap());
    frame[28..32].fill(0);
    let actual = !checksum(!0, frame);
    frame[28..32].copy_from_slice(&expected.to_le_bytes());
    if expected != actual {
        return Err(invalid("journal checksum"));
    }
    Ok(())
}

impl Journal {
    pub fn create(
        path: &Path,
        base_path: &Path,
        scope: [u8; 16],
        max_records: usize,
        candidate_slots: usize,
    ) -> io::Result<Self> {
        if max_records == 0
            || max_records > MAX_RECORDS
            || candidate_slots > 65_536
            || !candidate_slots.is_power_of_two()
        {
            return Err(invalid("journal bounds"));
        }
        let base = Base::open(base_path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;
        let mut header = [0; FILE_HEADER];
        header[..8].copy_from_slice(b"SACJTRY3");
        header[8..24].copy_from_slice(&scope);
        header[24..116].copy_from_slice(&base.binding);
        let crc = !checksum(!0, &header[..124]);
        header[124..].copy_from_slice(&crc.to_le_bytes());
        file.write_all(&header)?;
        Ok(Self {
            base,
            file,
            scope,
            length: FILE_HEADER as u64,
            buffer_offset: FILE_HEADER as u64,
            buffer: Vec::with_capacity(BUFFER),
            frame: Vec::new(),
            records: 0,
            seen: Seen::new(max_records),
            max_records,
            candidates: vec![Candidate::default(); candidate_slots],
            hasher: Default::default(),
            statistics: Default::default(),
        })
    }
    fn check_reference(&self, reference: Reference) -> io::Result<()> {
        match reference {
            Reference::Local(id) => {
                if id.scope != self.scope
                    || id.sequence == 0
                    || !self.seen.get(id.sequence as usize - 1)
                {
                    return Err(invalid("foreign or future journal reference"));
                }
            }
            Reference::Base(reference) => {
                self.base.check_hint(reference)?;
            }
        }
        Ok(())
    }
    /// Preserve a producer-supplied identity without rereading its header.
    /// This is a hint within the bound base, not an authenticated identity.
    /// NativeStore authenticates it when the journal is materialized.
    pub fn base_hint(&self, reference: ObjectRef) -> io::Result<Reference> {
        self.base.check_hint(reference)?;
        Ok(Reference::Base(reference))
    }
    pub fn existing(&mut self, reference: ObjectRef) -> io::Result<Reference> {
        if self.base.reference(reference.address.offset)? != reference {
            return Err(invalid("base identity mismatch"));
        }
        Ok(Reference::Base(reference))
    }
    /// Reuse a retained immutable identity without inspecting its payload.
    pub fn reuse(&self, reference: Reference) -> io::Result<Reference> {
        self.check_reference(reference)?;
        Ok(reference)
    }
    fn sample(&self, kind: u16, version: u16, body: &[u8], children: &[Reference]) -> u64 {
        let mut hash = self.hasher.build_hasher();
        kind.hash(&mut hash);
        version.hash(&mut hash);
        body.len().hash(&mut hash);
        children.len().hash(&mut hash);
        body[..body.len().min(32)].hash(&mut hash);
        body[body.len().saturating_sub(32)..].hash(&mut hash);
        let middle = body.len() / 2;
        body[middle..(middle + 16).min(body.len())].hash(&mut hash);
        children.first().hash(&mut hash);
        children.last().hash(&mut hash);
        children.get(children.len() / 2).hash(&mut hash);
        hash.finish()
    }
    fn read_at(&mut self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        if offset >= self.buffer_offset {
            let start = (offset - self.buffer_offset) as usize;
            let data = self
                .buffer
                .get(start..start + out.len())
                .ok_or_else(|| invalid("journal buffered span"))?;
            out.copy_from_slice(data);
            return Ok(());
        }
        // A record is wholly buffered or wholly on disk: append flushes before
        // writing a frame that cannot fit in the bounded append buffer.
        if offset + out.len() as u64 > self.buffer_offset {
            return Err(invalid("journal split record"));
        }
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(out)
    }
    fn same_candidate(&mut self, candidate: Candidate) -> io::Result<bool> {
        let mut scratch = [0; 4096];
        let mut at = HEADER;
        while at < self.frame.len() {
            let n = (self.frame.len() - at).min(scratch.len());
            self.read_at(candidate.offset + at as u64, &mut scratch[..n])?;
            self.statistics.compared_bytes += n as u64;
            if scratch[..n] != self.frame[at..at + n] {
                return Ok(false);
            }
            at += n;
        }
        Ok(true)
    }
    fn append(&mut self) -> io::Result<()> {
        if self.frame.len() > BUFFER {
            self.flush()?;
            self.file.seek(SeekFrom::Start(self.length))?;
            self.file.write_all(&self.frame)?;
            self.length += self.frame.len() as u64;
            self.buffer_offset = self.length;
        } else {
            if self.buffer.len() + self.frame.len() > BUFFER {
                self.flush()?;
            }
            self.buffer.extend_from_slice(&self.frame);
            self.length += self.frame.len() as u64;
        }
        Ok(())
    }
    pub fn put(
        &mut self,
        kind: u16,
        version: u16,
        body: &[u8],
        children: &[Reference],
    ) -> io::Result<Reference> {
        self.put_numbered(self.records + 1, kind, version, body, children)
    }
    fn put_numbered(
        &mut self,
        sequence: u64,
        kind: u16,
        version: u16,
        body: &[u8],
        children: &[Reference],
    ) -> io::Result<Reference> {
        if sequence == 0
            || sequence > self.max_records as u64
            || self.seen.get(sequence as usize - 1)
        {
            return Err(invalid("journal record limit or duplicate ID"));
        }
        let canonical = children
            .len()
            .checked_mul(32)
            .and_then(|n| n.checked_add(8))
            .and_then(|n| n.checked_add(body.len()))
            .ok_or_else(|| invalid("journal object size"))?;
        if canonical > sac::v1::MAX_CHUNK_SIZE || children.len() > sac::v1::MAX_CHILDREN {
            return Err(invalid("journal object size"));
        }
        for child in children {
            self.check_reference(*child)?;
            if matches!(child, Reference::Local(id) if id.sequence >= sequence) {
                return Err(invalid("journal logical forward reference"));
            }
        }
        let fingerprint = self.sample(kind, version, body, children);
        self.frame.clear();
        self.frame.resize(HEADER, 0);
        for child in children {
            self.frame
                .extend_from_slice(&encoded_reference(*child, self.scope)?);
        }
        append_hints(&mut self.frame, children);
        self.frame.extend_from_slice(body);
        self.frame.resize(self.frame.len().next_multiple_of(8), 0);
        let slot = fingerprint as usize & (self.candidates.len() - 1);
        let candidate = self.candidates[slot];
        if candidate.sequence != 0
            && candidate.sequence < sequence
            && candidate.fingerprint == fingerprint
            && candidate.length as usize == self.frame.len()
            && candidate.kind == kind
            && candidate.version == version
            && candidate.children as usize == children.len()
            && candidate.body as usize == body.len()
        {
            self.statistics.candidates += 1;
            if self.same_candidate(candidate)? {
                self.statistics.reused += 1;
                return Ok(Reference::Local(RecordId {
                    scope: self.scope,
                    sequence: candidate.sequence,
                }));
            }
        }
        let offset = self.length;
        let length = self.frame.len() as u32;
        self.frame[..4].copy_from_slice(b"SJr1");
        self.frame[4..8].copy_from_slice(&length.to_le_bytes());
        self.frame[8..16].copy_from_slice(&sequence.to_le_bytes());
        self.frame[16..18].copy_from_slice(&kind.to_le_bytes());
        self.frame[18..20].copy_from_slice(&version.to_le_bytes());
        self.frame[20..24].copy_from_slice(&(children.len() as u32).to_le_bytes());
        self.frame[24..28].copy_from_slice(&(body.len() as u32).to_le_bytes());
        seal_frame(&mut self.frame);
        self.append()?;
        self.records = self.records.max(sequence);
        self.seen.insert(sequence as usize - 1);
        self.candidates[slot] = Candidate {
            fingerprint,
            sequence,
            offset,
            length,
            kind,
            version,
            children: children.len() as u32,
            body: body.len() as u32,
        };
        self.statistics.appended += 1;
        Ok(Reference::Local(RecordId {
            scope: self.scope,
            sequence,
        }))
    }
    pub fn publish(&mut self, generation: u64, root: Reference) -> io::Result<()> {
        self.check_reference(root)?;
        self.frame.clear();
        self.frame.resize(HEADER, 0);
        self.frame[..4].copy_from_slice(b"SJc1");
        self.frame[8..16].copy_from_slice(&generation.to_le_bytes());
        self.frame
            .extend_from_slice(&encoded_reference(root, self.scope)?);
        append_hints(&mut self.frame, &[root]);
        self.frame.resize(self.frame.len().next_multiple_of(8), 0);
        let length = self.frame.len() as u32;
        self.frame[4..8].copy_from_slice(&length.to_le_bytes());
        seal_frame(&mut self.frame);
        self.append()?;
        self.flush()?;
        self.file.sync_all()?;
        // Candidates are publication-local; retired records need not remain in
        // the dedup window. Explicit immutable IDs remain valid in the journal.
        self.candidates.fill(Candidate::default());
        Ok(())
    }
    pub fn flush(&mut self) -> io::Result<()> {
        if !self.buffer.is_empty() {
            self.file.seek(SeekFrom::Start(self.buffer_offset))?;
            self.file.write_all(&self.buffer)?;
            self.buffer.clear();
            self.buffer_offset = self.length;
        }
        Ok(())
    }
    pub fn length(&self) -> u64 {
        self.length
    }
}

/// Bounded adapter index for monotonically arriving source frame offsets.
/// Producer code holding journal handles directly does not need this index.
pub struct OffsetReferences {
    rows: Vec<(u64, Reference)>,
    limit: usize,
}
impl OffsetReferences {
    pub fn new(capacity: usize) -> io::Result<Self> {
        if capacity > MAX_RECORDS {
            return Err(invalid("source reference index limit"));
        }
        Ok(Self {
            rows: Vec::with_capacity(capacity),
            limit: MAX_RECORDS,
        })
    }
    pub fn insert(&mut self, offset: u64, reference: Reference) -> io::Result<()> {
        if self.rows.len() == self.limit || self.rows.last().is_some_and(|r| r.0 >= offset) {
            return Err(invalid("source reference offset order or limit"));
        }
        self.rows.push((offset, reference));
        Ok(())
    }
    pub fn get(&self, offset: u64) -> io::Result<Reference> {
        let index = self
            .rows
            .binary_search_by_key(&offset, |r| r.0)
            .map_err(|_| invalid("unknown source reference"))?;
        Ok(self.rows[index].1)
    }
}

/// Dense sequence IDs need an array, not a hash table or per-record tree nodes,
/// when resolving the retained graph into canonical SAC references.
pub struct MaterializedReferences {
    scope: [u8; 16],
    values: Vec<ObjectRef>,
    slots: Vec<u32>,
    remaining: Vec<u32>,
    free: Vec<u32>,
    recycling: bool,
    base: Base,
}
impl MaterializedReferences {
    pub fn new(scope: [u8; 16], records: usize, base_path: &Path) -> io::Result<Self> {
        if records > 100_000 {
            return Err(invalid("journal materialization record limit"));
        }
        Self::with_base(scope, records, Base::open(base_path)?)
    }
    pub fn with_base(scope: [u8; 16], records: usize, base: Base) -> io::Result<Self> {
        if records > MAX_RECORDS {
            return Err(invalid("journal materialization record limit"));
        }
        Ok(Self {
            scope,
            values: vec![
                ObjectRef {
                    hash: ObjectHash([0; 32]),
                    address: ChunkAddress {
                        offset: 0,
                        length: 0
                    }
                };
                records
            ],
            slots: Vec::new(),
            remaining: Vec::new(),
            free: Vec::new(),
            recycling: false,
            base,
        })
    }
    /// Recycle full canonical references at their last selected local edge.
    /// The caller releases children only after successfully writing the parent.
    pub fn with_lifetimes(scope: [u8; 16], remaining: Vec<u32>, base: Base) -> io::Result<Self> {
        if remaining.len() > MAX_RECORDS {
            return Err(invalid("journal materialization record limit"));
        }
        let mut result = Self::with_base(scope, 0, base)?;
        result.slots = vec![0; remaining.len()];
        result.remaining = remaining;
        result.values = Vec::with_capacity(1024);
        result.free = Vec::with_capacity(1024);
        result.recycling = true;
        Ok(result)
    }
    pub fn release_children(&mut self, children: &[Reference]) -> io::Result<()> {
        if !self.recycling {
            return Err(invalid("reference recycling disabled"));
        }
        for child in children {
            if let Reference::Local(id) = child {
                if id.scope != self.scope || id.sequence == 0 {
                    return Err(invalid("foreign journal reference"));
                }
                let index = id.sequence as usize - 1;
                let remaining = self
                    .remaining
                    .get_mut(index)
                    .ok_or_else(|| invalid("journal reference bounds"))?;
                if *remaining == 0 {
                    return Err(invalid("journal reference released twice"));
                }
                *remaining -= 1;
                if *remaining == 0 {
                    let slot = std::mem::replace(&mut self.slots[index], 0);
                    if slot == 0 {
                        return Err(invalid("unmaterialized journal reference"));
                    }
                    self.values[slot as usize - 1].address.length = 0;
                    self.free.push(slot);
                }
            }
        }
        Ok(())
    }
    fn slot(&self, sequence: u64) -> io::Result<usize> {
        if sequence == 0 {
            return Err(invalid("zero journal reference"));
        }
        let index = sequence as usize - 1;
        if self.slots.is_empty() {
            return Ok(index);
        }
        let slot = self.slots.get(index).copied().unwrap_or(0);
        if slot == 0 {
            return Err(invalid("unselected journal reference"));
        }
        Ok(slot as usize - 1)
    }
    pub fn resolve(&mut self, reference: Reference) -> io::Result<ObjectRef> {
        match reference {
            Reference::Base(reference) => {
                self.base.check_hint(reference)?;
                Ok(reference)
            }
            Reference::Local(id) => {
                if id.scope != self.scope || id.sequence == 0 {
                    return Err(invalid("foreign journal reference"));
                }
                self.values
                    .get(self.slot(id.sequence)?)
                    .copied()
                    .filter(|r| r.address.length != 0)
                    .ok_or_else(|| invalid("unmaterialized journal reference"))
            }
        }
    }
    pub fn insert(&mut self, id: RecordId, reference: ObjectRef) -> io::Result<()> {
        if id.scope != self.scope || id.sequence == 0 {
            return Err(invalid("foreign journal reference"));
        }
        if reference.address.length == 0 {
            return Err(invalid("empty canonical reference"));
        }
        if self.recycling {
            let index = id.sequence as usize - 1;
            if self.remaining.get(index).copied().unwrap_or(0) == 0 {
                return Err(invalid("unselected journal reference"));
            }
            let slot = self.slots[index];
            if slot != 0 {
                if self.values[slot as usize - 1] != reference {
                    return Err(invalid("journal record remapped twice"));
                }
                return Ok(());
            }
            let slot = if let Some(slot) = self.free.pop() {
                self.values[slot as usize - 1] = reference;
                slot
            } else {
                self.values.push(reference);
                self.values.len() as u32
            };
            self.slots[index] = slot;
            return Ok(());
        }
        let index = self.slot(id.sequence)?;
        let slot = self
            .values
            .get_mut(index)
            .ok_or_else(|| invalid("journal materialization record limit"))?;
        if slot.address.length != 0 && *slot != reference {
            return Err(invalid("journal record remapped twice"));
        }
        *slot = reference;
        Ok(())
    }
    pub fn base_header_reads(&self) -> u64 {
        self.base.reads
    }
    /// Retire adapter state once its final root is resolved, before canonical
    /// publication allocates its own graph metadata. The immutable base pin
    /// remains held until this resolver is dropped.
    pub fn retire_mapping(&mut self) {
        self.values = Vec::new();
        self.slots = Vec::new();
        self.remaining = Vec::new();
        self.free = Vec::new();
    }
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut ObjectRef> {
        self.values.iter_mut().filter(|r| r.address.length != 0)
    }
}

pub enum Event<'a> {
    Object {
        id: RecordId,
        kind: u16,
        version: u16,
        body: &'a [u8],
        children: &'a [Reference],
    },
    Publication {
        generation: u64,
        root: Reference,
    },
}
pub struct JournalReader {
    file: io::BufReader<File>,
    scope: [u8; 16],
    offset: u64,
    end: u64,
    records: u64,
    seen: Seen,
    first_base: u64,
    end_base: u64,
    frame: Vec<u8>,
    children: Vec<Reference>,
    windows: [ReadWindow; 2],
    clock: u64,
}
#[derive(Default)]
struct ReadWindow {
    start: u64,
    age: u64,
    bytes: Vec<u8>,
}
impl JournalReader {
    pub fn scope(&self) -> [u8; 16] {
        self.scope
    }
    pub fn open(path: &Path, base_path: &Path) -> io::Result<Self> {
        Self::open_bound(path, &Base::open(base_path)?)
    }
    pub fn open_bound(path: &Path, base: &Base) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let end = file.metadata()?.len();
        let mut header = [0; FILE_HEADER];
        file.read_exact(&mut header)?;
        if &header[..8] != b"SACJTRY3"
            || header[24..116] != base.binding
            || header[116..124].iter().any(|b| *b != 0)
            || !checksum(!0, &header[..124])
                != u32::from_le_bytes(header[124..].try_into().unwrap())
        {
            return Err(invalid("journal header"));
        }
        Ok(Self {
            file: io::BufReader::with_capacity(0, file),
            scope: header[8..24].try_into().unwrap(),
            offset: FILE_HEADER as u64,
            end,
            records: 0,
            seen: Seen::new(MAX_RECORDS),
            first_base: base.first,
            end_base: base.end,
            frame: Vec::new(),
            children: Vec::new(),
            windows: Default::default(),
            clock: 0,
        })
    }
    fn reference(&self, bytes: &[u8], hints: &mut &[u8], before: u64) -> io::Result<Reference> {
        let r = decoded_reference(bytes, hints, self.scope, before.saturating_sub(1))?;
        match r {
            Reference::Local(id) if !self.seen.get(id.sequence as usize - 1) => {
                Err(invalid("journal physical forward reference"))
            }
            Reference::Base(reference)
                if reference.address.offset < self.first_base
                    || reference.address.length < 56
                    || !reference.address.length.is_multiple_of(8)
                    || reference
                        .address
                        .offset
                        .checked_add(u64::from(reference.address.length))
                        .is_none_or(|n| n > self.end_base) =>
            {
                Err(invalid("base handle bounds"))
            }
            _ => Ok(r),
        }
    }
    fn length(&self, header: &[u8], offset: u64) -> io::Result<usize> {
        let length = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
        if !(HEADER..=MAX_RECORD).contains(&length)
            || !length.is_multiple_of(8)
            || offset < FILE_HEADER as u64
            || offset
                .checked_add(length as u64)
                .is_none_or(|n| n > self.end)
        {
            return Err(invalid("journal frame bounds"));
        }
        Ok(length)
    }
    fn event(&mut self) -> io::Result<Event<'_>> {
        check_frame(&mut self.frame)?;
        let header = &self.frame[..HEADER];
        let length = self.frame.len();
        let sequence = u64::from_le_bytes(header[8..16].try_into().unwrap());
        if &header[..4] == b"SJc1" {
            if length < HEADER + REF_BYTES || header[16..28].iter().any(|b| *b != 0) {
                return Err(invalid("journal publication shape"));
            }
            let mut hints = &self.frame[HEADER + REF_BYTES..];
            let root = self.reference(
                &self.frame[HEADER..HEADER + REF_BYTES],
                &mut hints,
                self.records + 1,
            )?;
            let used = length - hints.len();
            if used.next_multiple_of(8) != length || hints.iter().any(|b| *b != 0) {
                return Err(invalid("journal publication hints"));
            }
            return Ok(Event::Publication {
                generation: sequence,
                root,
            });
        }
        if &header[..4] != b"SJr1"
            || sequence == 0
            || sequence > MAX_RECORDS as u64
            || self.seen.get(sequence as usize - 1)
        {
            return Err(invalid("journal record sequence"));
        }
        let kind = u16::from_le_bytes(header[16..18].try_into().unwrap());
        let version = u16::from_le_bytes(header[18..20].try_into().unwrap());
        let count = u32::from_le_bytes(header[20..24].try_into().unwrap()) as usize;
        let size = u32::from_le_bytes(header[24..28].try_into().unwrap()) as usize;
        let start = count
            .checked_mul(REF_BYTES)
            .and_then(|n| n.checked_add(HEADER))
            .ok_or_else(|| invalid("journal child table size"))?;
        if count > sac::v1::MAX_CHILDREN
            || start > length
            || 8 + 32 * count + size > sac::v1::MAX_CHUNK_SIZE
        {
            return Err(invalid("journal canonical bounds"));
        }
        self.children.clear();
        let mut hints = &self.frame[start..];
        for child in self.frame[HEADER..start].chunks_exact(REF_BYTES) {
            self.children
                .push(self.reference(child, &mut hints, sequence)?);
        }
        let start = length - hints.len();
        if start
            .checked_add(size)
            .is_none_or(|end| end.next_multiple_of(8) != length)
            || self.frame[start + size..].iter().any(|b| *b != 0)
        {
            return Err(invalid("journal identity hints or padding"));
        }
        self.records = self.records.max(sequence);
        self.seen.insert(sequence as usize - 1);
        Ok(Event::Object {
            id: RecordId {
                scope: self.scope,
                sequence,
            },
            kind,
            version,
            body: &self.frame[start..start + size],
            children: &self.children,
        })
    }
    pub fn release_buffers(&mut self) {
        self.frame = Vec::new();
        self.children = Vec::new();
        for window in &mut self.windows {
            window.bytes = Vec::new();
        }
    }
    pub fn position(&self) -> u64 {
        self.offset
    }
    pub fn next(&mut self) -> io::Result<Option<Event<'_>>> {
        if self.offset == self.end {
            return Ok(None);
        }
        if self.file.capacity() == 0 {
            self.file = io::BufReader::with_capacity(BUFFER, self.file.get_ref().try_clone()?);
            self.file.seek(SeekFrom::Start(self.offset))?;
        }
        let mut header = [0; HEADER];
        self.file.read_exact(&mut header)?;
        let length = self.length(&header, self.offset)?;
        self.frame.clear();
        self.frame.extend_from_slice(&header);
        self.frame.resize(length, 0);
        self.file.read_exact(&mut self.frame[HEADER..])?;
        self.offset += length as u64;
        self.event().map(Some)
    }
    // Two bounded windows follow interleaved ordinary and transient records.
    // Logical ordering restores the original canonical append layout without
    // copying or sorting the payloads themselves into another temporary file.
    fn cached_read(&mut self, mut offset: u64, out: &mut [u8]) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        let mut copied = 0;
        while copied < out.len() {
            let slot = if let Some(slot) = self
                .windows
                .iter()
                .position(|w| offset >= w.start && offset < w.start + w.bytes.len() as u64)
            {
                slot
            } else {
                let slot = usize::from(self.windows[0].age > self.windows[1].age);
                let w = &mut self.windows[slot];
                w.start = offset / BUFFER as u64 * BUFFER as u64;
                w.bytes
                    .resize((self.end - w.start).min(BUFFER as u64) as usize, 0);
                self.file.get_ref().read_exact_at(&mut w.bytes, w.start)?;
                slot
            };
            self.clock += 1;
            let w = &mut self.windows[slot];
            w.age = self.clock;
            let first = (offset - w.start) as usize;
            let n = (out.len() - copied).min(w.bytes.len() - first);
            out[copied..copied + n].copy_from_slice(&w.bytes[first..first + n]);
            copied += n;
            offset += n as u64;
        }
        Ok(())
    }
    /// Read a verified retained-record offset, in ascending logical ID order.
    /// A fresh reader is required; physical and ordered iteration cannot mix.
    pub fn object_at(&mut self, offset: u64) -> io::Result<Event<'_>> {
        if offset < FILE_HEADER as u64
            || offset
                .checked_add(HEADER as u64)
                .is_none_or(|n| n > self.end)
        {
            return Err(invalid("journal frame offset"));
        }
        let mut header = [0; HEADER];
        self.cached_read(offset, &mut header)?;
        let length = self.length(&header, offset)?;
        let mut frame = std::mem::take(&mut self.frame);
        frame.clear();
        frame.extend_from_slice(&header);
        frame.resize(length, 0);
        self.cached_read(offset + HEADER as u64, &mut frame[HEADER..])?;
        self.frame = frame;
        if &header[..4] != b"SJr1" {
            return Err(invalid("expected journal object"));
        }
        self.event()
    }
}

/// Reachability from the last complete publication. Logical backward IDs
/// permit one reverse pass even when transient nodes reach disk out of order.
pub struct RetainedRecords {
    pub selected: Vec<bool>,
    pub offsets: Vec<u64>,
    pub uses: Vec<u32>,
    pub generation: u64,
    pub root: Reference,
    pub total_payload_bytes: u64,
    pub retained_payload_bytes: u64,
}
pub fn retained_records(path: &Path, base_path: &Path) -> io::Result<RetainedRecords> {
    retained_records_bound(path, &Base::open(base_path)?)
}
pub fn retained_records_bound(path: &Path, base: &Base) -> io::Result<RetainedRecords> {
    let mut reader = JournalReader::open_bound(path, base)?;
    let mut edges = Vec::with_capacity(16_384);
    let mut rows = Vec::with_capacity(4096);
    let mut offsets = Vec::with_capacity(4096);
    let mut base_edges = 0usize;
    let mut root = None;
    let mut generation = 0;
    let mut total_payload_bytes = 0;
    // Independently bounded metadata; no payload-sized in-memory graph.
    const MAX_LOCAL_EDGES: usize = 1_000_000;
    loop {
        let offset = reader.position();
        let Some(event) = reader.next()? else { break };
        match event {
            Event::Object {
                id, body, children, ..
            } => {
                let index = id.sequence() as usize - 1;
                if rows.len() <= index {
                    rows.resize(index + 1, (0u32, 0u32, 0u32));
                    offsets.resize(index + 1, 0);
                }
                let first = edges.len();
                for child in children {
                    if let Reference::Local(id) = child {
                        if edges.len() == MAX_LOCAL_EDGES {
                            return Err(invalid("journal retirement edge limit"));
                        }
                        edges.push(id.sequence() as u32 - 1);
                    } else {
                        base_edges += 1;
                        if base_edges > MAX_LOCAL_EDGES {
                            return Err(invalid("base reference edge limit"));
                        }
                    }
                }
                let bytes = (8 + 32 * children.len() + body.len()) as u64;
                rows[index] = (first as u32, edges.len() as u32, bytes as u32);
                offsets[index] = offset;
                total_payload_bytes += bytes;
            }
            Event::Publication {
                generation: next,
                root: reference,
            } => {
                if next <= generation {
                    return Err(invalid("journal publication order"));
                }
                generation = next;
                root = Some(reference);
            }
        }
    }
    let root = root.ok_or_else(|| invalid("journal has no publication"))?;
    let mut selected = vec![false; rows.len()];
    let mut uses = vec![0u32; rows.len()];
    if let Reference::Local(id) = root {
        selected[id.sequence() as usize - 1] = true;
        uses[id.sequence() as usize - 1] = 1;
    }
    let mut retained_payload_bytes = 0;
    for index in (0..rows.len()).rev() {
        if selected[index] {
            let (first, end, bytes) = rows[index];
            retained_payload_bytes += u64::from(bytes);
            for child in &edges[first as usize..end as usize] {
                selected[*child as usize] = true;
                uses[*child as usize] += 1;
            }
        }
    }
    Ok(RetainedRecords {
        selected,
        offsets,
        uses,
        generation,
        root,
        total_payload_bytes,
        retained_payload_bytes,
    })
}

/// Publication-local native map nodes. Resident bodies stay private until
/// selected. Overflow resolves descendants and spills immutable journal records
/// once; reachability excludes dead spilled records during materialization.
/// The replay supplies the exact original map bodies, preserving page cuts.
/// This is not an alternate canonical ObjectStore identity implementation.
pub struct TransientJournal {
    journal: Journal,
    next_ordinal: u64,
    finished: bool,
    nodes: Vec<TransientNode>,
    resident: Vec<u8>,
    resident_limit: usize,
    spill_children: Vec<Reference>,
    frame: Vec<u8>,
    children: Vec<Reference>,
    pending: Vec<usize>,
    order: Vec<usize>,
    pub statistics: TransientStatistics,
}
const STAGED: u64 = 1 << 62;
#[derive(Clone, Copy)]
struct TransientNode {
    ordinal: u64,
    position: u64,
    resolved: u64,
    size: u32,
    children_bytes: u32,
    children: u16,
    kind: u16,
    version: u16,
    selected: bool,
}
#[derive(Default, Debug)]
pub struct TransientStatistics {
    pub staged: u64,
    pub omitted: u64,
    pub spilled_bytes: u64,
    pub peak_allocated_bytes: u64,
}
impl TransientJournal {
    pub fn create(
        path: &Path,
        base: &Path,
        scope: [u8; 16],
        max_records: usize,
        resident_limit: usize,
    ) -> io::Result<Self> {
        if resident_limit > 1024 * 1024 {
            return Err(invalid("transient resident bound"));
        }
        Ok(Self {
            journal: Journal::create(path, base, scope, max_records, 4096)?,
            next_ordinal: 1,
            finished: false,
            nodes: Vec::with_capacity(4096),
            resident: Vec::with_capacity(resident_limit),
            resident_limit,
            spill_children: Vec::new(),
            frame: Vec::new(),
            children: Vec::new(),
            pending: Vec::new(),
            order: Vec::new(),
            statistics: Default::default(),
        })
    }
    pub fn existing(&mut self, reference: ObjectRef) -> io::Result<Reference> {
        self.journal.existing(reference)
    }
    pub fn base_hint(&self, reference: ObjectRef) -> io::Result<Reference> {
        self.journal.base_hint(reference)
    }
    pub fn journal_statistics(&self) -> &Statistics {
        &self.journal.statistics
    }
    pub fn length(&self) -> u64 {
        self.journal.length()
    }
    fn staged(&self, reference: Reference) -> io::Result<Option<usize>> {
        if let Reference::Local(id) = reference {
            if id.scope != self.journal.scope {
                return Err(invalid("foreign transient reference"));
            }
            if id.sequence & STAGED != 0 {
                let index = (id.sequence & !STAGED) as usize;
                let node = self
                    .nodes
                    .get(index)
                    .ok_or_else(|| invalid("transient reference bounds"))?;
                if node.resolved == u64::MAX {
                    return Err(invalid("retired transient reference"));
                }
                return Ok(Some(index));
            }
        }
        self.journal.check_reference(reference)?;
        Ok(None)
    }
    fn load(&mut self, index: usize, children_only: bool) -> io::Result<()> {
        let node = self.nodes[index];
        let size = if children_only {
            node.children_bytes as usize
        } else {
            node.size as usize
        };
        self.frame.resize(size, 0);
        if size == 0 {
            return Ok(());
        }
        let start = node.position as usize;
        self.frame
            .copy_from_slice(&self.resident[start..start + size]);
        Ok(())
    }
    fn resolve(&mut self, reference: Reference) -> io::Result<Reference> {
        let Some(root) = self.staged(reference)? else {
            return Ok(reference);
        };
        if self.nodes[root].resolved == 0 {
            self.pending.clear();
            self.order.clear();
            self.nodes[root].selected = true;
            self.pending.push(root);
            while let Some(index) = self.pending.pop() {
                if self.nodes[index].resolved != 0 {
                    continue;
                }
                self.nodes[index].selected = true;
                self.order.push(index);
                self.load(index, true)?;
                let count = self.nodes[index].children as usize;
                let handles_end = count * REF_BYTES;
                let mut hints = &self.frame[handles_end..];
                for child in 0..count {
                    let reference = decoded_reference(
                        &self.frame[child * 8..child * 8 + 8],
                        &mut hints,
                        self.journal.scope,
                        u64::MAX / 2,
                    )?;
                    if let Some(child) = self.staged(reference)? {
                        if child >= index {
                            return Err(invalid("transient forward reference"));
                        }
                        if self.nodes[child].resolved == 0 && !self.nodes[child].selected {
                            self.nodes[child].selected = true;
                            self.pending.push(child);
                        }
                    }
                }
            }
            // Original node IDs already form a topological order. Materialize
            // only the selected closure; shared descendants are resolved once.
            self.order.sort_unstable();
            for ordinal in 0..self.order.len() {
                let index = self.order[ordinal];
                let node = self.nodes[index];
                self.load(index, false)?;
                self.children.clear();
                let mut hints =
                    &self.frame[node.children as usize * REF_BYTES..node.children_bytes as usize];
                for child in self.frame[..node.children as usize * 8].chunks_exact(8) {
                    let reference =
                        decoded_reference(child, &mut hints, self.journal.scope, u64::MAX / 2)?;
                    let resolved = if let Reference::Local(id) = reference
                        && id.sequence & STAGED != 0
                    {
                        let child = (id.sequence & !STAGED) as usize;
                        let value = self.nodes[child].resolved;
                        if value == 0 || value == u64::MAX {
                            return Err(invalid("unresolved transient edge"));
                        }
                        decoded_reference(
                            &value.to_le_bytes(),
                            &mut &[][..],
                            self.journal.scope,
                            self.journal.records,
                        )?
                    } else {
                        reference
                    };
                    self.children.push(resolved);
                }
                let body = &self.frame[node.children_bytes as usize..];
                let written = self.journal.put_numbered(
                    node.ordinal,
                    node.kind,
                    node.version,
                    body,
                    &self.children,
                )?;
                self.nodes[index].resolved =
                    u64::from_le_bytes(encoded_reference(written, self.journal.scope)?);
            }
        }
        decoded_reference(
            &self.nodes[root].resolved.to_le_bytes(),
            &mut &[][..],
            self.journal.scope,
            self.journal.records,
        )
    }
    pub fn put(
        &mut self,
        kind: u16,
        version: u16,
        body: &[u8],
        children: &[Reference],
    ) -> io::Result<Reference> {
        if self.finished {
            return Err(invalid("transient writer finished"));
        }
        let ordinal = self.next_ordinal;
        if ordinal > self.journal.max_records as u64 {
            return Err(invalid("transient record limit"));
        }
        self.next_ordinal += 1;
        let transient = matches!(kind, 4096 | 4097)
            || children
                .iter()
                .any(|r| matches!(r, Reference::Local(id) if id.sequence & STAGED != 0));
        if !transient {
            return self
                .journal
                .put_numbered(ordinal, kind, version, body, children);
        }
        if children.len() > sac::v1::MAX_CHILDREN
            || 8 + 32 * children.len() + body.len() > sac::v1::MAX_CHUNK_SIZE
            || self.nodes.len() == 100_000
        {
            return Err(invalid("transient map bounds"));
        }
        self.statistics.staged += 1;
        let bytes = children.len() * REF_BYTES
            + children
                .iter()
                .filter(|child| matches!(child, Reference::Base(_)))
                .count()
                * 36
            + body.len();
        if bytes > self.resident_limit - self.resident.len() {
            // Spill immutable wire records directly into the journal. Resolve
            // their private descendants first, then write this body once. A
            // publication syncs its closure; latest-root retirement excludes
            // spilled records that never become reachable. No second payload
            // copy or separate anonymous map-spill file is needed.
            let mut resolved = std::mem::take(&mut self.spill_children);
            resolved.clear();
            for child in children {
                resolved.push(self.resolve(*child)?);
            }
            let before = self.journal.length();
            let written = self
                .journal
                .put_numbered(ordinal, kind, version, body, &resolved);
            self.spill_children = resolved;
            self.statistics.spilled_bytes += self.journal.length() - before;
            return written;
        }
        self.frame.clear();
        for child in children {
            self.staged(*child)?;
            self.frame
                .extend_from_slice(&encoded_reference(*child, self.journal.scope)?);
        }
        append_hints(&mut self.frame, children);
        let children_bytes = self.frame.len() as u32;
        self.frame.extend_from_slice(body);
        let position = self.resident.len() as u64;
        self.resident.extend_from_slice(&self.frame);
        let index = self.nodes.len();
        self.nodes.push(TransientNode {
            ordinal,
            position,
            resolved: 0,
            size: self.frame.len() as u32,
            children_bytes,
            children: children.len() as u16,
            kind,
            version,
            selected: false,
        });
        Ok(Reference::Local(RecordId {
            scope: self.journal.scope,
            sequence: STAGED | index as u64,
        }))
    }
    pub fn publish(&mut self, generation: u64, root: Reference) -> io::Result<()> {
        if self.finished {
            return Err(invalid("transient writer finished"));
        }
        let root = self.resolve(root)?;
        self.journal.publish(generation, root)?;
        Ok(())
    }
    /// Drop caller-private nodes only when the writer is finished. An object
    /// not selected by one publication can still be held by the producer and
    /// selected by a later publication; it cannot be retired at publish time.
    pub fn finish(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        self.journal.flush()?;
        for node in &mut self.nodes {
            if node.resolved == 0 {
                node.resolved = u64::MAX;
                self.statistics.omitted += 1;
            }
        }
        use std::os::unix::fs::MetadataExt;
        let allocated = self.journal.file.metadata()?.blocks() * 512;
        self.resident.clear();
        self.statistics.peak_allocated_bytes = self.statistics.peak_allocated_bytes.max(allocated);
        self.finished = true;
        Ok(())
    }
    pub fn flush(&mut self) -> io::Result<()> {
        self.journal.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sac::ObjectStore;
    fn base(dir: &Path, name: &str, incarnation: u8) -> (std::path::PathBuf, ObjectRef) {
        let path = dir.join(name);
        let mut store = sac::NativeStore::create_live(&path, [incarnation; 16]).unwrap();
        let blob = store.put(7, 1, b"immutable base payload", &[]).unwrap();
        use sac::v1::cbor::{self, Value as V};
        let len = b"immutable base payload".len() as u64;
        let extent = store
            .put(
                5,
                1,
                &cbor::encode(&V::Array(vec![V::Array(vec![V::Uint(len), V::Uint(0)])])),
                &[blob],
            )
            .unwrap();
        let row = V::Array(vec![
            V::Bytes(b"file".to_vec()),
            V::Uint(0),
            V::Map(vec![]),
            V::Array(vec![V::Uint(len), V::Uint(1), V::Uint(0)]),
        ]);
        let directory = store
            .put(3, 1, &cbor::encode(&V::Array(vec![row])), &[extent])
            .unwrap();
        let snapshot = store
            .put(2, 1, &[0x83, 0, 0x80, 0x80], &[directory])
            .unwrap();
        store.publish(snapshot).unwrap();
        drop(store);
        (path, blob)
    }
    #[test]
    fn eight_byte_handles_bind_base_and_scope_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let (base, blob) = base(dir.path(), "base", 1);
        let path = dir.path().join("journal");
        let mut writer = Journal::create(&path, &base, [2; 16], 128, 8).unwrap();
        let existing = writer.existing(blob).unwrap();
        assert_eq!(encoded_reference(existing, [2; 16]).unwrap().len(), 8);
        let child = writer.put(7, 1, b"new", &[]).unwrap();
        let root = writer.put(4096, 1, b"map", &[existing, child]).unwrap();
        assert_eq!(writer.length(), (FILE_HEADER + 40 + 88) as u64);
        assert_eq!(
            writer.put(4096, 1, b"map", &[existing, child]).unwrap(),
            root
        );
        assert!(
            writer
                .reuse(Reference::Local(RecordId {
                    scope: [3; 16],
                    sequence: 1
                }))
                .is_err()
        );
        assert!(
            writer
                .existing(ObjectRef {
                    hash: ObjectHash([0; 32]),
                    ..blob
                })
                .is_err()
        );
        writer.publish(2, root).unwrap();
        drop(writer);
        let mut reader = JournalReader::open(&path, &base).unwrap();
        let mut material = MaterializedReferences::new([2; 16], 2, &base).unwrap();
        material
            .insert(
                RecordId {
                    scope: [2; 16],
                    sequence: 1,
                },
                blob,
            )
            .unwrap();
        assert!(matches!(
            reader.next().unwrap(),
            Some(Event::Object { kind: 7, .. })
        ));
        let Some(Event::Object { children, .. }) = reader.next().unwrap() else {
            panic!()
        };
        assert_eq!(material.resolve(children[0]).unwrap(), blob);
        assert_eq!(material.resolve(children[1]).unwrap(), blob);
        assert!(matches!(
            reader.next().unwrap(),
            Some(Event::Publication { generation: 2, .. })
        ));
        assert!(reader.next().unwrap().is_none());
        let (other, _) = self::base(dir.path(), "other", 4);
        assert!(JournalReader::open(&path, &other).is_err());
    }
    #[test]
    fn transient_shared_graph_omits_dead_nodes_and_preserves_earlier_publications() {
        for resident in [0, 64 * 1024] {
            let dir = tempfile::tempdir().unwrap();
            let (base, _) = base(dir.path(), "base", 1);
            let path = dir.path().join("journal");
            let mut writer =
                TransientJournal::create(&path, &base, [9; 16], 10000, resident).unwrap();
            let shared = writer.put(4096, 1, b"shared", &[]).unwrap();
            let dead = writer.put(4096, 1, b"dead", &[]).unwrap();
            let leaf = writer.put(4096, 1, b"live leaf", &[shared]).unwrap();
            let branch = writer.put(4097, 1, b"branch", &[shared, leaf]).unwrap();
            let root = writer.put(65000, 1, b"root", &[branch]).unwrap();
            writer.publish(2, root).unwrap();
            assert_eq!(writer.statistics.omitted, 0);
            let late = writer.put(4097, 1, b"late", &[dead]).unwrap();
            writer.put(4096, 1, b"orphan", &[]).unwrap();
            let fresh = writer.put(4096, 1, b"fresh", &[shared]).unwrap();
            let root = writer.put(65000, 1, b"root2", &[fresh, late]).unwrap();
            writer.publish(3, root).unwrap();
            writer.finish().unwrap();
            assert_eq!(writer.statistics.omitted, u64::from(resident != 0));
            drop(writer);
            let selected = retained_records(&path, &base).unwrap();
            assert_eq!(selected.generation, 3);
            assert_eq!(selected.selected.iter().filter(|x| **x).count(), 5);
            let mut reader = JournalReader::open(&path, &base).unwrap();
            let mut objects = 0;
            let mut pubs = 0;
            while let Some(event) = reader.next().unwrap() {
                match event {
                    Event::Object { body, .. } => {
                        if resident != 0 {
                            assert_ne!(body, b"orphan");
                        }
                        objects += 1
                    }
                    Event::Publication { .. } => pubs += 1,
                }
            }
            assert_eq!((objects, pubs), (if resident == 0 { 9 } else { 8 }, 2));
        }
    }
    #[test]
    fn sampled_collisions_compare_complete_body_and_edges() {
        let dir = tempfile::tempdir().unwrap();
        let (base, _) = base(dir.path(), "base", 1);
        let path = dir.path().join("journal");
        let mut writer = Journal::create(&path, &base, [1; 16], 100, 1).unwrap();
        let a = writer.put(7, 1, b"a", &[]).unwrap();
        let b = writer.put(7, 1, b"b", &[]).unwrap();
        let mut body = vec![0; 100_000];
        let one = writer.put(65000, 1, &body, &[a, a, a, a]).unwrap();
        writer.flush().unwrap();
        body[1000] = 1;
        let two = writer.put(65000, 1, &body, &[a, a, a, a]).unwrap();
        assert_ne!(one, two);
        assert_eq!(writer.put(65000, 1, &body, &[a, a, a, a]).unwrap(), two);
        assert_ne!(writer.put(65000, 1, &body, &[a, b, a, a]).unwrap(), two);
    }
    #[test]
    fn corruption_truncation_forward_and_alignment_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (base, _) = base(dir.path(), "base", 1);
        let path = dir.path().join("journal");
        let mut writer = Journal::create(&path, &base, [1; 16], 10, 8).unwrap();
        let root = writer.put(7, 1, b"x", &[]).unwrap();
        writer.publish(2, root).unwrap();
        drop(writer);
        assert!(decoded_reference(&3u64.to_le_bytes(), &mut &[][..], [1; 16], 0).is_err());
        assert!(decoded_reference(&2u64.to_le_bytes(), &mut &[][..], [1; 16], 10).is_err());
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::Start(FILE_HEADER as u64 + HEADER as u64))
            .unwrap();
        file.write_all(b"z").unwrap();
        assert!(JournalReader::open(&path, &base).unwrap().next().is_err());
        file.set_len(FILE_HEADER as u64 + 1).unwrap();
        assert!(JournalReader::open(&path, &base).unwrap().next().is_err());
    }
    #[test]
    fn logical_order_restores_interleaved_large_objects_and_sparse_ids() {
        let dir = tempfile::tempdir().unwrap();
        let (base, _) = base(dir.path(), "base", 1);
        let path = dir.path().join("journal");
        let mut writer = TransientJournal::create(&path, &base, [7; 16], 128, 256 * 1024).unwrap();
        let a = writer.put(4096, 1, &vec![0xa5; 100_000], &[]).unwrap();
        writer.put(4096, 1, b"unused", &[]).unwrap();
        let b = writer.put(7, 1, &vec![0xb5; 100_000], &[]).unwrap();
        let c = writer.put(4097, 1, b"c", &[a, b]).unwrap();
        let d = writer.put(7, 1, b"d", &[]).unwrap();
        let root = writer.put(65000, 1, b"root", &[c, d]).unwrap();
        writer.publish(2, root).unwrap();
        writer.finish().unwrap();
        drop(writer);
        let retained = retained_records(&path, &base).unwrap();
        assert_eq!(retained.selected, [true, false, true, true, true, true]);
        assert_eq!(retained.offsets[1], 0);
        let mut reader = JournalReader::open(&path, &base).unwrap();
        let mut ids = Vec::new();
        for (index, selected) in retained.selected.iter().enumerate() {
            if *selected {
                let Event::Object { id, body, .. } =
                    reader.object_at(retained.offsets[index]).unwrap()
                else {
                    panic!()
                };
                if index == 0 {
                    assert_eq!(body, vec![0xa5; 100_000]);
                }
                if index == 2 {
                    assert_eq!(body, vec![0xb5; 100_000]);
                }
                ids.push(id.sequence());
            }
        }
        assert_eq!(ids, [1, 3, 4, 5, 6]);
        reader.release_buffers();
        assert!(reader.object_at(retained.offsets[0]).is_err());
        assert!(reader.object_at(u64::MAX).is_err());
    }
    #[test]
    fn deep_shared_graph_is_iterative_and_enforces_record_budget() {
        let dir = tempfile::tempdir().unwrap();
        let (base, _) = base(dir.path(), "base", 1);
        let path = dir.path().join("journal");
        let mut writer =
            TransientJournal::create(&path, &base, [1; 16], 10_000, 1024 * 1024).unwrap();
        let shared = writer.put(4096, 1, b"leaf", &[]).unwrap();
        let mut root = shared;
        for n in 1u64..10_000 {
            root = writer
                .put(4097, 1, &n.to_le_bytes(), &[root, shared])
                .unwrap();
        }
        assert!(writer.put(4096, 1, b"over limit", &[]).is_err());
        writer.publish(2, root).unwrap();
        writer.finish().unwrap();
        drop(writer);
        let retained = retained_records(&path, &base).unwrap();
        assert_eq!(retained.selected.iter().filter(|x| **x).count(), 10_000);
    }
    #[test]
    fn checksum_matches_bitwise_reference_at_word_and_buffer_boundaries() {
        let bytes: Vec<_> = (0..=BUFFER + 1)
            .map(|n| (n.wrapping_mul(71)) as u8)
            .collect();
        for len in [
            0,
            1,
            7,
            8,
            9,
            31,
            32,
            33,
            255,
            256,
            257,
            BUFFER - 1,
            BUFFER,
            BUFFER + 1,
        ] {
            let mut crc = !0u32;
            for byte in &bytes[..len] {
                crc ^= u32::from(*byte);
                for _ in 0..8 {
                    crc = (crc >> 1) ^ (0x82f63b78 & 0u32.wrapping_sub(crc & 1));
                }
            }
            assert_eq!(checksum(!0, &bytes[..len]), crc);
        }
    }
    #[test]
    fn base_headers_hints_and_offset_index_preserve_exact_identities() {
        let dir = tempfile::tempdir().unwrap();
        let (path, blob) = base(dir.path(), "base", 1);
        let mut admitted = Base::open(&path).unwrap();
        assert_eq!(admitted.reference(blob.address.offset).unwrap(), blob);
        assert!(admitted.check_hint(blob).is_ok());
        assert!(admitted.check_offset(u64::MAX).is_err());
        let mut index = OffsetReferences::new(10).unwrap();
        index.insert(100, Reference::Base(blob)).unwrap();
        index.insert(200, Reference::Base(blob)).unwrap();
        assert_eq!(index.get(100).unwrap(), Reference::Base(blob));
        assert!(index.get(101).is_err());
        assert!(index.insert(200, Reference::Base(blob)).is_err());
        assert!(index.insert(199, Reference::Base(blob)).is_err());
    }
    #[test]
    fn base_hints_survive_transient_spill_and_do_not_bypass_authentication() {
        for resident in [0, BUFFER] {
            let dir = tempfile::tempdir().unwrap();
            let (base, blob) = base(dir.path(), "base", 1);
            let path = dir.path().join("journal");
            let forged = ObjectRef {
                hash: ObjectHash([0xa5; 32]),
                ..blob
            };
            let mut writer =
                TransientJournal::create(&path, &base, [2; 16], 100, resident).unwrap();
            let hint = writer.base_hint(forged).unwrap();
            let node = writer.put(4096, 1, b"base hint", &[hint]).unwrap();
            writer.publish(2, node).unwrap();
            let root = writer.base_hint(blob).unwrap();
            writer.publish(3, root).unwrap();
            writer.finish().unwrap();
            drop(writer);
            let mut reader = JournalReader::open(&path, &base).unwrap();
            let Some(Event::Object { children, body, .. }) = reader.next().unwrap() else {
                panic!()
            };
            assert_eq!(children, [Reference::Base(forged)]);
            assert_eq!(body, b"base hint");
            let mut refs = MaterializedReferences::new([2; 16], 1, &base).unwrap();
            let hinted = refs.resolve(children[0]).unwrap();
            let mut store = sac::NativeStore::open(&base, true).unwrap();
            assert!(store.put(65000, 1, b"good", &[blob]).is_ok());
            assert!(store.put(65000, 1, b"bad", &[hinted]).is_err());
            assert!(matches!(
                reader.next().unwrap(),
                Some(Event::Publication { generation: 2, .. })
            ));
            let Some(Event::Publication {
                generation: 3,
                root,
            }) = reader.next().unwrap()
            else {
                panic!()
            };
            assert_eq!(root, Reference::Base(blob));
            assert!(reader.next().unwrap().is_none());
        }
    }
    #[test]
    fn lifetime_slots_recycle_only_after_the_last_duplicate_or_shared_edge() {
        let dir = tempfile::tempdir().unwrap();
        let (path, blob) = base(dir.path(), "base", 1);
        let mut refs = MaterializedReferences::with_lifetimes(
            [3; 16],
            vec![3, 1, 1],
            Base::open(&path).unwrap(),
        )
        .unwrap();
        let id = |sequence| RecordId {
            scope: [3; 16],
            sequence,
        };
        let child = Reference::Local(id(1));
        refs.insert(id(1), blob).unwrap();
        refs.release_children(&[child, child]).unwrap();
        assert_eq!(refs.resolve(child).unwrap(), blob);
        refs.insert(id(2), blob).unwrap();
        assert_eq!(refs.values.len(), 2);
        refs.release_children(&[child, Reference::Local(id(2))])
            .unwrap();
        assert!(refs.resolve(child).is_err());
        refs.insert(id(3), blob).unwrap();
        assert_eq!(refs.values.len(), 2);
        assert_eq!(refs.resolve(Reference::Local(id(3))).unwrap(), blob);
        assert!(refs.release_children(&[child]).is_err());
        refs.retire_mapping();
        assert!(refs.resolve(Reference::Local(id(3))).is_err());
        assert_eq!(refs.resolve(Reference::Base(blob)).unwrap(), blob);
    }
    #[test]
    fn numbered_records_reject_duplicates_holes_and_logical_forward_edges() {
        let dir = tempfile::tempdir().unwrap();
        let (base, _) = base(dir.path(), "base", 1);
        let path = dir.path().join("journal");
        let mut writer = Journal::create(&path, &base, [3; 16], 128, 1).unwrap();
        let later = writer.put_numbered(3, 7, 1, b"later", &[]).unwrap();
        assert!(writer.put_numbered(3, 7, 1, b"duplicate", &[]).is_err());
        assert!(writer.put_numbered(2, 7, 1, b"forward", &[later]).is_err());
        assert!(
            writer
                .reuse(Reference::Local(RecordId {
                    scope: [3; 16],
                    sequence: 2
                }))
                .is_err()
        );
        let first = writer.put_numbered(1, 7, 1, b"first", &[]).unwrap();
        let root = writer
            .put_numbered(4, 4097, 1, b"root", &[first, later])
            .unwrap();
        writer.publish(2, root).unwrap();
        drop(writer);
        let mut reader = JournalReader::open(&path, &base).unwrap();
        for expected in [3, 1, 4] {
            let Some(Event::Object { id, .. }) = reader.next().unwrap() else {
                panic!()
            };
            assert_eq!(id.sequence(), expected);
        }
        assert!(matches!(
            reader.next().unwrap(),
            Some(Event::Publication { .. })
        ));
    }
    #[cfg(feature = "allocations")]
    #[test]
    fn reference_frontier_reuses_one_slot_without_warmed_allocations() {
        let dir = tempfile::tempdir().unwrap();
        let (path, blob) = base(dir.path(), "base", 1);
        let mut refs = MaterializedReferences::with_lifetimes(
            [3; 16],
            vec![1; 10_000],
            Base::open(&path).unwrap(),
        )
        .unwrap();
        let measured = allocation_counter::measure(|| {
            for sequence in 1..=10_000 {
                let id = RecordId {
                    scope: [3; 16],
                    sequence,
                };
                refs.insert(id, blob).unwrap();
                assert_eq!(refs.resolve(Reference::Local(id)).unwrap(), blob);
                refs.release_children(&[Reference::Local(id)]).unwrap();
            }
        });
        assert_eq!(measured.count_total, 0, "{measured:?}");
        assert_eq!(refs.values.len(), 1);
    }
    #[cfg(feature = "allocations")]
    #[test]
    fn warmed_resident_and_spilled_graph_publications_allocate_zero() {
        for resident in [0, BUFFER] {
            let dir = tempfile::tempdir().unwrap();
            let (base, _) = base(dir.path(), "base", 1);
            let path = dir.path().join("journal");
            let mut writer =
                TransientJournal::create(&path, &base, [3; 16], 10_000, resident).unwrap();
            let append = |writer: &mut TransientJournal, generation: u64| {
                let mut root = writer.put(4096, 1, &generation.to_le_bytes(), &[]).unwrap();
                for n in 1u64..1000 {
                    root = writer.put(4097, 1, &n.to_le_bytes(), &[root]).unwrap();
                }
                writer.publish(generation, root).unwrap();
            };
            append(&mut writer, 2);
            let measured = allocation_counter::measure(|| append(&mut writer, 3));
            assert_eq!(measured.count_total, 0, "{measured:?}");
            writer.finish().unwrap();
            assert!(writer.put(4096, 1, b"finished", &[]).is_err());
        }
    }
    #[cfg(feature = "allocations")]
    #[test]
    fn warmed_transient_staging_and_raw_append_allocate_zero() {
        let dir = tempfile::tempdir().unwrap();
        let (base, _) = base(dir.path(), "base", 1);
        let path = dir.path().join("journal");
        let mut writer = TransientJournal::create(&path, &base, [1; 16], 10000, 64 * 1024).unwrap();
        let mut body = [0; 32];
        writer.put(4096, 1, &body, &[]).unwrap();
        writer.put(7, 1, &body, &[]).unwrap();
        let measured = allocation_counter::measure(|| {
            for n in 0u64..1000 {
                body[..8].copy_from_slice(&n.to_le_bytes());
                writer.put(4096, 1, &body, &[]).unwrap();
                writer.put(7, 1, &body, &[]).unwrap();
            }
            writer.flush().unwrap();
        });
        assert_eq!(measured.count_total, 0, "{measured:?}");
    }
}
