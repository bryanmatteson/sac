//! Explicit recovery. Only publication binding or an externally expected ID
//! chooses the recovered root. Candidate positions provide no authority.
use super::*;
use crate::v1::{ChunkAddress, LocatorPolicy, Preamble, ReadAt, Slot, Trailer, wire};
use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct SalvageReport {
    pub snapshot: ObjectRef,
    pub snapshot_id: ObjectHash,
    pub scanned_bytes: u64,
    pub candidates: u64,
    pub authority: String,
    pub selected_commit: Option<ObjectHash>,
    pub attachments_preserved: bool,
    pub repaired: bool,
}

pub fn salvage<R: ReadAt + ?Sized, D: ObjectStore + ?Sized>(
    source: &R,
    expected_snapshot: Option<ObjectHash>,
    destination: &mut D,
    limits: Limits,
) -> Result<SalvageReport> {
    let mut accounting = Accounting::new(limits.clone());
    let (wanted, authority, selected_commit) = if let Some(expected) = expected_snapshot {
        (expected, "externally-expected-snapshot".to_owned(), None)
    } else {
        authorized_snapshot(source, &mut accounting)?
    };
    let len = source.len()?;
    let temporary = tempfile::tempdir()?;
    let mut index = CandidateIndex {
        source,
        temporary,
        accounting: RefCell::new(accounting),
    };
    let mut offset = 0u64;
    let mut candidates = 0u64;
    let mut window = Vec::new();
    let mut window_start = 0u64;
    while offset
        .checked_add(wire::FRAME as u64)
        .is_some_and(|end| end <= len)
    {
        index.accounting.borrow().time()?;
        if offset < window_start || offset + wire::FRAME as u64 > window_start + window.len() as u64
        {
            let n = (len - offset).min(1024 * 1024) as usize;
            index.accounting.borrow_mut().read(n as u64)?;
            window.resize(n, 0);
            source.read_exact_at(offset, &mut window)?;
            window_start = offset;
        }
        let relative = (offset - window_start) as usize;
        let header = &window[relative..relative + wire::FRAME];
        if header.starts_with(b"SO1\0") {
            index.accounting.borrow_mut().attempt()?;
            if let Ok(span) = wire::frame_span(header)
                && offset
                    .checked_add(span as u64)
                    .is_some_and(|end| end <= len)
            {
                let hash = ObjectHash(header[16..48].try_into().unwrap());
                let r = ObjectRef {
                    hash,
                    address: ChunkAddress {
                        offset,
                        length: span as u32,
                    },
                };
                // Every candidate is verified, including candidates inside
                // another frame. Failed claims advance exactly eight bytes.
                match index.read_candidate(r) {
                    Ok(_) => {
                        index.insert(r)?;
                        candidates += 1;
                    }
                    Err(Error::Corrupt(_) | Error::Unsupported(_)) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        offset = offset
            .checked_add(8)
            .ok_or(Error::Limit("salvage scan offset"))?;
    }
    let snapshot = rebuild(&index, destination, wanted)?;
    let reader = ArchiveReader::open(destination, snapshot, limits)?;
    reader.verify()?;
    Ok(SalvageReport {
        snapshot,
        snapshot_id: wanted,
        scanned_bytes: len,
        candidates,
        authority,
        selected_commit,
        attachments_preserved: false,
        repaired: true,
    })
}

struct Accounting {
    limits: Limits,
    start: Instant,
    source: u64,
    decoded: u64,
    attempts: u64,
    temp: u64,
    edges: u64,
}
impl Accounting {
    fn new(limits: Limits) -> Self {
        Self {
            limits,
            start: Instant::now(),
            source: 0,
            decoded: 0,
            attempts: 0,
            temp: 0,
            edges: 0,
        }
    }
    fn time(&self) -> Result<()> {
        if self.start.elapsed() > self.limits.max_elapsed {
            Err(Error::Limit("salvage elapsed work"))
        } else {
            Ok(())
        }
    }
    fn read(&mut self, n: u64) -> Result<()> {
        self.time()?;
        charge(
            &mut self.source,
            n,
            self.limits.max_source_bytes,
            "salvage source bytes",
        )
    }
    fn attempt(&mut self) -> Result<()> {
        self.time()?;
        charge(
            &mut self.attempts,
            1,
            self.limits.max_frames,
            "salvage candidate attempts",
        )
    }
    fn decoded(&mut self, n: u64) -> Result<()> {
        charge(
            &mut self.decoded,
            n,
            self.limits.max_decoded_bytes,
            "salvage decoded bytes",
        )
    }
    fn temporary(&mut self, n: u64) -> Result<()> {
        charge(
            &mut self.temp,
            n,
            self.limits.max_temp_bytes,
            "salvage temporary storage",
        )
    }
    fn edge(&mut self) -> Result<()> {
        self.time()?;
        charge(
            &mut self.edges,
            1,
            self.limits.max_edges,
            "salvage dependency edges",
        )
    }
    fn memory(&self, bytes: usize) -> Result<()> {
        if bytes > self.limits.max_memory_bytes {
            Err(Error::Limit("salvage resident memory"))
        } else {
            Ok(())
        }
    }
}

struct CandidateIndex<'a, R: ReadAt + ?Sized> {
    source: &'a R,
    temporary: tempfile::TempDir,
    accounting: RefCell<Accounting>,
}
impl<R: ReadAt + ?Sized> CandidateIndex<'_, R> {
    fn path(&self, hash: ObjectHash) -> PathBuf {
        let hex = hex::encode(hash.0);
        self.temporary.path().join(&hex[..2]).join(&hex[2..])
    }
    fn insert(&mut self, reference: ObjectRef) -> Result<()> {
        let path = self.path(reference.hash);
        if path.exists() {
            return Ok(());
        }
        // Reserve disk blocks before creating either the bucket or row.
        self.accounting.borrow_mut().temporary(8192)?;
        std::fs::create_dir_all(path.parent().unwrap())?;
        match OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(mut file) => {
                file.write_all(&reference.address.offset.to_le_bytes())?;
                file.write_all(&reference.address.length.to_le_bytes())?;
                file.write_all(&[0; 13])?;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
    fn source_ref(&self, hash: ObjectHash) -> Result<ObjectRef> {
        let mut file = File::open(self.path(hash)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::Missing
            } else {
                e.into()
            }
        })?;
        let mut row = [0; 12];
        file.read_exact(&mut row)?;
        Ok(ObjectRef {
            hash,
            address: ChunkAddress {
                offset: u64::from_le_bytes(row[..8].try_into().unwrap()),
                length: u32::from_le_bytes(row[8..].try_into().unwrap()),
            },
        })
    }
    fn destination_ref(&self, hash: ObjectHash) -> Result<Option<ObjectRef>> {
        let mut file = File::open(self.path(hash)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::Missing
            } else {
                e.into()
            }
        })?;
        file.seek(SeekFrom::Start(12))?;
        let mut row = [0; 13];
        file.read_exact(&mut row)?;
        if row[0] != 1 {
            return Ok(None);
        }
        Ok(Some(ObjectRef {
            hash,
            address: ChunkAddress {
                offset: u64::from_le_bytes(row[1..9].try_into().unwrap()),
                length: u32::from_le_bytes(row[9..].try_into().unwrap()),
            },
        }))
    }
    fn active(&self, hash: ObjectHash) -> Result<bool> {
        let mut file = File::open(self.path(hash))?;
        file.seek(SeekFrom::Start(12))?;
        let mut status = [0];
        file.read_exact(&mut status)?;
        Ok(status[0] == 2)
    }
    fn mark_active(&self, hash: ObjectHash) -> Result<()> {
        let mut file = OpenOptions::new().write(true).open(self.path(hash))?;
        file.seek(SeekFrom::Start(12))?;
        file.write_all(&[2])?;
        Ok(())
    }
    fn completed(&self, reference: ObjectRef) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .open(self.path(reference.hash))?;
        file.seek(SeekFrom::Start(12))?;
        file.write_all(&[1])?;
        file.write_all(&reference.address.offset.to_le_bytes())?;
        file.write_all(&reference.address.length.to_le_bytes())?;
        Ok(())
    }
    fn read_candidate(&self, reference: ObjectRef) -> Result<CanonicalObject> {
        let length = reference.address.length as usize;
        self.accounting
            .borrow()
            .memory(1024 * 1024 + 3 * crate::v1::MAX_CHUNK_SIZE)?;
        self.accounting.borrow_mut().read(length as u64)?;
        let mut bytes = vec![0; length];
        self.source
            .read_exact_at(reference.address.offset, &mut bytes)?;
        let decoded = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as u64;
        self.accounting.borrow_mut().decoded(decoded)?;
        let object = wire::decode_frame_salvage(reference, &bytes)?;
        Ok(object)
    }
}

// A bounded on-disk LIFO keeps long retained histories off the call stack.
// Candidate rows already hold the active/completed color and rebuilt locator.
struct RebuildStack {
    file: File,
    len: u64,
    reserved: u64,
}
impl RebuildStack {
    fn new<R: ReadAt + ?Sized>(index: &CandidateIndex<'_, R>) -> Result<Self> {
        index.accounting.borrow_mut().temporary(4096)?;
        Ok(Self {
            file: tempfile::tempfile()?,
            len: 0,
            reserved: 4096,
        })
    }
    fn push<R: ReadAt + ?Sized>(
        &mut self,
        index: &CandidateIndex<'_, R>,
        hash: ObjectHash,
        exit: bool,
    ) -> Result<()> {
        let end = self
            .len
            .checked_add(1)
            .and_then(|n| n.checked_mul(33))
            .ok_or(Error::Limit("salvage stack storage"))?;
        let reserved = end
            .checked_add(4095)
            .ok_or(Error::Limit("salvage stack storage"))?
            / 4096
            * 4096;
        if reserved > self.reserved {
            index
                .accounting
                .borrow_mut()
                .temporary(reserved - self.reserved)?;
            self.reserved = reserved;
        }
        self.file.seek(SeekFrom::Start(self.len * 33))?;
        self.file.write_all(&hash.0)?;
        self.file.write_all(&[u8::from(exit)])?;
        self.len += 1;
        Ok(())
    }
    fn pop(&mut self) -> Result<Option<(ObjectHash, bool)>> {
        if self.len == 0 {
            return Ok(None);
        }
        self.file.seek(SeekFrom::Start((self.len - 1) * 33))?;
        let mut frame = [0; 33];
        self.file.read_exact(&mut frame)?;
        self.len -= 1;
        Ok(Some((
            ObjectHash(frame[..32].try_into().unwrap()),
            frame[32] != 0,
        )))
    }
}
fn rebuild<R: ReadAt + ?Sized, D: ObjectStore + ?Sized>(
    index: &CandidateIndex<'_, R>,
    destination: &mut D,
    root: ObjectHash,
) -> Result<ObjectRef> {
    let mut stack = RebuildStack::new(index)?;
    index.accounting.borrow_mut().edge()?;
    stack.push(index, root, false)?;
    while let Some((hash, exit)) = stack.pop()? {
        index.accounting.borrow().time()?;
        if index.destination_ref(hash)?.is_some() {
            continue;
        }
        if !exit {
            if index.active(hash)? {
                return Err(corrupt("salvage cyclic dependencies"));
            }
            let object = index.read_candidate(index.source_ref(hash)?)?;
            index.mark_active(hash)?;
            stack.push(index, hash, true)?;
            for child in object.children.iter().rev() {
                index.accounting.borrow_mut().edge()?;
                stack.push(index, child.hash, false)?;
            }
        } else {
            let object = index.read_candidate(index.source_ref(hash)?)?;
            let mut children = Vec::with_capacity(object.children.len());
            for child in &object.children {
                children.push(
                    index
                        .destination_ref(child.hash)?
                        .ok_or_else(|| corrupt("salvage unfinished dependency"))?,
                );
            }
            let reference =
                destination.put(object.kind, object.version, &object.bytes, &children)?;
            if reference.hash != hash {
                return Err(corrupt("salvage changed canonical object"));
            }
            index.completed(reference)?;
        }
    }
    index
        .destination_ref(root)?
        .ok_or_else(|| corrupt("salvage root was not rebuilt"))
}

fn authorized_snapshot<R: ReadAt + ?Sized>(
    source: &R,
    budget: &mut Accounting,
) -> Result<(ObjectHash, String, Option<ObjectHash>)> {
    let len = source.len()?;
    if len < 128 {
        return Err(corrupt(
            "salvage requires publication authority or expected snapshot",
        ));
    }
    budget.read(128)?;
    let mut preamble = [0; 128];
    source.read_exact_at(0, &mut preamble)?;
    let header = Preamble::decode(&preamble)?;
    let (offset, selected) = match header.policy {
        LocatorPolicy::Sealed => (
            len.checked_sub(160)
                .ok_or_else(|| corrupt("short sealed trailer"))?,
            None,
        ),
        LocatorPolicy::Live => {
            budget.read(3968)?;
            let mut padding = [0; 3968];
            source.read_exact_at(128, &mut padding)?;
            if padding.iter().any(|b| *b != 0) {
                return Err(corrupt("live bootstrap padding"));
            }
            budget.read(8192)?;
            let mut bytes = [0; 8192];
            source.read_exact_at(4096, &mut bytes)?;
            let mut slots = Vec::new();
            for i in 0..2 {
                match Slot::decode(&bytes[i * 4096..(i + 1) * 4096], &header, i) {
                    Ok(Some(slot)) => slots.push(slot),
                    Ok(None) => {}
                    Err(Error::Corrupt(reason)) if reason == "slot checksum" => {}
                    Err(e) => return Err(e),
                }
            }
            slots.sort_by_key(|s| s.generation);
            let slot = slots.pop().ok_or(Error::RecoveryRequired)?;
            (slot.trailer_offset, Some(slot))
        }
    };
    if offset.checked_add(160).is_none_or(|end| end > len) {
        return Err(corrupt("authorized trailer outside source"));
    }
    budget.read(160)?;
    let mut bytes = [0; 160];
    source.read_exact_at(offset, &mut bytes)?;
    let trailer = Trailer::decode(&bytes, &header, offset, len)?;
    if selected
        .is_some_and(|s| s.generation != trailer.generation || s.trailer_digest != trailer.digest())
    {
        return Err(corrupt("salvage slot trailer mismatch"));
    }
    wire::validate_address(
        trailer.commit.address,
        wire::control_start(header.first_record_offset(), trailer.committed_end)?,
        offset,
    )?;
    budget.read(trailer.commit.address.length as u64)?;
    let mut encoded = vec![0; trailer.commit.address.length as usize];
    source.read_exact_at(trailer.commit.address.offset, &mut encoded)?;
    let commit = wire::decode_frame_salvage(trailer.commit, &encoded)?;
    if commit.kind != 1 || commit.version != 1 {
        return Err(corrupt("authorized commit type"));
    }
    let body = cbor::decode(&commit.bytes)?;
    let fields = values(&body)?;
    if fields.len() != 3 {
        return Err(corrupt("authorized commit arity"));
    }
    if header.policy == LocatorPolicy::Sealed && fields[2] != Value::Null {
        return Err(corrupt("sealed publication has local root"));
    }
    let wanted = child(&commit, &fields[0])?.hash;
    Ok((
        wanted,
        if selected.is_some() {
            "selected-live-publication"
        } else {
            "sealed-eof-publication"
        }
        .into(),
        Some(trailer.commit.hash),
    ))
}
