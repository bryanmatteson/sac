//! Disposable exact tables. A fixed resident prefix, then fixed slots in a
//! mapped temporary file, keep closure traversal independent of archive size.
//! The operating system keeps the mapped slots in memory while it has room and
//! can write them out when it does not. None of these tables are authority.
use super::*;
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicU64, Ordering};
const SLOT: usize = 92;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use platform::Mapping;
// Hosts without block reservation use positional I/O only.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
enum Mapping {}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
impl Mapping {
    fn allocate(_: &File, _: u64) -> std::io::Result<Self> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
    fn bytes(&self) -> &[u8] {
        match *self {}
    }
    fn bytes_mut(&mut self) -> &mut [u8] {
        match *self {}
    }
}
pub(super) const MAX_DISK: u64 = 64 * 1024 * 1024 * 1024;
#[derive(Clone, Copy, Default, Debug)]
pub struct TemporaryIoStatistics {
    pub reserved_bytes: u64,
    pub peak_reserved_bytes: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}
struct BudgetState {
    maximum: u64,
    statistics: TemporaryIoStatistics,
    aggregate: Option<Budget>,
}
// A table counts every slot that it reads or writes. The counters are atomic
// so that a lookup does not take the reservation lock.
struct BudgetShared {
    state: Mutex<BudgetState>,
    read: AtomicU64,
    written: AtomicU64,
}
#[derive(Clone)]
pub(super) struct Budget(Arc<BudgetShared>);
impl Budget {
    fn with_state(state: BudgetState) -> Self {
        Self(Arc::new(BudgetShared {
            state: Mutex::new(state),
            read: AtomicU64::new(0),
            written: AtomicU64::new(0),
        }))
    }
    pub fn new(max: u64) -> Self {
        Self::with_state(BudgetState {
            maximum: max,
            statistics: TemporaryIoStatistics::default(),
            aggregate: None,
        })
    }
    pub fn used(&self) -> u64 {
        self.0.state.lock().unwrap().statistics.reserved_bytes
    }
    pub fn statistics(&self) -> TemporaryIoStatistics {
        let mut statistics = self.0.state.lock().unwrap().statistics;
        statistics.read_bytes = self.0.read.load(Ordering::Relaxed);
        statistics.write_bytes = self.0.written.load(Ordering::Relaxed);
        statistics
    }
    pub fn read(&self, bytes: u64) {
        self.0.read.fetch_add(bytes, Ordering::Relaxed);
    }
    pub fn wrote(&self, bytes: u64) {
        self.0.written.fetch_add(bytes, Ordering::Relaxed);
    }
    pub fn set_limit(&self, max: u64) -> Result<()> {
        let mut b = self.0.state.lock().unwrap();
        if b.statistics.reserved_bytes > max {
            return Err(Error::Limit("temporary disk bytes"));
        }
        b.maximum = max;
        Ok(())
    }
    pub fn attach_aggregate(&self, aggregate: Budget) -> Result<()> {
        let mut local = self.0.state.lock().unwrap();
        if local.aggregate.is_some() {
            return Err(corrupt("temporary aggregate already attached"));
        }
        aggregate.reserve_bytes(local.statistics.reserved_bytes)?;
        local.aggregate = Some(aggregate);
        Ok(())
    }
    pub fn detach_aggregate(&self) {
        let mut local = self.0.state.lock().unwrap();
        if let Some(aggregate) = local.aggregate.take() {
            aggregate.release_bytes(local.statistics.reserved_bytes);
        }
    }
    pub fn child(maximum: u64, aggregate: Budget) -> Self {
        Self::with_state(BudgetState {
            maximum,
            statistics: TemporaryIoStatistics::default(),
            aggregate: Some(aggregate),
        })
    }
    fn reserve_bytes(&self, bytes: u64) -> Result<()> {
        let mut b = self.0.state.lock().unwrap();
        let next = b
            .statistics
            .reserved_bytes
            .checked_add(bytes)
            .ok_or(Error::Limit("temporary disk bytes"))?;
        if next > b.maximum {
            return Err(Error::Limit("temporary disk bytes"));
        }
        if let Some(aggregate) = &b.aggregate {
            aggregate.reserve_bytes(bytes)?;
        }
        b.statistics.reserved_bytes = next;
        b.statistics.peak_reserved_bytes = b.statistics.peak_reserved_bytes.max(next);
        Ok(())
    }
    fn release_bytes(&self, bytes: u64) {
        let mut b = self.0.state.lock().unwrap();
        b.statistics.reserved_bytes -= bytes;
        if let Some(aggregate) = &b.aggregate {
            aggregate.release_bytes(bytes);
        }
    }
    pub fn reserve(&self, bytes: u64) -> Result<Reservation> {
        self.reserve_bytes(bytes)?;
        Ok(Reservation {
            budget: self.clone(),
            bytes,
        })
    }
}
pub(super) struct Reservation {
    budget: Budget,
    bytes: u64,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.release_bytes(self.bytes);
    }
}

impl Reservation {
    pub fn grow_to(&mut self, bytes: u64) -> Result<()> {
        if bytes > self.bytes {
            let mut extra = self.budget.reserve(bytes - self.bytes)?;
            self.bytes = bytes;
            extra.bytes = 0;
        }
        Ok(())
    }
}

// One key or value of at most 44 bytes, stored inline. The resident tier
// makes no allocation for an entry, and its size is a fixed number of bytes
// for each entry.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Cell<const BYTES: usize = 44> {
    len: u8,
    bytes: [u8; BYTES],
}
impl<const BYTES: usize> std::borrow::Borrow<[u8]> for Cell<BYTES> {
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}
impl<const BYTES: usize> std::hash::Hash for Cell<BYTES> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Match borrowed slice lookup: include the length, but never hash the
        // padding reserved for a larger key. Canonical IDs need only 32 bytes.
        std::hash::Hash::hash(self.as_slice(), state);
    }
}
impl<const BYTES: usize> std::ops::Deref for Cell<BYTES> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}
impl<const BYTES: usize> Cell<BYTES> {
    fn new(bytes: &[u8]) -> Self {
        let mut cell = Self {
            len: bytes.len() as u8,
            bytes: [0; BYTES],
        };
        cell.bytes[..bytes.len()].copy_from_slice(bytes);
        cell
    }
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

pub(super) type GraphTable = ValueGraphTable<44>;
pub(super) type ReferenceTable = ValueGraphTable<12>;
pub(super) struct ValueGraphTable<const VALUE_BYTES: usize> {
    resident: HashMap<Cell, Cell<VALUE_BYTES>, TableHash>,
    resident_limit: usize,
    disk: Option<DiskTable<VALUE_BYTES>>,
    // False only in a test of the positional I/O that a host without block
    // reservation uses.
    mapped: bool,
    pub(super) budget: Budget,
}
struct DiskTable<const VALUE_BYTES: usize> {
    // The slots of `file`, mapped. None on a host or filesystem that cannot
    // reserve blocks: the table then reads and writes each slot in the file.
    mapping: Option<Mapping>,
    file: File,
    slots: u64,
    count: u64,
    // The slot order is private to this table, so a keyed hash that an
    // archive cannot predict is sufficient.
    hasher: TableHash,
    _reservation: Reservation,
}
impl<const VALUE_BYTES: usize> DiskTable<VALUE_BYTES> {
    const ROW_BYTES: usize = 48 + VALUE_BYTES;
    fn with_mapping(slots: u64, budget: &Budget, mapped: bool) -> Result<Self> {
        let size = slots
            .checked_mul(Self::ROW_BYTES as u64)
            .ok_or(Error::Limit("temporary index bytes"))?;
        if size > MAX_DISK {
            return Err(Error::Limit("temporary index bytes"));
        }
        let reservation = budget.reserve(size)?;
        let file = tempfile::tempfile()?;
        let mapping = if mapped {
            match Mapping::allocate(&file, size) {
                Ok(mapping) => Some(mapping),
                Err(error) if error.kind() == std::io::ErrorKind::Unsupported => None,
                Err(error) => return Err(error.into()),
            }
        } else {
            None
        };
        if mapping.is_none() {
            file.set_len(size)?;
        }
        Ok(Self {
            mapping,
            file,
            slots,
            count: 0,
            hasher: TableHash::default(),
            _reservation: reservation,
        })
    }
    fn row(&self, index: u64) -> Result<[u8; SLOT]> {
        let mut row = [0; SLOT];
        match &self.mapping {
            Some(mapping) => {
                let at = index as usize * Self::ROW_BYTES;
                row[..Self::ROW_BYTES].copy_from_slice(&mapping.bytes()[at..at + Self::ROW_BYTES]);
            }
            None => read_at(
                &self.file,
                &mut row[..Self::ROW_BYTES],
                index * Self::ROW_BYTES as u64,
            )?,
        }
        Ok(row)
    }
    fn set_row(&mut self, index: u64, row: &[u8; SLOT]) -> Result<()> {
        match &mut self.mapping {
            Some(mapping) => {
                let at = index as usize * Self::ROW_BYTES;
                mapping.bytes_mut()[at..at + Self::ROW_BYTES]
                    .copy_from_slice(&row[..Self::ROW_BYTES]);
            }
            None => write_at(
                &mut self.file,
                &row[..Self::ROW_BYTES],
                index * Self::ROW_BYTES as u64,
            )?,
        }
        Ok(())
    }
    // A probe ends at the slot that holds the key, or at the first empty slot.
    fn selects(row: &[u8], key: &[u8]) -> bool {
        row[0] == 0 || (row[1] as usize == key.len() && &row[4..4 + key.len()] == key)
    }
    fn find(&self, key: &[u8]) -> Result<(u64, [u8; SLOT])> {
        let mut index = self.hasher.hash_one(key) & (self.slots - 1);
        for probe in 1..=self.slots {
            let found = match &self.mapping {
                // Examine a mapped slot in place; copy only the selected one.
                Some(mapping) => {
                    let at = index as usize * Self::ROW_BYTES;
                    let row = &mapping.bytes()[at..at + Self::ROW_BYTES];
                    Self::selects(row, key).then(|| {
                        let mut found = [0; SLOT];
                        found[..Self::ROW_BYTES].copy_from_slice(row);
                        found
                    })
                }
                None => {
                    let row = self.row(index)?;
                    Self::selects(&row, key).then_some(row)
                }
            };
            if let Some(row) = found {
                self._reservation
                    .budget
                    .read(probe * Self::ROW_BYTES as u64);
                return Ok((index, row));
            }
            index = (index + 1) & (self.slots - 1);
        }
        Err(corrupt("full temporary index"))
    }
    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        let (index, old) = self.find(key)?;
        let mut row = [0; SLOT];
        row[0] = 1;
        row[1] = key.len() as u8;
        row[2] = value.len() as u8;
        row[4..4 + key.len()].copy_from_slice(key);
        row[48..48 + value.len()].copy_from_slice(value);
        self.set_row(index, &row)?;
        self._reservation.budget.wrote(Self::ROW_BYTES as u64);
        if old[0] == 0 {
            self.count += 1;
        }
        Ok(())
    }
}
impl<const VALUE_BYTES: usize> ValueGraphTable<VALUE_BYTES> {
    pub const RESIDENT_ENTRIES: usize = 2048;
    pub fn new() -> Result<Self> {
        Ok(Self::with_budget(
            Self::RESIDENT_ENTRIES,
            Budget::new(MAX_DISK),
        ))
    }
    pub fn with_budget(resident_limit: usize, budget: Budget) -> Self {
        const { assert!(VALUE_BYTES <= 44) };
        Self {
            resident: HashMap::default(),
            resident_limit,
            disk: None,
            mapped: true,
            budget,
        }
    }
    pub fn get(&self, key: &[u8]) -> Result<Option<Cell<VALUE_BYTES>>> {
        if key.len() > 44 {
            return Err(Error::Limit("temporary key"));
        }
        if let Some(value) = self.resident.get(key) {
            return Ok(Some(*value));
        }
        let Some(disk) = &self.disk else {
            return Ok(None);
        };
        let (_, row) = disk.find(key)?;
        if row[0] == 0 {
            Ok(None)
        } else {
            let length = row[2] as usize;
            if length > VALUE_BYTES {
                return Err(corrupt("temporary value length"));
            }
            Ok(Some(Cell::new(&row[48..48 + length])))
        }
    }
    pub fn insert_cancellable(
        &mut self,
        key: &[u8],
        value: &[u8],
        cancelled: &impl Fn() -> bool,
    ) -> Result<()> {
        if cancelled() {
            return Err(std::io::Error::from(std::io::ErrorKind::Interrupted).into());
        }
        if key.len() > 44 || value.len() > VALUE_BYTES {
            return Err(Error::Limit("temporary record"));
        }
        if self.disk.is_none() {
            let cell = Cell::<44>::new(key);
            if self.resident.len() < self.resident_limit || self.resident.contains_key(&cell) {
                self.resident.insert(cell, Cell::new(value));
                return Ok(());
            }
            self.spill_resident(cancelled)?;
        }
        if self.disk.as_ref().unwrap().count * 4 >= self.disk.as_ref().unwrap().slots * 3 {
            let old = self.disk.as_ref().unwrap();
            let mut next = DiskTable::with_mapping(
                old.slots
                    .checked_mul(2)
                    .ok_or(Error::Limit("temporary index slots"))?,
                &self.budget,
                self.mapped,
            )?;
            for index in 0..old.slots {
                if cancelled() {
                    return Err(std::io::Error::from(std::io::ErrorKind::Interrupted).into());
                }
                let row = old.row(index)?;
                self.budget.read(DiskTable::<VALUE_BYTES>::ROW_BYTES as u64);
                if row[0] != 0 {
                    next.insert(&row[4..4 + row[1] as usize], &row[48..48 + row[2] as usize])?;
                }
            }
            self.disk = Some(next);
        }
        self.disk.as_mut().unwrap().insert(key, value)
    }
    // Reserve conservatively for HashMap bucket growth, control bytes and
    // allocator overhead. This is a bound rather than payload-only counting.
    const RESIDENT_ENTRY_BYTES: usize = 256;
    const RESIDENT_FIXED_BYTES: usize = 512;
    pub fn set_resident_memory_budget(&mut self, bytes: usize) -> Result<()> {
        let limit = bytes.saturating_sub(Self::RESIDENT_FIXED_BYTES) / Self::RESIDENT_ENTRY_BYTES;
        if self.disk.is_none() && self.resident.len() > limit {
            self.spill_resident(&|| false)?;
        }
        self.resident_limit = limit;
        Ok(())
    }
    pub fn resident_limit(&self) -> usize {
        self.resident_limit
    }
    pub fn resident_memory_bytes(&self) -> usize {
        if self.resident.is_empty() {
            0
        } else {
            Self::RESIDENT_FIXED_BYTES + self.resident.len() * Self::RESIDENT_ENTRY_BYTES
        }
    }
    fn spill_resident(&mut self, cancelled: &impl Fn() -> bool) -> Result<()> {
        // Keep the resident map until the entire spill succeeds. A quota or
        // I/O failure must leave every prior key available for a retry.
        let mut slots = 4096u64;
        while (self.resident.len() as u64 + 1) * 2 > slots {
            slots = slots
                .checked_mul(2)
                .ok_or(Error::Limit("temporary index slots"))?;
        }
        let mut disk = DiskTable::with_mapping(slots, &self.budget, self.mapped)?;
        for (key, value) in &self.resident {
            if cancelled() {
                return Err(std::io::Error::from(std::io::ErrorKind::Interrupted).into());
            }
            disk.insert(key.as_slice(), value.as_slice())?;
        }
        self.resident = HashMap::default();
        self.disk = Some(disk);
        Ok(())
    }
    pub fn disk_bytes(&self) -> Result<u64> {
        Ok(self
            .disk
            .as_ref()
            .map_or(0, |d| d.slots * DiskTable::<VALUE_BYTES>::ROW_BYTES as u64))
    }
}
pub(super) struct FixedRecordStack<const N: usize> {
    file: File,
    len: u64,
    capacity: u64,
    reservation: Reservation,
}
impl<const N: usize> FixedRecordStack<N> {
    pub fn len(&self) -> u64 {
        self.len
    }
    pub fn read(&self, index: u64) -> Result<[u8; N]> {
        if index >= self.len {
            return Err(corrupt("temporary record index"));
        }
        let mut row = [0; N];
        read_at(&self.file, &mut row, index * N as u64)?;
        self.reservation.budget.read(N as u64);
        Ok(row)
    }
    pub fn with_budget(budget: Budget) -> Result<Self> {
        Ok(Self {
            file: tempfile::tempfile()?,
            len: 0,
            capacity: 0,
            reservation: budget.reserve(0)?,
        })
    }
    pub fn push(&mut self, row: &[u8; N]) -> Result<()> {
        self.push_many(std::slice::from_ref(row))
    }
    pub fn push_many(&mut self, rows: &[[u8; N]]) -> Result<()> {
        let length = self
            .len
            .checked_add(rows.len() as u64)
            .ok_or(Error::Limit("temporary stack"))?;
        if length.checked_mul(N as u64).is_none_or(|b| b > MAX_DISK) {
            return Err(Error::Limit("temporary stack bytes"));
        }
        if length > self.capacity {
            let mut extra = self
                .reservation
                .budget
                .reserve((length - self.capacity) * N as u64)?;
            // APFS can speculatively allocate beyond a small extending write.
            // Set the already-reserved sparse extent first, so spill storage
            // follows the actual high-water mark rather than append timing.
            #[cfg(target_os = "macos")]
            self.file.set_len(length * N as u64)?;
            self.reservation.bytes += extra.bytes;
            extra.bytes = 0;
            self.capacity = length;
        }
        if !rows.is_empty() {
            // DiskStack already groups its hot-window spills. Preserve that
            // grouping through the physical I/O layer instead of issuing one
            // positioned write for every fixed-width frame. Array slices are
            // contiguous, so flattening borrows the existing bounded window.
            let bytes = rows.as_flattened();
            write_at(&mut self.file, bytes, self.len * N as u64)?;
            self.reservation.budget.wrote(bytes.len() as u64);
        }
        self.len = length;
        self.capacity = self.capacity.max(length);
        Ok(())
    }
    pub fn pop(&mut self) -> Result<Option<[u8; N]>> {
        if self.len == 0 {
            return Ok(None);
        }
        let mut row = [0; N];
        self.pop_many(std::slice::from_mut(&mut row))?;
        Ok(Some(row))
    }
    pub fn pop_many(&mut self, rows: &mut [[u8; N]]) -> Result<()> {
        if rows.len() as u64 > self.len {
            return Err(corrupt("temporary stack underflow"));
        }
        let next = self.len - rows.len() as u64;
        if !rows.is_empty() {
            let bytes = rows.as_flattened_mut();
            read_at(&self.file, bytes, next * N as u64)?;
            self.reservation.budget.read(bytes.len() as u64);
        }
        self.len = next;
        Ok(())
    }
    pub fn disk_bytes(&self) -> u64 {
        self.capacity * N as u64
    }
}

#[cfg(test)]
#[test]
fn narrow_resident_values_preserve_mixed_records_when_budget_forces_spill() {
    let budget = Budget::new(1 << 20);
    let mut table = ReferenceTable::with_budget(2048, budget.clone());
    let mut records: Vec<_> = (0..512u64)
        .map(|index| {
            let mut key = vec![0; if index % 2 == 0 { 32 } else { 44 }];
            key[..8].copy_from_slice(&index.to_le_bytes());
            let value = vec![index as u8; index as usize % 13];
            (key, value)
        })
        .collect();
    // A borrowed lookup must distinguish equal prefixes and zero padding.
    for length in [0, 1, 31, 33, 44] {
        records.push((vec![0; length], vec![length as u8; 12]));
    }
    for (key, value) in &records {
        table.insert_cancellable(key, value, &|| false).unwrap();
    }
    assert_eq!(table.disk_bytes().unwrap(), 0);
    for (key, value) in &records {
        assert_eq!(&*table.get(key).unwrap().unwrap(), value);
    }
    // Updates include replacing a full value with an empty one. The compact
    // resident representation and its spill must retain the actual length.
    table
        .insert_cancellable(&records[12].0, &[], &|| false)
        .unwrap();
    table.set_resident_memory_budget(0).unwrap();
    assert!(table.disk_bytes().unwrap() > 0);
    for (index, (key, value)) in records.iter().enumerate() {
        let expected = if index == 12 { &[][..] } else { value };
        assert_eq!(&*table.get(key).unwrap().unwrap(), expected);
    }
    assert_eq!(table.resident_memory_bytes(), 0);
    drop(table);
    assert_eq!(budget.used(), 0);
}

#[cfg(test)]
#[test]
fn narrow_table_preserves_values_and_cancellation_across_mapped_and_io_growth() {
    for mapped in [true, false] {
        let budget = Budget::new(4 << 20);
        let mut table = ReferenceTable::with_budget(8, budget.clone());
        table.mapped = mapped;
        for ordinal in 0..6144u32 {
            let mut value = [0; 12];
            value[..4].copy_from_slice(&ordinal.to_le_bytes());
            value[4..].copy_from_slice(&(u64::from(ordinal) * 4096).to_le_bytes());
            table
                .insert_cancellable(&ordinal.to_le_bytes(), &value, &|| false)
                .unwrap();
        }
        assert_eq!(table.disk_bytes().unwrap(), 8192 * 60);
        let before = budget.used();
        let calls = std::cell::Cell::new(0);
        assert!(
            table
                .insert_cancellable(&6144u32.to_le_bytes(), &[1; 12], &|| {
                    calls.set(calls.get() + 1);
                    calls.get() > 32
                })
                .is_err()
        );
        assert_eq!(budget.used(), before);
        assert!(table.get(&6144u32.to_le_bytes()).unwrap().is_none());
        assert!(table.insert_cancellable(&[1], &[1; 13], &|| false).is_err());
        for ordinal in (0..6144u32).step_by(17) {
            let value = table.get(&ordinal.to_le_bytes()).unwrap().unwrap();
            assert_eq!(&value[..4], &ordinal.to_le_bytes());
            assert_eq!(&value[4..], &(u64::from(ordinal) * 4096).to_le_bytes());
        }
        table.insert_cancellable(&[1], &[7; 12], &|| false).unwrap();
        assert_eq!(&table.get(&[1]).unwrap().unwrap()[..], &[7; 12]);
        assert_eq!(table.disk_bytes().unwrap(), 16384 * 60);
        drop(table);
        assert_eq!(budget.used(), 0);
    }
}

#[cfg(test)]
#[test]
fn stack_batches_preserve_lifo_overwrites_and_failed_reservations() {
    fn frame(ordinal: u64) -> [u8; 45] {
        let mut frame = [0; 45];
        for chunk in frame[..40].chunks_exact_mut(8) {
            chunk.copy_from_slice(&ordinal.to_le_bytes());
        }
        frame[40..].fill(ordinal as u8);
        frame
    }
    let budget = Budget::new(1024 * 45);
    let mut stack = FixedRecordStack::<45>::with_budget(budget.clone()).unwrap();
    let initial: Vec<_> = (0..1024).map(frame).collect();
    stack.push_many(&initial).unwrap();
    let mut popped = vec![[0; 45]; 300];
    stack.pop_many(&mut popped).unwrap();
    assert_eq!(popped, initial[724..]);
    let replacement: Vec<_> = (2000..2100).map(frame).collect();
    stack.push_many(&replacement).unwrap();
    let before = budget.statistics();
    assert!(stack.push_many(&vec![[0; 45]; 201]).is_err());
    assert!(stack.pop_many(&mut vec![[0; 45]; 825]).is_err());
    assert_eq!(stack.len, 824);
    assert_eq!(budget.statistics().reserved_bytes, before.reserved_bytes);
    assert_eq!(budget.statistics().write_bytes, before.write_bytes);
    assert_eq!(budget.statistics().read_bytes, before.read_bytes);
    stack.push_many(&[]).unwrap();
    stack.pop_many(&mut []).unwrap();
    for expected in replacement.iter().rev().chain(initial[..724].iter().rev()) {
        assert_eq!(stack.pop().unwrap().as_ref(), Some(expected));
    }
    assert!(stack.pop().unwrap().is_none());
    assert_eq!(budget.statistics().write_bytes, (1024 + 100) * 45);
    assert_eq!(budget.statistics().read_bytes, (1024 + 100) * 45);
    drop(stack);
    assert_eq!(budget.statistics().reserved_bytes, 0);
}

#[cfg(test)]
#[test]
fn scratch_statistics_include_resize_overlap_and_stack_io() {
    let budget = Budget::new(2 << 20);
    let mut table = GraphTable::with_budget(0, budget.clone());
    for ordinal in 0..3073u32 {
        table
            .insert_cancellable(&ordinal.to_le_bytes(), &ordinal.to_le_bytes(), &|| false)
            .unwrap();
    }
    let stats = budget.statistics();
    assert_eq!(stats.reserved_bytes, 8192 * SLOT as u64);
    assert_eq!(stats.peak_reserved_bytes, (4096 + 8192) * SLOT as u64);
    assert_eq!(stats.write_bytes, (3073 + 3072) * SLOT as u64);
    assert!(stats.read_bytes >= 4096 * SLOT as u64);
    assert_eq!(
        table.get(&3072u32.to_le_bytes()).unwrap().unwrap()[..],
        3072u32.to_le_bytes()
    );
    drop(table);
    assert_eq!(budget.statistics().reserved_bytes, 0);
    let budget = Budget::new(1 << 20);
    let mut stack = FixedRecordStack::<45>::with_budget(budget.clone()).unwrap();
    stack.push_many(&[[7; 45]; 512]).unwrap();
    stack.pop_many(&mut [[0; 45]; 256]).unwrap();
    for _ in 0..256 {
        stack.pop().unwrap().unwrap();
    }
    assert_eq!(budget.statistics().write_bytes, 512 * 45);
    assert_eq!(budget.statistics().read_bytes, 512 * 45);
    assert_eq!(budget.statistics().peak_reserved_bytes, 512 * 45);
    drop(stack);
    assert_eq!(budget.statistics().reserved_bytes, 0);
}

#[cfg(test)]
#[test]
fn aggregate_reservations_reject_before_growth_and_release_exactly() {
    let aggregate = Budget::new(100);
    let left = Budget::child(100, aggregate.clone());
    let right = Budget::new(100);
    right.attach_aggregate(aggregate.clone()).unwrap();
    let a = left.reserve(70).unwrap();
    assert!(right.reserve(31).is_err());
    assert_eq!(aggregate.used(), 70);
    let mut b = right.reserve(30).unwrap();
    assert_eq!(aggregate.used(), 100);
    assert!(b.grow_to(31).is_err());
    assert_eq!(right.used(), 30);
    assert_eq!(aggregate.used(), 100);
    drop(a);
    aggregate.set_limit(30).unwrap();
    assert!(b.grow_to(31).is_err());
    right.detach_aggregate();
    assert_eq!(aggregate.used(), 0);
    drop(b);
    assert_eq!(right.used(), 0);
    assert_eq!(aggregate.statistics().peak_reserved_bytes, 100);
    let a = left.reserve(20).unwrap();
    assert_eq!(aggregate.used(), 20);
    drop(a);
    assert_eq!(aggregate.used(), 0);
}

#[cfg(test)]
#[test]
fn mapped_and_positional_tables_agree_across_the_resident_prefix_and_growth() {
    fn key(ordinal: u32) -> [u8; 32] {
        *blake3::hash(&ordinal.to_le_bytes()).as_bytes()
    }
    for mapped in [true, false] {
        let budget = Budget::new(MAX_DISK);
        let mut table = GraphTable::with_budget(64, budget.clone());
        table.mapped = mapped;
        for ordinal in 0..10_000u32 {
            table
                .insert_cancellable(&key(ordinal), &ordinal.to_le_bytes(), &|| false)
                .unwrap();
            if ordinal == 63 {
                assert_eq!(table.disk_bytes().unwrap(), 0);
            }
        }
        // The entry after the prefix moved every resident entry to the slots.
        assert!(table.resident.is_empty());
        let disk = table.disk.as_ref().unwrap();
        assert_eq!(disk.count, 10_000);
        assert_eq!(
            disk.mapping.is_some(),
            mapped && cfg!(any(target_os = "macos", target_os = "linux"))
        );
        table
            .insert_cancellable(&key(0), b"replaced", &|| false)
            .unwrap();
        assert_eq!(table.get(&key(0)).unwrap().unwrap()[..], b"replaced"[..]);
        for ordinal in 1..10_000u32 {
            assert_eq!(
                table.get(&key(ordinal)).unwrap().unwrap()[..],
                ordinal.to_le_bytes()
            );
        }
        assert!(table.get(&key(10_000)).unwrap().is_none());
        assert_eq!(table.disk.as_ref().unwrap().count, 10_000);
        assert_eq!(budget.statistics().reserved_bytes, 16384 * SLOT as u64);
        drop(table);
        assert_eq!(budget.statistics().reserved_bytes, 0);
    }
}
