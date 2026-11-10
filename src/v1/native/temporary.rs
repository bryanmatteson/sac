//! Disposable exact tables. Fixed resident prefixes and positional disk slots
//! keep closure traversal independent of archive size; none are authority.
use super::*;
const SLOT: usize = 96;
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
#[derive(Clone)]
pub(super) struct Budget(Arc<Mutex<BudgetState>>);
impl Budget {
    pub fn new(max: u64) -> Self {
        Self(Arc::new(Mutex::new(BudgetState {
            maximum: max,
            statistics: TemporaryIoStatistics::default(),
            aggregate: None,
        })))
    }
    pub fn used(&self) -> u64 {
        self.0.lock().unwrap().statistics.reserved_bytes
    }
    pub fn statistics(&self) -> TemporaryIoStatistics {
        self.0.lock().unwrap().statistics
    }
    pub fn read(&self, bytes: u64) {
        let mut state = self.0.lock().unwrap();
        state.statistics.read_bytes = state.statistics.read_bytes.saturating_add(bytes);
    }
    pub fn wrote(&self, bytes: u64) {
        let mut state = self.0.lock().unwrap();
        state.statistics.write_bytes = state.statistics.write_bytes.saturating_add(bytes);
    }
    pub fn set_limit(&self, max: u64) -> Result<()> {
        let mut b = self.0.lock().unwrap();
        if b.statistics.reserved_bytes > max {
            return Err(Error::Limit("temporary disk bytes"));
        }
        b.maximum = max;
        Ok(())
    }
    pub fn attach_aggregate(&self, aggregate: Budget) -> Result<()> {
        let mut local = self.0.lock().unwrap();
        if local.aggregate.is_some() {
            return Err(corrupt("temporary aggregate already attached"));
        }
        aggregate.reserve_bytes(local.statistics.reserved_bytes)?;
        local.aggregate = Some(aggregate);
        Ok(())
    }
    pub fn detach_aggregate(&self) {
        let mut local = self.0.lock().unwrap();
        if let Some(aggregate) = local.aggregate.take() {
            aggregate.release_bytes(local.statistics.reserved_bytes);
        }
    }
    pub fn child(maximum: u64, aggregate: Budget) -> Self {
        Self(Arc::new(Mutex::new(BudgetState {
            maximum,
            statistics: TemporaryIoStatistics::default(),
            aggregate: Some(aggregate),
        })))
    }
    fn reserve_bytes(&self, bytes: u64) -> Result<()> {
        let mut b = self.0.lock().unwrap();
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
        let mut b = self.0.lock().unwrap();
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

pub(super) struct GraphTable {
    resident: BTreeMap<Vec<u8>, Vec<u8>>,
    resident_limit: usize,
    disk: Option<DiskTable>,
    pub(super) budget: Budget,
}
struct DiskTable {
    file: File,
    slots: u64,
    count: u64,
    _reservation: Reservation,
}
impl DiskTable {
    fn new(slots: u64, budget: &Budget) -> Result<Self> {
        let size = slots
            .checked_mul(SLOT as u64)
            .ok_or(Error::Limit("temporary index bytes"))?;
        if size > MAX_DISK {
            return Err(Error::Limit("temporary index bytes"));
        }
        let reservation = budget.reserve(size)?;
        let file = tempfile::tempfile()?;
        file.set_len(size)?;
        Ok(Self {
            file,
            slots,
            count: 0,
            _reservation: reservation,
        })
    }
    fn index(key: &[u8], slots: u64) -> u64 {
        u64::from_le_bytes(blake3::hash(key).as_bytes()[..8].try_into().unwrap()) & (slots - 1)
    }
    fn find(&self, key: &[u8]) -> Result<(u64, [u8; SLOT])> {
        let mut index = Self::index(key, self.slots);
        for _ in 0..self.slots {
            let mut row = [0; SLOT];
            read_at(&self.file, &mut row, index * SLOT as u64)?;
            self._reservation.budget.read(SLOT as u64);
            if row[0] == 0 || (row[1] as usize == key.len() && &row[4..4 + key.len()] == key) {
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
        write_at(&mut self.file, &row, index * SLOT as u64)?;
        self._reservation.budget.wrote(SLOT as u64);
        if old[0] == 0 {
            self.count += 1;
        }
        Ok(())
    }
}
impl GraphTable {
    pub const RESIDENT_ENTRIES: usize = 2048;
    pub fn new() -> Result<Self> {
        Ok(Self::with_budget(
            Self::RESIDENT_ENTRIES,
            Budget::new(MAX_DISK),
        ))
    }
    pub fn with_budget(resident_limit: usize, budget: Budget) -> Self {
        Self {
            resident: BTreeMap::new(),
            resident_limit,
            disk: None,
            budget,
        }
    }
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if key.len() > 44 {
            return Err(Error::Limit("temporary key"));
        }
        if let Some(value) = self.resident.get(key) {
            return Ok(Some(value.clone()));
        }
        let Some(disk) = &self.disk else {
            return Ok(None);
        };
        let (_, row) = disk.find(key)?;
        if row[0] == 0 {
            Ok(None)
        } else {
            let length = row[2] as usize;
            if length > 44 {
                return Err(corrupt("temporary value length"));
            }
            Ok(Some(row[48..48 + length].to_vec()))
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
        if key.len() > 44 || value.len() > 44 {
            return Err(Error::Limit("temporary record"));
        }
        if self.resident.contains_key(key) || self.resident.len() < self.resident_limit {
            self.resident.insert(key.into(), value.into());
            return Ok(());
        }
        if self.disk.is_none() {
            self.disk = Some(DiskTable::new(4096, &self.budget)?);
        }
        if self.disk.as_ref().unwrap().count * 4 >= self.disk.as_ref().unwrap().slots * 3 {
            let old = self.disk.as_ref().unwrap();
            let mut next = DiskTable::new(
                old.slots
                    .checked_mul(2)
                    .ok_or(Error::Limit("temporary index slots"))?,
                &self.budget,
            )?;
            for index in 0..old.slots {
                if cancelled() {
                    return Err(std::io::Error::from(std::io::ErrorKind::Interrupted).into());
                }
                let mut row = [0; SLOT];
                read_at(&old.file, &mut row, index * SLOT as u64)?;
                self.budget.read(SLOT as u64);
                if row[0] != 0 {
                    next.insert(&row[4..4 + row[1] as usize], &row[48..48 + row[2] as usize])?;
                }
            }
            self.disk = Some(next);
        }
        self.disk.as_mut().unwrap().insert(key, value)
    }
    pub fn disk_bytes(&self) -> Result<u64> {
        Ok(self.disk.as_ref().map_or(0, |d| d.slots * SLOT as u64))
    }
}
pub(super) struct FixedRecordStack<const N: usize> {
    file: File,
    len: u64,
    capacity: u64,
    reservation: Reservation,
}
impl<const N: usize> FixedRecordStack<N> {
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
        table.get(&3072u32.to_le_bytes()).unwrap().unwrap(),
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
