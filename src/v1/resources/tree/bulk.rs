//! Initial packing: external key sort followed by one encoding per directory
//! page. Temporary files are private, quota-charged, and never durable state.
use super::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

#[derive(Default)]
struct Counters {
    bytes: AtomicU64,
    peak: AtomicU64,
    read: AtomicU64,
    written: AtomicU64,
}
#[derive(Clone)]
struct Quota {
    counters: Arc<Counters>,
    maximum: u64,
}
impl Quota {
    fn reserve(&self, n: u64) -> Result<()> {
        let previous = self
            .counters
            .bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(n).filter(|next| *next <= self.maximum)
            })
            .map_err(|_| Error::Limit("bulk temporary bytes"))?;
        self.counters
            .peak
            .fetch_max(previous + n, Ordering::Relaxed);
        Ok(())
    }
}
struct Spool {
    file: File,
    bytes: u64,
    count: u64,
    quota: Quota,
    max_record: usize,
    // Records wait here for one write of the file, and one read of the file
    // supplies many records. The file holds the same bytes as before.
    pending: Vec<u8>,
    loaded: Vec<u8>,
    consumed: usize,
}
// One system call moves this many spool bytes. A record that is larger
// passes through its own call.
const SPOOL_BUFFER: usize = 16 * 1024;
impl Drop for Spool {
    fn drop(&mut self) {
        self.quota
            .counters
            .bytes
            .fetch_sub(self.bytes, Ordering::Relaxed);
    }
}
impl Spool {
    fn new(quota: Quota, max_record: usize) -> Result<Self> {
        Ok(Self {
            file: tempfile::tempfile()?,
            bytes: 0,
            count: 0,
            quota,
            max_record,
            pending: Vec::new(),
            loaded: Vec::new(),
            consumed: 0,
        })
    }
    fn flush(&mut self) -> Result<()> {
        if !self.pending.is_empty() {
            self.file.write_all(&self.pending)?;
            self.pending.clear();
        }
        Ok(())
    }
    // Copy the next `output.len()` spool bytes. `Ok(false)` is the end of the
    // spool before the first byte.
    fn load(&mut self, output: &mut [u8]) -> Result<bool> {
        let mut filled = 0;
        while filled < output.len() {
            if self.consumed == self.loaded.len() {
                self.loaded.resize(SPOOL_BUFFER, 0);
                let n = loop {
                    match self.file.read(&mut self.loaded) {
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        other => break other?,
                    }
                };
                self.loaded.truncate(n);
                self.consumed = 0;
                if n == 0 {
                    if filled == 0 {
                        return Ok(false);
                    }
                    return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
                }
            }
            let n = (self.loaded.len() - self.consumed).min(output.len() - filled);
            output[filled..filled + n]
                .copy_from_slice(&self.loaded[self.consumed..self.consumed + n]);
            self.consumed += n;
            filled += n;
        }
        Ok(true)
    }
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > self.max_record {
            return Err(Error::Limit("bulk record memory"));
        }
        let span = bytes.len() as u64 + 4;
        self.quota.reserve(span)?;
        self.bytes += span;
        let size = (bytes.len() as u32).to_le_bytes();
        if self.pending.len() + size.len() + bytes.len() > SPOOL_BUFFER {
            self.flush()?;
        }
        if size.len() + bytes.len() > SPOOL_BUFFER {
            self.file.write_all(&size)?;
            self.file.write_all(bytes)?;
        } else {
            if self.pending.capacity() == 0 {
                self.pending = Vec::with_capacity(SPOOL_BUFFER);
            }
            self.pending.extend_from_slice(&size);
            self.pending.extend_from_slice(bytes);
        }
        self.quota
            .counters
            .written
            .fetch_add(span, Ordering::Relaxed);
        self.count += 1;
        Ok(())
    }
    fn seal(&mut self) -> Result<()> {
        self.flush()?;
        self.pending = Vec::new();
        Ok(())
    }
    fn rewind(&mut self) -> Result<()> {
        self.seal()?;
        self.file.seek(SeekFrom::Start(0))?;
        self.loaded.clear();
        self.consumed = 0;
        Ok(())
    }
    fn read(&mut self) -> Result<Option<Vec<u8>>> {
        let mut size = [0; 4];
        if !self.load(&mut size)? {
            return Ok(None);
        }
        let n = u32::from_le_bytes(size) as usize;
        if n > self.max_record {
            return Err(Error::Limit("bulk record memory"));
        }
        let mut bytes = vec![0; n];
        if !self.load(&mut bytes)? && n != 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }
        self.quota
            .counters
            .read
            .fetch_add(n as u64 + 4, Ordering::Relaxed);
        Ok(Some(bytes))
    }
}
struct Record {
    path: ResourcePath,
    entry: Entry,
    encoded: Vec<u8>,
}

struct MergeHead {
    path: ResourcePath,
    encoded: Vec<u8>,
}
impl MergeHead {
    fn read(run: &mut Spool) -> Result<Option<Self>> {
        let Some(encoded) = run.read()? else {
            return Ok(None);
        };
        let path = crate::v1::cbor_view::admitted(&encoded)?
            .first_field(3)?
            .array()?
            .map(|key| Ok(key?.bytes()?.to_vec()))
            .collect::<Result<_>>()?;
        Ok(Some(Self { path, encoded }))
    }
}

fn reference(r: ObjectRef) -> Value {
    array(vec![
        Value::Bytes(r.hash.0.to_vec()),
        uint(r.address.offset),
        uint(u64::from(r.address.length)),
    ])
}
fn decode_reference(v: &Value) -> Result<ObjectRef> {
    let v = values(v)?;
    if v.len() != 3 {
        return Err(corrupt("bulk locator"));
    }
    Ok(ObjectRef {
        hash: ObjectHash(bytes(&v[0])?.try_into().map_err(|_| corrupt("bulk hash"))?),
        address: super::super::super::ChunkAddress {
            offset: number(&v[1])?,
            length: u32::try_from(number(&v[2])?).map_err(|_| corrupt("bulk span"))?,
        },
    })
}
fn value_heap_bytes(value: &Value) -> usize {
    match value {
        Value::Bytes(bytes) => bytes.capacity(),
        Value::Text(text) => text.capacity(),
        Value::Array(values) => values
            .capacity()
            .saturating_mul(std::mem::size_of::<Value>())
            .saturating_add(values.iter().map(value_heap_bytes).sum::<usize>()),
        Value::Map(entries) => entries
            .capacity()
            .saturating_mul(std::mem::size_of::<cbor::MapEntry>())
            .saturating_add(
                entries
                    .iter()
                    .map(|entry| {
                        entry
                            .key_bytes
                            .capacity()
                            .saturating_add(value_heap_bytes(&entry.key))
                            .saturating_add(value_heap_bytes(&entry.value))
                    })
                    .sum::<usize>(),
            ),
        _ => 0,
    }
}
impl Record {
    fn resident_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(
                self.path
                    .capacity()
                    .saturating_mul(std::mem::size_of::<Vec<u8>>()),
            )
            .saturating_add(self.path.iter().map(Vec::capacity).sum::<usize>())
            .saturating_add(self.entry.name.capacity())
            .saturating_add(value_heap_bytes(&self.entry.metadata))
            .saturating_add(match &self.entry.data {
                EntryData::File {
                    data: FileData::Inline(bytes),
                    ..
                } => bytes.capacity(),
                EntryData::Symlink(bytes) => bytes.capacity(),
                _ => 0,
            })
            .saturating_add(self.encoded.capacity())
    }
    fn new(path: &[Vec<u8>], metadata: Value, data: EntryData) -> Self {
        let value = match &data {
            EntryData::File {
                length,
                data: FileData::Inline(b),
            } => array(vec![
                uint(0),
                uint(*length),
                uint(0),
                Value::Bytes(b.clone()),
            ]),
            EntryData::File {
                length,
                data: FileData::Extents(r),
            } => array(vec![uint(0), uint(*length), uint(1), reference(*r)]),
            EntryData::Directory(r) => array(vec![uint(1), reference(*r)]),
            EntryData::Symlink(target) => array(vec![uint(2), Value::Bytes(target.clone())]),
        };
        let encoded = cbor::encode(&array(vec![
            array(path.iter().cloned().map(Value::Bytes).collect()),
            metadata.clone(),
            value,
        ]));
        Self {
            path: path.to_vec(),
            entry: Entry {
                name: path.last().unwrap().clone(),
                metadata,
                data,
            },
            encoded,
        }
    }
    fn decode(encoded: Vec<u8>) -> Result<Self> {
        let value = cbor::decode(&encoded)?;
        let fields = values(&value)?;
        if fields.len() != 3 {
            return Err(corrupt("bulk record"));
        }
        let path: ResourcePath = values(&fields[0])?
            .iter()
            .map(|v| Ok(bytes(v)?.to_vec()))
            .collect::<Result<_>>()?;
        let v = values(&fields[2])?;
        let data = match number(&v[0])? {
            0 => EntryData::File {
                length: number(&v[1])?,
                data: if number(&v[2])? == 0 {
                    FileData::Inline(bytes(&v[3])?.to_vec())
                } else {
                    FileData::Extents(decode_reference(&v[3])?)
                },
            },
            1 => EntryData::Directory(decode_reference(&v[1])?),
            2 => EntryData::Symlink(bytes(&v[1])?.to_vec()),
            _ => return Err(corrupt("bulk resource kind")),
        };
        Ok(Self {
            entry: Entry {
                name: path
                    .last()
                    .ok_or_else(|| corrupt("bulk empty path"))?
                    .clone(),
                metadata: fields[1].clone(),
                data,
            },
            path,
            encoded,
        })
    }
}

pub(super) struct Bulk {
    limits: Limits,
    quota: Quota,
    buffered: Vec<Record>,
    memory: usize,
    levels: Vec<Vec<Spool>>,
    started: Instant,
    max_record: usize,
    poisoned: bool,
}
impl Bulk {
    pub fn new(limits: Limits) -> Result<Self> {
        if limits.max_memory_bytes < 1024 * 1024 {
            return Err(Error::Limit("bulk packing memory"));
        }
        Ok(Self {
            quota: Quota {
                counters: Arc::new(Counters::default()),
                maximum: limits.max_temp_bytes,
            },
            max_record: (limits.max_memory_bytes / 64).min(u32::MAX as usize),
            limits,
            buffered: Vec::new(),
            memory: 0,
            levels: Vec::new(),
            started: Instant::now(),
            poisoned: false,
        })
    }
    fn time(&self) -> Result<()> {
        if self.started.elapsed() > self.limits.max_elapsed {
            Err(Error::Limit("bulk packing elapsed"))
        } else {
            Ok(())
        }
    }
    pub fn push(&mut self, path: &[Vec<u8>], metadata: Value, data: EntryData) -> Result<()> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        self.time()?;
        let record = Record::new(path, metadata, data);
        if record.encoded.len() > self.max_record {
            return Err(Error::Limit("bulk record memory"));
        }
        let charge = record
            .resident_bytes()
            .max(record.encoded.len().saturating_mul(4).saturating_add(512));
        if charge > self.limits.max_memory_bytes / 8 {
            return Err(Error::Limit("bulk record resident memory"));
        }
        if self.memory.saturating_add(charge) > self.limits.max_memory_bytes / 8 {
            self.flush().inspect_err(|_| self.poisoned = true)?;
        }
        self.memory += charge;
        self.buffered.push(record);
        Ok(())
    }
    fn spool(&self) -> Result<Spool> {
        Spool::new(self.quota.clone(), self.max_record)
    }
    fn flush(&mut self) -> Result<()> {
        if self.buffered.is_empty() {
            return Ok(());
        }
        self.buffered.sort_by(|a, b| a.path.cmp(&b.path));
        let mut run = self.spool()?;
        for record in self.buffered.drain(..) {
            run.write(&record.encoded)?;
        }
        self.memory = 0;
        run.seal()?;
        self.promote(run, 0)
    }
    fn promote(&mut self, run: Spool, level: usize) -> Result<()> {
        while self.levels.len() <= level {
            self.levels.push(Vec::new());
        }
        self.levels[level].push(run);
        if self.levels[level].len() == 8 {
            let runs = std::mem::take(&mut self.levels[level]);
            let run = self.merge(runs)?;
            self.promote(run, level + 1)?;
        }
        Ok(())
    }
    fn merge(&self, mut runs: Vec<Spool>) -> Result<Spool> {
        let mut output = self.spool()?;
        let mut heads = Vec::new();
        for run in &mut runs {
            run.rewind()?;
            heads.push(MergeHead::read(run)?);
        }
        loop {
            self.time()?;
            let next = heads
                .iter()
                .enumerate()
                .filter_map(|(i, r)| r.as_ref().map(|r| (i, &r.path)))
                .min_by(|(_, a), (_, b)| a.cmp(b))
                .map(|(i, _)| i);
            let Some(i) = next else {
                break;
            };
            output.write(&heads[i].take().unwrap().encoded)?;
            heads[i] = MergeHead::read(&mut runs[i])?;
        }
        output.seal()?;
        Ok(output)
    }
    pub fn finish<S: ObjectStore + ?Sized>(
        self,
        store: &mut S,
    ) -> Result<(ObjectRef, PackingStatistics)> {
        let counters = self.quota.counters.clone();
        let root = self.finish_inner(store)?;
        Ok((
            root,
            PackingStatistics {
                temporary_peak_bytes: counters.peak.load(Ordering::Relaxed),
                temporary_read_bytes: counters.read.load(Ordering::Relaxed),
                temporary_write_bytes: counters.written.load(Ordering::Relaxed),
            },
        ))
    }
    fn finish_inner<S: ObjectStore + ?Sized>(mut self, store: &mut S) -> Result<ObjectRef> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.levels.is_empty() {
            let mut records = std::mem::take(&mut self.buffered);
            records.sort_by(|a, b| a.path.cmp(&b.path));
            return self.build_directories(
                store,
                records.into_iter().map(|record| {
                    crate::v1::cbor_view::view(&record.encoded)?;
                    Ok(record)
                }),
            );
        }
        self.flush()?;
        let mut runs: Vec<_> = self.levels.drain(..).flatten().collect();
        if runs.is_empty() {
            return Ok(store_leaf(store, &[])?.1);
        }
        while runs.len() > 1 {
            let mut next = Vec::new();
            let mut iter = runs.into_iter();
            loop {
                let group: Vec<_> = iter.by_ref().take(8).collect();
                if group.is_empty() {
                    break;
                }
                next.push(if group.len() == 1 {
                    group.into_iter().next().unwrap()
                } else {
                    self.merge(group)?
                });
            }
            runs = next;
        }
        let mut sorted = runs.pop().unwrap();
        sorted.rewind()?;
        self.build_directories(
            store,
            std::iter::from_fn(|| {
                sorted
                    .read()
                    .and_then(|r| r.map(Record::decode).transpose())
                    .transpose()
            }),
        )
    }
    fn build_directories<S: ObjectStore + ?Sized>(
        &self,
        store: &mut S,
        records: impl Iterator<Item = Result<Record>>,
    ) -> Result<ObjectRef> {
        let mut directories = vec![Directory::new(Vec::new(), empty_metadata())];
        let mut previous: Option<(ResourcePath, bool)> = None;
        for record in records {
            self.time()?;
            let record = record?;
            let is_directory = matches!(record.entry.data, EntryData::Directory(_));
            if previous.as_ref().is_some_and(|(p, _)| p == &record.path) {
                if is_directory && previous.as_ref().unwrap().1 {
                    continue;
                }
                return Err(corrupt("duplicate resource path"));
            }
            previous = Some((record.path.clone(), is_directory));
            let parent = &record.path[..record.path.len() - 1];
            while directories.last().unwrap().path.len() > parent.len()
                || !parent.starts_with(&directories.last().unwrap().path)
            {
                close_directory(store, &mut directories, self)?;
            }
            while directories.last().unwrap().path.len() < parent.len() {
                let depth = directories.last().unwrap().path.len();
                let name = &parent[depth];
                if directories
                    .last()
                    .unwrap()
                    .last
                    .as_ref()
                    .is_some_and(|last| last >= name)
                {
                    return Err(corrupt("resource parent is not a directory"));
                }
                directories.push(Directory::new(parent[..=depth].to_vec(), empty_metadata()));
            }
            if is_directory {
                if directories
                    .last()
                    .unwrap()
                    .last
                    .as_ref()
                    .is_some_and(|last| last >= &record.entry.name)
                {
                    return Err(corrupt("duplicate resource path"));
                }
                directories.push(Directory::new(record.path, record.entry.metadata));
            } else {
                directories
                    .last_mut()
                    .unwrap()
                    .push(store, self, record.entry)?;
            }
            let memory: usize = directories.iter().map(Directory::memory).sum();
            if memory > self.limits.max_memory_bytes / 2 {
                return Err(Error::Limit("bulk directory frontier memory"));
            }
        }
        while directories.len() > 1 {
            close_directory(store, &mut directories, self)?;
        }
        directories.pop().unwrap().finish(store, self)
    }
}

fn close_directory<S: ObjectStore + ?Sized>(
    store: &mut S,
    directories: &mut Vec<Directory>,
    bulk: &Bulk,
) -> Result<()> {
    let directory = directories
        .pop()
        .ok_or_else(|| corrupt("bulk directory stack"))?;
    let name = directory.path.last().unwrap().clone();
    let metadata = directory.metadata.clone();
    let root = directory.finish(store, bulk)?;
    directories
        .last_mut()
        .ok_or_else(|| corrupt("bulk directory parent"))?
        .push(
            store,
            bulk,
            Entry {
                name,
                metadata,
                data: EntryData::Directory(root),
            },
        )
}
fn node_bytes(key: &[u8], reference: ObjectRef) -> Vec<u8> {
    cbor::encode(&array(vec![
        Value::Bytes(key.to_vec()),
        self::reference(reference),
    ]))
}
fn node_decode(bytes_: Vec<u8>) -> Result<(Vec<u8>, ObjectRef)> {
    let value = cbor::decode(&bytes_)?;
    let v = values(&value)?;
    Ok((bytes(&v[0])?.to_vec(), decode_reference(&v[1])?))
}
struct Directory {
    path: ResourcePath,
    metadata: Value,
    rows: Vec<u8>,
    row_count: usize,
    children: Vec<ObjectRef>,
    last: Option<Vec<u8>>,
    first_node: Option<(Vec<u8>, ObjectRef)>,
    nodes: Option<Spool>,
}
impl Directory {
    fn new(path: ResourcePath, metadata: Value) -> Self {
        Self {
            path,
            metadata,
            rows: Vec::new(),
            row_count: 0,
            children: Vec::new(),
            last: None,
            first_node: None,
            nodes: None,
        }
    }
    fn memory(&self) -> usize {
        self.rows.capacity()
            + self.children.capacity() * std::mem::size_of::<ObjectRef>()
            + self.path.iter().map(|p| p.capacity() + 32).sum::<usize>()
            + value_heap_bytes(&self.metadata)
            + self
                .nodes
                .as_ref()
                .map_or(0, |spool| spool.pending.capacity())
            + 16384
    }
    fn push<S: ObjectStore + ?Sized>(
        &mut self,
        store: &mut S,
        bulk: &Bulk,
        entry: Entry,
    ) -> Result<()> {
        if self.last.as_ref().is_some_and(|last| last >= &entry.name) {
            return Err(corrupt("bulk directory key order"));
        }
        let before = self.children.len();
        let row_start = self.rows.len();
        write_entry_row(&entry, &mut self.children, &mut self.rows);
        if self.children.len() > 1024
            || 8 + 32 * self.children.len()
                + cbor::head_len((self.row_count + 1) as u64)
                + self.rows.len()
                > DIRECTORY_LEAF_LIMIT
        {
            self.children.truncate(before);
            self.rows.truncate(row_start);
            if self.row_count == 0 {
                return Err(Error::Limit("directory entry too large"));
            }
            self.flush(store, bulk)?;
            write_entry_row(&entry, &mut self.children, &mut self.rows);
            if 8 + 32 * self.children.len() + 1 + self.rows.len() > DIRECTORY_LEAF_LIMIT {
                return Err(Error::Limit("directory entry too large"));
            }
        }
        self.row_count += 1;
        self.last = Some(entry.name);
        Ok(())
    }
    fn flush<S: ObjectStore + ?Sized>(&mut self, store: &mut S, bulk: &Bulk) -> Result<()> {
        if self.row_count == 0 {
            return Ok(());
        }
        let count = self.row_count as u64;
        let mut body = Vec::with_capacity(cbor::head_len(count) + self.rows.len());
        cbor::write_head(4, count, &mut body);
        body.extend_from_slice(&self.rows);
        let reference = store.put(3, 1, &body, &self.children)?;
        let key = self.last.as_ref().unwrap();
        if let Some(nodes) = &mut self.nodes {
            nodes.write(&node_bytes(key, reference))?;
        } else if let Some((first_key, first_ref)) = self.first_node.take() {
            let mut nodes = bulk.spool()?;
            nodes.write(&node_bytes(&first_key, first_ref))?;
            nodes.write(&node_bytes(key, reference))?;
            self.nodes = Some(nodes);
        } else {
            self.first_node = Some((key.clone(), reference));
        }
        self.rows.clear();
        self.children.clear();
        self.row_count = 0;
        Ok(())
    }
    fn finish<S: ObjectStore + ?Sized>(mut self, store: &mut S, bulk: &Bulk) -> Result<ObjectRef> {
        self.flush(store, bulk)?;
        let Some(mut nodes) = self.nodes else {
            return match self.first_node {
                Some((_, reference)) => Ok(reference),
                None => Ok(store_leaf(store, &[])?.1),
            };
        };
        let mut level = 0;
        while nodes.count > 1 {
            bulk.time()?;
            level += 1;
            if level > 16 {
                return Err(Error::Limit("directory tree height"));
            }
            nodes.rewind()?;
            let mut next = bulk.spool()?;
            let mut group = Vec::new();
            let total = nodes.count;
            let mut size = BranchSize::default();
            for ordinal in 0..total {
                let node = node_decode(nodes.read()?.ok_or_else(|| corrupt("bulk node spool"))?)?;
                size.push(&node);
                if !size.fits(group.len() + 1) {
                    // Avoid a unary final branch by moving one prior child into
                    // the final group when precisely one node remains.
                    let tail = if ordinal + 1 == total {
                        Some(group.pop().ok_or_else(|| corrupt("bulk branch split"))?)
                    } else {
                        None
                    };
                    let (key, r) = store_branch(store, level, &group)?;
                    next.write(&node_bytes(&key, r))?;
                    group.clear();
                    size.clear();
                    if let Some(tail) = tail {
                        size.push(&tail);
                        group.push(tail);
                    }
                    size.push(&node);
                }
                group.push(node);
            }
            if !group.is_empty() {
                let (key, r) = store_branch(store, level, &group)?;
                next.write(&node_bytes(&key, r))?;
            }
            nodes = next;
        }
        nodes.rewind()?;
        Ok(node_decode(nodes.read()?.unwrap())?.1)
    }
}

#[derive(Default)]
struct BranchSize {
    children: HashMap<ObjectHash, u64>,
    row_bytes: usize,
}
impl BranchSize {
    fn push(&mut self, (key, reference): &(Vec<u8>, ObjectRef)) {
        let next = self.children.len() as u64;
        let index = *self.children.entry(reference.hash).or_insert(next);
        self.row_bytes += 1 + cbor::head_len(key.len() as u64) + key.len() + cbor::head_len(index);
    }
    fn fits(&self, rows: usize) -> bool {
        // Eight canonical header bytes, the child hash table, the enclosing
        // pair and one-byte height (1..=16), then the CBOR rows array.
        self.children.len() <= 1024
            && 8 + 32 * self.children.len() + 2 + cbor::head_len(rows as u64) + self.row_bytes
                <= PAGE_LIMIT
    }
    fn clear(&mut self) {
        self.children.clear();
        self.row_bytes = 0;
    }
}

#[cfg(test)]
mod memory_tests {
    use super::*;
    #[test]
    fn small_inline_reader_does_not_retain_large_probe_capacity() {
        let mut store = crate::v1::MemoryStore::sealed();
        let limits = Limits {
            max_memory_bytes: 1 << 20,
            ..Default::default()
        };
        let mut builder = ArchiveBuilder::bulk(&mut store, limits).unwrap();
        builder
            .add_file(&path_from_str("small").unwrap(), &[7; 512])
            .unwrap();
        let bulk = builder.bulk.as_ref().unwrap();
        let EntryData::File {
            data: FileData::Inline(bytes),
            ..
        } = &bulk.buffered[0].entry.data
        else {
            panic!()
        };
        assert_eq!(bytes, &[7; 512]);
        assert!(
            bytes.capacity() <= 1024,
            "a512B file must not retain the48KiB probe"
        );
    }
    #[test]
    fn bulk_flushes_by_owned_capacity_not_encoded_length() {
        let mut bulk = Bulk::new(Limits {
            max_memory_bytes: 1 << 20,
            ..Default::default()
        })
        .unwrap();
        for name in ["a", "b"] {
            let mut bytes = Vec::with_capacity(80 * 1024);
            bytes.resize(512, 7);
            bulk.push(
                &path_from_str(name).unwrap(),
                empty_metadata(),
                EntryData::File {
                    length: 512,
                    data: FileData::Inline(bytes),
                },
            )
            .unwrap();
        }
        assert_eq!(
            bulk.buffered.len(),
            1,
            "second oversize backing allocation must flush the first"
        );
        assert!(bulk.quota.counters.written.load(Ordering::Relaxed) > 0);
        assert!(bulk.memory <= bulk.limits.max_memory_bytes / 8);
    }
}
