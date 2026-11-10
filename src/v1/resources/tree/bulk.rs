//! Initial packing: external key sort followed by one encoding per directory
//! page. Temporary files are private, quota-charged, and never durable state.
use super::*;
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
}
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
        })
    }
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > self.max_record {
            return Err(Error::Limit("bulk record memory"));
        }
        let span = bytes.len() as u64 + 4;
        self.quota.reserve(span)?;
        self.bytes += span;
        self.file.write_all(&(bytes.len() as u32).to_le_bytes())?;
        self.file.write_all(bytes)?;
        self.quota
            .counters
            .written
            .fetch_add(span, Ordering::Relaxed);
        self.count += 1;
        Ok(())
    }
    fn rewind(&mut self) -> Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        Ok(())
    }
    fn read(&mut self) -> Result<Option<Vec<u8>>> {
        let mut size = [0; 4];
        let n = self.file.read(&mut size)?;
        if n == 0 {
            return Ok(None);
        }
        self.file.read_exact(&mut size[n..])?;
        let n = u32::from_le_bytes(size) as usize;
        if n > self.max_record {
            return Err(Error::Limit("bulk record memory"));
        }
        let mut bytes = vec![0; n];
        self.file.read_exact(&mut bytes)?;
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
            self.flush()?;
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
            heads.push(run.read()?.map(Record::decode).transpose()?);
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
            heads[i] = runs[i].read()?.map(Record::decode).transpose()?;
        }
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
        let mut directories = vec![Directory::new(Vec::new(), empty_metadata(), self.spool()?)];
        let mut previous: Option<(ResourcePath, bool)> = None;
        while let Some(encoded) = sorted.read()? {
            self.time()?;
            let record = Record::decode(encoded)?;
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
                close_directory(store, &mut directories, &self)?;
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
                directories.push(Directory::new(
                    parent[..=depth].to_vec(),
                    empty_metadata(),
                    self.spool()?,
                ));
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
                directories.push(Directory::new(
                    record.path,
                    record.entry.metadata,
                    self.spool()?,
                ));
            } else {
                directories.last_mut().unwrap().push(store, record.entry)?;
            }
            let memory: usize = directories.iter().map(Directory::memory).sum();
            if memory > self.limits.max_memory_bytes / 2 {
                return Err(Error::Limit("bulk directory frontier memory"));
            }
        }
        while directories.len() > 1 {
            close_directory(store, &mut directories, &self)?;
        }
        directories.pop().unwrap().finish(store, &self)
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
            Entry {
                name,
                metadata,
                data: EntryData::Directory(root),
            },
        )
}
fn header(major: u8, n: usize) -> Vec<u8> {
    let encoded = cbor::encode(&uint(n as u64));
    let mut encoded = encoded;
    encoded[0] |= major << 5;
    encoded
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
    page_last: Vec<u8>,
    nodes: Spool,
}
impl Directory {
    fn new(path: ResourcePath, metadata: Value, nodes: Spool) -> Self {
        Self {
            path,
            metadata,
            rows: Vec::new(),
            row_count: 0,
            children: Vec::new(),
            last: None,
            page_last: Vec::new(),
            nodes,
        }
    }
    fn memory(&self) -> usize {
        self.rows.capacity()
            + self.children.capacity() * std::mem::size_of::<ObjectRef>()
            + self.path.iter().map(|p| p.capacity() + 32).sum::<usize>()
            + 16384
    }
    fn row(&mut self, entry: &Entry) -> Vec<u8> {
        let (value, _) = encode_leaf(std::slice::from_ref(entry));
        let Value::Array(mut rows) = value else {
            unreachable!()
        };
        let Value::Array(mut row) = rows.pop().unwrap() else {
            unreachable!()
        };
        match &entry.data {
            EntryData::Directory(r) => row[3] = uint(child_index(&mut self.children, *r)),
            EntryData::File {
                data: FileData::Extents(r),
                ..
            } => {
                let Value::Array(v) = &mut row[3] else {
                    unreachable!()
                };
                v[2] = uint(child_index(&mut self.children, *r));
            }
            _ => {}
        }
        cbor::encode(&array(row))
    }
    fn push<S: ObjectStore + ?Sized>(&mut self, store: &mut S, entry: Entry) -> Result<()> {
        if self.last.as_ref().is_some_and(|last| last >= &entry.name) {
            return Err(corrupt("bulk directory key order"));
        }
        let before = self.children.len();
        let mut row = self.row(&entry);
        if self.children.len() > 1024
            || 8 + 32 * self.children.len()
                + header(4, self.row_count + 1).len()
                + self.rows.len()
                + row.len()
                > DIRECTORY_LEAF_LIMIT
        {
            self.children.truncate(before);
            if self.row_count == 0 {
                return Err(Error::Limit("directory entry too large"));
            }
            self.flush(store)?;
            row = self.row(&entry);
        }
        if 8 + 32 * self.children.len() + header(4, 1).len() + row.len() > DIRECTORY_LEAF_LIMIT {
            return Err(Error::Limit("directory entry too large"));
        }
        self.rows.extend(row);
        self.row_count += 1;
        self.page_last = entry.name.clone();
        self.last = Some(entry.name);
        Ok(())
    }
    fn flush<S: ObjectStore + ?Sized>(&mut self, store: &mut S) -> Result<()> {
        if self.row_count == 0 {
            return Ok(());
        }
        let mut body = header(4, self.row_count);
        body.append(&mut self.rows);
        let reference = store.put(3, 1, &body, &self.children)?;
        self.nodes.write(&node_bytes(&self.page_last, reference))?;
        self.children.clear();
        self.row_count = 0;
        Ok(())
    }
    fn finish<S: ObjectStore + ?Sized>(mut self, store: &mut S, bulk: &Bulk) -> Result<ObjectRef> {
        self.flush(store)?;
        if self.nodes.count == 0 {
            return Ok(store_leaf(store, &[])?.1);
        }
        let mut level = 0;
        while self.nodes.count > 1 {
            bulk.time()?;
            level += 1;
            if level > 16 {
                return Err(Error::Limit("directory tree height"));
            }
            self.nodes.rewind()?;
            let mut next = bulk.spool()?;
            let mut group = Vec::new();
            let total = self.nodes.count;
            for ordinal in 0..total {
                let node = node_decode(
                    self.nodes
                        .read()?
                        .ok_or_else(|| corrupt("bulk node spool"))?,
                )?;
                group.push(node);
                let (v, c) = encode_branch(level, &group);
                if !fits(&v, &c) {
                    let last = group.pop().unwrap();
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
                    if let Some(tail) = tail {
                        group.push(tail);
                    }
                    group.push(last);
                }
            }
            if !group.is_empty() {
                let (key, r) = store_branch(store, level, &group)?;
                next.write(&node_bytes(&key, r))?;
            }
            self.nodes = next;
        }
        self.nodes.rewind()?;
        Ok(node_decode(self.nodes.read()?.unwrap())?.1)
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
