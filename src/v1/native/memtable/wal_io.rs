//! Bounded WAL framing with borrowed payloads and complete short-write handling.
use super::Table;
use std::fs::File;
use std::io::{self, IoSlice, Write};

const GROUP_ENTRIES: usize = 64;
const GROUP_SLICES: usize = 3 * GROUP_ENTRIES + 2;
const METADATA_BYTES: usize = 4096;
const OUTPUT_SCRATCH_LIMIT: usize = 8192;
// Framing bytes and descriptors share the original 8 KiB output limit.
// Large values and keys that do not fit are borrowed from the admitted batch.
const _: () =
    assert!(METADATA_BYTES + size_of::<[IoSlice<'_>; GROUP_SLICES]>() <= OUTPUT_SCRATCH_LIMIT);

pub(super) fn write_record(file: &mut File, header: &[u8; 64], batch: &Table) -> io::Result<()> {
    #[cfg(unix)]
    {
        write_vectored_record(file, header, batch)
    }
    #[cfg(not(unix))]
    {
        write_buffered_record(file, header, batch)
    }
}

fn prefix(key: &[u8], value: Option<&[u8]>) -> [u8; 13] {
    let mut bytes = [0; 13];
    bytes[0] = u8::from(value.is_some());
    bytes[1..5].copy_from_slice(&(key.len() as u32).to_le_bytes());
    bytes[5..].copy_from_slice(&(value.map_or(0, <[u8]>::len) as u64).to_le_bytes());
    bytes
}

#[cfg(any(unix, test))]
fn write_vectored_record(
    writer: &mut impl Write,
    header: &[u8; 64],
    batch: &Table,
) -> io::Result<()> {
    debug_assert!(!batch.is_empty());
    let mut hash = blake3::Hasher::new_derive_key("sac.memtable.wal.record.v1");
    hash.update(&header[..32]);
    let mut entries = batch.iter();
    let mut first = true;
    while entries.len() > 0 {
        let count = entries.len().min(GROUP_ENTRIES);
        let last = entries.len() == count;
        let key_bytes: usize = entries
            .clone()
            .take(count)
            .map(|(key, _)| 13 + key.len())
            .sum();
        let pack_keys = key_bytes <= METADATA_BYTES;
        // Reserve every prefix (and every key when they fit) before using any
        // space for small values. Long keys never increase the group count.
        let mut required = if pack_keys { key_bytes } else { 13 * count };
        let mut metadata = [0; METADATA_BYTES];
        let mut end = 0;
        let mut packed_values = 0u64;
        for (index, (key, value)) in entries.clone().take(count).enumerate() {
            let start = end;
            metadata[end..end + 13].copy_from_slice(&prefix(key, value.as_deref()));
            end += 13;
            if pack_keys {
                metadata[end..end + key.len()].copy_from_slice(key);
                end += key.len();
                required -= 13 + key.len();
                if let Some(value) = value.as_deref().filter(|value| {
                    value.len() <= 256 && end + value.len() + required <= METADATA_BYTES
                }) {
                    metadata[end..end + value.len()].copy_from_slice(value);
                    end += value.len();
                    packed_values |= 1 << index;
                }
                hash.update(&metadata[start..end]);
            } else {
                required -= 13;
                hash.update(&metadata[start..end]);
                hash.update(key);
            }
            if packed_values & (1 << index) == 0 {
                hash.update(value.as_deref().unwrap_or(&[]));
            }
        }
        let digest = if last {
            *hash.finalize().as_bytes()
        } else {
            [0; 32]
        };
        let mut slices = [IoSlice::new(&[]); GROUP_SLICES];
        let mut used = 0;
        if first {
            slices[used] = IoSlice::new(header);
            used += 1;
        }
        let mut start = 0;
        let mut end = 0;
        for (index, (key, value)) in entries.by_ref().take(count).enumerate() {
            end += 13 + if pack_keys { key.len() } else { 0 };
            if packed_values & (1 << index) != 0 {
                end += value.as_deref().map_or(0, <[u8]>::len);
                continue;
            }
            slices[used] = IoSlice::new(&metadata[start..end]);
            used += 1;
            start = end;
            for part in [
                if pack_keys { &[] } else { key.as_ref() },
                value.as_deref().unwrap_or(&[]),
            ] {
                if !part.is_empty() {
                    slices[used] = IoSlice::new(part);
                    used += 1;
                }
            }
        }
        if start < end {
            slices[used] = IoSlice::new(&metadata[start..end]);
            used += 1;
        }
        if last {
            slices[used] = IoSlice::new(&digest);
            used += 1;
        }
        write_all_vectored(writer, &mut slices[..used])?;
        first = false;
    }
    Ok(())
}

#[cfg(any(unix, test))]
fn write_all_vectored(writer: &mut impl Write, mut slices: &mut [IoSlice<'_>]) -> io::Result<()> {
    while !slices.is_empty() {
        match writer.write_vectored(slices) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(written) => IoSlice::advance_slices(&mut slices, written),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

// Preserve buffered writes on platforms whose File implementation does not
// provide Unix writev, rather than relying on the scalar Write fallback there.
#[cfg(any(not(unix), test))]
fn write_buffered_record(
    writer: &mut impl Write,
    header: &[u8; 64],
    batch: &Table,
) -> io::Result<()> {
    let mut hash = blake3::Hasher::new_derive_key("sac.memtable.wal.record.v1");
    hash.update(&header[..32]);
    let mut writer = io::BufWriter::with_capacity(OUTPUT_SCRATCH_LIMIT, writer);
    writer.write_all(header)?;
    for (key, value) in batch {
        let prefix = prefix(key, value.as_deref());
        for part in [&prefix[..], key.as_ref(), value.as_deref().unwrap_or(&[])] {
            writer.write_all(part)?;
            hash.update(part);
        }
    }
    writer.write_all(hash.finalize().as_bytes())?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Sink {
        bytes: Vec<u8>,
        calls: usize,
        max_slices: usize,
        max_write: Option<usize>,
        interrupt_every: Option<usize>,
        fail_after: Option<usize>,
        zero: bool,
    }
    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.write_vectored(&[IoSlice::new(bytes)])
        }
        fn write_vectored(&mut self, slices: &[IoSlice<'_>]) -> io::Result<usize> {
            self.calls += 1;
            self.max_slices = self.max_slices.max(slices.len());
            if self.zero {
                return Ok(0);
            }
            if self
                .interrupt_every
                .is_some_and(|n| self.calls.is_multiple_of(n))
            {
                return Err(io::ErrorKind::Interrupted.into());
            }
            if self.fail_after.is_some_and(|n| self.bytes.len() >= n) {
                return Err(io::ErrorKind::Other.into());
            }
            let mut remaining = self.max_write.unwrap_or(usize::MAX);
            if let Some(end) = self.fail_after {
                remaining = remaining.min(end - self.bytes.len());
            }
            let before = self.bytes.len();
            for slice in slices {
                let take = slice.len().min(remaining);
                self.bytes.extend_from_slice(&slice[..take]);
                remaining -= take;
                if remaining == 0 {
                    break;
                }
            }
            Ok(self.bytes.len() - before)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    fn batch(count: usize, size: usize) -> Table {
        (0..count)
            .map(|i| {
                (
                    (i as u64).to_be_bytes().into(),
                    Some(vec![i as u8; size].into_boxed_slice()),
                )
            })
            .collect()
    }
    fn compare(batch: &Table, sink: &mut Sink) {
        let header = [3; 64];
        let mut reference = Vec::new();
        write_buffered_record(&mut reference, &header, batch).unwrap();
        write_vectored_record(sink, &header, batch).unwrap();
        assert_eq!(sink.bytes, reference);
    }
    #[test]
    fn wide_batch_is_one_write_without_a_larger_output_buffer() {
        let batch = batch(64, 1024);
        let mut sink = Sink::default();
        compare(&batch, &mut sink);
        assert_eq!(sink.calls, 1);
        assert_eq!(sink.max_slices, 130);
        assert_eq!(sink.bytes.len(), 66976);
        let mut buffered = Sink::default();
        write_buffered_record(&mut buffered, &[3; 64], &batch).unwrap();
        assert!(buffered.calls > sink.calls);
        eprintln!(
            "64 x 1 KiB WAL record: buffered {} file writes -> vectored {}",
            buffered.calls, sink.calls
        );
    }
    #[test]
    fn small_values_coalesce_without_expanding_output_scratch() {
        let mut sink = Sink::default();
        compare(&batch(64, 128), &mut sink);
        assert_eq!(sink.calls, 1);
        assert_eq!(sink.max_slices, 88);
    }
    #[test]
    fn group_boundaries_large_values_and_tombstones_preserve_legacy_bytes() {
        for count in [1, 63, 64, 65, 127, 128, 129, 1024] {
            for size in [0, 128, 256, 257, 1024] {
                let mut sink = Sink::default();
                compare(&batch(count, size), &mut sink);
                assert_eq!(sink.calls, count.div_ceil(GROUP_ENTRIES));
            }
        }
        let mixed = Table::from([
            (Box::from(&b""[..]), Some(Box::from(&b""[..]))),
            (Box::from(&b"deleted"[..]), None),
            (
                Box::from(&b"large"[..]),
                Some(vec![7; 128 * 1024].into_boxed_slice()),
            ),
        ]);
        compare(&mixed, &mut Sink::default());
    }
    #[test]
    fn long_keys_preserve_group_count_and_record_bytes() {
        let batch: Table = (0u64..129)
            .map(|i| {
                let mut key = vec![0; 2047];
                key[..8].copy_from_slice(&i.to_be_bytes());
                (
                    key.into_boxed_slice(),
                    Some(vec![7; 1024].into_boxed_slice()),
                )
            })
            .collect();
        let mut sink = Sink::default();
        compare(&batch, &mut sink);
        assert_eq!(sink.calls, batch.len().div_ceil(GROUP_ENTRIES));
        compare(
            &batch,
            &mut Sink {
                max_write: Some(1024),
                interrupt_every: Some(3),
                ..Default::default()
            },
        );
    }
    #[test]
    fn partial_writes_and_interruptions_advance_across_every_kind_of_slice() {
        let mut batch = batch(3, 1024);
        batch.insert(
            Box::from(&b"small"[..]),
            Some(vec![7; 99].into_boxed_slice()),
        );
        batch.insert(Box::from(&b""[..]), None);
        batch.insert(Box::from(&b"empty"[..]), Some(Box::from(&b""[..])));
        for max_write in [1, 12, 13, 31, 63, 64, 65, 96, 127, 1024] {
            compare(
                &batch,
                &mut Sink {
                    max_write: Some(max_write),
                    interrupt_every: Some(3),
                    ..Default::default()
                },
            );
        }
    }
    #[test]
    fn write_zero_and_partial_record_failures_are_returned() {
        let header = [3; 64];
        let batch = batch(65, 1024);
        let mut zero = Sink {
            zero: true,
            ..Default::default()
        };
        assert_eq!(
            write_vectored_record(&mut zero, &header, &batch)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WriteZero
        );
        let mut reference = Vec::new();
        write_buffered_record(&mut reference, &header, &batch).unwrap();
        for end in [1, 63, 64, 65, 80, 1024, 66944, 66976, reference.len() - 1] {
            let mut sink = Sink {
                fail_after: Some(end),
                ..Default::default()
            };
            assert_eq!(
                write_vectored_record(&mut sink, &header, &batch)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Other
            );
            assert_eq!(sink.bytes, reference[..end]);
        }
    }
}
