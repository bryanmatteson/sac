//! Functional erasure/corruption tests; no performance measurements.
use sac::recovery::{self, RecoveryLimits, RecoveryOptions};
use std::io::{Cursor, Read, Seek, SeekFrom};

fn bytes(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 71 + i / 17) % 251) as u8).collect()
}
fn options() -> RecoveryOptions {
    RecoveryOptions {
        block_size: 1024,
        data_shards: 4,
        parity_shards: 2,
    }
}
fn records(source: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let info = recovery::create(
        &mut Cursor::new(source),
        &mut out,
        options(),
        &RecoveryLimits::default(),
    )
    .unwrap();
    assert_eq!(out.len() as u64, info.record_bytes);
    out
}
fn repair(source: &[u8], records: &[u8]) -> sac::Result<(Vec<u8>, recovery::RecoveryReport)> {
    let mut out = Vec::new();
    let report = recovery::repair(
        &mut Cursor::new(source),
        &mut Cursor::new(records),
        &mut out,
        &RecoveryLimits::default(),
    )?;
    Ok((out, report))
}

#[test]
fn multiple_stripes_partial_tail_and_exact_copy() {
    for n in [1, 1023, 1024, 1025, 4096, 4097, 12345] {
        let source = bytes(n);
        let records = records(&source);
        let (out, report) = repair(&source, &records).unwrap();
        assert_eq!(out, source);
        assert_eq!(report.repaired_data_shards, 0);
        assert_eq!(report.damaged_parity_shards, 0);
        assert_eq!(report.degraded_metadata_copies, 0);
    }
}

#[test]
fn every_pair_of_data_or_parity_erasures_is_repairable() {
    let source = bytes(4096);
    let original = records(&source);
    let metadata_size = (4 + 2) * 32 + 32;
    for first in 0..6 {
        for second in first + 1..6 {
            let mut data = source.clone();
            let mut parity = original.clone();
            for index in [first, second] {
                if index < 4 {
                    data[index * 1024 + 91] ^= 0x91;
                } else {
                    parity[128 + metadata_size + (index - 4) * 1024 + 73] ^= 0x73;
                }
            }
            let (out, report) = repair(&data, &parity).unwrap();
            assert_eq!(out, source, "erased {first}/{second}");
            assert_eq!(
                report.repaired_data_shards + report.damaged_parity_shards,
                2
            );
        }
    }
}

#[test]
fn damaged_preamble_and_truncated_trailer_restore_exact_bytes() {
    let source = bytes(8199);
    let parity = records(&source);
    let mut damaged = source.clone();
    damaged[0..128].fill(0);
    damaged.truncate(8192);
    let (out, report) = repair(&damaged, &parity).unwrap();
    assert_eq!(out, source);
    assert_eq!(report.repaired_data_shards, 2);
}

#[test]
fn duplicate_headers_and_metadata_survive_one_damaged_copy() {
    let source = bytes(4096);
    let mut parity = records(&source);
    parity[0] ^= 1;
    parity[128] ^= 1;
    let mut damaged = source.clone();
    damaged[0] ^= 7;
    let (out, report) = repair(&damaged, &parity).unwrap();
    assert_eq!(out, source);
    assert_eq!(report.degraded_metadata_copies, 1);
    let mut parity = records(&source);
    let last = parity.len() - 1;
    parity[last] ^= 1;
    assert_eq!(repair(&damaged, &parity).unwrap().0, source);
}

#[test]
fn missing_parity_tail_still_allows_an_intact_source() {
    let source = bytes(4096);
    let mut parity = records(&source);
    parity.truncate(128 + (4 + 2) * 32 + 32); // first metadata only
    let (out, report) = repair(&source, &parity).unwrap();
    assert_eq!(out, source);
    assert_eq!(report.damaged_parity_shards, 2);
    assert_eq!(report.degraded_metadata_copies, 1);
}

#[test]
fn excessive_damage_and_unrelated_records_reject() {
    let source = bytes(4096);
    let parity = records(&source);
    let mut damaged = source.clone();
    for index in 0..3 {
        damaged[index * 1024] ^= 1;
    }
    assert!(repair(&damaged, &parity).is_err());
    assert!(repair(&vec![0; 4096], &parity).is_err());
    let mut both_headers = parity.clone();
    let last = both_headers.len() - 1;
    both_headers[0] ^= 1;
    both_headers[last] ^= 1;
    assert!(repair(&source, &both_headers).is_err());
    let mut both_metadata = parity.clone();
    both_metadata[128] ^= 1;
    both_metadata[128 + (6 * 32 + 32) + 2 * 1024] ^= 1;
    assert!(repair(&source, &both_metadata).is_err());
}

#[test]
fn malformed_geometry_conflicting_headers_and_finite_limits_reject() {
    let source = bytes(4096);
    let parity = records(&source);
    for o in [
        RecoveryOptions {
            block_size: 1000,
            ..options()
        },
        RecoveryOptions {
            data_shards: 0,
            ..options()
        },
        RecoveryOptions {
            parity_shards: 129,
            ..options()
        },
    ] {
        assert!(
            recovery::create(
                &mut Cursor::new(&source),
                &mut Vec::new(),
                o,
                &RecoveryLimits::default()
            )
            .is_err()
        );
    }
    assert!(RecoveryOptions::with_percent(0).is_err());
    assert!(RecoveryOptions::with_percent(101).is_err());
    let mut conflicting = parity.clone();
    let other = records(&bytes(4097));
    let n = conflicting.len();
    conflicting[n - 128..].copy_from_slice(&other[other.len() - 128..]);
    assert!(repair(&source, &conflicting).is_err());
    for limits in [
        RecoveryLimits {
            max_source_bytes: 1,
            ..Default::default()
        },
        RecoveryLimits {
            max_record_bytes: 1,
            ..Default::default()
        },
        RecoveryLimits {
            max_memory_bytes: 1,
            ..Default::default()
        },
        RecoveryLimits {
            max_stripes: 0,
            ..Default::default()
        },
    ] {
        assert!(recovery::inspect(&mut Cursor::new(&parity), &limits).is_err());
    }
    let limits = RecoveryLimits {
        max_output_bytes: 1,
        ..Default::default()
    };
    assert!(
        recovery::repair(
            &mut Cursor::new(&source),
            &mut Cursor::new(&parity),
            &mut Vec::new(),
            &limits
        )
        .is_err()
    );
    let mut extra = parity.clone();
    extra.push(0);
    assert!(repair(&source, &extra).is_err());
}

#[test]
fn percentages_and_maximum_field_geometry_roundtrip() {
    let source = bytes(1024 * 3 + 7);
    for percent in [1, 5, 10, 50, 100] {
        let mut o = RecoveryOptions::with_percent(percent).unwrap();
        o.block_size = 1024;
        let mut parity = Vec::new();
        recovery::create(
            &mut Cursor::new(&source),
            &mut parity,
            o,
            &RecoveryLimits::default(),
        )
        .unwrap();
        let mut damaged = source.clone();
        damaged[0] ^= 1;
        assert_eq!(repair(&damaged, &parity).unwrap().0, source);
    }
    let mut parity = Vec::new();
    let o = RecoveryOptions {
        block_size: 1024,
        data_shards: 128,
        parity_shards: 128,
    };
    let source = bytes(128 * 1024);
    recovery::create(
        &mut Cursor::new(&source),
        &mut parity,
        o,
        &RecoveryLimits::default(),
    )
    .unwrap();
    let mut damaged = source.clone();
    for i in [0, 63, 127] {
        damaged[i * 1024] ^= 1;
    }
    assert_eq!(repair(&damaged, &parity).unwrap().0, source);
}

#[test]
fn generation_rejects_source_changed_between_passes() {
    struct Changing {
        inner: Cursor<Vec<u8>>,
        starts: u32,
    }
    impl Read for Changing {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.inner.read(b)
        }
    }
    impl Seek for Changing {
        fn seek(&mut self, p: SeekFrom) -> std::io::Result<u64> {
            if p == SeekFrom::Start(0) {
                self.starts += 1;
                if self.starts == 2 {
                    self.inner.get_mut()[0] ^= 1;
                }
            }
            self.inner.seek(p)
        }
    }
    let mut source = Changing {
        inner: Cursor::new(bytes(4096)),
        starts: 0,
    };
    assert!(
        recovery::create(
            &mut source,
            &mut Vec::new(),
            options(),
            &RecoveryLimits::default()
        )
        .is_err()
    );
}
