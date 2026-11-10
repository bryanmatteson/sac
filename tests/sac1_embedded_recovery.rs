#![cfg(feature = "native")]
use sac::recovery::{self, RecoveryLimits, RecoveryOptions, embedded};
use sac::v1::{
    cbor::Value,
    metadata::MetadataEditor,
    resources::{ArchiveBuilder, ArchiveReader, Limits},
};
use sac::{NativeReader, NativeStore, ObjectStore};
use std::{fs, io::Cursor};

fn data(n: usize) -> Vec<u8> {
    let mut state = 0x12345678u32;
    (0..n)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}
fn source(path: &std::path::Path, n: usize) -> (sac::ObjectHash, Vec<u8>) {
    let mut store = NativeStore::create_live(path, [73; 16]).unwrap();
    let bytes = data(n);
    let mut builder = ArchiveBuilder::new(&mut store);
    builder.add_file(&[b"input.bin".to_vec()], &bytes).unwrap();
    let snapshot = builder.finish().unwrap();
    let directory = store.get(snapshot).unwrap().children[0];
    let root = store
        .put(
            8,
            1,
            &sac::cbor::encode(&Value::Array(vec![
                Value::text("example.opaque"),
                Value::text("root"),
                Value::Uint(1),
                Value::bytes([0, 255, 31]),
            ])),
            &[],
        )
        .unwrap();
    let snapshot = sac::resources::snapshot(
        &mut store,
        directory,
        vec![sac::resources::Profile {
            id: "example.opaque".into(),
            version: 1,
            root,
        }],
        vec![],
    )
    .unwrap();
    let mut editor = MetadataEditor::open(&mut store, snapshot, Limits::default()).unwrap();
    editor
        .set(
            "example.unknown",
            &Value::Array(vec![Value::text("kept"), Value::bytes([0, 1, 255])]),
        )
        .unwrap();
    let snapshot = editor.finish().unwrap();
    store.publish(snapshot).unwrap();
    (snapshot.hash, bytes)
}

#[test]
fn embedded_profile_keeps_resources_and_metadata_and_repairs_without_admission() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("live.sac");
    let output = tmp.path().join("protected.sac");
    let (snapshot, bytes) = source(&input, 180_000);
    let options = RecoveryOptions {
        block_size: 1024,
        ..RecoveryOptions::with_percent(20).unwrap()
    };
    let info = embedded::embed_file(
        &input,
        &output,
        options,
        &embedded::EmbeddedLimits::default(),
        false,
    )
    .unwrap();
    assert_eq!(info.protected_snapshot, snapshot);
    let container = NativeReader::open(&output).unwrap();
    container.validate().unwrap();
    let current = container.reader().snapshot().unwrap();
    assert_ne!(current.hash, snapshot);
    let resources = ArchiveReader::open(&container, current, Limits::default()).unwrap();
    assert_eq!(
        resources
            .read_file_bounded(&[b"input.bin".to_vec()], bytes.len())
            .unwrap()
            .unwrap()
            .1,
        bytes
    );
    let metadata = sac::v1::metadata::MetadataReader::open(&container, current, Limits::default())
        .unwrap()
        .unwrap();
    assert!(metadata.get_encoded("example.unknown").unwrap().is_some());
    let original = fs::read(&output).unwrap();
    let mut damaged = original.clone();
    let beacons: Vec<_> = original
        .windows(8)
        .enumerate()
        .filter_map(|(i, b)| (b == b"SAC1RSEG").then_some(i))
        .collect();
    assert!(beacons.len() >= 2);
    let physical = u64::from_le_bytes(
        original[beacons[0] + 84..beacons[0] + 92]
            .try_into()
            .unwrap(),
    ) as usize;
    let header = physical + 128;
    let k = 100;
    let m = 20;
    damaged[header + (k + m) * 32 + 32 + 71] ^= 1; // parity damage inside an invalidated profile frame
    damaged[beacons[0]] ^= 1; // one discovery copy lost
    damaged[..128].fill(0);
    damaged[13 * 1024] ^= 1;
    let end = damaged.len();
    damaged[end - 128..].fill(0); // outer publication lost
    let inspect =
        embedded::inspect(&mut Cursor::new(&damaged), &RecoveryLimits::default()).unwrap();
    assert_eq!(inspect, info);
    let mut repaired = Vec::new();
    let report = embedded::repair(
        &mut Cursor::new(&damaged),
        &mut repaired,
        &RecoveryLimits::default(),
    )
    .unwrap();
    assert!(report.repaired_data_shards >= 2);
    assert!(report.damaged_parity_shards >= 1);
    assert_eq!(repaired.len() as u64, info.recovery.source_bytes);
    let restored = tmp.path().join("restored.sac");
    fs::write(&restored, &repaired).unwrap();
    let reader = NativeReader::open(&restored).unwrap();
    reader.validate().unwrap();
    assert_eq!(reader.reader().snapshot().unwrap().hash, snapshot);
    assert_eq!(fs::read(&input).unwrap()[..4], *b"SAC1");
    assert!(
        embedded::embed_file(
            &input,
            &output,
            options,
            &embedded::EmbeddedLimits::default(),
            false
        )
        .is_err()
    );
    assert_eq!(fs::read(&output).unwrap(), original);
}

#[test]
fn repeated_embedding_replaces_old_profile_without_nested_growth_and_spans_segments() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input.sac");
    let first = tmp.path().join("first.sac");
    let second = tmp.path().join("second.sac");
    let (snapshot, _) = source(&input, 1_200_000);
    let options = RecoveryOptions {
        block_size: 1024,
        ..RecoveryOptions::with_percent(100).unwrap()
    };
    let a = embedded::embed_file(
        &input,
        &first,
        options,
        &embedded::EmbeddedLimits::default(),
        false,
    )
    .unwrap();
    assert!(a.segments > 1);
    let b = embedded::embed_file(
        &first,
        &second,
        options,
        &embedded::EmbeddedLimits::default(),
        false,
    )
    .unwrap();
    assert_eq!(a, b);
    assert_eq!(a.protected_snapshot, snapshot);
    assert_eq!(
        fs::metadata(&first).unwrap().len(),
        fs::metadata(&second).unwrap().len()
    );
    let mut damaged = fs::read(&second).unwrap();
    damaged[0] ^= 1;
    let mut restored = Vec::new();
    embedded::repair(
        &mut Cursor::new(damaged),
        &mut restored,
        &RecoveryLimits::default(),
    )
    .unwrap();
    assert_eq!(
        sac::MemoryStore::from_bytes(restored)
            .unwrap()
            .reader()
            .unwrap()
            .snapshot()
            .unwrap()
            .hash,
        snapshot
    );
}

#[test]
fn embedded_limits_and_excess_damage_reject() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input.sac");
    let output = tmp.path().join("protected.sac");
    source(&input, 180_000);
    let o = RecoveryOptions {
        block_size: 1024,
        ..RecoveryOptions::with_percent(1).unwrap()
    };
    embedded::embed_file(
        &input,
        &output,
        o,
        &embedded::EmbeddedLimits::default(),
        false,
    )
    .unwrap();
    let mut damaged = fs::read(&output).unwrap();
    damaged[0] ^= 1;
    damaged[1024] ^= 1;
    assert!(
        embedded::repair(
            &mut Cursor::new(&damaged),
            &mut Vec::new(),
            &RecoveryLimits::default()
        )
        .is_err()
    );
    assert!(
        embedded::inspect(
            &mut Cursor::new(&damaged),
            &RecoveryLimits {
                max_memory_bytes: 1,
                ..Default::default()
            }
        )
        .is_err()
    );
    let failed = tmp.path().join("failed.sac");
    assert!(
        embedded::embed_file(
            &input,
            &failed,
            o,
            &embedded::EmbeddedLimits {
                max_temp_bytes: 1024,
                ..Default::default()
            },
            false
        )
        .is_err()
    );
    assert!(!failed.exists());
    assert!(recovery::inspect(&mut Cursor::new(&damaged), &RecoveryLimits::default()).is_err());
}

#[test]
fn local_removal_is_explicit_and_checkpoint_attestations_survive_refresh() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input.sac");
    let output = tmp.path().join("protected.sac");
    let refreshed = tmp.path().join("refreshed.sac");
    source(&input, 8193);
    let mut store = NativeStore::open(&input, true).unwrap();
    let snapshot = store.reader().snapshot().unwrap();
    let att = store
        .put(
            9,
            1,
            &sac::cbor::encode(&Value::Array(vec![Value::bytes(
                b"retained optional signature material",
            )])),
            &[],
        )
        .unwrap();
    let local = store
        .put(
            8,
            1,
            &sac::cbor::encode(&Value::Array(vec![
                Value::text("example.local"),
                Value::text("root"),
                Value::Uint(1),
                Value::bytes([1, 2, 3]),
            ])),
            &[],
        )
        .unwrap();
    let commit = sac::resources::commit(&mut store, snapshot, Some(att), Some(local)).unwrap();
    store.publish_commit(commit).unwrap();
    drop(store);
    let options = RecoveryOptions::default();
    assert!(
        embedded::embed_file(
            &input,
            &output,
            options,
            &embedded::EmbeddedLimits::default(),
            false
        )
        .is_err()
    );
    assert!(!output.exists());
    embedded::embed_file(
        &input,
        &output,
        options,
        &embedded::EmbeddedLimits::default(),
        true,
    )
    .unwrap();
    embedded::embed_file(
        &output,
        &refreshed,
        options,
        &embedded::EmbeddedLimits::default(),
        false,
    )
    .unwrap();
    let mut repaired = Vec::new();
    embedded::repair(
        &mut Cursor::new(fs::read(refreshed).unwrap()),
        &mut repaired,
        &RecoveryLimits::default(),
    )
    .unwrap();
    let restored = sac::MemoryStore::from_bytes(repaired).unwrap();
    let commit = restored.get(restored.root().unwrap().root).unwrap();
    let value = sac::cbor::decode(&commit.bytes).unwrap();
    let Value::Array(fields) = value else {
        panic!()
    };
    assert_eq!(fields[2], Value::Null);
    let Value::Uint(i) = fields[1] else { panic!() };
    assert_eq!(commit.children[i as usize].hash, att.hash);
    assert_eq!(
        restored.reader().unwrap().snapshot().unwrap().hash,
        snapshot.hash
    );
}
