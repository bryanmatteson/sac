#![cfg(feature = "native")]

use sac::resources::{ArchiveBuilder, ArchiveReader, Limits, commit, path_from_str};
use sac::v1::wire::frame_span;
use sac::{
    CanonicalObject, Error, NativeReader, NativeStore, ObjectHash, ObjectRef, ObjectStore,
    ObjectView, SealedWriter, SealingOptions, pack_commit_with_limits, pack_commit_with_options,
};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use std::process::{Command, Stdio};

fn fixture(path: &Path, level: i32) -> (ObjectRef, Vec<u8>) {
    let mut store = NativeStore::create_live(path, [31; 16]).unwrap();
    store.set_compression_level(level);
    let data: Vec<u8> = (0..360_000)
        .map(|i| ((i / 97 + i % 31) % 251) as u8)
        .collect();
    let mut builder = ArchiveBuilder::new(&mut store);
    builder.set_chunk_size(65536).unwrap();
    builder
        .add_file(&path_from_str("chunked").unwrap(), &data)
        .unwrap();
    builder
        .add_file(&path_from_str("nested/inline").unwrap(), b"hello")
        .unwrap();
    for i in 0..210 {
        builder
            .add_file(
                &path_from_str(&format!("rows/{i:04}")).unwrap(),
                &[i as u8; 192],
            )
            .unwrap();
    }
    let snapshot = builder.finish().unwrap();
    let root = commit(&mut store, snapshot, None, None).unwrap();
    store.publish_commit(root).unwrap();
    (root, data)
}

// These files have already passed physical validation. Compare stored payloads
// independently of the child locator table that relocation must rewrite.
fn payloads(bytes: &[u8]) -> BTreeMap<ObjectHash, (u8, Vec<u8>)> {
    let mut at = if bytes[8] == 1 { 12288 } else { 128 };
    let mut result = BTreeMap::new();
    while at < bytes.len() {
        if &bytes[at..at + 8] == b"SAC1END\0" {
            at += 160;
            continue;
        }
        let frame = &bytes[at..];
        let span = frame_span(&frame[..56]).unwrap();
        let stored = u32::from_le_bytes(frame[8..12].try_into().unwrap()) as usize;
        result.insert(
            ObjectHash(frame[16..48].try_into().unwrap()),
            (frame[4], frame[56..56 + stored].to_vec()),
        );
        at += span;
    }
    result
}

struct CanonicalOnly<'a>(&'a NativeReader);
impl ObjectStore for CanonicalOnly<'_> {
    fn get(&self, reference: ObjectRef) -> sac::Result<CanonicalObject> {
        self.0.get(reference)
    }
    fn visit_verified(
        &self,
        reference: ObjectRef,
        visitor: &mut dyn FnMut(ObjectView<'_>) -> sac::Result<()>,
    ) -> sac::Result<()> {
        self.0.visit_verified(reference, visitor)
    }
    fn put(&mut self, _: u16, _: u16, _: &[u8], _: &[ObjectRef]) -> sac::Result<ObjectRef> {
        Err(Error::Missing)
    }
}

#[test]
fn encoded_sealing_preserves_each_source_codec_and_generic_fallback_is_canonical() {
    let temp = tempfile::tempdir().unwrap();
    for level in [-3, 0, 1, 9] {
        let path = temp.path().join(format!("source-{level}.sac"));
        let (root, data) = fixture(&path, level);
        let reader = NativeReader::open(&path).unwrap();
        reader.validate().unwrap();
        let ordinary =
            pack_commit_with_limits(&reader, root, Vec::new(), Limits::default()).unwrap();
        let options = SealingOptions {
            preserve_source_encoding: true,
            ..SealingOptions::default()
        };
        let preserved =
            pack_commit_with_options(&reader, root, Vec::new(), Limits::default(), options)
                .unwrap();
        let original_payloads = payloads(&fs::read(&path).unwrap());
        for (hash, payload) in payloads(&preserved) {
            assert_eq!(
                original_payloads.get(&hash),
                Some(&payload),
                "level {level}"
            );
        }
        if level == 1 {
            assert_eq!(preserved, ordinary);
        } else if level == 0 || level == 9 {
            assert_ne!(
                preserved, ordinary,
                "fixture must distinguish source encoding policy"
            );
        }
        assert_eq!(
            pack_commit_with_options(
                &CanonicalOnly(&reader),
                root,
                Vec::new(),
                Limits::default(),
                options
            )
            .unwrap(),
            ordinary
        );
        assert_eq!(
            pack_commit_with_options(
                &reader,
                root,
                Vec::new(),
                Limits::default(),
                SealingOptions::default()
            )
            .unwrap(),
            ordinary
        );
        let sealed = temp.path().join(format!("seal-{level}.sac"));
        fs::write(&sealed, &preserved).unwrap();
        let sealed = NativeReader::open(&sealed).unwrap();
        sealed.validate().unwrap();
        let archive = ArchiveReader::open(
            &sealed,
            sealed.reader().snapshot().unwrap(),
            Limits::default(),
        )
        .unwrap();
        archive.verify().unwrap();
        assert_eq!(
            archive
                .read_range(&path_from_str("chunked").unwrap(), 65_510, 90)
                .unwrap(),
            data[65_510..65_600]
        );
    }
}

#[test]
fn encoded_visits_check_exact_payload_even_after_decoded_cache_admission() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("source.sac");
    let mut store = NativeStore::create_live(&path, [32; 16]).unwrap();
    let mut state = 0x12345678u32;
    let mut data = Vec::new();
    for _ in 0..8192 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        data.push(state as u8);
    }
    data.extend_from_within(..);
    let child = store.put(7, 1, &data, &[]).unwrap();
    // Warming the decoded cache must not also retain a tiny raw read window.
    assert!(child.address.length > 1024);
    // Keep this occurrence outside the small immutable control read window.
    store.set_compression_level(0);
    store.put(0x8001, 1, &vec![0; 1 << 20], &[]).unwrap();
    store.set_compression_level(1);
    let parent = store.put(0x8000, 1, b"opaque parent", &[child]).unwrap();
    let snapshot = {
        let mut builder = ArchiveBuilder::new(&mut store);
        builder
            .add_file(&path_from_str("file").unwrap(), b"hello")
            .unwrap();
        builder.finish().unwrap()
    };
    let root = commit(&mut store, snapshot, None, None).unwrap();
    store.publish_commit(root).unwrap();
    drop(store);
    let reader = NativeReader::open(&path).unwrap();
    // Start encoded visits before the ordinary role/read admission so the
    // child's existing decoded entry carries a proof of its exact frame.
    reader
        .visit_verified_encoded(parent, &mut |_| Ok(()))
        .unwrap();
    reader.get_verified_shared(child).unwrap();
    reader
        .visit_verified_encoded(child, &mut |_| Err(Error::Missing))
        .unwrap_err();
    let mut destination = SealedWriter::new(Vec::new()).unwrap();
    destination.set_preserve_source_encoding(true);
    let moved = reader.visit_verified_encoded(child, &mut |view| {
        destination.put_verified_view(&view, &[]).map(|_| ())
    });
    moved.unwrap();
    reader
        .visit_verified_encoded(parent, &mut |view| {
            let mut wrong = child;
            wrong.hash = ObjectHash::digest(b"different child");
            assert!(destination.put_verified_view(&view, &[wrong]).is_err());
            let mut outside = child;
            outside.address.offset = u64::MAX;
            assert!(destination.put_verified_view(&view, &[outside]).is_err());
            Ok(())
        })
        .unwrap();
    let mut wrong = child;
    wrong.hash = ObjectHash::digest(b"different object");
    assert!(
        reader
            .visit_verified_encoded(wrong, &mut |_| panic!("wrong identity reached visitor"))
            .is_err()
    );
    wrong = child;
    wrong.address.length += 8;
    assert!(
        reader
            .visit_verified_encoded(wrong, &mut |_| panic!("wrong span reached visitor"))
            .is_err()
    );
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    file.seek(SeekFrom::Start(child.address.offset + 56))
        .unwrap();
    file.write_all(&[0]).unwrap();
    file.sync_all().unwrap();
    assert!(
        reader
            .visit_verified_encoded(child, &mut |_| panic!(
                "corrupt encoded bytes reached visitor"
            ))
            .is_err()
    );
}

#[test]
fn preserve_encoding_cli_handles_streams_and_preserves_installation_and_quota_rules() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source.sac");
    fixture(&source, 1);
    let ordinary = temp.path().join("ordinary.sac");
    let preserved = temp.path().join("preserved.sac");
    let cli = env!("CARGO_BIN_EXE_sac");
    for (output, preserve) in [(&ordinary, false), (&preserved, true)] {
        let mut command = Command::new(cli);
        command.arg("compact").arg(&source).arg(output);
        if preserve {
            command.arg("--preserve-encoding");
        }
        let result = command.output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let expected = fs::read(&ordinary).unwrap();
    assert_eq!(fs::read(&preserved).unwrap(), expected);
    let piped = Command::new(cli)
        .args(["compact", "-", "-", "--preserve-encoding"])
        .stdin(Stdio::from(fs::File::open(&source).unwrap()))
        .output()
        .unwrap();
    assert!(
        piped.status.success(),
        "{}",
        String::from_utf8_lossy(&piped.stderr)
    );
    assert_eq!(piped.stdout, expected);
    let failed = temp.path().join("failed.sac");
    for quota in ["--max-output-bytes", "--max-temp-bytes"] {
        assert!(
            !Command::new(cli)
                .arg("compact")
                .arg(&source)
                .arg(&failed)
                .args(["--preserve-encoding", quota, "128"])
                .output()
                .unwrap()
                .status
                .success()
        );
        assert!(!failed.exists());
    }
    assert!(
        !Command::new(cli)
            .arg("compact")
            .arg(&source)
            .arg(&preserved)
            .arg("--preserve-encoding")
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(fs::read(&preserved).unwrap(), expected);
    assert!(
        !Command::new(cli)
            .arg("verify")
            .arg(&source)
            .arg("--preserve-encoding")
            .output()
            .unwrap()
            .status
            .success()
    );
}
