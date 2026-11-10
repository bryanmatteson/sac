#![cfg(feature = "native")]
//! These tests spawn the production binary; they cover transport and installation.
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sac"))
}
fn success(output: Output) -> Output {
    assert!(
        output.status.success(),
        "stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    output
}
fn run(args: &[&std::ffi::OsStr]) -> Output {
    success(command().args(args).output().unwrap())
}
fn arg(path: &Path) -> &std::ffi::OsStr {
    path.as_os_str()
}
fn pack(source: &Path, archive: &Path) {
    run(&["pack".as_ref(), arg(source), arg(archive)]);
}
fn snapshot(archive: &Path) -> String {
    let output = run(&["inspect".as_ref(), arg(archive)]);
    serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["snapshot"]
        .as_str()
        .unwrap()
        .into()
}

#[test]
fn recovery_records_repair_real_sealed_and_live_archives_without_overwriting() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("input.bin");
    let mut state = 0x12345678u32;
    let data: Vec<u8> = (0..180_000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    fs::write(&source, &data).unwrap();
    for live in [false, true] {
        let archive = tmp.path().join(format!("archive-{live}.sac"));
        let parity = tmp.path().join(format!("archive-{live}.sac.rr"));
        let repaired = tmp.path().join(format!("repaired-{live}.sac"));
        let mut args = vec!["pack".as_ref(), arg(&source), arg(&archive)];
        if live {
            args.push("--live".as_ref());
        }
        run(&args);
        let original = fs::read(&archive).unwrap();
        let original_snapshot = snapshot(&archive);
        run(&[
            "recovery".as_ref(),
            "create".as_ref(),
            arg(&archive),
            arg(&parity),
            "--block-size".as_ref(),
            "1024".as_ref(),
            "--redundancy-percent".as_ref(),
            "20".as_ref(),
        ]);
        assert_eq!(fs::read(&archive).unwrap(), original);
        let info = run(&["recovery".as_ref(), "inspect".as_ref(), arg(&parity)]);
        let info: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
        assert_eq!(info["parity_shards"], 20);
        let mut damaged = original.clone();
        damaged[..128].fill(0);
        damaged.truncate(damaged.len() - 81);
        fs::write(&archive, &damaged).unwrap();
        assert!(
            !command()
                .arg("verify")
                .arg(&archive)
                .output()
                .unwrap()
                .status
                .success()
        );
        let result = run(&[
            "recovery".as_ref(),
            "repair".as_ref(),
            arg(&archive),
            arg(&parity),
            arg(&repaired),
        ]);
        let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert!(report["repaired_data_shards"].as_u64().unwrap() >= 2);
        assert_eq!(fs::read(&archive).unwrap(), damaged);
        assert_eq!(fs::read(&repaired).unwrap(), original);
        assert_eq!(snapshot(&repaired), original_snapshot);
        run(&["verify".as_ref(), arg(&repaired)]);
        let extracted = tmp.path().join(format!("extracted-{live}"));
        run(&["unpack".as_ref(), arg(&repaired), arg(&extracted)]);
        assert_eq!(fs::read(extracted.join("content/input.bin")).unwrap(), data);
        assert!(
            !command()
                .args(["recovery", "repair"])
                .arg(&archive)
                .arg(&parity)
                .arg(&repaired)
                .output()
                .unwrap()
                .status
                .success()
        );
        assert_eq!(fs::read(&repaired).unwrap(), original);
        let too_small = tmp.path().join(format!("too-small-{live}"));
        assert!(
            !command()
                .args(["recovery", "repair"])
                .arg(&archive)
                .arg(&parity)
                .arg(&too_small)
                .args(["--max-output-bytes", "1"])
                .output()
                .unwrap()
                .status
                .success()
        );
        assert!(!too_small.exists());
        // Ordinary admission doesn't consult even a corrupt sidecar.
        fs::write(&parity, b"broken recovery record").unwrap();
        run(&["verify".as_ref(), arg(&repaired)]);
    }
}

#[test]
fn recovery_cli_exhausted_parity_never_installs_partial_output() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("input.sac");
    let parity = tmp.path().join("input.sac.rr");
    let destination = tmp.path().join("repaired.sac");
    fs::write(&archive, vec![71; 100 * 1024]).unwrap();
    run(&[
        "recovery".as_ref(),
        "create".as_ref(),
        arg(&archive),
        arg(&parity),
        "--block-size".as_ref(),
        "1024".as_ref(),
        "--redundancy-percent".as_ref(),
        "1".as_ref(),
    ]);
    let mut damaged = fs::read(&archive).unwrap();
    damaged[0] ^= 1;
    damaged[1024] ^= 1;
    fs::write(&archive, &damaged).unwrap();
    assert!(
        !command()
            .args(["recovery", "repair"])
            .arg(&archive)
            .arg(&parity)
            .arg(&destination)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(!destination.exists());
    assert_eq!(fs::read(&archive).unwrap(), damaged);
    assert!(
        !command()
            .args(["recovery", "create"])
            .arg(&archive)
            .arg(&destination)
            .args(["--redundancy-percent", "101"])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(!destination.exists());
}

#[test]
fn embedded_recovery_cli_preserves_normal_reads_and_repairs_a_damaged_root() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("input.bin");
    let input = tmp.path().join("input.sac");
    let protected = tmp.path().join("protected.sac");
    let repaired = tmp.path().join("repaired.sac");
    fs::write(&source, b"single-file recovery with an independent profile").unwrap();
    pack(&source, &input);
    let original_snapshot = snapshot(&input);
    run(&[
        "recovery".as_ref(),
        "embed".as_ref(),
        arg(&input),
        arg(&protected),
        "--redundancy-percent".as_ref(),
        "20".as_ref(),
        "--block-size".as_ref(),
        "1024".as_ref(),
    ]);
    run(&["verify".as_ref(), arg(&protected)]);
    let info = run(&[
        "recovery".as_ref(),
        "inspect".as_ref(),
        arg(&protected),
        "--embedded".as_ref(),
    ]);
    let info: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
    assert_eq!(info["protected_snapshot"], original_snapshot);
    let before = tmp.path().join("before");
    run(&["unpack".as_ref(), arg(&protected), arg(&before)]);
    assert_eq!(
        fs::read(before.join("content/input.bin")).unwrap(),
        fs::read(&source).unwrap()
    );
    let mut damaged = fs::read(&protected).unwrap();
    damaged[..128].fill(0);
    let end = damaged.len();
    damaged[end - 128..].fill(0);
    fs::write(&protected, &damaged).unwrap();
    assert!(
        !command()
            .arg("verify")
            .arg(&protected)
            .output()
            .unwrap()
            .status
            .success()
    );
    run(&[
        "recovery".as_ref(),
        "repair".as_ref(),
        arg(&protected),
        arg(&repaired),
        "--embedded".as_ref(),
    ]);
    run(&["verify".as_ref(), arg(&repaired)]);
    assert_eq!(snapshot(&repaired), original_snapshot);
    assert_eq!(fs::read(&protected).unwrap(), damaged);
    assert!(
        !command()
            .args(["recovery", "repair"])
            .arg(&protected)
            .arg(&repaired)
            .arg("--embedded")
            .output()
            .unwrap()
            .status
            .success()
    );
}

#[cfg(unix)]
fn host_raw_name() -> std::ffi::OsString {
    use std::os::unix::ffi::OsStringExt;
    // APFS rejects invalid UTF-8 names; the archive and CLI retain raw bytes.
    #[cfg(target_os = "macos")]
    let bytes = "🧰~".as_bytes().to_vec();
    #[cfg(not(target_os = "macos"))]
    let bytes = vec![0xff, b'~'];
    std::ffi::OsString::from_vec(bytes)
}

#[test]
fn sealed_cli_pack_list_verify_ranges_and_identity_preserving_compaction() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::create_dir(source.join("empty")).unwrap();
    fs::write(source.join("hello.txt"), b"hello from a real process").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("../../outside", source.join("link")).unwrap();
        fs::write(source.join(host_raw_name()), b"raw name").unwrap();
    }
    let bytes: Vec<u8> = (0..(768 * 1024))
        .map(|n| ((n * 37 + n / 7919) % 251) as u8)
        .collect();
    fs::write(source.join("large.bin"), &bytes).unwrap();
    let archive = tmp.path().join("archive.sac");
    pack(&source, &archive);
    let listing = run(&["list".as_ref(), arg(&archive)]);
    let rows: Vec<serde_json::Value> = String::from_utf8(listing.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(rows.iter().any(|v| v["path"] == "hello.txt"));
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        assert!(rows.iter().any(|v| v["path"] == "link"
            && v["kind"] == "symlink"
            && v["link_target_hex"] == hex::encode(b"../../outside")));
        assert!(
            rows.iter()
                .any(|v| v["path_hex"]
                    == serde_json::json!([hex::encode(host_raw_name().as_bytes())]))
        );
        let raw = host_raw_name();
        assert_eq!(
            run(&["read".as_ref(), arg(&archive), &raw]).stdout,
            b"raw name"
        );
    }
    assert!(
        rows.iter()
            .any(|v| v["path"] == "empty" && v["kind"] == "directory")
    );
    let verify = run(&["verify".as_ref(), arg(&archive)]);
    let report: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(report["physical"], "verified");
    assert_eq!(report["core"], "verified");
    let range = run(&[
        "read".as_ref(),
        arg(&archive),
        "large.bin".as_ref(),
        "--offset".as_ref(),
        "262130".as_ref(),
        "--length".as_ref(),
        "65536".as_ref(),
    ]);
    assert_eq!(range.stdout, bytes[262130..262130 + 65536]);
    let compact = tmp.path().join("compact.sac");
    run(&["compact".as_ref(), arg(&archive), arg(&compact)]);
    assert_eq!(snapshot(&archive), snapshot(&compact));
    let destination = tmp.path().join("extracted");
    run(&["unpack".as_ref(), arg(&compact), arg(&destination)]);
    assert_eq!(
        fs::read(destination.join("content/hello.txt")).unwrap(),
        b"hello from a real process"
    );
    assert_eq!(
        fs::read(destination.join("content/large.bin")).unwrap(),
        bytes
    );
    assert!(destination.join("content/empty").is_dir());
    assert!(!destination.join("content/link").exists());
    assert!(destination.join("report.cbor").is_file());
}

#[test]
fn pipe_output_and_input_are_real_forward_streams() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("hello.txt"), b"pipe roundtrip").unwrap();
    let packed = run(&["pack".as_ref(), arg(&source), "-".as_ref()]).stdout;
    assert!(packed.starts_with(b"SAC1"));
    assert_eq!(&packed[4..8], &[0; 4]);
    let destination = tmp.path().join("received");
    let mut child = command()
        .arg("unpack")
        .arg("-")
        .arg(&destination)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&packed).unwrap();
    success(child.wait_with_output().unwrap());
    assert_eq!(
        fs::read(destination.join("content/hello.txt")).unwrap(),
        b"pipe roundtrip"
    );
    let destination = tmp.path().join("truncated");
    let mut child = command()
        .arg("unpack")
        .arg("-")
        .arg(&destination)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&packed[..packed.len() - 1])
        .unwrap();
    assert!(!child.wait_with_output().unwrap().status.success());
    assert!(!destination.exists());
}

#[test]
fn no_clobber_includes_preexisting_empty_directory_and_symlink_destinations() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("value"), b"new").unwrap();
    let archive = tmp.path().join("archive.sac");
    pack(&source, &archive);
    let original = fs::read(&archive).unwrap();
    assert!(
        !command()
            .arg("pack")
            .arg(&source)
            .arg(&archive)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(fs::read(&archive).unwrap(), original);
    let destination = tmp.path().join("existing");
    fs::create_dir(&destination).unwrap();
    assert!(
        !command()
            .arg("unpack")
            .arg(&archive)
            .arg(&destination)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
    #[cfg(unix)]
    {
        let link = tmp.path().join("linked");
        std::os::unix::fs::symlink(&destination, &link).unwrap();
        assert!(
            !command()
                .arg("unpack")
                .arg(&archive)
                .arg(&link)
                .output()
                .unwrap()
                .status
                .success()
        );
        assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
    }
}

#[test]
fn quotas_fail_without_publishing_partial_output() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("value"), vec![3u8; 8193]).unwrap();
    let archive = tmp.path().join("limited.sac");
    let output = command()
        .arg("pack")
        .arg(&source)
        .arg(&archive)
        .args(["--max-output-bytes", "1"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!archive.exists());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"]["code"], "LimitExceeded");
    let archive = tmp.path().join("ok.sac");
    pack(&source, &archive);
    let destination = tmp.path().join("too-large");
    let output = command()
        .arg("unpack")
        .arg(&archive)
        .arg(&destination)
        .args(["--max-output-bytes", "8192"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!destination.exists());
    let output = command()
        .arg("verify")
        .arg(&archive)
        .args(["--max-input-bytes", "10"])
        .output()
        .unwrap();
    assert!(!output.status.success());

    let empty = tmp.path().join("many-empty");
    fs::create_dir(&empty).unwrap();
    for i in 0..8 {
        fs::write(empty.join(format!("empty-{i}")), b"").unwrap();
    }
    let archive = tmp.path().join("empty.sac");
    pack(&empty, &archive);
    let output = command()
        .arg("list")
        .arg(&archive)
        .args(["--max-output-bytes", "256"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.len() <= 256);
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"]["code"], "LimitExceeded");
}

#[test]
fn quotas_leave_failed_live_destinations_absent() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("empty-source");
    fs::create_dir(&source).unwrap();
    let original = tmp.path().join("original.sac");
    pack(&source, &original);
    let original_bytes = fs::read(&original).unwrap();
    for operation in ["pack", "recover-live"] {
        let destination = tmp.path().join(format!("failed-{operation}.sac"));
        let mut child = command();
        child
            .arg(operation)
            .arg(if operation == "pack" {
                &source
            } else {
                &original
            })
            .arg(&destination);
        if operation == "pack" {
            child.arg("--live");
        }
        let output = child.args(["--max-output-bytes", "1"]).output().unwrap();
        assert!(
            !output.status.success(),
            "{operation} unexpectedly succeeded"
        );
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(
            error["error"]["code"], "LimitExceeded",
            "{operation}: {error}"
        );
        assert!(
            !destination.exists(),
            "{operation} exposed a partial live archive"
        );
        assert_eq!(fs::read(&original).unwrap(), original_bytes);
    }
    assert!(fs::read_dir(tmp.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".sac-")
    }));
}

#[test]
fn live_pack_recovers_into_fresh_incarnation_and_preserves_original() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("value"), b"durable").unwrap();
    let live = tmp.path().join("live.sac");
    run(&["pack".as_ref(), arg(&source), arg(&live), "--live".as_ref()]);
    let original = fs::read(&live).unwrap();
    let recovery = tmp.path().join("recovered.sac");
    run(&["recover-live".as_ref(), arg(&live), arg(&recovery)]);
    assert_eq!(fs::read(&live).unwrap(), original);
    assert_eq!(snapshot(&live), snapshot(&recovery));
    assert_ne!(&original[16..32], &fs::read(&recovery).unwrap()[16..32]);
    run(&["verify".as_ref(), arg(&recovery)]);
}

#[test]
fn compact_preserves_attestations_and_requires_explicit_local_attachment_removal() {
    use sac::v1::{Header, MemoryStore, ObjectStore, cbor::Value, resources};
    let tmp = tempfile::tempdir().unwrap();
    let mut store = MemoryStore::new(Header::new([0; 16], [9; 16]));
    let mut builder = resources::ArchiveBuilder::new(&mut store);
    builder
        .add_file(&resources::path_from_str("value").unwrap(), b"kept")
        .unwrap();
    let snapshot = builder.finish().unwrap();
    let attestation = store
        .put(9, 1, &sac::v1::cbor::encode(&Value::Array(vec![])), &[])
        .unwrap();
    let local = store
        .put(
            8,
            1,
            &sac::v1::cbor::encode(&Value::Array(vec![
                Value::Text("test.local".into()),
                Value::Text("authority".into()),
                Value::Uint(1),
                Value::Bytes(b"local attachment".to_vec()),
            ])),
            &[],
        )
        .unwrap();
    let commit = resources::commit(&mut store, snapshot, Some(attestation), Some(local)).unwrap();
    store.publish_commit(commit).unwrap();
    let archive = tmp.path().join("local.sac");
    fs::write(&archive, store.as_bytes()).unwrap();
    let output = tmp.path().join("compact.sac");
    assert!(
        !command()
            .arg("compact")
            .arg(&archive)
            .arg(&output)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(!output.exists());
    run(&[
        "compact".as_ref(),
        arg(&archive),
        arg(&output),
        "--strip-local".as_ref(),
    ]);
    let reader = sac::v1::NativeReader::open(&output).unwrap();
    let commit = reader.get(reader.root().unwrap().root).unwrap();
    let Value::Array(fields) = sac::v1::cbor::decode(&commit.bytes).unwrap() else {
        panic!()
    };
    assert_eq!(fields[2], Value::Null);
    let Value::Uint(index) = fields[1] else {
        panic!()
    };
    assert_eq!(
        reader.get(commit.children[index as usize]).unwrap().hash(),
        attestation.hash
    );
}

#[test]
fn recovery_of_a_torn_newest_slot_preserves_the_old_admitted_head() {
    use sac::v1::{Header, MemoryStore, resources};
    let tmp = tempfile::tempdir().unwrap();
    let mut store = MemoryStore::new(Header::new([0; 16], [8; 16]));
    let mut b = resources::ArchiveBuilder::new(&mut store);
    b.add_file(&resources::path_from_str("value").unwrap(), b"old")
        .unwrap();
    let old = b.finish().unwrap();
    store.publish(old).unwrap();
    let mut b = resources::ArchiveBuilder::new(&mut store);
    b.add_file(&resources::path_from_str("value").unwrap(), b"new")
        .unwrap();
    let new = b.finish().unwrap();
    store.publish(new).unwrap();
    let mut bytes = store.as_bytes().to_vec();
    bytes[4096] ^= 1;
    let source = tmp.path().join("torn.sac");
    fs::write(&source, &bytes).unwrap();
    let output = tmp.path().join("recovered.sac");
    let report = run(&["recover-live".as_ref(), arg(&source), arg(&output)]);
    let report: serde_json::Value = serde_json::from_slice(&report.stdout).unwrap();
    assert!(
        !report["recovery_diagnostics"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(fs::read(&source).unwrap(), bytes);
    assert_eq!(
        run(&["read".as_ref(), arg(&output), "value".as_ref()]).stdout,
        b"old"
    );
    assert_eq!(snapshot(&output), old.hash.to_string());
}

#[test]
fn explicit_salvage_repairs_locator_damage_without_changing_snapshot_identity() {
    use sac::v1::ObjectStore;
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("source");
    fs::create_dir(&input).unwrap();
    let payload: Vec<u8> = (0..9000)
        .map(|n| ((n * 17 + n / 199) % 251) as u8)
        .collect();
    fs::write(input.join("value"), &payload).unwrap();
    let archive = tmp.path().join("intact.sac");
    pack(&input, &archive);
    let reader = sac::v1::NativeReader::open(&archive).unwrap();
    let root = reader.reader().snapshot().unwrap();
    let object = reader.get(root).unwrap();
    assert!(!object.children.is_empty());
    let mut bytes = fs::read(&archive).unwrap();
    let start = root.address.offset as usize;
    let stored = u32::from_le_bytes(bytes[start + 8..start + 12].try_into().unwrap()) as usize;
    bytes[start + 56 + stored..start + 56 + stored + 8].copy_from_slice(&0u64.to_le_bytes());
    let damaged = tmp.path().join("damaged.sac");
    fs::write(&damaged, &bytes).unwrap();
    assert!(
        !command()
            .arg("verify")
            .arg(&damaged)
            .output()
            .unwrap()
            .status
            .success()
    );
    let repaired = tmp.path().join("repaired.sac");
    run(&[
        "salvage".as_ref(),
        arg(&damaged),
        arg(&repaired),
        "--snapshot".as_ref(),
        root.hash.to_string().as_ref(),
    ]);
    assert_eq!(snapshot(&repaired), root.hash.to_string());
    assert_eq!(fs::read(&damaged).unwrap(), bytes);
    assert_eq!(
        run(&["read".as_ref(), arg(&repaired), "value".as_ref()]).stdout,
        payload
    );
    run(&["verify".as_ref(), arg(&repaired)]);
}

/// Intrinsically well-formed frames with intentionally wrong contextual links.
/// Raw frame construction deliberately bypasses application schema validation.
fn wrong_core_link(which: &str) -> Vec<u8> {
    use sac::v1::{
        CanonicalObject, ChunkAddress, ObjectRef, Preamble, Slot, Trailer,
        cbor::{self, Value},
    };
    let live = which == "local";
    let preamble = if live {
        Preamble::live([11; 16]).unwrap()
    } else {
        Preamble::sealed()
    };
    let mut bytes = vec![0; preamble.first_record_offset() as usize];
    bytes[..128].copy_from_slice(&preamble.encode());
    fn append(
        bytes: &mut Vec<u8>,
        kind: u16,
        body: Vec<u8>,
        children: Vec<ObjectRef>,
    ) -> ObjectRef {
        let object = CanonicalObject {
            kind,
            version: 1,
            bytes: body,
            children,
        };
        let canonical = object.canonical_bytes();
        let mut frame = vec![0; (56 + canonical.len() + 12 * object.children.len() + 7) & !7];
        frame[..4].copy_from_slice(b"SO1\0");
        frame[5] = 1;
        frame[6..8].copy_from_slice(&(object.children.len() as u16).to_le_bytes());
        frame[8..12].copy_from_slice(&(canonical.len() as u32).to_le_bytes());
        frame[12..16].copy_from_slice(&(canonical.len() as u32).to_le_bytes());
        frame[16..48].copy_from_slice(&object.hash().0);
        let mut crc = !0u32;
        for byte in &frame[..56] {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ ((0u32.wrapping_sub(crc & 1)) & 0x82f63b78);
            }
        }
        frame[48..52].copy_from_slice(&(!crc).to_le_bytes());
        frame[56..56 + canonical.len()].copy_from_slice(&canonical);
        for (i, child) in object.children.iter().enumerate() {
            let at = 56 + canonical.len() + 12 * i;
            frame[at..at + 8].copy_from_slice(&child.address.offset.to_le_bytes());
            frame[at + 8..at + 12].copy_from_slice(&child.address.length.to_le_bytes());
        }
        let reference = ObjectRef {
            hash: object.hash(),
            address: ChunkAddress {
                offset: bytes.len() as u64,
                length: frame.len() as u32,
            },
        };
        bytes.extend(frame);
        reference
    }
    let directory = append(&mut bytes, 3, cbor::encode(&Value::Array(vec![])), vec![]);
    let bad = append(
        &mut bytes,
        7,
        b"not a catalogue or local profile".to_vec(),
        vec![],
    );
    let mut snapshot_children = vec![directory];
    let mut profiles = vec![];
    if which == "profile-version" || which == "profile-type" {
        let ty = if which == "profile-type" {
            "record"
        } else {
            "root"
        };
        let version = if which == "profile-version" { 1 } else { 2 };
        let root = append(
            &mut bytes,
            8,
            cbor::encode(&Value::Array(vec![
                Value::Text("test.profile".into()),
                Value::Text(ty.into()),
                Value::Uint(version),
                Value::Bytes(vec![]),
            ])),
            vec![],
        );
        snapshot_children.push(root);
        profiles.push(Value::Array(vec![
            Value::Text("test.profile".into()),
            Value::Uint(2),
            Value::Uint(1),
        ]));
    }
    let snapshot = append(
        &mut bytes,
        2,
        cbor::encode(&Value::Array(vec![
            Value::Uint(0),
            Value::Array(profiles),
            Value::Array(vec![]),
        ])),
        snapshot_children,
    );
    let mut children = vec![snapshot];
    let mut att = Value::Null;
    let mut local = Value::Null;
    if which == "attestation" {
        children.push(bad);
        att = Value::Uint(1);
    }
    if which.starts_with("attestation-") {
        let envelope = if which == "attestation-structure" {
            b"not COSE".to_vec()
        } else {
            let algorithm = if which == "attestation-unsupported" {
                7
            } else {
                18
            };
            let protected = Value::Map(vec![sac::cbor::MapEntry {
                key: Value::Uint(1),
                key_bytes: vec![1],
                value: Value::NInt(algorithm),
            }]);
            let payload = Value::Array(vec![
                Value::Text("sac.snapshot.v1".into()),
                Value::Text("release".into()),
                Value::Bytes(snapshot.hash.0.to_vec()),
            ]);
            let mut envelope = vec![0xd2];
            envelope.extend(cbor::encode(&Value::Array(vec![
                Value::Bytes(cbor::encode(&protected)),
                Value::Map(vec![]),
                Value::Bytes(cbor::encode(&payload)),
                Value::Bytes(vec![0; 64]),
            ])));
            envelope
        };
        children.push(append(
            &mut bytes,
            9,
            cbor::encode(&Value::Array(vec![Value::Bytes(envelope)])),
            vec![],
        ));
        att = Value::Uint(1);
    }
    if live {
        children.push(bad);
        local = Value::Uint(1);
    }
    let commit = append(
        &mut bytes,
        1,
        cbor::encode(&Value::Array(vec![Value::Uint(0), att, local])),
        children,
    );
    let trailer_offset = bytes.len() as u64;
    let trailer = Trailer {
        preamble_digest: preamble.digest(),
        generation: 1,
        committed_end: trailer_offset + 160,
        commit,
    };
    bytes.extend(trailer.encode());
    if live {
        let slot = Slot {
            preamble_digest: preamble.digest(),
            generation: 1,
            trailer_offset,
            trailer_digest: trailer.digest(),
        };
        bytes[8192..12288].copy_from_slice(&slot.encode());
    }
    bytes
}

#[test]
fn full_cli_verification_rejects_wrong_core_link_roles_and_profile_bindings() {
    let tmp = tempfile::tempdir().unwrap();
    for which in ["attestation", "local", "profile-version", "profile-type"] {
        let archive = tmp.path().join(format!("{which}.sac"));
        fs::write(&archive, wrong_core_link(which)).unwrap();
        let output = command().arg("verify").arg(&archive).output().unwrap();
        assert!(
            !output.status.success(),
            "accepted invalid {which}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let destination = tmp.path().join(format!("extract-{which}"));
        assert!(
            !command()
                .arg("unpack")
                .arg(&archive)
                .arg(&destination)
                .output()
                .unwrap()
                .status
                .success()
        );
        assert!(!destination.exists());
    }
}

#[test]
fn optional_attestation_failures_remain_visible_without_blocking_content_recovery() {
    let tmp = tempfile::tempdir().unwrap();
    for (which, status) in [
        ("attestation-structure", "invalid"),
        ("attestation-unsupported", "unsupported"),
        ("attestation-unaccepted", "valid-structure"),
    ] {
        let archive = tmp.path().join(format!("{which}.sac"));
        fs::write(&archive, wrong_core_link(which)).unwrap();
        let output = run(&["verify".as_ref(), arg(&archive)]);
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["core"], "verified");
        assert_eq!(report["trust"], "unaccepted");
        assert_eq!(report["attestations"][0]["structure"], status);
        assert_eq!(report["attestations"][0]["signature"], "unaccepted");
        let destination = tmp.path().join(format!("extract-{which}"));
        run(&["unpack".as_ref(), arg(&archive), arg(&destination)]);
        assert!(destination.join("content").is_dir());
    }
}

#[cfg(feature = "http")]
fn http_archive(
    bytes: Vec<u8>,
    change_version: bool,
) -> (
    String,
    std::net::SocketAddr,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::thread::JoinHandle<Vec<String>>,
) {
    use std::io::{Read, Write};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let shutdown = stop.clone();
    let join = std::thread::spawn(move || {
        let mut requests = Vec::new();
        loop {
            let (mut stream, _) = listener.accept().unwrap();
            if shutdown.load(Ordering::Acquire) {
                break;
            }
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < 16384);
            }
            let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
            if request.starts_with("head ") {
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",bytes.len()).unwrap();
            } else {
                assert!(request.starts_with("get "));
                let range = request
                    .lines()
                    .find_map(|l| l.strip_prefix("range: bytes="))
                    .unwrap();
                let (start, end) = range.split_once('-').unwrap();
                let start: usize = start.parse().unwrap();
                let end: usize = end.parse().unwrap();
                assert!(start <= end && end < bytes.len());
                let version = if change_version { "v2" } else { "v1" };
                write!(stream,"HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{end}/{}\r\nETag: \"{version}\"\r\nConnection: close\r\n\r\n",end-start+1,bytes.len()).unwrap();
                let _ = stream.write_all(&bytes[start..=end]);
            }
            requests.push(request);
        }
        requests
    });
    (format!("http://{address}/archive.sac"), address, stop, join)
}

#[cfg(feature = "http")]
#[test]
fn http_cli_reads_actual_pinned_ranges_and_reports_separate_wire_statistics() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    fs::create_dir(&source).unwrap();
    let mut payload = vec![0; 131072];
    blake3::Hasher::new()
        .update(b"SAC1 HTTP CLI range fixture")
        .finalize_xof()
        .fill(&mut payload);
    fs::write(source.join("value"), &payload).unwrap();
    let archive = tmp.path().join("archive.sac");
    pack(&source, &archive);
    let (url, address, stop, join) = http_archive(fs::read(&archive).unwrap(), false);
    let output = command()
        .args([
            "read",
            &url,
            "value",
            "--offset",
            "32760",
            "--length",
            "65536",
            "--http-statistics",
        ])
        .output()
        .unwrap();
    stop.store(true, std::sync::atomic::Ordering::Release);
    let _ = std::net::TcpStream::connect(address);
    let requests = join.join().unwrap();
    let output = success(output);
    assert_eq!(output.stdout, payload[32760..32760 + 65536]);
    let stats: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(stats["schema"], "sac.http-statistics.v1");
    assert_eq!(stats["discovery_requests"], 1);
    assert!(stats["range_requests"].as_u64().unwrap() >= 2);
    assert!(stats["cache_hits"].as_u64().unwrap() > 0);
    assert_eq!(
        stats["range_requests"].as_u64().unwrap() + 1,
        requests.len() as u64
    );
    assert!(stats["cache_resident_bytes"].as_u64().unwrap() <= 1 << 20);
    assert!(requests[0].starts_with("head "));
    assert!(
        requests[1..]
            .iter()
            .all(|r| r.contains("if-match: \"v1\"") && r.contains("accept-encoding: identity"))
    );
}

#[cfg(feature = "http")]
#[test]
fn http_cli_rejects_changed_versions_and_large_sources_before_content_output() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("value"), b"original").unwrap();
    let archive = tmp.path().join("archive.sac");
    pack(&source, &archive);
    let bytes = fs::read(&archive).unwrap();
    for too_large in [false, true] {
        let (url, address, stop, join) = http_archive(bytes.clone(), !too_large);
        let mut process = command();
        process.args(["read", &url, "value"]);
        if too_large {
            process.args(["--max-input-bytes", "1"]);
        }
        let output = process.output().unwrap();
        stop.store(true, std::sync::atomic::Ordering::Release);
        let _ = std::net::TcpStream::connect(address);
        let requests = join.join().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(requests.len(), if too_large { 1 } else { 2 });
    }
}

#[cfg(unix)]
#[test]
fn same_file_maintenance_commands_preserve_root_inode_and_readability() {
    use sac::{
        NativeStore,
        resources::{ArchiveBuilder, path_from_str},
    };
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("live.sac");
    let mut store = NativeStore::create_live(&path, [18; 16]).unwrap();
    for seed in 0..3u8 {
        let mut data = vec![0; 512 << 10];
        blake3::Hasher::new()
            .update(&[seed])
            .finalize_xof()
            .fill(&mut data);
        let mut b = ArchiveBuilder::new(&mut store);
        b.add_file(&path_from_str("data").unwrap(), &data).unwrap();
        let snapshot = b.finish().unwrap();
        store.publish(snapshot).unwrap();
    }
    drop(store);
    let inode = fs::metadata(&path).unwrap().ino();
    let original = snapshot(&path);
    let out = run(&["reclaim".as_ref(), arg(&path)]);
    let stats: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(stats["punched_bytes"].as_u64().unwrap() > 0);
    assert_eq!(snapshot(&path), original);
    run(&["verify".as_ref(), arg(&path)]);
    let out = run(&["compact-in-place".as_ref(), arg(&path)]);
    let stats: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        stats["file_bytes_after"].as_u64().unwrap() < stats["file_bytes_before"].as_u64().unwrap()
    );
    assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
    assert_eq!(snapshot(&path), original);
    run(&["verify".as_ref(), arg(&path)]);
}

#[test]
fn metadata_cli_live_edits_export_compaction_and_limits() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::write(&input, b"keep this input").unwrap();
    let live = tmp.path().join("live.sac");
    run(&["pack".as_ref(), arg(&input), arg(&live), "--live".as_ref()]);
    let value = tmp.path().join("value.json");
    fs::write(
        &value,
        br#"{"label":"hello","future":[null,true,18446744073709551615]}"#,
    )
    .unwrap();
    run(&[
        "metadata".as_ref(),
        "set".as_ref(),
        arg(&live),
        "org.example.custom".as_ref(),
        arg(&value),
        "--json".as_ref(),
    ]);
    let raw = run(&[
        "metadata".as_ref(),
        "get".as_ref(),
        arg(&live),
        "org.example.custom".as_ref(),
    ])
    .stdout;
    sac::v1::cbor::decode(&raw).unwrap();
    let binary = tmp.path().join("large.cbor");
    fs::write(
        &binary,
        sac::v1::cbor::encode(&sac::v1::cbor::Value::Bytes(vec![0xff; 100_000])),
    )
    .unwrap();
    run(&[
        "metadata".as_ref(),
        "set".as_ref(),
        arg(&live),
        "org.example.binary".as_ref(),
        arg(&binary),
    ]);
    run(&[
        "metadata".as_ref(),
        "remove".as_ref(),
        arg(&live),
        "org.example.binary".as_ref(),
    ]);
    assert_eq!(
        run(&[
            "metadata".as_ref(),
            "get".as_ref(),
            arg(&live),
            "org.example.custom".as_ref()
        ])
        .stdout,
        raw
    );
    let before = fs::read(&live).unwrap();
    let failed = command()
        .args([
            "metadata".as_ref(),
            "set".as_ref(),
            arg(&live),
            "invalid".as_ref(),
            arg(&value),
            "--json".as_ref(),
        ])
        .output()
        .unwrap();
    assert!(!failed.status.success());
    assert_eq!(fs::read(&live).unwrap(), before);
    let export = tmp.path().join("metadata");
    run(&[
        "metadata".as_ref(),
        "export".as_ref(),
        arg(&live),
        arg(&export),
    ]);
    assert_eq!(
        fs::read(export.join("content/org.example.custom")).unwrap(),
        raw
    );
    assert!(
        !command()
            .args([
                "metadata".as_ref(),
                "export".as_ref(),
                arg(&live),
                arg(&export)
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    let sealed = tmp.path().join("sealed.sac");
    run(&["compact".as_ref(), arg(&live), arg(&sealed)]);
    run(&["verify".as_ref(), arg(&sealed)]);
    assert_eq!(
        run(&[
            "metadata".as_ref(),
            "get".as_ref(),
            arg(&sealed),
            "org.example.custom".as_ref()
        ])
        .stdout,
        raw
    );
    assert!(
        !command()
            .args([
                "metadata".as_ref(),
                "get".as_ref(),
                arg(&sealed),
                "org.example.custom".as_ref(),
                "--max-output-bytes".as_ref(),
                "1".as_ref()
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        !command()
            .args([
                "metadata".as_ref(),
                "set".as_ref(),
                arg(&sealed),
                "org.example.custom".as_ref(),
                arg(&value),
                "--json".as_ref()
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
}
