#![cfg(feature = "privacy-age")]
use age::secrecy::ExposeSecret;
use sac::v1::{
    MemoryStore,
    privacy::{self, PrivacyLimits},
    resources::ArchiveBuilder,
};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
fn inner(path: &Path) -> Vec<u8> {
    let mut store = MemoryStore::sealed();
    let mut builder = ArchiveBuilder::new(&mut store);
    builder
        .add_file(
            &[b"notes.txt".to_vec()],
            b"names, comments and exact source",
        )
        .unwrap();
    let snapshot = builder.finish().unwrap();
    store.publish(snapshot).unwrap();
    let bytes = store.as_bytes().to_vec();
    fs::write(path, &bytes).unwrap();
    bytes
}
fn identity(dir: &Path, name: &str) -> (String, PathBuf) {
    let key = age::x25519::Identity::generate();
    let path = dir.join(name);
    fs::write(
        &path,
        format!(
            "# external test identity\n{}\n",
            key.to_string().expose_secret()
        ),
    )
    .unwrap();
    (key.to_public().to_string(), path)
}
#[test]
fn standard_age_roundtrip_preserves_entire_sealed_stream_and_no_clobber() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let original = inner(&d.join("inner.sac"));
    let (recipient, key) = identity(d, "identity");
    privacy::wrap_file(
        d.join("inner.sac"),
        d.join("private.sac"),
        std::slice::from_ref(&recipient),
        PrivacyLimits::default(),
    )
    .unwrap();
    let wrapped = fs::read(d.join("private.sac")).unwrap();
    assert!(!wrapped.windows(5).any(|w| w == b"names"));
    privacy::open_file(
        d.join("private.sac"),
        d.join("opened.sac"),
        std::slice::from_ref(&key),
        PrivacyLimits::default(),
    )
    .unwrap();
    assert_eq!(fs::read(d.join("opened.sac")).unwrap(), original);
    assert!(
        privacy::open_file(
            d.join("private.sac"),
            d.join("opened.sac"),
            &[key],
            PrivacyLimits::default()
        )
        .is_err()
    );
    assert!(
        privacy::wrap_file(
            d.join("inner.sac"),
            d.join("private.sac"),
            &[recipient],
            PrivacyLimits::default()
        )
        .is_err()
    );
    assert_eq!(fs::read(d.join("private.sac")).unwrap(), wrapped);
    assert_eq!(fs::read(d.join("inner.sac")).unwrap(), original);
    assert!(!fs::read_dir(d).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".sac1-private-")
    }));
}
#[test]
fn wrong_key_bad_shape_and_quotas_publish_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let original = inner(&d.join("inner.sac"));
    let (recipient, _) = identity(d, "right");
    let (_, wrong) = identity(d, "wrong");
    privacy::wrap_file(
        d.join("inner.sac"),
        d.join("private.sac"),
        std::slice::from_ref(&recipient),
        PrivacyLimits::default(),
    )
    .unwrap();
    assert!(
        privacy::open_file(
            d.join("private.sac"),
            d.join("wrong.sac"),
            std::slice::from_ref(&wrong),
            PrivacyLimits::default()
        )
        .is_err()
    );
    assert!(
        privacy::open_file(
            d.join("inner.sac"),
            d.join("badshape.sac"),
            &[wrong],
            PrivacyLimits::default()
        )
        .is_err()
    );
    for (name, mut limits) in [
        ("input", PrivacyLimits::default()),
        ("output", PrivacyLimits::default()),
        ("temp", PrivacyLimits::default()),
        ("time", PrivacyLimits::default()),
        ("nesting", PrivacyLimits::default()),
    ] {
        match name {
            "input" => limits.max_input_bytes = 1,
            "output" => limits.max_output_bytes = 1,
            "temp" => limits.max_temp_bytes = 1,
            "time" => limits.resources.max_elapsed = Duration::ZERO,
            _ => limits.max_nesting = 0,
        }
        assert!(
            privacy::wrap_file(
                d.join("inner.sac"),
                d.join(name),
                std::slice::from_ref(&recipient),
                limits
            )
            .is_err(),
            "{name}"
        );
        assert!(!d.join(name).exists());
    }
    assert!(!d.join("wrong.sac").exists());
    assert!(!d.join("badshape.sac").exists());
    assert_eq!(fs::read(d.join("inner.sac")).unwrap(), original);
}
#[test]
fn age_ciphertext_is_independently_decryptable_and_nested_wrappers_rejected() {
    use sac::v1::{
        NativeReader,
        resources::{ArchiveReader, Limits},
    };
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let original = inner(&d.join("inner.sac"));
    let (recipient, key) = identity(d, "key");
    privacy::wrap_file(
        d.join("inner.sac"),
        d.join("private.sac"),
        std::slice::from_ref(&recipient),
        PrivacyLimits::default(),
    )
    .unwrap();
    let source = NativeReader::open(d.join("private.sac")).unwrap();
    let reader = ArchiveReader::open(
        &source,
        source.reader().snapshot().unwrap(),
        Limits::default(),
    )
    .unwrap();
    let (_, ciphertext) = reader
        .read_file_bounded(&[b"payload.age".to_vec()], 1 << 20)
        .unwrap()
        .unwrap();
    let identity = fs::read_to_string(key)
        .unwrap()
        .lines()
        .find(|l| !l.starts_with('#'))
        .unwrap()
        .parse::<age::x25519::Identity>()
        .unwrap();
    assert_eq!(age::decrypt(&identity, &ciphertext).unwrap(), original);
    assert!(
        privacy::wrap_file(
            d.join("private.sac"),
            d.join("nested.sac"),
            &[recipient],
            PrivacyLimits::default()
        )
        .is_err()
    );
    assert!(!d.join("nested.sac").exists());
}

#[test]
fn multi_extent_payload_and_header_budget() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let mut store = MemoryStore::sealed();
    // Deterministic incompressible bytes force ciphertext across extent chunks.
    let mut bytes = vec![0u8; 700_000];
    for (i, chunk) in bytes.chunks_mut(32).enumerate() {
        let hash = blake3::hash(&(i as u64).to_le_bytes());
        chunk.copy_from_slice(&hash.as_bytes()[..chunk.len()]);
    }
    let mut builder = ArchiveBuilder::new(&mut store);
    builder.add_file(&[b"bytes".to_vec()], &bytes).unwrap();
    let snapshot = builder.finish().unwrap();
    store.publish(snapshot).unwrap();
    let expected = store.as_bytes();
    assert!(expected.len() > 512_000);
    fs::write(d.join("large.sac"), expected).unwrap();
    let (recipient, key) = identity(d, "key");
    privacy::wrap_file(
        d.join("large.sac"),
        d.join("wrapped.sac"),
        &[recipient],
        PrivacyLimits::default(),
    )
    .unwrap();
    let small_header = PrivacyLimits {
        max_age_header_bytes: 8,
        ..Default::default()
    };
    assert!(
        privacy::open_file(
            d.join("wrapped.sac"),
            d.join("bad.sac"),
            std::slice::from_ref(&key),
            small_header
        )
        .is_err()
    );
    assert!(!d.join("bad.sac").exists());
    privacy::open_file(
        d.join("wrapped.sac"),
        d.join("opened.sac"),
        &[key],
        PrivacyLimits::default(),
    )
    .unwrap();
    assert_eq!(fs::read(d.join("opened.sac")).unwrap(), expected);
}
#[test]
fn valid_outer_wrapper_cannot_publish_invalid_decrypted_inner_or_extra_resource() {
    use sac::v1::resources::{self, Feature};
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let (recipient, key) = identity(d, "key");
    let recipient = recipient.parse::<age::x25519::Recipient>().unwrap();
    for extra in [false, true] {
        let ciphertext = age::encrypt(&recipient, b"not a sealed SAC1 stream").unwrap();
        let mut store = MemoryStore::sealed();
        let mut builder = ArchiveBuilder::new(&mut store);
        builder
            .add_file(&[b"payload.age".to_vec()], &ciphertext)
            .unwrap();
        if extra {
            builder
                .add_file(&[b"hidden".to_vec()], b"unexpected")
                .unwrap();
        }
        let root = builder.directory_root().unwrap();
        drop(builder);
        let snapshot = resources::snapshot(
            &mut store,
            root,
            vec![],
            vec![Feature {
                scope: None,
                id: "sac.privacy.age".into(),
                version: 1,
                required: false,
            }],
        )
        .unwrap();
        store.publish(snapshot).unwrap();
        fs::write(d.join("malformed.sac"), store.as_bytes()).unwrap();
        assert!(
            privacy::open_file(
                d.join("malformed.sac"),
                d.join("opened.sac"),
                std::slice::from_ref(&key),
                PrivacyLimits::default()
            )
            .is_err()
        );
        assert!(!d.join("opened.sac").exists());
    }
}

#[test]
fn production_cli_pack_wrap_open_verify_and_read() {
    use std::process::Command;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let (recipient, key) = identity(d, "external.key");
    fs::write(d.join("notes.txt"), b"portable saved note").unwrap();
    let cli = env!("CARGO_BIN_EXE_sac");
    let run = |args: Vec<std::ffi::OsString>| {
        let output = Command::new(cli).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(vec![
        "pack".into(),
        d.join("notes.txt").into(),
        d.join("inner.sac").into(),
    ]);
    run(vec![
        "privacy-wrap".into(),
        d.join("inner.sac").into(),
        d.join("private.sac").into(),
        "--recipient".into(),
        recipient.into(),
    ]);
    run(vec![
        "privacy-open".into(),
        d.join("private.sac").into(),
        d.join("opened.sac").into(),
        "--identity".into(),
        key.into(),
    ]);
    assert_eq!(
        fs::read(d.join("inner.sac")).unwrap(),
        fs::read(d.join("opened.sac")).unwrap()
    );
    run(vec!["verify".into(), d.join("opened.sac").into()]);
    let read = run(vec![
        "read".into(),
        d.join("opened.sac").into(),
        "notes.txt".into(),
    ]);
    assert_eq!(read.stdout, b"portable saved note");
}

#[test]
fn outer_unreachable_plaintext_is_rejected() {
    use sac::v1::{
        ObjectStore, SealedWriter,
        resources::{self, Feature, Limits},
    };
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let (recipient, key) = identity(d, "key");
    let mut store = MemoryStore::sealed();
    let ciphertext = age::encrypt(
        &recipient.parse::<age::x25519::Recipient>().unwrap(),
        b"badinner",
    )
    .unwrap();
    let mut builder = ArchiveBuilder::new(&mut store);
    builder
        .add_file(&[b"payload.age".to_vec()], &ciphertext)
        .unwrap();
    let directory = builder.directory_root().unwrap();
    drop(builder);
    let snapshot = resources::snapshot(
        &mut store,
        directory,
        vec![],
        vec![Feature {
            scope: None,
            id: "sac.privacy.age".into(),
            version: 1,
            required: false,
        }],
    )
    .unwrap();
    let mut writer = SealedWriter::new(Vec::new()).unwrap();
    writer
        .put(7, 1, b"unreachable unencrypted content", &[])
        .unwrap();
    let copied =
        resources::copy_snapshot(&store, &mut writer, snapshot, Limits::default()).unwrap();
    let bytes = writer.finish(copied).unwrap();
    fs::write(d.join("outer.sac"), bytes).unwrap();
    let error = privacy::open_file(
        d.join("outer.sac"),
        d.join("opened.sac"),
        &[key],
        PrivacyLimits::default(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("unreachable frames"), "{error}");
    assert!(!d.join("opened.sac").exists());
}
