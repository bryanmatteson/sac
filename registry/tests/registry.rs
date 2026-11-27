use sac::{
    MemoryStore, ObjectStore,
    cbor::{Value, encode},
    resources::{ArchiveBuilder, Limits, Profile, path_from_str, snapshot},
    v1::metadata::MetadataEditor,
};
use sac_registry::{DEFAULT_MAX_BYTES, Error, Reference, Registry, http, oci};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    sync::{Arc, Barrier, Mutex},
};
use tempfile::TempDir;

const PROFILE: &str = "example.investigation";

fn fixture(title: &str, codec: i32) -> Vec<u8> {
    let mut store = MemoryStore::sealed();
    store.set_compression_level(codec);
    let mut builder = ArchiveBuilder::new(&mut store);
    builder
        .add_file(
            &path_from_str("payload.bin").unwrap(),
            &vec![139; 512 << 10],
        )
        .unwrap();
    let directory = builder.finish_directory().unwrap();
    let root = store
        .put(
            8,
            1,
            &encode(&Value::Array(vec![
                Value::Text(PROFILE.into()),
                Value::Text("root".into()),
                Value::Uint(1),
                Value::Bytes(vec![0]),
            ])),
            &[directory],
        )
        .unwrap();
    let snapshot = snapshot(
        &mut store,
        directory,
        vec![Profile {
            id: PROFILE.into(),
            version: 1,
            root,
        }],
        vec![],
    )
    .unwrap();
    let mut metadata = MetadataEditor::open(&mut store, snapshot, Limits::default()).unwrap();
    metadata
        .set("sac.registry.title", &Value::Text(title.into()))
        .unwrap();
    metadata
        .set(
            "sac.registry.tags",
            &Value::Array(vec![Value::Text("arm64".into())]),
        )
        .unwrap();
    let snapshot = metadata.finish().unwrap();
    store.publish(snapshot).unwrap();
    store.as_bytes().to_vec()
}

fn count_objects(directory: &TempDir) -> usize {
    fs::read_dir(directory.path().join("objects"))
        .unwrap()
        .count()
}

fn registry(directory: &TempDir) -> Registry {
    Registry::open(directory.path(), DEFAULT_MAX_BYTES).unwrap()
}

fn reference(version: &str) -> Reference {
    Reference::new("tests", "investigation", version).unwrap()
}

#[test]
fn exact_downloads_share_objects_across_annotations_and_codecs() {
    let root = TempDir::new().unwrap();
    let registry = registry(&root);
    let first = fixture("First", 0);
    let second = fixture("Second", 0);
    let compressed = fixture("Second", 3);
    let a = registry
        .publish(&reference("1"), Some(PROFILE), first.as_slice())
        .unwrap();
    let initial_objects = count_objects(&root);
    let b = registry
        .publish(&reference("2"), None, second.as_slice())
        .unwrap();
    let reauthored_objects = count_objects(&root);
    assert_ne!(a.artifact.snapshot_id, b.artifact.snapshot_id);
    assert_eq!(a.artifact.profiles[0], b.artifact.profiles[0]);
    assert!(reauthored_objects < initial_objects * 2);
    let c = registry
        .publish(&reference("3"), Some(PROFILE), compressed.as_slice())
        .unwrap();
    assert_eq!(reauthored_objects, count_objects(&root));
    assert_eq!(b.artifact.snapshot_id, c.artifact.snapshot_id);
    assert_ne!(b.artifact.sha256, c.artifact.sha256);
    assert_eq!(
        registry
            .list(Some(PROFILE), Some(1), Some("arm64"))
            .unwrap()
            .len(),
        3
    );
    assert!(
        registry
            .list(Some(PROFILE), Some(2), None)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        a.artifact.annotations["sac.registry.title"],
        sac_registry::Annotation::Text("First".into())
    );

    for (version, bytes) in [(1, first), (2, second), (3, compressed)] {
        let destination = root.path().join(format!("archive-{version}.sac"));
        let release = registry
            .fetch(&reference(&version.to_string()), &destination)
            .unwrap();
        assert_eq!(bytes, fs::read(destination).unwrap());
        let mut source = registry.archive(&release.artifact.sha256).unwrap();
        source.seek(SeekFrom::Start(122)).unwrap();
        let mut range = vec![0; 1087];
        source.read_exact(&mut range).unwrap();
        assert_eq!(range, &bytes[122..1209]);
    }
}

#[test]
fn invalid_archives_and_concurrent_conflicts_leave_exactly_one_release() {
    let root = TempDir::new().unwrap();
    let registry = registry(&root);
    let version = reference("1");
    assert!(registry.publish(&version, None, &b"broken"[..]).is_err());
    assert!(matches!(
        registry.resolve(&version),
        Err(Error::NotFound(_))
    ));
    let barrier = Arc::new(Barrier::new(2));
    let candidates = ["First", "Second"]
        .map(|title| {
            let registry = registry.clone();
            let version = version.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let bytes = fixture(title, 0);
                barrier.wait();
                let answer = registry.publish(&version, None, bytes.as_slice());
                (bytes, answer)
            })
        })
        .map(|child| child.join().unwrap());
    let [(bytes, winner), (_, loser)] = if candidates[0].1.is_ok() {
        candidates
    } else {
        let [first, second] = candidates;
        [second, first]
    };
    let winner = winner.unwrap();
    assert!(matches!(loser, Err(Error::Conflict(_))));
    assert_eq!(
        registry.publish(&version, None, bytes.as_slice()).unwrap(),
        winner
    );
    assert_eq!(registry.resolve(&version).unwrap(), winner);
}

fn spawn_server(
    router: axum::Router,
) -> (
    String,
    tokio::sync::oneshot::Sender<()>,
    std::thread::JoinHandle<()>,
) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = std::thread::spawn(move || {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                axum::serve(listener, router)
                    .with_graceful_shutdown(async {
                        let _ = stopped.await;
                    })
                    .await
                    .unwrap();
            });
    });
    (address.to_string(), stop, task)
}

#[test]
fn http_publish_fetch_and_native_sac_range_reader() {
    let root = TempDir::new().unwrap();
    let registry = registry(&root);
    let uploaded = Arc::new(Mutex::new(0u64));
    let counter = uploaded.clone();
    let router =
        http::router(registry.clone(), true, None)
            .unwrap()
            .layer(axum::middleware::from_fn(
                move |request: axum::extract::Request, next: axum::middleware::Next| {
                    let counter = counter.clone();
                    async move {
                        if request.method() == axum::http::Method::PUT
                            && request.uri().path().starts_with("/v1/objects/")
                        {
                            *counter.lock().unwrap() += request.headers()["content-length"]
                                .to_str()
                                .unwrap()
                                .parse::<u64>()
                                .unwrap();
                        }
                        next.run(request).await
                    }
                },
            ));
    let (address, stop, task) = spawn_server(router);
    let url = format!("http://{address}");
    let client = http::Client::new(&url, None).unwrap();
    let bytes = fixture("Remote", 0);
    let input = root.path().join("input.sac");
    let output = root.path().join("output.sac");
    fs::write(&input, &bytes).unwrap();
    let release = client
        .publish(
            &reference("1"),
            Some(PROFILE),
            File::open(input).unwrap(),
            DEFAULT_MAX_BYTES,
        )
        .unwrap();
    assert_eq!(
        client
            .list(Some(PROFILE), Some(1), Some("arm64"))
            .unwrap()
            .as_slice(),
        std::slice::from_ref(&release)
    );
    assert_eq!(
        client
            .fetch(
                &reference("1"),
                &output,
                DEFAULT_MAX_BYTES,
                Some(&release.artifact.sha256)
            )
            .unwrap(),
        release
    );
    assert_eq!(fs::read(output).unwrap(), bytes);
    assert_eq!(registry.resolve(&reference("1")).unwrap(), release);
    let first_upload = *uploaded.lock().unwrap();
    assert!(first_upload >= 256 << 10);

    let edited = fixture("Remote title update", 0);
    let edited_path = root.path().join("edited.sac");
    fs::write(&edited_path, &edited).unwrap();
    let edit = client
        .publish(
            &reference("2"),
            None,
            File::open(edited_path).unwrap(),
            DEFAULT_MAX_BYTES,
        )
        .unwrap();
    assert_eq!(registry.resolve(&reference("2")).unwrap(), edit);
    assert!(*uploaded.lock().unwrap() - first_upload < 32 << 10);
    let local = registry
        .publish(&reference("3"), Some(PROFILE), edited.as_slice())
        .unwrap();
    assert_eq!(client.resolve(&reference("3")).unwrap(), local);

    let raw_client = reqwest::blocking::Client::new();
    let raw = raw_client
        .put(format!("{url}/v1/releases/tests/investigation/4"))
        .header("If-None-Match", "*")
        .header("Sac-Profile", PROFILE)
        .body(bytes)
        .send()
        .unwrap();
    assert_eq!(raw.status(), 201);
    assert_eq!(
        registry.resolve(&reference("4")).unwrap().artifact,
        release.artifact
    );

    let archive = format!("{url}/v1/archives/{}", release.artifact.sha256);
    use sac::v1::{
        PositionalStore,
        http::{HttpLimits, HttpSource},
    };
    let source = HttpSource::open(&archive, HttpLimits::default()).unwrap();
    let store = PositionalStore::open(source).unwrap();
    let snapshot = store.reader().snapshot().unwrap();
    let reader = sac::resources::ArchiveReader::open(&store, snapshot, Limits::default()).unwrap();
    assert_eq!(
        reader
            .read_range(&path_from_str("payload.bin").unwrap(), 262_144, 256)
            .unwrap(),
        vec![139; 256]
    );
    let wrong = reqwest::blocking::Client::new()
        .get(&archive)
        .header("Range", "bytes=0-7")
        .header("If-Match", "\"wrong\"")
        .send()
        .unwrap();
    assert_eq!(wrong.status(), 412);
    stop.send(()).unwrap();
    task.join().unwrap();
}

#[derive(Default)]
struct OciState {
    blobs: BTreeMap<String, Vec<u8>>,
    manifests: BTreeMap<String, Vec<u8>>,
    writes: usize,
    create_only: bool,
}

async fn oci_server(
    axum::extract::State(state): axum::extract::State<Arc<Mutex<OciState>>>,
    req: axum::extract::Request,
) -> axum::response::Response {
    use axum::{
        http::{Method, StatusCode, header},
        response::IntoResponse,
    };
    use sha2::{Digest as _, Sha256};
    let uri = req.uri().clone();
    let meth = req.method().clone();
    let precondition = req
        .headers()
        .get(header::IF_NONE_MATCH)
        .is_some_and(|header| header == "*");
    let body = axum::body::to_bytes(req.into_body(), 32 << 20)
        .await
        .unwrap()
        .to_vec();
    let path = uri.path().strip_prefix("/v2/test/archive/").unwrap();
    let mut state = state.lock().unwrap();
    if let Some(tag) = path.strip_prefix("manifests/") {
        if meth == Method::GET {
            if let Some(data) = state.manifests.get(tag) {
                return data.clone().into_response();
            }
            return StatusCode::NOT_FOUND.into_response();
        }
        if state.create_only && precondition && state.manifests.contains_key(tag) {
            return StatusCode::PRECONDITION_FAILED.into_response();
        }
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        for layer in value["layers"].as_array().unwrap() {
            assert!(state.blobs.contains_key(layer["digest"].as_str().unwrap()));
        }
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&body)));
        if tag.starts_with("sha256:") && tag != digest {
            return StatusCode::BAD_REQUEST.into_response();
        }
        state.manifests.insert(digest, body.clone());
        state.manifests.insert(tag.into(), body);
        return StatusCode::CREATED.into_response();
    }
    if path == "blobs/uploads/" {
        return (
            StatusCode::ACCEPTED,
            [(header::LOCATION, "/v2/test/archive/blobs/uploads/session")],
        )
            .into_response();
    }
    if path == "blobs/uploads/session" {
        let expected = format!("sha256:{}", hex::encode(Sha256::digest(&body)));
        assert_eq!(
            uri.query().unwrap().replace("%3A", ":"),
            format!("digest={expected}")
        );
        state.writes += 1;
        state.blobs.insert(expected, body);
        return StatusCode::CREATED.into_response();
    }
    if let Some(bytes) = state.blobs.get(path.strip_prefix("blobs/").unwrap()) {
        if meth == Method::HEAD {
            return StatusCode::OK.into_response();
        }
        return bytes.clone().into_response();
    }
    StatusCode::NOT_FOUND.into_response()
}

#[test]
fn oci_reuses_frame_layers_and_preserves_physical_bytes_on_pull() {
    let local = TempDir::new().unwrap();
    let source = registry(&local);
    let received = TempDir::new().unwrap();
    let destination = registry(&received);
    let first = fixture("First", 0);
    let second = fixture("Second", 0);
    source
        .publish(&reference("1"), Some(PROFILE), first.as_slice())
        .unwrap();
    let release = source
        .publish(&reference("2"), Some(PROFILE), second.as_slice())
        .unwrap();
    let state = Arc::new(Mutex::new(OciState {
        create_only: true,
        ..OciState::default()
    }));
    let app = axum::Router::new()
        .fallback(oci_server)
        .with_state(state.clone());
    let (address, stop, task) = spawn_server(app);
    let client = oci::Client::new(&format!("oci+http://{address}/test/archive"), None).unwrap();
    client.push(&source, &reference("1")).unwrap();
    let first_writes = state.lock().unwrap().writes;
    assert!(client.push(&source, &reference("2")).unwrap().named);
    let after = state.lock().unwrap().writes;
    assert!(after - first_writes < first_writes);
    assert_eq!(
        client.push(&source, &reference("2")).unwrap().release,
        release
    );
    assert_eq!(state.lock().unwrap().writes, after);
    assert_eq!(
        client
            .pull(
                &destination,
                &reference("2"),
                Some(&release.artifact.sha256)
            )
            .unwrap(),
        release
    );
    let output = received.path().join("download.sac");
    destination.fetch(&reference("2"), &output).unwrap();
    assert_eq!(fs::read(output).unwrap(), second);

    let fresh = TempDir::new().unwrap();
    let fresh = registry(&fresh);
    let mut remote = state.lock().unwrap();
    let payload_digest = remote
        .manifests
        .values()
        .filter_map(|manifest| {
            let manifest: serde_json::Value = serde_json::from_slice(manifest).unwrap();
            manifest["layers"].as_array()?.iter().find_map(|layer| {
                (layer["mediaType"] == "application/vnd.sac.registry.frame-body.v1")
                    .then(|| layer["digest"].as_str().unwrap().to_owned())
            })
        })
        .next()
        .unwrap();
    remote.blobs.get_mut(&payload_digest).unwrap()[0] ^= 1;
    drop(remote);
    assert!(matches!(
        client.pull(&fresh, &reference("2"), None),
        Err(Error::Integrity(_))
    ));
    assert!(matches!(
        fresh.resolve(&reference("2")),
        Err(Error::NotFound(_))
    ));
    stop.send(()).unwrap();
    task.join().unwrap();
}

#[test]
fn oci_falls_back_to_manifest_digest_on_servers_without_create_only_tags() {
    let local = TempDir::new().unwrap();
    let source = registry(&local);
    let exact = fixture("Digest publication", 0);
    let release = source
        .publish(&reference("1"), None, exact.as_slice())
        .unwrap();
    let state = Arc::new(Mutex::new(OciState::default()));
    let app = axum::Router::new()
        .fallback(oci_server)
        .with_state(state.clone());
    let (address, stop, task) = spawn_server(app);
    let client = oci::Client::new(&format!("oci+http://{address}/test/archive"), None).unwrap();
    let published = client.push(&source, &reference("1")).unwrap();
    assert!(!published.named);
    assert_eq!(published.release, release);
    let writes = state.lock().unwrap().writes;
    let retry = client.push(&source, &reference("1")).unwrap();
    assert_eq!(retry.manifest_digest, published.manifest_digest);
    assert_eq!(state.lock().unwrap().writes, writes);
    assert!(matches!(
        client.push_with_naming(&source, &reference("1"), oci::Naming::RequireName),
        Err(Error::Invalid(_))
    ));
    let received = TempDir::new().unwrap();
    let destination = registry(&received);
    let pulled = client
        .pull_manifest(
            &destination,
            &reference("1"),
            Some(&published.manifest_digest),
            Some(&release.artifact.sha256),
        )
        .unwrap();
    assert_eq!(pulled, release);
    let path = received.path().join("pulled.sac");
    destination.fetch(&reference("1"), &path).unwrap();
    assert_eq!(fs::read(path).unwrap(), exact);
    assert!(
        !state
            .lock()
            .unwrap()
            .manifests
            .keys()
            .any(|key| key.starts_with("sac-release-"))
    );
    stop.send(()).unwrap();
    task.join().unwrap();
}
