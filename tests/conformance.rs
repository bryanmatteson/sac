use sac::{
    PositionalStore,
    resources::{ArchiveReader, Limits, path_from_str},
};
use serde_json::Value;

#[test]
fn independent_sac1_vectors_agree_on_admission_snapshot_and_content() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("conformance");
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();
    for vector in manifest["vectors"].as_array().unwrap() {
        let name = vector["file"].as_str().unwrap();
        let bytes = std::fs::read(root.join(name)).unwrap();
        let result = (|| -> sac::Result<_> {
            let store = PositionalStore::open(bytes.as_slice())?;
            let reader = store.reader();
            let archive =
                ArchiveReader::open(&store, reader.snapshot().unwrap(), Limits::default())?;
            let report = archive.verify_commit(reader.publication.unwrap().root)?;
            let content = archive.read_range(
                &path_from_str("hello.txt")?,
                0,
                vector["content_hex"]
                    .as_str()
                    .map_or(0, |hex| hex.len() / 2),
            )?;
            Ok((hex::encode(report.snapshot_id), hex::encode(content)))
        })();
        if vector["valid"].as_bool().unwrap() {
            let (snapshot, content) = result.unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(snapshot, vector["snapshot"].as_str().unwrap(), "{name}");
            assert_eq!(content, vector["content_hex"].as_str().unwrap(), "{name}");
        } else {
            if vector["error_class"] == "unsupported" {
                assert!(
                    matches!(result, Err(sac::Error::Unsupported(_))),
                    "{name}: {result:?}"
                );
            }
            assert!(result.is_err(), "{name} must reject");
        }
    }
}
