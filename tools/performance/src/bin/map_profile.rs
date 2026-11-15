//! Attribute real directory edits without changing the native store's checks.
use sac::resources::{ArchiveBuilder, ArchiveReader, Limits, path_from_str};
use sac::{CanonicalObject, NativeStore, ObjectRef, ObjectStore, Result, RewriteSource};
use std::{cell::Cell, sync::Arc, time::Instant};

#[derive(Default)]
struct Phase {
    calls: Cell<u64>,
    ns: Cell<u128>,
}
impl Phase {
    fn run<T>(&self, operation: impl FnOnce() -> T) -> T {
        let start = Instant::now();
        let result = operation();
        self.calls.set(self.calls.get() + 1);
        self.ns.set(self.ns.get() + start.elapsed().as_nanos());
        result
    }
    fn json(&self) -> serde_json::Value {
        serde_json::json!({"calls":self.calls.get(),"wall_ns":self.ns.get()})
    }
}
struct Profile<'a> {
    store: &'a mut NativeStore,
    get: Phase,
    put: Phase,
    source: Phase,
    rewrite: Phase,
}
impl ObjectStore for Profile<'_> {
    fn get(&self, reference: ObjectRef) -> Result<CanonicalObject> {
        self.get.run(|| self.store.get(reference))
    }
    fn get_verified_shared(&self, reference: ObjectRef) -> Result<Arc<CanonicalObject>> {
        self.get.run(|| self.store.get_verified_shared(reference))
    }
    fn put(
        &mut self,
        kind: u16,
        version: u16,
        bytes: &[u8],
        children: &[ObjectRef],
    ) -> Result<ObjectRef> {
        self.put
            .run(|| self.store.put(kind, version, bytes, children))
    }
    fn rewrite_source(&self, reference: ObjectRef) -> Result<Option<RewriteSource>> {
        self.source.run(|| self.store.rewrite_source(reference))
    }
    fn rewrite(
        &mut self,
        source: &RewriteSource,
        kind: u16,
        version: u16,
        bytes: &[u8],
        children: &[ObjectRef],
    ) -> Result<ObjectRef> {
        self.rewrite
            .run(|| self.store.rewrite(source, kind, version, bytes, children))
    }
}
fn main() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = NativeStore::create_live(dir.path().join("map.sac"), [42; 16]).unwrap();
    let keys = std::env::var("SAC_MAP_KEYS")
        .map(|s| s.parse::<usize>().unwrap())
        .unwrap_or(128);
    let variable = std::env::var_os("SAC_MAP_RESIZE").is_some();
    let page_limit = std::env::var("SAC_MAP_PAGE_LIMIT")
        .map(|s| s.parse::<usize>().unwrap())
        .ok();
    let mut builder = ArchiveBuilder::new(&mut store);
    if let Some(limit) = page_limit {
        builder.set_page_limit(limit).unwrap();
    }
    for i in 0..keys {
        builder
            .add_file(
                &path_from_str(&format!("file-{i:04}")).unwrap(),
                &vec![71; if keys == 128 { 512 } else { 64 }],
            )
            .unwrap();
    }
    let snapshot = builder.finish().unwrap();
    store.publish(snapshot).unwrap();
    let pin = store.pin().unwrap();
    let mut directory = ArchiveReader::open(&pin, snapshot, Limits::default())
        .unwrap()
        .directory_root();
    let mut object = store.get(directory).unwrap();
    while object.kind == 4 {
        object = store.get(object.children[0]).unwrap();
    }
    let hash = Phase::default();
    let schema = Phase::default();
    let encode = Phase::default();
    let mut encoder = sac::v1::wire::FrameEncoder::default();
    for _ in 0..1000 {
        hash.run(|| std::hint::black_box(object.hash()));
        schema.run(|| sac::validate_core_object(&object).unwrap());
        encode.run(|| {
            std::hint::black_box(encoder.encode(&object, 1).unwrap());
        });
    }
    let mut profile = Profile {
        store: &mut store,
        get: Phase::default(),
        put: Phase::default(),
        source: Phase::default(),
        rewrite: Phase::default(),
    };
    let paths: Vec<_> = (0..keys)
        .map(|i| path_from_str(&format!("file-{i:04}")).unwrap())
        .collect();
    let cpu = cpu_time::ProcessTime::now();
    let start = Instant::now();
    for ordinal in 0..10_000u64 {
        let mut builder =
            ArchiveBuilder::from_directory(&mut profile, directory, Limits::default());
        if let Some(limit) = page_limit {
            builder.set_page_limit(limit).unwrap();
        }
        let key = (ordinal as usize * 4051) % keys;
        let length = if variable {
            [0, 8, 64, 512, 4096, 65536][(key + ordinal as usize / keys) % 6]
        } else {
            8
        };
        let mut payload = vec![ordinal as u8; length];
        let n = length.min(8);
        payload[..n].copy_from_slice(&ordinal.to_le_bytes()[..n]);
        builder
            .set_file(&paths[key], &payload, sac::cbor::Value::Map(Vec::new()))
            .unwrap();
        directory = builder.finish_directory().unwrap();
    }
    println!(
        "{}",
        serde_json::json!({"iterations":10000,"wall_ns":start.elapsed().as_nanos(),"cpu_ns":cpu.elapsed().as_nanos(),"get":profile.get.json(),"put":profile.put.json(),"source":profile.source.json(),"rewrite":profile.rewrite.json(),"directory":directory.hash.to_string(),"page_bytes":object.bytes.len(),"components":{"hash":hash.json(),"schema":schema.json(),"encode_including_hash_and_schema":encode.json()}})
    );
}
