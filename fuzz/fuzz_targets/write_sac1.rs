#![no_main]
//! A successful current writer publication must pass its owning core reader.
use libfuzzer_sys::fuzz_target;
use sac::{
    resources::{path_from_str, ArchiveBuilder, ArchiveReader, Limits},
    MemoryStore,
};

fuzz_target!(|data: &[u8]| {
    if data.len() > 1 << 20 {
        return;
    }
    let mut store = MemoryStore::sealed();
    let snapshot = {
        let mut builder = ArchiveBuilder::new(&mut store);
        builder.set_chunk_size(1024).unwrap();
        for (ordinal, bytes) in data.chunks(4096).take(16).enumerate() {
            builder
                .add_file(&path_from_str(&format!("file{ordinal}")).unwrap(), bytes)
                .unwrap();
        }
        builder.finish().unwrap()
    };
    store.publish(snapshot).unwrap();
    let reader = store.reader().unwrap();
    let archive =
        ArchiveReader::open(&store, reader.snapshot().unwrap(), Limits::default()).unwrap();
    archive
        .verify_commit(reader.publication.unwrap().root)
        .unwrap();
});
