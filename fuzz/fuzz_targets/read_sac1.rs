#![no_main]
//! Exercise current SAC1 admission and bounded authenticated graph traversal.
use libfuzzer_sys::fuzz_target;
use sac::{
    resources::{ArchiveReader, Limits},
    PositionalStore,
};
use std::time::Duration;

fuzz_target!(|data: &[u8]| {
    // Small inputs cannot exhaust the owned decoder's operational allocation
    // budget, so both representations must agree on canonical CBOR validity.
    if data.len() <= 64 * 1024 {
        assert_eq!(
            sac::cbor::decode(data).is_ok(),
            sac::v1::cbor_view::view(data).is_ok()
        );
    }
    if data.len() > 16 * 1024 * 1024 {
        return;
    }
    let Ok(store) = PositionalStore::open(data) else {
        return;
    };
    let Some(snapshot) = store.reader().snapshot() else {
        return;
    };
    let limits = Limits {
        max_frames: 4096,
        max_edges: 16384,
        max_source_bytes: 32 << 20,
        max_decoded_bytes: 32 << 20,
        max_memory_bytes: 32 << 20,
        max_temp_bytes: 32 << 20,
        max_elapsed: Duration::from_millis(100),
        ..Limits::default()
    };
    if let Ok(archive) = ArchiveReader::open(&store, snapshot, limits) {
        let route = [b"hello.txt".to_vec()];
        let _ = archive.lookup_shared(&route);
        if let Ok(Some(file)) = archive.open_file(&route) {
            let mut output = [0; 256];
            let n = file.len().min(output.len() as u64) as usize;
            let _ = file.read_into(0, &mut output[..n]);
        }
        if let Some(publication) = store.reader().publication {
            let _ = archive.verify_commit(publication.root);
        }
    }
});
