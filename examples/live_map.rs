//! cargo run --example live_map -- /tmp/live-map.sac
#[cfg(feature = "native")]
fn main() -> sac::Result<()> {
    use sac::{
        NativeStore,
        resources::{ArchiveReader, Limits},
    };
    let path = std::env::args()
        .nth(1)
        .expect("live_map PATH (new archive)");
    let mut store = NativeStore::create_live(path, [17; 16])?;
    let mut map = store.live_map()?;
    map.set(&mut store, b"record-1", b"first")?;
    map.publish(&mut store)?;
    let old = store.pin()?;
    map.set(&mut store, b"record-1", b"a growing replacement")?;
    map.set(&mut store, b"record-2", b"")?;
    map.publish(&mut store)?;
    assert_eq!(
        map.reader(&store)?.get(b"record-1")?,
        Some(b"a growing replacement".to_vec())
    );
    let old_map = sac::LiveMap::open(&old, old.reader().snapshot().unwrap())?;
    assert_eq!(
        old_map.reader(&old)?.get(b"record-1")?,
        Some(b"first".to_vec())
    );
    let exported = map.checkpoint(&mut store)?;
    assert_eq!(
        ArchiveReader::open(&store, exported, Limits::default())?
            .verify()?
            .files,
        2
    );
    println!(
        "Published live map; ordinary resource export: {}",
        exported.hash
    );
    Ok(())
}
#[cfg(not(feature = "native"))]
fn main() {}
