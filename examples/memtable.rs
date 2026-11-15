//! Run with: cargo build --example memtable
//! Then: target/debug/examples/memtable /path/to/new-or-existing.sac
#[cfg(feature = "native")]
fn main() -> sac::Result<()> {
    use sac::{MemtableOptions, MemtableStore, Mutation, NativeReader};
    use std::io::Read;
    use std::path::PathBuf;
    use std::time::Duration;

    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "supply a SAC destination path",
            )
        })?;
    let options = MemtableOptions {
        max_memory_bytes: 8 * 1024 * 1024,
        max_wal_bytes: 32 * 1024 * 1024,
        flush_interval: Duration::from_millis(500),
        ..Default::default()
    };
    let store = if path.try_exists()? {
        MemtableStore::open(&path, options)?
    } else {
        let mut incarnation = [0; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut incarnation)?;
        MemtableStore::create(&path, incarnation, options)?
    };
    let sequence = store.write_batch(&[
        Mutation::Put {
            key: b"answer",
            value: b"42",
        },
        Mutation::Put {
            key: b"status",
            value: b"ready",
        },
        Mutation::Delete { key: b"obsolete" },
    ])?;
    assert_eq!(store.get(b"answer")?.as_deref(), Some(&b"42"[..]));
    // Schedule publication without stopping foreground operations. Explicit
    // flush/close can wait for the accepted watermark when needed.
    let checkpoint_target = store.request_flush()?;
    assert_eq!(store.get(b"status")?.as_deref(), Some(&b"ready"[..]));
    let pending = store.statistics()?;
    store.close()?;

    // Verify that ordinary SAC readers consume the completed checkpoint.
    let reader = NativeReader::open(&path)?;
    reader.validate()?;
    let archive = sac::resources::ArchiveReader::open(
        &reader,
        reader.reader().snapshot().unwrap(),
        Default::default(),
    )?;
    archive.verify_commit(reader.root().unwrap().root)?;
    assert_eq!(
        archive.read_range(&[b"k616e73776572".to_vec()], 0, 2)?,
        b"42"
    );
    println!(
        "{}",
        serde_json::json!({
            "sequence": sequence,
            "checkpoint_target": checkpoint_target,
            "pending_entries_before_close": pending.pending_entries,
            "wal_bytes_before_close": pending.wal_bytes,
            "checkpoint_verified": true,
        })
    );
    Ok(())
}

#[cfg(not(feature = "native"))]
fn main() {
    eprintln!("the memtable example requires the native feature");
}
