use sac::{
    MemoryStore,
    resources::{ArchiveBuilder, ArchiveReader, Limits, path_from_str},
};

fn main() -> sac::Result<()> {
    let mut store = MemoryStore::sealed();
    let snapshot = {
        let mut builder = ArchiveBuilder::new(&mut store);
        builder.add_file(&path_from_str("hello.txt")?, b"hello SAC1\n")?;
        builder.finish()?
    };
    store.publish(snapshot)?;
    let admitted = store.reader()?;
    let archive = ArchiveReader::open(&store, admitted.snapshot().unwrap(), Limits::default())?;
    archive.verify_commit(store.root().unwrap().root)?;
    assert_eq!(
        archive.read_range(&path_from_str("hello.txt")?, 0, 11)?,
        b"hello SAC1\n"
    );
    Ok(())
}
