use sac::v1::resources::{
    ArchiveBuilder, ArchiveReader, ExtentAccumulator, Limits, ResourcePath, path_from_str,
};
use sac::v1::{CanonicalObject, MemoryStore, ObjectRef, ObjectStore, Result, cbor::Value as V};

struct Counted {
    inner: MemoryStore,
    leaves: usize,
    branches: usize,
    puts: usize,
    fail_at: Option<usize>,
}
impl Counted {
    fn new() -> Self {
        Self {
            inner: MemoryStore::sealed(),
            leaves: 0,
            branches: 0,
            puts: 0,
            fail_at: None,
        }
    }
    fn reset(&mut self) {
        self.leaves = 0;
        self.branches = 0;
        self.puts = 0;
    }
}
impl ObjectStore for Counted {
    fn get(&self, r: ObjectRef) -> Result<CanonicalObject> {
        self.inner.get(r)
    }
    fn put(
        &mut self,
        kind: u16,
        version: u16,
        bytes: &[u8],
        children: &[ObjectRef],
    ) -> Result<ObjectRef> {
        self.puts += 1;
        if self.fail_at == Some(self.puts) {
            return Err(sac::v1::Error::Missing);
        }
        self.leaves += usize::from(kind == 3);
        self.branches += usize::from(kind == 4);
        self.inner.put(kind, version, bytes, children)
    }
}
fn metadata() -> V {
    V::Map(Vec::new())
}
fn extent(store: &mut impl ObjectStore, data: &[u8]) -> ObjectRef {
    let mut a = ExtentAccumulator::new();
    a.push_data(store, data).unwrap();
    a.finish(store).unwrap().unwrap()
}
fn snapshot(store: &mut impl ObjectStore, root: ObjectRef) -> ObjectRef {
    ArchiveBuilder::from_directory(store, root, Limits::default())
        .finish()
        .unwrap()
}
fn parent_child(store: &impl ObjectStore, root: ObjectRef, name: &[u8]) -> ObjectRef {
    let object = store.get(root).unwrap();
    let V::Array(rows) = sac::v1::cbor::decode(&object.bytes).unwrap() else {
        panic!()
    };
    for row in rows {
        let V::Array(row) = row else { panic!() };
        if row[0] == V::Bytes(name.into()) {
            let V::Uint(index) = row[3] else { panic!() };
            return object.children[index as usize];
        }
    }
    panic!("missing parent")
}

#[test]
fn batch_rewrites_shared_pages_once_and_keeps_unsplit_identity() {
    let mut store = Counted::new();
    let old = extent(&mut store, b"before");
    let new = extent(&mut store, b"after!");
    let base = {
        let mut builder = ArchiveBuilder::new(&mut store);
        builder.set_page_limit(16 * 1024).unwrap();
        for dir in ["a", "b", "untouched"] {
            for i in 0..24 {
                builder
                    .set_extent_file(
                        &path_from_str(&format!("{dir}/{i:04}")).unwrap(),
                        6,
                        old,
                        metadata(),
                    )
                    .unwrap();
            }
        }
        builder.directory_root().unwrap()
    };
    let preserved = parent_child(&store, base, b"untouched");
    let edits: Vec<_> = ["a", "b"]
        .iter()
        .flat_map(|dir| {
            (0..8).map(move |i| {
                (
                    path_from_str(&format!("{dir}/{i:04}")).unwrap(),
                    6,
                    new,
                    metadata(),
                )
            })
        })
        .collect();
    store.reset();
    let expected = {
        let mut sequential = ArchiveBuilder::from_directory(&mut store, base, Limits::default());
        sequential.set_page_limit(16 * 1024).unwrap();
        for (path, len, extent, metadata) in &edits {
            sequential
                .set_extent_file(path, *len, *extent, metadata.clone())
                .unwrap();
        }
        sequential.directory_root().unwrap()
    };
    let individual_puts = store.puts;
    store.reset();
    let actual = {
        let mut batch = ArchiveBuilder::from_directory(&mut store, base, Limits::default());
        batch.set_page_limit(16 * 1024).unwrap();
        batch.set_extent_files_batch(&edits).unwrap();
        batch.directory_root().unwrap()
    };
    assert_eq!(actual.hash, expected.hash);
    assert_eq!(
        store.leaves, 3,
        "two changed child directories and their parent only"
    );
    assert_eq!(store.branches, 0);
    assert!(individual_puts >= 10 * store.puts);
    assert_eq!(parent_child(&store, actual, b"untouched"), preserved);
    store.reset();
    {
        let mut batch = ArchiveBuilder::from_directory(&mut store, actual, Limits::default());
        batch.set_page_limit(16 * 1024).unwrap();
        batch.set_extent_files_batch(&edits).unwrap();
        assert_eq!(batch.directory_root(), Some(actual));
    }
    assert_eq!(
        store.puts, 0,
        "an unchanged batch must not append directory frames"
    );
    let snap = snapshot(&mut store, actual);
    let reader = ArchiveReader::open(&store, snap, Limits::default()).unwrap();
    reader.verify().unwrap();
    for (path, ..) in &edits {
        assert_eq!(reader.read_range(path, 0, 6).unwrap(), b"after!");
    }
    assert_eq!(
        reader
            .read_range(&path_from_str("untouched/0000").unwrap(), 0, 6)
            .unwrap(),
        b"before"
    );
}

#[test]
fn batch_splits_multiple_levels_with_exact_semantics_and_bounded_pages() {
    let mut store = Counted::new();
    let data = vec![0x57; 77];
    let root = extent(&mut store, &data);
    let edits: Vec<_> = (0..128)
        .map(|i| {
            let name = format!("{i:04}{}", "x".repeat(180));
            (
                vec![b"nested".to_vec(), name.into_bytes()],
                data.len() as u64,
                root,
                sac::v1::cbor::text_map(vec![("test.detail", V::Bytes(vec![i as u8; 180]))]),
            )
        })
        .collect();
    let mut individual = ArchiveBuilder::new(&mut store);
    individual.set_page_limit(1024).unwrap();
    for (path, len, extent, metadata) in &edits {
        individual
            .set_extent_file(path, *len, *extent, metadata.clone())
            .unwrap();
    }
    let individual = individual.finish().unwrap();
    let mut batch = ArchiveBuilder::new(&mut store);
    batch.set_page_limit(1024).unwrap();
    batch.set_extent_files_batch(&edits).unwrap();
    let batch = batch.finish().unwrap();
    let a = ArchiveReader::open(&store, individual, Limits::default()).unwrap();
    let b = ArchiveReader::open(&store, batch, Limits::default()).unwrap();
    assert_eq!(a.list().unwrap(), b.list().unwrap());
    b.verify().unwrap();
    for (path, ..) in &edits {
        assert_eq!(b.read_range(path, 0, data.len()).unwrap(), data);
    }
    let mut todo = vec![batch];
    let mut seen = std::collections::BTreeSet::new();
    let mut branches = 0;
    while let Some(r) = todo.pop() {
        if !seen.insert(r.hash) {
            continue;
        }
        let o = store.get(r).unwrap();
        if matches!(o.kind, 3 | 4) {
            assert!(o.canonical_len() <= 1024);
        }
        branches += usize::from(o.kind == 4);
        todo.extend(o.children);
    }
    assert!(branches > 10, "fixture must split several branch levels");
}

#[test]
fn batch_rejects_invalid_input_without_changing_root_or_writing() {
    let mut store = Counted::new();
    let r = extent(&mut store, b"payload");
    let base = {
        let mut b = ArchiveBuilder::new(&mut store);
        b.add_file(&path_from_str("old").unwrap(), b"kept").unwrap();
        b.directory_root().unwrap()
    };
    store.reset();
    let edit = |p: &str| (path_from_str(p).unwrap(), 7, r, metadata());
    let cases = vec![
        vec![edit("z"), edit("a")],
        vec![edit("a"), edit("a")],
        vec![edit("a"), edit("a/b")],
        (0..513).map(|i| edit(&format!("{i:04}"))).collect(),
        vec![(path_from_str("a").unwrap(), 0, r, metadata())],
        vec![(path_from_str("a").unwrap(), 7, r, V::Uint(1))],
    ];
    for edits in cases {
        let mut b = ArchiveBuilder::from_directory(&mut store, base, Limits::default());
        assert!(b.set_extent_files_batch(&edits).is_err());
        assert_eq!(b.directory_root(), Some(base));
    }
    assert_eq!(store.puts, 0);
    let limits = Limits {
        max_logical_bytes: 10,
        ..Default::default()
    };
    let mut b = ArchiveBuilder::from_directory(&mut store, base, limits);
    assert!(b.set_extent_files_batch(&[edit("a"), edit("b")]).is_err());
    assert_eq!(b.directory_root(), Some(base));
    let limits = Limits {
        max_memory_bytes: 128,
        ..Default::default()
    };
    let mut b = ArchiveBuilder::from_directory(&mut store, base, limits);
    assert!(b.set_extent_files_batch(&[edit("a")]).is_err());
    assert_eq!(b.directory_root(), Some(base));
}

#[test]
fn batch_failure_keeps_original_root_and_old_contents() {
    let mut store = Counted::new();
    let r = extent(&mut store, b"payload");
    let base = {
        let mut b = ArchiveBuilder::new(&mut store);
        b.add_file(&path_from_str("old").unwrap(), b"kept").unwrap();
        b.directory_root().unwrap()
    };
    store.reset();
    store.fail_at = Some(2);
    let edits: Vec<(ResourcePath, u64, ObjectRef, V)> = ["a/file", "b/file"]
        .iter()
        .map(|p| (path_from_str(p).unwrap(), 7, r, metadata()))
        .collect();
    {
        let mut b = ArchiveBuilder::from_directory(&mut store, base, Limits::default());
        assert!(b.set_extent_files_batch(&edits).is_err());
        assert_eq!(b.directory_root(), Some(base));
    }
    assert_eq!(
        store.puts, 2,
        "failure occurs after one actual subtree write"
    );
    store.fail_at = None;
    let snap = snapshot(&mut store, base);
    let reader = ArchiveReader::open(&store, snap, Limits::default()).unwrap();
    reader.verify().unwrap();
    assert_eq!(reader.list().unwrap().len(), 1);
    assert_eq!(
        reader
            .read_range(&path_from_str("old").unwrap(), 0, 4)
            .unwrap(),
        b"kept"
    );
}

#[test]
fn batch_random_insert_splits_leave_room_and_bound_rewrites() {
    const TARGET: usize = 2048;
    let mut store = Counted::new();
    let data = extent(&mut store, b"kept");
    let meta = sac::v1::cbor::text_map(vec![("test.detail", V::Bytes(vec![0x91; 180]))]);
    let name = |n: u64| vec![format!("{n:064x}").into_bytes()];
    let mut previous = None;
    let mut full = None;
    let mut old_count = 0;
    for n in 0..32u64 {
        let mut b = match previous {
            Some(root) => ArchiveBuilder::from_directory(&mut store, root, Limits::default()),
            None => ArchiveBuilder::new(&mut store),
        };
        b.set_page_limit(TARGET).unwrap();
        b.set_extent_file(&name(n << 32), 4, data, meta.clone())
            .unwrap();
        let root = b.directory_root().unwrap();
        if store.get(root).unwrap().kind == 4 {
            full = previous;
            old_count = n;
            break;
        }
        previous = Some(root);
    }
    let mut root = full.expect("fixture must fill a leaf");
    assert!(old_count >= 5);
    store.reset();
    let mut state = 0xd9c4_792a_8156_3bbdu64;
    let mut names = std::collections::BTreeSet::new();
    for _ in 0..64 {
        let n = loop {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let candidate = state % ((old_count - 1) << 32);
            if candidate & 0xffff_ffff != 0 && names.insert(candidate) {
                break candidate;
            }
        };
        let mut builder = ArchiveBuilder::from_directory(&mut store, root, Limits::default());
        builder.set_page_limit(TARGET).unwrap();
        builder
            .set_extent_files_batch(&[(name(n), 4, data, meta.clone())])
            .unwrap();
        root = builder.directory_root().unwrap();
    }
    assert!(
        store.leaves <= 88,
        "64 random inserts should rewrite one leaf plus occasional balanced splits, got {} leaf writes",
        store.leaves
    );
    let writes = store.leaves;
    let mut todo = vec![root];
    let mut leaves = Vec::new();
    while let Some(reference) = todo.pop() {
        let object = store.get(reference).unwrap();
        if object.kind == 3 {
            assert!(object.canonical_len() <= TARGET);
            let V::Array(rows) = sac::v1::cbor::decode(&object.bytes).unwrap() else {
                panic!()
            };
            leaves.push(rows.len());
        } else if object.kind == 4 {
            assert!(object.canonical_len() <= TARGET);
            assert!(object.children.len() >= 2);
            todo.extend(object.children);
        }
    }
    assert!(
        leaves.iter().all(|&count| count >= 2),
        "equal-size incremental records must not produce one-row overflow tails: {leaves:?}"
    );
    let snap = snapshot(&mut store, root);
    let reader = ArchiveReader::open(&store, snap, Limits::default()).unwrap();
    reader.verify().unwrap();
    assert_eq!(reader.list().unwrap().len(), old_count as usize + 64);
    for n in names {
        assert_eq!(reader.read_range(&name(n), 0, 4).unwrap(), b"kept");
    }
    eprintln!("64 random batch inserts: {writes} leaf writes, final occupancy {leaves:?}");
}

#[cfg(feature = "native")]
#[test]
fn native_512_row_batch_coalesces_random_projection_with_bounded_work() {
    use sac::v1::{NativeStore, RewriteSource};
    use std::collections::BTreeMap;
    struct CountedNative {
        inner: NativeStore,
        directory_writes: usize,
        directory_bytes: u64,
    }
    impl CountedNative {
        fn account(&mut self, kind: u16, before: u64) {
            let bytes = self.inner.file_len() - before;
            if matches!(kind, 3 | 4) && bytes != 0 {
                self.directory_writes += 1;
                self.directory_bytes += bytes;
            }
        }
    }
    impl ObjectStore for CountedNative {
        fn get(&self, r: ObjectRef) -> Result<CanonicalObject> {
            self.inner.get(r)
        }
        fn get_shared(&self, r: ObjectRef) -> Result<std::sync::Arc<CanonicalObject>> {
            self.inner.get_shared(r)
        }
        fn get_verified_shared(&self, r: ObjectRef) -> Result<std::sync::Arc<CanonicalObject>> {
            self.inner.get_verified_shared(r)
        }
        fn physical_identity(&self) -> Option<u64> {
            self.inner.physical_identity()
        }
        fn physical_dependencies(&self, r: ObjectRef) -> Result<Vec<ObjectRef>> {
            self.inner.physical_dependencies(r)
        }
        fn rewrite_source(&self, r: ObjectRef) -> Result<Option<RewriteSource>> {
            self.inner.rewrite_source(r)
        }
        fn put(
            &mut self,
            kind: u16,
            version: u16,
            bytes: &[u8],
            children: &[ObjectRef],
        ) -> Result<ObjectRef> {
            let before = self.inner.file_len();
            let result = self.inner.put(kind, version, bytes, children);
            self.account(kind, before);
            result
        }
        fn rewrite(
            &mut self,
            source: &RewriteSource,
            kind: u16,
            version: u16,
            bytes: &[u8],
            children: &[ObjectRef],
        ) -> Result<ObjectRef> {
            let before = self.inner.file_len();
            let result = self.inner.rewrite(source, kind, version, bytes, children);
            self.account(kind, before);
            result
        }
    }
    fn key(n: u64) -> ResourcePath {
        let mut state = n.wrapping_add(0x9e37_79b9_7f4a_7c15);
        state = (state ^ (state >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        state = (state ^ (state >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        state ^= state >> 31;
        path_from_str(&format!(
            "app/records/native-records/{state:016x}{n:048x}.cbor"
        ))
        .unwrap()
    }
    fn meta(n: u64) -> V {
        sac::v1::cbor::text_map(vec![
            ("test.ordinal", V::Uint(n)),
            ("test.detail", V::Bytes(vec![0x35; 96])),
        ])
    }
    let temporary = tempfile::tempdir().unwrap();
    let base_path = temporary.path().join("base.sac");
    let mut base = NativeStore::create_live(&base_path, [19; 16]).unwrap();
    let old = extent(&mut base, b"kept");
    let new = extent(&mut base, b"new!");
    let root = {
        let mut builder = ArchiveBuilder::new(&mut base);
        builder.set_page_limit(4096).unwrap();
        for start in (0..4096u64).step_by(128) {
            let mut edits: Vec<_> = (start..start + 128)
                .map(|n| (key(n), 4, old, meta(n)))
                .collect();
            edits.sort_by(|a, b| a.0.cmp(&b.0));
            builder.set_extent_files_batch(&edits).unwrap();
        }
        builder.directory_root().unwrap()
    };
    let snap = snapshot(&mut base, root);
    base.publish(snap).unwrap();
    drop(base);
    let edits: Vec<_> = (4096..4608).map(|n| (key(n), 4, new, meta(n))).collect();
    let mut outputs = Vec::new();
    for batch_size in [128, 512] {
        let path = temporary.path().join(format!("batch-{batch_size}.sac"));
        std::fs::copy(&base_path, &path).unwrap();
        let mut store = CountedNative {
            inner: NativeStore::open(&path, true).unwrap(),
            directory_writes: 0,
            directory_bytes: 0,
        };
        store.inner.discard_disposable_caches();
        let final_root = {
            let mut builder = ArchiveBuilder::from_directory(&mut store, root, Limits::default());
            builder.set_page_limit(4096).unwrap();
            for batch in edits.chunks(batch_size) {
                let mut ordered = batch.to_vec();
                ordered.sort_by(|a, b| a.0.cmp(&b.0));
                builder.set_extent_files_batch(&ordered).unwrap();
            }
            builder.directory_root().unwrap()
        };
        let measurements = (store.directory_writes, store.directory_bytes);
        let snap = snapshot(&mut store, final_root);
        let reader = ArchiveReader::open(&store, snap, Limits::default()).unwrap();
        reader.verify().unwrap();
        let rows = reader.list().unwrap();
        assert_eq!(
            rows.iter()
                .filter(|row| row.kind == sac::v1::resources::EntryKind::File)
                .count(),
            4608
        );
        let inventory: BTreeMap<_, _> = rows
            .into_iter()
            .map(|row| (row.path, (row.kind, row.length, row.metadata)))
            .collect();
        for n in 0..4608 {
            assert_eq!(inventory[&key(n)].2, meta(n));
        }
        for n in [0, 127, 4095, 4096, 4352, 4607] {
            assert_eq!(
                reader.read_range(&key(n), 0, 4).unwrap(),
                if n < 4096 { b"kept" } else { b"new!" }
            );
        }
        let mut todo = vec![final_root];
        let mut checked = std::collections::BTreeSet::new();
        while let Some(reference) = todo.pop() {
            if !checked.insert(reference) {
                continue;
            }
            let object = store.get(reference).unwrap();
            if matches!(object.kind, 3 | 4) {
                assert!(object.canonical_len() <= 4096);
                todo.extend(object.children);
            }
        }
        outputs.push((measurements, inventory));
    }
    assert_eq!(
        outputs[0].1, outputs[1].1,
        "batch capacity cannot alter namespace or metadata"
    );
    assert!(
        outputs[1].0.0 < outputs[0].0.0,
        "directory writes: {:?}",
        outputs.iter().map(|o| o.0).collect::<Vec<_>>()
    );
    assert!(
        outputs[1].0.1 * 10 <= outputs[0].0.1 * 9,
        "larger bounded batches must remove repeated ancestor/leaf writes: {:?}",
        outputs.iter().map(|o| o.0).collect::<Vec<_>>()
    );
    eprintln!(
        "native512-vs4x128 directory writes/bytes: {:?} -> {:?}; operation memory limit64MiB",
        outputs[0].0, outputs[1].0
    );
}

#[test]
fn batch_512_metadata_quota_rejects_before_writes_and_keeps_root() {
    let mut store = Counted::new();
    let data = extent(&mut store, b"kept");
    let base = {
        let mut builder = ArchiveBuilder::new(&mut store);
        builder
            .add_file(&path_from_str("old").unwrap(), b"kept")
            .unwrap();
        builder.directory_root().unwrap()
    };
    let metadata_cases = [
        sac::v1::cbor::text_map(vec![("test.detail", V::Bytes(vec![0x71; 8192]))]),
        // This encodes in about 512 bytes but owns 512 Value slots per row.
        sac::v1::cbor::text_map(vec![("test.detail", V::Array(vec![V::Uint(0); 512]))]),
    ];
    for metadata in metadata_cases {
        let edits: Vec<_> = (0..512)
            .map(|n| {
                (
                    path_from_str(&format!("{n:04}")).unwrap(),
                    4,
                    data,
                    metadata.clone(),
                )
            })
            .collect();
        store.reset();
        let limits = Limits {
            max_memory_bytes: 2 * 1024 * 1024,
            ..Default::default()
        };
        {
            let mut builder = ArchiveBuilder::from_directory(&mut store, base, limits);
            builder.set_page_limit(16 * 1024).unwrap();
            assert!(matches!(
                builder.set_extent_files_batch(&edits),
                Err(sac::v1::Error::Limit("resident memory"))
            ));
            assert_eq!(builder.directory_root(), Some(base));
        }
        assert_eq!(
            store.puts, 0,
            "all metadata memory must be admitted before any rewrite"
        );
    }
}

#[test]
fn smaller_writer_edits_wide_inherited_pages_and_keeps_inline_descriptors() {
    let mut store = Counted::new();
    let ext = extent(&mut store, b"new!");
    let old_inline = vec![0x5a; 6000];
    let base = {
        let mut builder = ArchiveBuilder::new(&mut store);
        builder.set_page_limit(16 * 1024).unwrap();
        for n in 0..120 {
            builder
                .set_file(
                    &path_from_str(&format!("dense/{n:04}")).unwrap(),
                    &[n as u8; 64],
                    metadata(),
                )
                .unwrap();
        }
        builder
            .set_file(
                &path_from_str("mixed/large").unwrap(),
                &old_inline,
                metadata(),
            )
            .unwrap();
        builder
            .set_file(&path_from_str("mixed/small").unwrap(), b"kept", metadata())
            .unwrap();
        builder.directory_root().unwrap()
    };
    for batched in [false, true] {
        let root = {
            let mut builder = ArchiveBuilder::from_directory(&mut store, base, Limits::default());
            builder.set_page_limit(4096).unwrap();
            let edits =
                ["dense/new", "mixed/new"].map(|p| (path_from_str(p).unwrap(), 4, ext, metadata()));
            if batched {
                builder.set_extent_files_batch(&edits).unwrap();
            } else {
                for (path, length, extent, meta) in &edits {
                    builder
                        .set_extent_file(path, *length, *extent, meta.clone())
                        .unwrap();
                }
            }
            builder
                .remove_file(&path_from_str("dense/0001").unwrap())
                .unwrap();
            builder.directory_root().unwrap()
        };
        let snap = snapshot(&mut store, root);
        let reader = ArchiveReader::open(&store, snap, Limits::default()).unwrap();
        reader.verify().unwrap();
        assert_eq!(
            reader
                .read_range(&path_from_str("mixed/large").unwrap(), 0, 6000)
                .unwrap(),
            old_inline
        );
        for path in ["dense/new", "mixed/new"] {
            assert_eq!(
                reader
                    .read_range(&path_from_str(path).unwrap(), 0, 4)
                    .unwrap(),
                b"new!"
            );
        }
        for n in (0..120).filter(|n| *n != 1) {
            assert_eq!(
                reader
                    .read_range(&path_from_str(&format!("dense/{n:04}")).unwrap(), 0, 64)
                    .unwrap(),
                [n as u8; 64]
            );
        }
        let large = parent_child(&store, root, b"mixed");
        // A directory row larger than the new target keeps its authenticated
        // inline representation, rather than silently changing to an extent.
        let mut pending = vec![large];
        let mut found = false;
        while let Some(reference) = pending.pop() {
            let object = store.get(reference).unwrap();
            if object.kind == 4 {
                pending.extend(object.children);
                continue;
            }
            let V::Array(rows) = sac::v1::cbor::decode(&object.bytes).unwrap() else {
                panic!()
            };
            for row in rows {
                let V::Array(row) = row else { panic!() };
                if row[0] == V::Bytes(b"large".to_vec()) {
                    let V::Array(data) = &row[3] else { panic!() };
                    assert_eq!(data[1], V::Uint(0));
                    assert_eq!(data[2], V::Bytes(old_inline.clone()));
                    found = true;
                }
            }
        }
        assert!(found);
    }
}
