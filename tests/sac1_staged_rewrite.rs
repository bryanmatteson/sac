#![cfg(feature = "native")]
use sac::v1::resources::{ArchiveBuilder, ArchiveReader, ExtentAccumulator, Limits, path_from_str};
use sac::v1::{CanonicalObject, NativeStore, ObjectRef, ObjectStore, Result};

// A generic adapter deliberately retains the existing strict defaults.
struct Strict<'a>(&'a mut NativeStore);
impl ObjectStore for Strict<'_> {
    fn get(&self, r: ObjectRef) -> Result<CanonicalObject> {
        self.0.get(r)
    }
    fn put(&mut self, k: u16, v: u16, b: &[u8], c: &[ObjectRef]) -> Result<ObjectRef> {
        self.0.put(k, v, b, c)
    }
}
fn key(n: u64) -> Vec<Vec<u8>> {
    let mut x = n.wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    path_from_str(&format!("app/records/{x:016x}{n:016x}.cbor")).unwrap()
}
fn batch(
    store: &mut impl ObjectStore,
    prior: Option<ObjectRef>,
    start: u64,
    count: u64,
) -> ObjectRef {
    let mut edits: Vec<_> = (start..start + count)
        .map(|n| {
            // A real public projection emits one distinct retained resource
            // extent per record; a single shared four-byte extent masks that
            // workload and makes repeated child authentication artificially cheap.
            let data = [
                b"same".as_slice(),
                &n.to_le_bytes(),
                blake3::hash(&n.to_le_bytes()).as_bytes(),
            ]
            .concat();
            let mut accumulator = ExtentAccumulator::new();
            accumulator.push_data(store, &data).unwrap();
            let extent = accumulator.finish(store).unwrap().unwrap();
            (
                key(n),
                data.len() as u64,
                extent,
                sac::cbor::text_map(vec![("test.ordinal", sac::cbor::Value::Uint(n))]),
            )
        })
        .collect();
    edits.sort_by(|a, b| a.0.cmp(&b.0));
    let mut builder = if let Some(root) = prior {
        ArchiveBuilder::from_directory(store, root, Limits::default())
    } else {
        ArchiveBuilder::new(store)
    };
    builder.set_page_limit(4096).unwrap();
    builder.set_extent_files_batch(&edits).unwrap();
    builder.directory_root().unwrap()
}
#[test]
fn repeated_native_staged_batches_bound_reads_with_identical_archive_bytes() {
    let temporary = tempfile::tempdir().unwrap();
    let mut outputs = Vec::new();
    for checked in [false, true] {
        let path = temporary
            .path()
            .join(if checked { "checked.sac" } else { "strict.sac" });
        let mut store = NativeStore::create_live(&path, [71; 16]).unwrap();
        let mut root = None;
        // Identical initial history for both stores; only subsequent staged
        // Context-like flushes differ in their rewrite admission policy.
        for start in (0..2048).step_by(128) {
            root = Some(batch(&mut Strict(&mut store), root, start, 128));
        }
        let initial = ArchiveBuilder::from_directory(&mut store, root.unwrap(), Limits::default())
            .finish()
            .unwrap();
        store.publish(initial).unwrap();
        let mut reads = Vec::new();
        for start in (2048..2560).step_by(128) {
            // Cold between flushes, with production's bounded within-flush
            // parent reuse. Preserve writer append provenance while clearing
            // every decoded/verified entry and physical read window.
            store.set_decoded_cache_budget(0);
            store.set_decoded_cache_budget(32 * 1024 * 1024);
            let before = store.physical_statistics();
            root = Some(if checked {
                batch(&mut store, root, start, 128)
            } else {
                batch(&mut Strict(&mut store), root, start, 128)
            });
            reads.push(store.physical_statistics().read_bytes - before.read_bytes);
        }
        let snapshot = ArchiveBuilder::from_directory(&mut store, root.unwrap(), Limits::default())
            .finish()
            .unwrap();
        let reader = ArchiveReader::open(&store, snapshot, Limits::default()).unwrap();
        reader.verify().unwrap();
        assert_eq!(
            reader
                .list()
                .unwrap()
                .iter()
                .filter(|r| r.kind == sac::resources::EntryKind::File)
                .count(),
            2560
        );
        for n in [0, 2047, 2048, 2175, 2304, 2559] {
            assert_eq!(reader.read_range(&key(n), 0, 4).unwrap(), b"same");
        }
        store.publish(snapshot).unwrap();
        outputs.push((reads, std::fs::read(path).unwrap()));
    }
    assert_eq!(
        outputs[0].1, outputs[1].1,
        "capability optimization preserves every canonical ID, physical locator and archive byte"
    );
    // The first batch has committed ancestors, which both writers read. The
    // ancestors of the later batches are frames that the same writer
    // appended: an ordinary put admits them from the append index, and the
    // capability adds only the exact authentication of each rewritten parent.
    for n in 1..4 {
        let (strict, checked) = (outputs[0].0[n], outputs[1].0[n]);
        assert!(
            strict <= checked && checked - strict <= strict / 16,
            "batch {n}: strict {:?}, checked {:?}",
            outputs[0].0,
            outputs[1].0
        );
    }
    eprintln!(
        "four staged batches strict/checked child-read bytes {:?} / {:?}",
        outputs[0].0, outputs[1].0
    );
}

#[test]
fn generic_staged_fanout_reuses_only_exact_edges_with_identical_bytes() {
    let temporary = tempfile::tempdir().unwrap();
    let mut outputs = Vec::new();
    for checked in [false, true] {
        let path = temporary
            .path()
            .join(if checked { "checked.sac" } else { "strict.sac" });
        let mut store = NativeStore::create_live(&path, [81; 16]).unwrap();
        let mut children = Vec::new();
        for n in 0..32u64 {
            let mut payload = Vec::new();
            for block in 0..1024u64 {
                payload.extend_from_slice(
                    blake3::hash(&[n.to_le_bytes(), block.to_le_bytes()].concat()).as_bytes(),
                );
            }
            children.push(store.put(7, 1, &payload, &[]).unwrap());
        }
        let prior = store.put(65001, 1, b"generic parent", &children).unwrap();
        let replacement = store.put(7, 1, b"replacement", &[]).unwrap();
        store.set_decoded_cache_budget(0);
        store.set_decoded_cache_budget(32 * 1024 * 1024);
        let before = store.physical_statistics();
        let mut changed = children.clone();
        changed[31] = replacement;
        let rewritten = if checked {
            let source = store
                .rewrite_source(prior)
                .unwrap()
                .expect("costly generic staged fanout");
            let result = store
                .rewrite(&source, 65001, 1, b"updated generic parent", &changed)
                .unwrap();
            let length = store.file_len();
            let mut bad = changed.clone();
            bad[0].address = children[1].address;
            assert!(
                store
                    .rewrite(&source, 65001, 1, b"bad physical edge", &bad)
                    .is_err()
            );
            assert_eq!(store.file_len(), length);
            result
        } else {
            store
                .put(65001, 1, b"updated generic parent", &changed)
                .unwrap()
        };
        let read_bytes = store.physical_statistics().read_bytes - before.read_bytes;
        assert_eq!(store.get(rewritten).unwrap().children, changed);
        let snapshot = ArchiveBuilder::new(&mut store).finish().unwrap();
        store.publish(snapshot).unwrap();
        outputs.push((read_bytes, rewritten, std::fs::read(path).unwrap()));
    }
    assert_eq!(outputs[0].1, outputs[1].1);
    assert_eq!(outputs[0].2, outputs[1].2);
    assert_eq!(
        outputs[0].0, 0,
        "an ordinary put admits the children that its writer appended"
    );
    // The capability reads the parent, and the body of the one rejected edge.
    assert!(
        outputs[1].0 < 32 * 32768 / 4,
        "checked reads: {}",
        outputs[1].0
    );
}
