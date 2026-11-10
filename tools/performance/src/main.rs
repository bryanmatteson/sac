use sac::{
    CanonicalObject, NativeStore, ObjectRef, ObjectStore,
    resources::{ArchiveBuilder, ArchiveReader, ExtentAccumulator, Limits, path_from_str},
};
use serde_json::{Value, json};
use std::{hint::black_box, time::Instant};

fn sample(mut operation: impl FnMut(), iterations: usize) -> Value {
    for _ in 0..8 {
        operation();
    }
    #[cfg(feature = "allocations")]
    let allocations = {
        let a = allocation_counter::measure(|| {
            for _ in 0..iterations {
                operation();
            }
        });
        json!({"count": a.count_total, "bytes": a.bytes_total, "peak_live_bytes": a.bytes_max, "retained_bytes": a.bytes_current})
    };
    #[cfg(not(feature = "allocations"))]
    let allocations = Value::Null;
    let cpu = cpu_time::ProcessTime::now();
    let started = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    json!({"iterations":iterations,"wall_ns":started.elapsed().as_nanos(),"cpu_ns":cpu.elapsed().as_nanos(),"allocations":allocations})
}
fn main() {
    let case = std::env::args().nth(1).unwrap_or_else(|| "lookup".into());
    let dir = tempfile::tempdir().unwrap();
    let mut store = NativeStore::create_live(dir.path().join("bench.sac"), [42; 16]).unwrap();
    let path = path_from_str("file-0063").unwrap();
    let payload = vec![71; 512];
    let mut builder = ArchiveBuilder::new(&mut store);
    for i in 0..128 {
        builder
            .add_file(&path_from_str(&format!("file-{i:04}")).unwrap(), &payload)
            .unwrap();
    }
    let extent_path = path_from_str("chunked").unwrap();
    if case.starts_with("extent-") {
        let data: Vec<_> = (0..1 << 20)
            .map(|i| ((i * 31 + i / 256) % 251) as u8)
            .collect();
        builder.add_file(&extent_path, &data).unwrap();
    }
    let snapshot = builder.finish().unwrap();
    store.publish(snapshot).unwrap();
    let pin = store.pin().unwrap();
    let archive = ArchiveReader::open(&pin, snapshot, Limits::default()).unwrap();
    let object = CanonicalObject {
        kind: 7,
        version: 1,
        bytes: vec![53; 1 << 20],
        children: vec![],
    };
    let encoded = sac::v1::wire::encode_frame(&object, 0).unwrap();
    let reference = ObjectRef {
        hash: object.hash(),
        address: sac::ChunkAddress {
            offset: 12288,
            length: encoded.len() as u32,
        },
    };
    let mut output = vec![0; 512];
    let mut operation_hash = None;
    let result = match case.as_str() {
        "extent-build" => {
            let references: Vec<_> = (0..2048u64)
                .map(|i| store.put(7, 1, &i.to_le_bytes(), &[]).unwrap())
                .collect();
            sample(
                || {
                    let mut accumulator = ExtentAccumulator::new();
                    for reference in &references {
                        accumulator.push(&mut store, 8, Some(*reference)).unwrap();
                    }
                    let root = accumulator.finish(&mut store).unwrap().unwrap();
                    operation_hash = Some(root.hash);
                    black_box(root);
                },
                16,
            )
        }
        "lookup" => sample(
            || {
                let entry = archive.lookup(black_box(&path)).unwrap();
                black_box(entry);
            },
            2000,
        ),
        "read" => sample(
            || {
                let mut out = output.as_mut_slice();
                archive.read_to(black_box(&path), &mut out).unwrap();
                assert_eq!(out.len(), 0);
                black_box(&output);
            },
            2000,
        ),
        "extent-read" => sample(
            || {
                let bytes = archive
                    .read_range(&extent_path, 256 * 1024 - 128, 4096)
                    .unwrap();
                assert_eq!(bytes.len(), 4096);
                black_box(bytes);
            },
            2000,
        ),
        "encode" => sample(
            || {
                black_box(sac::v1::wire::encode_frame(black_box(&object), 0).unwrap());
            },
            128,
        ),
        "decode" => sample(
            || {
                black_box(
                    sac::v1::wire::decode_frame(
                        reference,
                        black_box(&encoded),
                        12288,
                        12288 + encoded.len() as u64,
                    )
                    .unwrap(),
                );
            },
            128,
        ),
        "write" => {
            let mut i = 0u64;
            let mut data = (0..1 << 20)
                .map(|n| {
                    ((n as u64)
                        .wrapping_mul(0x9e3779b97f4a7c15)
                        .rotate_left((n % 63) as u32)
                        >> 32) as u8
                })
                .collect::<Vec<_>>();
            sample(
                || {
                    data[..8].copy_from_slice(&i.to_le_bytes());
                    i += 1;
                    black_box(store.put(7, 1, black_box(&data), &[]).unwrap());
                },
                64,
            )
        }
        "compressed-write" => {
            let mut i = 0u64;
            let mut data = vec![71; 1 << 20];
            sample(
                || {
                    data[..8].copy_from_slice(&i.to_le_bytes());
                    i += 1;
                    black_box(store.put(7, 1, black_box(&data), &[]).unwrap());
                },
                64,
            )
        }
        #[cfg(feature = "optimized-api")]
        "extent-opened" => {
            let file = archive.open_file(&extent_path).unwrap().unwrap();
            let mut output = [0; 4096];
            let expected = archive
                .read_range(&extent_path, 256 * 1024 - 128, output.len())
                .unwrap();
            sample(
                || {
                    file.read_into(256 * 1024 - 128, &mut output).unwrap();
                    assert_eq!(output.as_slice(), expected);
                },
                2000,
            )
        }
        #[cfg(feature = "optimized-api")]
        "lookup-shared" => sample(
            || {
                let entry = archive.lookup_shared(black_box(&path)).unwrap().unwrap();
                assert_eq!(entry.file_length(), Some(512));
                black_box(entry);
            },
            2000,
        ),
        #[cfg(feature = "optimized-api")]
        "read-opened" => {
            let file = archive.open_file(&path).unwrap().unwrap();
            sample(
                || {
                    file.read_into(0, &mut output).unwrap();
                    assert_eq!(output, payload);
                },
                100_000,
            )
        }
        #[cfg(feature = "optimized-api")]
        "encode-reuse" => {
            let mut encoder = sac::v1::wire::FrameEncoder::default();
            sample(
                || {
                    black_box(encoder.encode(&object, 0).unwrap());
                },
                128,
            )
        }
        #[cfg(feature = "optimized-api")]
        "decode-view" => {
            let mut decoder = sac::v1::wire::FrameDecoder::default();
            sample(
                || {
                    let view = decoder
                        .decode(reference, &encoded, 12288, 12288 + encoded.len() as u64)
                        .unwrap();
                    assert_eq!(view.body.len(), object.bytes.len());
                    black_box(view);
                },
                128,
            )
        }
        #[cfg(feature = "optimized-api")]
        "compressed-decode-view" => {
            let bytes = sac::v1::wire::encode_frame(&object, 1).unwrap();
            let r = ObjectRef {
                hash: reference.hash,
                address: sac::ChunkAddress {
                    offset: 12288,
                    length: bytes.len() as u32,
                },
            };
            let mut decoder = sac::v1::wire::FrameDecoder::default();
            sample(
                || {
                    let view = decoder
                        .decode(r, &bytes, 12288, 12288 + bytes.len() as u64)
                        .unwrap();
                    assert_eq!(view.body.len(), object.bytes.len());
                    black_box(view);
                },
                128,
            )
        }
        _ => panic!("unknown case"),
    };
    #[cfg(all(feature = "allocations", feature = "optimized-api"))]
    if matches!(
        case.as_str(),
        "read"
            | "lookup-shared"
            | "read-opened"
            | "extent-opened"
            | "encode-reuse"
            | "decode-view"
            | "compressed-decode-view"
    ) {
        assert_eq!(
            result["allocations"]["count"], 0,
            "warm allocation regression in {case}"
        );
    }
    println!(
        "{}",
        json!({"case":case,"allocation_instrumented":cfg!(feature="allocations"),"snapshot":snapshot.hash.to_string(),"operation_hash":operation_hash.map(|h|h.to_string()),"result":result})
    );
}
