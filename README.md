# SAC: Sealed Artifact Container

SAC is a single-file container format, a Rust library and a command-line tool.
A SAC file holds a tree of named files and, optionally, application records.
A reader checks each object against its BLAKE3 identity before it uses the
object.

The current wire format is **SAC1**. Each file starts with the four ASCII bytes
`SAC1`.

## What you can do with SAC

- **Pack a file tree** into one sealed archive. Extract the same tree later
  into a new directory.
- **Read one byte range** of one file. The reader authenticates only the
  objects that the range needs. It does not read the full archive.
- **Keep a live store.** A live store is a SAC file that a local writer updates
  in place with durable, crash-safe publication.
- **Add your own records.** An application profile stores application data
  next to the files. SAC authenticates the data. The application defines its
  meaning.
- **Repair damaged bytes** with optional Reed–Solomon recovery records.
- **Read a file without this implementation.** An independent Python reader
  uses only the specification and two public libraries.

A sealed archive and a live store use the same objects, the same schemas and
the same snapshot identity. Only the rules for locators and publication are
different.

## Status

SAC is prerelease software.

- The package version is 0.2.0. The wire-format version is 1. The two versions
  are independent.
- SAC1 is the only supported format. Files from earlier prerelease formats are
  rejected. There is no migration command. Make such files again from their
  original inputs.
- The format can change before it becomes stable. The
  [changelog](CHANGELOG.md) records each change.

## Install

SAC is not published on crates.io. The crate name `sac` on crates.io belongs to
a different project. Use a Git dependency and pin a commit:

```toml
[dependencies]
sac = { git = "https://github.com/bryanmatteson/sac", rev = "<commit>" }
```

To install the `sac` command-line tool from a checkout:

```sh
cargo install --locked --path .
```

The minimum supported Rust version is 1.90.

## Quick start: command line

```sh
sac pack ./files portable.sac
sac inspect portable.sac
sac verify portable.sac
sac list portable.sac
sac read portable.sac images/program.bin --offset 4096 --length 512 > range.bin
sac extract portable.sac ./restored
sac unpack portable.sac ./recovered
```

- `pack` writes a sealed archive. Add `--live` to write a live store. Add
  `--preserve` to record permission bits and modification times.
- `extract` makes a new directory that is the packed tree: the recorded names,
  symbolic links, permission bits and modification times.
- `unpack` makes a new directory for input that you do not trust. The files are
  in its `content/` subdirectory with host-neutral names, and no link or
  permission is applied. A report is in `report.cbor`.
- A command that makes a new file or directory does not overwrite an existing
  path.
- Each command accepts finite limits for input, output, temporary storage,
  memory, entries and time.
- Status and diagnostics are JSON. Exit code 0 is success, 1 is a failure and 2
  is a usage error.

Run `sac --help` for the full command list. The [CLI guide](docs/sac1-cli.md)
describes each command.

## Quick start: Rust

```rust
use sac::{
    MemoryStore,
    resources::{ArchiveBuilder, ArchiveReader, Limits, path_from_str},
};

fn main() -> sac::Result<()> {
    // Build a tree with one file in an in-memory sealed store.
    let mut store = MemoryStore::sealed();
    let snapshot = {
        let mut builder = ArchiveBuilder::new(&mut store);
        builder.add_file(&path_from_str("hello.txt")?, b"hello SAC1\n")?;
        builder.finish()?
    };
    store.publish(snapshot)?;

    // Open the published snapshot and read a byte range.
    let admitted = store.reader()?;
    let archive = ArchiveReader::open(&store, admitted.snapshot().unwrap(), Limits::default())?;
    archive.verify_commit(store.root().unwrap().root)?;
    assert_eq!(
        archive.read_range(&path_from_str("hello.txt")?, 0, 11)?,
        b"hello SAC1\n"
    );
    Ok(())
}
```

This program is [`examples/basic.rs`](examples/basic.rs). To run it:

```sh
cargo run --example basic
```

The main types are:

| Type | Purpose |
| --- | --- |
| `resources::ArchiveBuilder` | Builds a tree of named files. |
| `resources::ArchiveReader` | Reads bounded ranges, streams entries and extracts files. |
| `MemoryStore` | Holds an object graph in memory. |
| `NativeStore` | Owns durable publication to a local file. Needs the `native` feature. |
| `NativeReader` | Pins one admitted, immutable view of a local file. Needs the `native` feature. |
| `v1::metadata::MetadataReader`, `MetadataEditor` | Read and edit generic container metadata. |
| `recovery` | Creates, inspects and applies recovery records. |

The public API is in the `v1` module. The crate root also exports the principal
types. The [Rust API notes](docs/api-notes.md) describe buffering, caches,
allocation-sensitive reads and compaction.

## Cargo features

| Feature | Default | Adds |
| --- | --- | --- |
| `native` | Yes | Durable local stores, confined extraction and the `sac` command-line tool. Includes `compression`. |
| `trust` | Yes | Ed25519 COSE signature verification under a policy that the caller supplies. |
| `privacy-age` | Yes | [age encryption](docs/privacy-age.md) of a complete sealed archive. Includes `native`. |
| `compression` | No | Zstandard encoding and accelerated native decoding. |
| `http` | No | Bounded HTTP range reads and `sac read URL`. |
| `serde` | No | Serialization of object hashes and references. |

A reader with `default-features = false` is a portable core reader. It decodes
compressed frames with a bounded pure-Rust Zstandard decoder.

## Optional functions

### Recovery records

[Recovery records](specs/03-recovery-records-v1.md) add Reed–Solomon parity. The
parity can be in a sidecar file or in the archive.

```sh
sac recovery create portable.sac portable.sac.rr --redundancy-percent 10
sac recovery inspect portable.sac.rr
sac recovery repair damaged.sac portable.sac.rr repaired.sac

sac recovery embed portable.sac protected.sac --redundancy-percent 10
sac recovery inspect protected.sac --embedded
sac recovery repair damaged-protected.sac repaired.sac --embedded
```

- Normal reads do not scan or decode parity.
- Make the records from a file that no writer changes at that time.
- Make the records again after each save or compaction.
- Repair does not change its inputs. It installs the output only after it
  checks the repaired blocks and the full source digest.

### Generic container metadata

The optional [`sac.metadata.v1` profile](specs/02-generic-metadata-v1.md) stores
namespaced CBOR values. It does not depend on an application.

```sh
sac metadata list portable.sac
sac metadata get portable.sac org.example.title --json
```

Edits need a live store. See the
[CLI guide](docs/sac1-cli.md#generic-container-metadata).

### Independent Python reader

[`tools/sac1_recover.py`](tools/SAC1_RECOVERY.md) reads SAC1 files without this
crate. It needs Python 3 and the packages in `tools/sac1-requirements.txt`. It
can verify, list, extract, salvage and repair a file offline.

## What a successful check tells you

SAC keeps these results separate. One result does not imply a different result.

| Result | Meaning |
| --- | --- |
| Root admission | The selected commit and its bounded control region are authentic. |
| Content verification | The bytes that you requested agree with their object identities. |
| Full core validation | Each reachable frame, locator and core schema is valid. |
| Profile validation | An application profile obeys the rules of its owner. SAC does not make this check for an application profile. |
| Publisher trust | A signature is acceptable under your policy. A valid hash or an included signature is not sufficient. |
| Live durability | A local writer made the publication durable. |

A limit error means that the check is incomplete. Read the
[security policy](SECURITY.md) for the full boundaries.

## Platform support

- Development and tests use macOS and Linux. Other hosts are not tested.
- Live-store publication and confined extraction need a Unix host.
- Hole punching for same-file maintenance operates on supported macOS and
  Linux filesystems.

## Documentation

| Document | Contents |
| --- | --- |
| [Specification index](specs/00-index-and-compatibility.md) | The list of specifications and the compatibility statement. |
| [Core format and API](specs/01-sac-core-v1.md) | The wire layout, canonical objects, schemas, limits and verification boundaries. |
| [Generic metadata profile](specs/02-generic-metadata-v1.md) | The `sac.metadata.v1` profile. |
| [Recovery records](specs/03-recovery-records-v1.md) | The erasure code and the record formats. |
| [CLI guide](docs/sac1-cli.md) | Each `sac` command, its limits and its diagnostics. |
| [Rust API notes](docs/api-notes.md) | Buffering, caches, borrowed reads and compaction. |
| [Same-file maintenance](docs/same-file-maintenance.md) | In-place compaction, online reclamation and the reader contract. |
| [Privacy](docs/privacy-age.md) | age encryption of a sealed archive. |
| [Independent recovery](tools/SAC1_RECOVERY.md) | The Python reader, extractor and salvage tool. |
| [Conformance vectors](conformance/README.md) | The byte fixtures that the Rust and Python readers share. |
| [Qualification](tools/SAC1_QUALIFICATION.md) | The size, I/O, memory and compaction workloads. |
| [Performance harness](tools/performance/README.md) | The allocation, CPU and memory benchmark. |

## Development

SAC has no hosted continuous integration. The checks run on your computer, on
request:

```sh
tools/ci.sh
```

[CONTRIBUTING.md](CONTRIBUTING.md) describes each job.

## Security

Report a vulnerability in private through GitHub security advisories. See
[SECURITY.md](SECURITY.md).

## License

SAC is licensed under the [MIT License](LICENSE).
