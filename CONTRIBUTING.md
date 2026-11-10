# Contributing to SAC

SAC is prerelease software. The wire format and the Rust API can change.
Open an issue before you start a large change.

## License of contributions

SAC is licensed under the [MIT License](LICENSE). When you submit a
contribution, you agree to license it under the same terms.

## Report a problem

- Report a bug or request a function in a GitHub issue. Include the commit, the
  Cargo features, the command and a minimal input.
- Report a vulnerability in private. Obey [SECURITY.md](SECURITY.md). Do not
  open a public issue for a vulnerability.

## Build and test

You need a Rust toolchain. The minimum supported Rust version is 1.90.

SAC has no hosted continuous integration. The checks run on your computer, on
request. Run all of them before you open a pull request:

```sh
tools/ci.sh
```

The script runs each job, writes the output of each job to
`target/ci/<job>.log`, and prints a summary. It exits with a nonzero code if a
job fails. To see the jobs or to run only some of them:

```sh
tools/ci.sh --list
tools/ci.sh rust python
```

| Job | Checks |
| --- | --- |
| `rust` | Format check, clippy and tests with all features. |
| `core-only` | Clippy and tests with no default features. |
| `features` | Tests with each optional feature alone. |
| `msrv` | Build with the minimum supported Rust version. |
| `fuzz-build` | Build of the fuzz targets. Needs a nightly toolchain and `cargo-fuzz`. |
| `package` | Build and file list of the crate package. |
| `python` | The independent Python reader and the conformance vectors. |

If a tool is missing, the job fails and prints the command that installs it.

The script runs the tests of each test program on one thread. Some tests start
a child process, and a new child holds a copy of each open file lock for a
short time. If you run `cargo test` with parallel tests on a loaded computer, a
test that closes a store and opens it again can fail with `Busy`. Run that test
again, or set `RUST_TEST_THREADS=1`.
Say in your pull request which jobs you ran and on which operating system.

## Independent Python reader

The Python reader in `tools/` is a second implementation of the format. A
change to the wire format must keep the two implementations in agreement. The
`python` job needs the packages in `tools/sac1-requirements.txt`:

```sh
python3 -m venv .venv
.venv/bin/pip install -r tools/sac1-requirements.txt
PYTHON=.venv/bin/python tools/ci.sh python
```

## Conformance vectors

The byte fixtures in `conformance/` are shared by the Rust tests and the Python
tests. If you change the wire format on purpose:

1. Update the specification in `specs/`.
2. Run `python3 tools/generate_conformance.py` to make the fixtures again.
3. Run the Rust tests and the Python tests.
4. Add an entry to [CHANGELOG.md](CHANGELOG.md).

## Fuzz targets

The fuzz targets are in `fuzz/`. They need a nightly toolchain and
`cargo-fuzz`.

```sh
cargo install cargo-fuzz --locked
cargo +nightly fuzz build --dev
cargo +nightly fuzz run read_sac1
```

## Rules for a change

- Keep `unsafe` code out of the crate. The crate denies `unsafe_code`. The only
  exception is the small native syscall adapter.
- Give each operation finite limits. A reader must not trust a length, a count
  or an offset from a file before it checks the value.
- Keep verification results separate. Do not report profile validation,
  publisher trust or durability from an operation that did not check it.
- Update the specification, the CLI guide and the changelog in the same change
  as the code.
