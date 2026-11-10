# SAC1 conformance vectors

This corpus describes the current immutable object-graph format. Earlier
prerelease section-format specifications and corpora have been replaced.

`manifest.json` binds each byte fixture's SHA-256, expected acceptance, selected
snapshot and exact `hello.txt` content. The independent Python fixture writer
produces sealed, live and compressed archives. Negative vectors cover trailing
bytes, corrupt trailer checksums, nonzero preamble reserved bytes with a valid
digest, a truncated magic-only file, and discarded prerelease signatures/layouts
including the former eight-byte signature. Valid files use exactly four ASCII
magic bytes `SAC1` followed by four reserved zero bytes.
Extension vectors cover opaque profile closures, unsupported schemas of known
core kinds beneath a profile, unknown optional core capabilities, and required
core versus profile capabilities. Generic core recovery does not claim profile
semantic validation.

The Rust `conformance` integration test and Python recovery tests consume these
same bytes. Core-only Rust builds exercise the mandatory pure-Rust Zstandard
decoder. This corpus checks admission, resource/core verification and exact
content; application-profile semantics, publisher trust and live durability
coordination remain separate. The owning Rust/Python suites additionally cover
faults, quotas, locator repair, profiles, extraction and publication interleavings.

```sh
python3 -m pip install -r tools/sac1-requirements.txt
python3 tools/generate_conformance.py --check
cargo +1.97.1 test --test conformance --all-features
cargo +1.97.1 test --test conformance --no-default-features
python3 tools/test_sac1_recover.py
```

Regenerate intentionally changed bytes with `python3 tools/generate_conformance.py`.
