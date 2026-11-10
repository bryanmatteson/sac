#!/usr/bin/env python3
"""Regenerate public SAC1 vectors with the independent Python fixture writer."""

import argparse
import hashlib
import json
from pathlib import Path

from test_sac1_recover import Builder, h


def vectors():
    cases = {}
    for name, live, compressed in (
        ("sealed", False, False),
        ("live", True, False),
        ("compressed", False, True),
    ):
        builder = Builder(live)
        content = b"hello SAC1\n" if not compressed else b"Z" * 1024
        if compressed:
            data = builder.add(7, content, compressed=True)
            extent = builder.add(5, [[len(content), 0]], [data])
            directory = builder.add(3, [[b"hello.txt", 0, {}, [len(content), 1, 0]]], [extent])
        else:
            directory = builder.add(3, [[b"hello.txt", 0, {}, [len(content), 0, content]]])
        snapshot = builder.publish(directory)
        cases[name] = (bytes(builder.data), True, snapshot[2].hex(), content.hex())
    sealed = cases["sealed"][0]
    cases["trailing-byte"] = (sealed + b"\0", False, None, None)
    corrupt = bytearray(sealed)
    corrupt[-1] ^= 1
    cases["trailer-checksum"] = (bytes(corrupt), False, None, None)
    cases["superseded-prerelease"] = (b"SAC2\r\n\x1a\n" + sealed[8:], False, None, None)
    old_signature = bytearray(sealed)
    old_signature[4:8] = b"\r\n\x1a\n"
    old_signature[96:128] = h("SAC1/preamble", old_signature[:96])
    cases["superseded-eight-byte-magic"] = (bytes(old_signature), False, None, None)
    cases["discarded-section-draft"] = (b"SAC1" + (1).to_bytes(4, "little")
                                         + (128).to_bytes(4, "little") + bytes(116), False, None, None)
    reserved = bytearray(sealed)
    reserved[6] = 1
    reserved[96:128] = h("SAC1/preamble", reserved[:96])
    cases["nonzero-preamble-reserved"] = (bytes(reserved), False, None, None)
    cases["truncated-magic-only"] = (b"SAC1", False, None, None)
    # Profiles preserve unknown closures, but cannot redefine a reserved core kind.
    for name, kind, schema, features, valid in (
        ("opaque-profile", 42000, 1, (), True),
        ("reserved-core-schema-in-profile", 7, 2, (), False),
        ("required-core-capability", 42000, 1, ((None, "example.unknown", 1, True),), False),
        ("optional-core-capability", 42000, 1, ((None, "example.unknown", 1, False),), True),
        ("required-profile-capability", 42000, 1, (("example.profile", "example.unknown", 1, True),), True),
    ):
        builder = Builder()
        directory = builder.add(3, [[b"hello.txt", 0, {}, [11, 0, b"hello SAC1\n"]]])
        opaque = builder.add(kind, b"opaque", body_bytes=b"opaque", schema=schema)
        profile = builder.add(8, ["example.profile", "root", 1, b""], [opaque])
        snapshot = builder.publish(directory, [("example.profile", 1, profile)], features=[list(f) for f in features])
        cases[name] = (bytes(builder.data), valid, snapshot[2].hex() if valid else None, b"hello SAC1\n".hex() if valid else None)
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent / "conformance"
    outputs = {}
    rows = []
    for name, (data, valid, snapshot, content) in sorted(vectors().items()):
        relative = f"{'valid' if valid else 'invalid'}/{name}.sac"
        outputs[relative] = data
        rows.append({"file": relative, "valid": valid, "sha256": hashlib.sha256(data).hexdigest(),
                     "snapshot": snapshot, "content_hex": content,
                     "error_class": "unsupported" if name in ("reserved-core-schema-in-profile", "required-core-capability") else None})
    outputs["manifest.json"] = (json.dumps({"format": "SAC1", "vectors": rows}, indent=2) + "\n").encode()
    if args.check:
        mismatches = [name for name, data in outputs.items()
                      if not (root / name).is_file() or (root / name).read_bytes() != data]
        if mismatches:
            raise SystemExit("stale conformance vectors: " + ", ".join(mismatches))
        print(f"SAC1 conformance: {len(rows)} deterministic vectors match")
    else:
        for name, data in outputs.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        print(f"Wrote {len(rows)} SAC1 vectors")


if __name__ == "__main__":
    main()
