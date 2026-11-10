"""Independent byte fixtures and actual offline CLI regressions for SAC1."""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import blake3
import zstandard

TOOL = Path(__file__).with_name("sac1_recover.py")
sys.path.insert(0, str(TOOL.parent))
import sac1_recover as sac


def enc(value):
    """Fixture encoder, independent of the reader's encoder."""
    def prefix(major, n):
        if n < 24:
            return bytes([major * 32 + n])
        for code, width in [(24, 1), (25, 2), (26, 4), (27, 8)]:
            if n < 2 ** (width * 8):
                return bytes([major * 32 + code]) + n.to_bytes(width, "big")
    if value is None:
        return b"\xf6"
    if type(value) is bool:
        return b"\xf5" if value else b"\xf4"
    if type(value) is int:
        return prefix(0, value) if value >= 0 else prefix(1, -1 - value)
    if type(value) in (str, bytes):
        data = value.encode() if type(value) is str else value
        return prefix(3 if type(value) is str else 2, len(data)) + data
    if type(value) is list:
        return prefix(4, len(value)) + b"".join(map(enc, value))
    if type(value) is dict or isinstance(value, sac.CborMap):
        entries = sorted((enc(k), enc(v)) for k, v in (value.items() if type(value) is dict else value))
        return prefix(5, len(entries)) + b"".join(k + v for k, v in entries)
    raise TypeError(value)


def h(domain, value):
    return blake3.blake3(domain.encode() + b"\0" + value).digest()


def crc(data):
    remainder = 0xffffffff
    for value in data:
        remainder ^= value
        for bit in range(8):
            remainder = (remainder >> 1) ^ (0x82f63b78 if remainder & 1 else 0)
    return remainder ^ 0xffffffff


class Builder:
    def __init__(self, live=False):
        self.live = live
        self.pre = sac.MAGIC + bytes(4) + bytes([live]) + bytes(7) + (b"I" * 16 if live else bytes(16)) + bytes(64)
        self.pre += h("SAC1/preamble", self.pre)
        self.data = bytearray(self.pre + (bytes(12288 - 128) if live else b""))

    def add(self, kind, value, children=(), compressed=False, body_bytes=None, schema=1):
        payload = value if kind == 7 else enc(value)
        if body_bytes is not None:
            payload = body_bytes
        canonical = struct.pack("<HHI", kind, schema, len(children)) + b"".join(child[2] for child in children) + payload
        oid = h("SAC1/object", canonical)
        encoded = zstandard.ZstdCompressor(write_content_size=True).compress(canonical) if compressed else canonical
        if compressed == "extra":
            encoded += zstandard.ZstdCompressor().compress(b"extra")
        header = bytearray(struct.pack("<4sBBHII32sII", b"SO1\0", int(bool(compressed)), 1, len(children), len(encoded), len(canonical), oid, 0, 0))
        struct.pack_into("<I", header, 48, crc(header))
        frame = header + encoded + b"".join(struct.pack("<QI", child[0], child[1]) for child in children)
        frame += bytes(-len(frame) % 8)
        locator = len(self.data), len(frame), oid
        self.data += frame
        return locator

    def publish(self, directory, profiles=(), generation=1, features=(), attestations=None):
        roots = [directory] + [item[2] for item in profiles]
        snapshot = self.add(2, [0, [[name, version, i + 1] for i, (name, version, _) in enumerate(profiles)], list(features)], roots)
        if attestations is None:
            commit = self.add(1, [0, None, None], [snapshot])
        else:
            catalogue = self.add(9, attestations(snapshot[2]))
            commit = self.add(1, [0, 1, None], [snapshot, catalogue])
        offset, end = len(self.data), len(self.data) + 160
        trailer = b"SAC1END\0" + self.pre[96:] + struct.pack("<QQQQ", generation, end, commit[0], commit[1]) + commit[2] + bytes(24)
        trailer += h("SAC1/trailer", trailer)
        self.data += trailer
        if self.live:
            slot = b"SAC1SLOT" + self.pre[96:] + struct.pack("<QQ", generation, offset) + trailer[128:] + bytes(3976)
            slot += h("SAC1/slot", slot)
            start = 4096 + (generation % 2) * 4096
            self.data[start:start + 4096] = slot
        return snapshot


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, builder, name="fixture.sac"):
        path = self.root / name
        path.write_bytes(builder.data)
        return path

    def tiny(self, live=False, value=b"hello"):
        b = Builder(live)
        directory = b.add(3, [[b"hello.txt", 0, {}, [len(value), 0, value]]])
        snapshot = b.publish(directory)
        return b, snapshot

    def error(self, path, category=None):
        with self.assertRaises(sac.SacError) as caught:
            with sac.Archive(path) as archive:
                archive.verify()
        if category:
            self.assertEqual(caught.exception.category, category)
        return caught.exception

    def test_public_conformance_vectors(self):
        root = TOOL.parent.parent / "conformance"
        manifest = json.loads((root / "manifest.json").read_text())
        for vector in manifest["vectors"]:
            with self.subTest(vector=vector["file"]):
                path = root / vector["file"]
                if not vector["valid"]:
                    error = self.error(path)
                    if vector.get("error_class") == "unsupported":
                        self.assertIn(error.category, ("unsupported_schema", "unsupported_capability"))
                    continue
                with sac.Archive(path) as archive:
                    self.assertEqual(archive.verify()["core"], "validated")
                    self.assertEqual(archive.snapshot.oid.hex(), vector["snapshot"])
                    logical, owner, entry = next(archive.entries())
                    self.assertEqual(logical, [b"hello.txt"])
                    self.assertEqual(b"".join(archive.chunks(owner, entry)).hex(), vector["content_hex"])

    def test_deterministic_cbor_vectors(self):
        self.assertEqual(sac.cbor_decode(enc({"z": [None, True, False, -1, 2**64 - 1], "a": b"raw"})),
                         {"z": [None, True, False, -1, 2**64 - 1], "a": b"raw"})
        for malformed in [b"\x18\x01", b"\x9f\xff", b"\x81", b"\x9b" + bytes([255]) * 8,
                          b"\xa2\x61a\x00\x61a\x01", b"\xa2\x61b\x00\x61a\x01",
                          b"\x61\xff", b"\xf9\0\0", b"\xc0\0", b"\0\0", b"\xf7",
                          b"\xa1\xf5\x00", b"\x81" * 65 + b"\x00"]:
            with self.subTest(malformed=malformed[:10]), self.assertRaises(sac.SacError):
                sac.cbor_decode(malformed)

    def test_four_byte_magic_and_reserved_preamble(self):
        for live in (False, True):
            builder, _ = self.tiny(live)
            self.assertEqual(builder.pre[:4], b"SAC1")
            self.assertEqual(builder.pre[4:8], bytes(4))
            self.assertEqual(len(builder.pre), 128)
            for reserved in range(4, 8):
                with self.subTest(live=live, reserved=reserved):
                    original = bytes(builder.data)
                    builder.data[reserved] = 1
                    builder.data[96:128] = h("SAC1/preamble", builder.data[:96])
                    self.assertIn("preamble reserved", str(self.error(self.write(builder))))
                    builder.data = bytearray(original)

    def test_live_and_sealed(self):
        for live in (False, True):
            b, snapshot = self.tiny(live)
            with sac.Archive(self.write(b)) as archive:
                self.assertEqual(archive.verify()["core"], "validated")
                self.assertEqual(archive.snapshot.oid, snapshot[2])
                path, owner, entry = next(archive.entries())
                self.assertEqual(path, [b"hello.txt"])
                self.assertEqual(b"".join(archive.chunks(owner, entry)), b"hello")

    def test_compressed_and_sparse_extents(self):
        b = Builder()
        payload = b.add(7, b"a" * 10000, compressed=True)
        extent = b.add(5, [[10000, 0], [7, None]], [payload])
        content = b"a" * 10000 + bytes(7)
        directory = b.add(3, [[b"x", 0, {"byte_digest": blake3.blake3(content).digest()}, [10007, 1, 0]]], [extent])
        b.publish(directory)
        with sac.Archive(self.write(b)) as archive:
            archive.verify()
            _, owner, entry = next(archive.entries())
            self.assertEqual(b"".join(archive.chunks(owner, entry)), content)

    def test_extra_sealed_byte_and_truncated_prefixes(self):
        b, _ = self.tiny()
        original = bytes(b.data)
        for length in [0, 127, 128, len(original) - 1]:
            b.data = bytearray(original[:length])
            self.error(self.write(b))
        b.data = bytearray(original + b"x")
        self.error(self.write(b))

    def test_crc_and_hash_tampering(self):
        b, _ = self.tiny()
        b.data[128 + 48] ^= 1
        self.error(self.write(b), "integrity_failure")
        b, _ = self.tiny()
        b.data[128 + 56 + 10] ^= 1
        self.error(self.write(b), "integrity_failure")

    def test_selected_corrupt_live_slot_never_falls_back(self):
        b, _ = self.tiny(True)
        second = b.add(3, [[b"new", 0, {}, [1, 0, b"n"]]])
        b.publish(second, generation=2)
        b.data[second[0] + 56 + 10] ^= 1
        self.error(self.write(b), "integrity_failure")

    def test_damaged_slot_is_degraded(self):
        b, _ = self.tiny(True)
        b.data[4096] = 1
        with sac.Archive(self.write(b)) as archive:
            self.assertEqual(archive.verify()["root"], "admitted_degraded")

    def test_checksum_valid_bad_slot_header_fails(self):
        b, _ = self.tiny(True)
        b.data[8192 + 88] = 1
        b.data[8192 + 4064:8192 + 4096] = h("SAC1/slot", b.data[8192:8192 + 4064])
        self.error(self.write(b))

    def test_conditional_fences_do_not_authorize_full_verify(self):
        b = Builder()
        left = b.add(3, [[b"z", 0, {}, [0, 0, b""]]])
        right = b.add(3, [[b"zz", 0, {}, [0, 0, b""]]])
        branch = b.add(4, [1, [[b"a", 0], [b"zz", 1]]], [left, right])
        b.publish(branch)
        self.error(self.write(b))

    def test_extent_wrong_length_and_wrong_kind(self):
        for wrong_kind in (False, True):
            b = Builder()
            child = b.add(3, []) if wrong_kind else b.add(7, b"x")
            extent = b.add(5, [[2, 0]], [child])
            directory = b.add(3, [[b"x", 0, {}, [2, 1, 0]]], [extent])
            b.publish(directory)
            self.error(self.write(b))

    def test_extra_zstandard_stream_rejected(self):
        b = Builder()
        child = b.add(7, b"x" * 10000, compressed="extra")
        extent = b.add(5, [[10000, 0]], [child])
        directory = b.add(3, [[b"x", 0, {}, [10000, 1, 0]]], [extent])
        b.publish(directory)
        self.error(self.write(b))

    def test_good_canonical_copy_never_authorizes_bad_locators(self):
        b = Builder()
        good = b.add(7, b"x")
        wrong = b.add(7, b"y")
        first = b.add(5, [[1, 0]], [good])
        second = b.add(5, [[1, 0]], [good])
        self.assertEqual(first[2], second[2])
        stored = struct.unpack_from("<I", b.data, second[0] + 8)[0]
        struct.pack_into("<QI", b.data, second[0] + 56 + stored, wrong[0], wrong[1])
        directory = b.add(3, [[b"a", 0, {}, [1, 1, 0]], [b"b", 0, {}, [1, 1, 1]]], [first, second])
        b.publish(directory)
        self.error(self.write(b), "integrity_failure")

    def test_unused_child_and_wrong_inline_type(self):
        for value in ([[b"x", 0, {}, [1, 0, "x"]]], []):
            b = Builder()
            child = b.add(7, b"x")
            directory = b.add(3, value, [child])
            b.publish(directory)
            self.error(self.write(b))

    def test_interior_locator_rejected_and_salvage_reframes(self):
        inner = Builder()
        leaf = inner.add(3, [[b"x", 0, {}, [1, 0, b"v"]]])
        inner_frame = bytes(inner.data[128:])
        b = Builder()
        outer = b.add(7, bytes(8) + inner_frame)
        inner_offset = outer[0] + 56 + 8 + 8
        directory = (inner_offset, leaf[1], leaf[2])
        snapshot = b.publish(directory)
        source = self.write(b)
        self.error(source)
        destination = self.root / "repaired.sac"
        result = sac.salvage(source, destination, snapshot[2])
        self.assertEqual(result["snapshot"], snapshot[2].hex())
        self.assertEqual(result["original_failure"]["physical"], "inventory_scanned")
        with sac.Archive(destination) as archive:
            self.assertEqual(archive.verify()["physical"], "validated")

    def test_orphan_without_authority_is_not_salvaged(self):
        b, _ = self.tiny(True)
        b.data[8192:12288] = bytes(4096)
        with self.assertRaises(sac.SacError):
            sac.salvage(self.write(b), self.root / "out.sac")
        self.assertFalse((self.root / "out.sac").exists())

    def test_broken_locator_is_repaired_from_expected_ids(self):
        b, snapshot = self.tiny()
        snapshot_offset, span, _ = snapshot
        stored = struct.unpack_from("<I", b.data, snapshot_offset + 8)[0]
        struct.pack_into("<QI", b.data, snapshot_offset + 56 + stored, 0, 64)
        source = self.write(b)
        self.error(source)
        result = sac.salvage(source, self.root / "out.sac", snapshot[2])
        self.assertEqual(result["snapshot"], snapshot[2].hex())

    def test_extraction_maps_names_and_never_instantiates_links(self):
        b = Builder()
        directory = b.add(3, [[b"A", 0, {}, [1, 0, b"a"]], [b"a", 0, {}, [1, 0, b"b"]],
                              [b"link", 2, {}, b"../../outside"], [b"sac-evil", 0, {}, [0, 0, b""]],
                              [b"\xff", 0, {}, [0, 0, b""]]])
        b.publish(directory)
        output = self.root / "extracted"
        with sac.Archive(self.write(b)) as archive:
            result = archive.extract(output)
            self.assertEqual(result["entries"], 5)
        files = list((output / "content").iterdir())
        self.assertEqual(len(files), 4)
        self.assertTrue(all(path.name.startswith("sac-") and not path.is_symlink() for path in files))
        report = sac.cbor_decode((output / "report.cbor").read_bytes())
        self.assertEqual(report[0][:2], ["sac.extract", 1])
        self.assertEqual(report[1][2][-1], b"../../outside")
        with sac.Archive(self.write(b)) as archive, self.assertRaises(sac.SacError):
            archive.extract(output)

    def test_sparse_output_limit_and_digest_failure_publish_nothing(self):
        b = Builder()
        extent = b.add(5, [[10000000, None]])
        directory = b.add(3, [[b"hole", 0, {}, [10000000, 1, 0]]], [extent])
        b.publish(directory)
        with sac.Archive(self.write(b), sac.Limits(output_bytes=100)) as archive, self.assertRaises(sac.SacError):
            archive.extract(self.root / "limited")
        self.assertFalse((self.root / "limited").exists())
        b = Builder()
        directory = b.add(3, [[b"x", 0, {"byte_digest": bytes(32)}, [1, 0, b"x"]]])
        b.publish(directory)
        with sac.Archive(self.write(b)) as archive, self.assertRaises(sac.SacError):
            archive.extract(self.root / "wrongdigest")
        self.assertFalse((self.root / "wrongdigest").exists())

    def test_unknown_required_capability_and_unknown_profile_scope(self):
        b = Builder()
        directory = b.add(3, [])
        b.publish(directory, features=[[None, "unknown.test", 1, True]])
        self.error(self.write(b), "unsupported_capability")

    def test_inline_48k_and_directory_128k_boundaries(self):
        b = Builder()
        value = b"a" * 49152
        directory = b.add(3, [[b"a", 0, {}, [len(value), 0, value]], [b"b", 0, {}, [len(value), 0, value]]])
        b.publish(directory)
        with sac.Archive(self.write(b)) as archive:
            self.assertEqual(archive.verify()["core"], "validated")
        b = Builder()
        directory = b.add(3, [[b"a", 0, {}, [49153, 0, b"a" * 49153]]])
        b.publish(directory)
        self.error(self.write(b))

        b = Builder()
        directory = b.add(3, [[bytes([97 + i]), 0, {}, [len(value), 0, value]] for i in range(3)])
        b.publish(directory)
        self.error(self.write(b))

    def test_optional_attestations_report_per_entry_without_blocking_recovery(self):
        def cose(snapshot, headers=None, purpose="archive", signature=None):
            if headers is None:
                headers = sac.CborMap([(1, -19), (4, b"key")])
            return b"\xd2" + enc([enc(headers), {}, enc(["sac.snapshot.v1", purpose, snapshot]), bytes(64) if signature is None else signature])
        b = Builder()
        directory = b.add(3, [[b"hello", 0, {}, [5, 0, b"hello"]]])
        b.publish(directory, attestations=lambda snapshot: [cose(snapshot), b"not COSE", cose(bytes(32)),
            cose(snapshot, sac.CborMap([(1, -8)])), cose(snapshot, sac.CborMap([(1, -19), (4, None)])),
            cose(snapshot, purpose=""), cose(snapshot, signature=b"short")])
        with sac.Archive(self.write(b)) as archive:
            state = archive.verify()
            self.assertEqual(state["attestations"], {"invalid": 5, "unsupported": 1, "valid_structure": 1})
            outcomes = list(archive.attestation_outcomes())
            self.assertEqual(len(outcomes), 7)
            self.assertEqual(outcomes[0]["signature"], "unchecked")
            self.assertEqual(outcomes[0]["trust"], "unaccepted")
            archive.extract(self.root / "with-invalid-optional-trust")
        self.assertEqual(sac.parse_attestation(cose(b"s" * 32))["snapshot"], (b"s" * 32).hex())

    def test_salvage_charges_output_limit_and_publishes_nothing(self):
        b, _ = self.tiny()
        source = self.write(b)
        output = self.root / "limited-salvage.sac"
        with self.assertRaises(sac.SacError) as caught:
            sac.salvage(source, output, limits=sac.Limits(output_bytes=1))
        self.assertEqual(caught.exception.dimension, "output_bytes")
        self.assertFalse(output.exists())

    def test_frame_memory_limit_precedes_large_source_read(self):
        b = Builder()
        chunk = b.add(7, b"x" * sac.MIB)
        extent = b.add(5, [[sac.MIB, 0]], [chunk])
        directory = b.add(3, [[b"large", 0, {}, [sac.MIB, 1, 0]]], [extent])
        b.publish(directory)
        with sac.Archive(self.write(b), sac.Limits(resident_memory=128 * 1024)) as archive:
            original = archive.read
            def bounded_read(offset, length):
                self.assertLessEqual(length, 128 * 1024)
                return original(offset, length)
            with mock.patch.object(archive, "read", side_effect=bounded_read), self.assertRaises(sac.SacError) as caught:
                archive.verify()
            self.assertEqual(caught.exception.dimension, "resident_memory")

    def test_unknown_object_cannot_replace_core_directory(self):
        b = Builder()
        node = b.add(256, None, body_bytes=b"opaque")
        b.publish(node)
        self.error(self.write(b), "unsupported_schema")

    def test_actual_cli_offline_and_error_exit(self):
        b, _ = self.tiny(True)
        source = self.write(b)
        hook = self.root / "sitecustomize.py"
        hook.write_text("import sys\ndef audit(event,args):\n if event.startswith('socket.'):\n  raise RuntimeError('network forbidden in offline test')\nsys.addaudithook(audit)\n")
        env = dict(os.environ, PYTHONPATH=str(self.root), HTTP_PROXY="http://127.0.0.1:1", HTTPS_PROXY="http://127.0.0.1:1")
        for command, tail in [("verify", []), ("attestations", []), ("list", []), ("extract", [str(self.root / "cli-output")]),
                              ("salvage", [str(self.root / "cli-repaired.sac")])]:
            result = subprocess.run([sys.executable, str(TOOL), command, str(source), *tail], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("snapshot", json.loads(result.stdout.splitlines()[-1]))
        result = subprocess.run([sys.executable, str(TOOL), "verify", str(source), "--max-source-bytes", "32"],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stderr)["dimension"], "source_bytes")

    def metadata_fixture(self, value=None, *, key="org.example.custom", version=1, payload=b"\x81\x00"):
        builder = Builder()
        data = enc({"future": [b"\xff\x00", None, True, 2**64 - 1, -(2**64)]}) if value is None else value
        directory = builder.add(3, [[key.encode(), 0, {}, [len(data), 0, data]]])
        root = builder.add(8, ["sac.metadata.v1", "root", version, payload], [directory])
        files = builder.add(3, [])
        opaque = builder.add(8, ["org.example.app", "root", 7, b"future opaque payload"])
        builder.publish(files, [("org.example.app", 7, opaque), ("sac.metadata.v1", version, root)])
        return self.write(builder), data

    def test_generic_metadata_preserves_binary_and_unknown_fields(self):
        source, expected = self.metadata_fixture()
        with sac.Archive(source) as archive:
            self.assertEqual(archive.metadata_get("org.example.custom"), expected)
            self.assertIsNone(archive.metadata_get("org.example.missing"))
            state = archive.verify()
            self.assertEqual(state["profiles"]["sac.metadata.v1"], "validated")
            self.assertEqual(state["profiles"]["org.example.app"], "semantics_unverified")
        result = subprocess.run([sys.executable, str(TOOL), "metadata", str(source), "--key", "org.example.custom"], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, expected)
        output = self.root / "metadata-export"
        with sac.Archive(source) as archive:
            archive.recover_metadata(output)
        self.assertTrue(any(p.read_bytes() == expected for p in (output / "content").rglob("*") if p.is_file()))
        with sac.Archive(source) as archive:
            with self.assertRaises(sac.SacError):
                archive.recover_metadata(output)

    def test_generic_metadata_rejects_malformed_values_keys_and_unknown_semantics(self):
        for value, key, version, payload in [(b"\x18\x00", "org.example.custom", 1, b"\x81\x00"),
                                               (b"\x00", "plain", 1, b"\x81\x00"),
                                               (b"\x00", "org.example.custom", 1, b"\x80")]:
            with self.subTest(value=value, key=key, payload=payload):
                source, _ = self.metadata_fixture(value, key=key, version=version, payload=payload)
                with sac.Archive(source) as archive:
                    with self.assertRaises(sac.SacError):
                        archive.verify()
        source, _ = self.metadata_fixture(version=2)
        with sac.Archive(source) as archive:
            self.assertEqual(archive.verify()["profiles"]["sac.metadata.v1"], "semantics_unsupported")
            with self.assertRaises(sac.SacError):
                archive.metadata_get("org.example.custom")

    @unittest.skipUnless(os.environ.get("SAC_TEST_BINARY"), "set SAC_TEST_BINARY for native CLI interoperability")
    def test_generic_metadata_native_cli_interoperability(self):
        native = os.environ["SAC_TEST_BINARY"]
        source = self.root / "original.bin"
        source.write_bytes(b"original resource bytes")
        live = self.root / "native.sac"
        def run(*args):
            result = subprocess.run([native, *map(str, args)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout
        run("pack", source, live, "--live")
        expected = enc({"unknown": [b"\x00\xff", 2**64 - 1], "nested": {"future": True}})
        value = self.root / "value.cbor"
        value.write_bytes(expected)
        run("metadata", "set", live, "org.example.custom", value)
        value.write_bytes(enc(b"z" * 100_000))
        run("metadata", "set", live, "org.example.large", value)
        streamed = subprocess.run([native, "metadata", "set", str(live), "org.example.stdin", "-"], input=enc("streamed value"), capture_output=True)
        self.assertEqual(streamed.returncode, 0, streamed.stderr)
        self.assertEqual(run("metadata", "get", live, "org.example.stdin"), enc("streamed value"))
        protected = Builder(live=True)
        protected.publish(protected.add(3, []), attestations=lambda _: [b"opaque attestation"])
        protected_path = self.write(protected, "attested.sac")
        before = protected_path.read_bytes()
        refused = subprocess.run([native, "metadata", "set", str(protected_path), "org.example.custom", str(value)], capture_output=True)
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(protected_path.read_bytes(), before)
        sealed = self.root / "sealed.sac"
        run("compact", live, sealed)
        native_json = json.loads(run("metadata", "get", sealed, "org.example.custom", "--json"))
        python = subprocess.run([sys.executable, str(TOOL), "metadata", str(sealed), "--key", "org.example.custom", "--json"], capture_output=True)
        self.assertEqual(python.returncode, 0, python.stderr)
        self.assertEqual(json.loads(python.stdout), native_json)
        with sac.Archive(sealed) as archive:
            self.assertEqual(archive.metadata_get("org.example.custom"), expected)
            self.assertEqual(sac.cbor_decode(archive.metadata_get("org.example.large")), b"z" * 100_000)
            self.assertEqual(archive.verify()["profiles"]["sac.metadata.v1"], "validated")
        recovered = self.root / "independent-export"
        export = subprocess.run([sys.executable, str(TOOL), "metadata", str(sealed), str(recovered)], capture_output=True)
        self.assertEqual(export.returncode, 0, export.stderr)
        self.assertTrue(any(p.read_bytes() == expected for p in (recovered / "content").rglob("*") if p.is_file()))


if __name__ == "__main__":
    unittest.main()
