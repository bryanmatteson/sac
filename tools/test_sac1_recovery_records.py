"""Recovery fault cases and independent native/Python wire interoperability."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import sac1_recover as sac

TOOL = Path(sac.__file__)


class RecoveryRecords(unittest.TestCase):
    def setUp(self):
        self.data = bytes((i * 71 + i // 17) % 251 for i in range(8193))
        self.records = io.BytesIO()
        sac.recovery_create(io.BytesIO(self.data), self.records, 50, 1024)
        self.records = self.records.getvalue()

    def repair(self, source, records):
        output = io.BytesIO()
        report = sac.recovery_repair(io.BytesIO(source), io.BytesIO(records), output)
        self.assertEqual(output.getvalue(), self.data)
        return report

    def test_data_and_parity_damage_with_duplicate_metadata(self):
        data, records = bytearray(self.data), bytearray(self.records)
        data[0] ^= 1
        data[2048] ^= 1
        # One stripe, nine data blocks and five parity blocks.
        records[128 + (9 + 5) * 32 + 32] ^= 1
        records[0] ^= 1
        records[128] ^= 1
        report = self.repair(data, records)
        self.assertEqual(report["repaired_data_shards"], 2)
        self.assertEqual(report["damaged_parity_shards"], 1)
        self.assertEqual(report["degraded_metadata_copies"], 1)

    def test_truncated_source_and_records(self):
        report = self.repair(self.data[:-1025], self.records)
        self.assertEqual(report["repaired_data_shards"], 2)
        report = self.repair(self.data, self.records[:128 + 14 * 32 + 32])
        self.assertEqual(report["damaged_parity_shards"], 5)

    def test_excessive_damage_conflicts_and_limits(self):
        with self.assertRaises(sac.SacError):
            self.repair(bytes(len(self.data)), self.records)
        records = bytearray(self.records)
        records[0] ^= 1
        records[-1] ^= 1
        with self.assertRaises(sac.SacError):
            self.repair(self.data, records)
        other = io.BytesIO()
        sac.recovery_create(io.BytesIO(self.data + b"x"), other, 50, 1024)
        with self.assertRaises(sac.SacError):
            self.repair(self.data, self.records[:-128] + other.getvalue()[-128:])
        for limits in [sac.Limits(source_bytes=1), sac.Limits(resident_memory=1), sac.Limits(entries=0)]:
            with self.assertRaises(sac.SacError):
                sac.recovery_inspect(io.BytesIO(self.records), limits)
        with self.assertRaises(sac.SacError):
            sac.recovery_repair(io.BytesIO(self.data), io.BytesIO(self.records), io.BytesIO(), sac.Limits(output_bytes=1))
        for percentage in [0, 101]:
            with self.assertRaises(sac.SacError):
                sac.recovery_create(io.BytesIO(self.data), io.BytesIO(), percentage)

    def test_standalone_cli_no_clobber_and_failed_output_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, records, repaired = root / "input", root / "input.rr", root / "repaired"
            source.write_bytes(self.data)
            def run(*args):
                return subprocess.run([sys.executable, str(TOOL), "recovery", *map(str,args)], capture_output=True)
            result = run("create",source,records,"--block-size",1024,"--redundancy-percent",50)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(run("inspect",records).returncode,0)
            source.write_bytes(self.data[:-1])
            result = run("repair",source,records,repaired)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(repaired.read_bytes(),self.data)
            self.assertNotEqual(run("repair",source,records,repaired).returncode,0)
            source.write_bytes(bytes(len(self.data)))
            failed = root / "failed"
            self.assertNotEqual(run("repair",source,records,failed).returncode,0)
            self.assertFalse(failed.exists())
            self.assertNotEqual(run("repair",source,records).returncode,0)

    @unittest.skipUnless(os.environ.get("SAC_TEST_BINARY"), "set SAC_TEST_BINARY for native interoperability")
    def test_embedded_profile_independent_repair_without_core_admission(self):
        native = os.environ["SAC_TEST_BINARY"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, archive, protected = root / "input.bin", root / "input.sac", root / "protected.sac"
            source.write_bytes(self.data)
            def run(*args):
                result = subprocess.run(list(map(str,args)), capture_output=True)
                self.assertEqual(result.returncode,0,result.stderr)
                return result
            run(native,"pack",source,archive)
            run(native,"recovery","embed",archive,protected,"--redundancy-percent",100,"--block-size",1024)
            # The profile is readable without teaching ordinary readers its semantics.
            run(sys.executable,TOOL,"verify",protected)
            with sac.Archive(protected) as current:
                self.assertIn("sac.recovery.v1",[p[0] for p in current.snapshot.body[1]])
            original = protected.read_bytes()
            damaged = bytearray(original)
            beacon = damaged.find(b"SAC1RSEG")
            self.assertGreaterEqual(beacon,0)
            physical = int.from_bytes(damaged[beacon+84:beacon+92],"little")
            # Lose one discovery copy and one parity byte; its frame hash is now bad.
            damaged[beacon] ^= 1
            record_header = sac._recovery_decode_header(bytes(damaged[physical:physical+128]))
            k,m = sac._recovery_geometry(record_header,0)
            damaged[physical+128+(k+m)*32+32] ^= 1
            damaged[:128] = bytes(128)
            damaged[-128:] = bytes(128)
            protected.write_bytes(damaged)
            info = run(sys.executable,TOOL,"recovery","inspect",protected,"--embedded")
            snapshot = json.loads(info.stdout)["protected_snapshot"]
            python_output, rust_output = root / "python.sac", root / "rust.sac"
            run(sys.executable,TOOL,"recovery","repair",protected,python_output,"--embedded")
            run(native,"recovery","repair",protected,rust_output,"--embedded")
            self.assertEqual(python_output.read_bytes(),rust_output.read_bytes())
            run(sys.executable,TOOL,"verify",python_output)
            observed = json.loads(run(native,"inspect",rust_output).stdout)["snapshot"]
            self.assertEqual(observed,snapshot)
            extracted = root / "extracted"
            run(sys.executable,TOOL,"extract",python_output,extracted)
            self.assertIn(self.data,[p.read_bytes() for p in (extracted / "content").rglob("*") if p.is_file()])
            self.assertEqual(protected.read_bytes(),damaged)

    @unittest.skipUnless(os.environ.get("SAC_TEST_BINARY"), "set SAC_TEST_BINARY for native interoperability")
    def test_rust_python_interoperability_on_real_archive_and_recovery(self):
        native = os.environ["SAC_TEST_BINARY"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, archive = root / "input.bin", root / "archive.sac"
            # Deterministic incompressible bytes exercise several code stripes.
            state, data = 0x12345678, bytearray()
            for _ in range(210000):
                state ^= (state << 13) & 0xffffffff
                state ^= state >> 17
                state ^= (state << 5) & 0xffffffff
                data.append(state & 255)
            source.write_bytes(data)
            def rust(*args):
                result = subprocess.run([native,*map(str,args)],capture_output=True)
                self.assertEqual(result.returncode,0,result.stderr)
                return result
            def python(*args):
                result = subprocess.run([sys.executable,str(TOOL),*map(str,args)],capture_output=True)
                self.assertEqual(result.returncode,0,result.stderr)
                return result
            rust("pack",source,archive)
            original = archive.read_bytes()
            rust_records, py_records = root / "rust.rr", root / "python.rr"
            rust("recovery","create",archive,rust_records,"--block-size",1024,"--redundancy-percent",20)
            python("recovery","create",archive,py_records,"--block-size",1024,"--redundancy-percent",20)
            self.assertEqual(rust_records.read_bytes(),py_records.read_bytes())
            damaged = bytearray(original)
            damaged[:128] = bytes(128)
            damaged[13 * 1024] ^= 0x99
            del damaged[-81:]
            archive.write_bytes(damaged)
            rust_output, python_output = root / "rust.sac", root / "python.sac"
            rust("recovery","repair",archive,py_records,rust_output)
            report = python("recovery","repair",archive,rust_records,python_output)
            self.assertGreaterEqual(json.loads(report.stdout)["repaired_data_shards"],3)
            self.assertEqual(rust_output.read_bytes(),original)
            self.assertEqual(python_output.read_bytes(),original)
            rust("verify",python_output)
            python("verify",rust_output)
            extracted = root / "extracted"
            rust("unpack",python_output,extracted)
            self.assertEqual((extracted / "content/input.bin").read_bytes(),data)
            self.assertEqual(archive.read_bytes(),damaged)


if __name__ == "__main__":
    unittest.main()
