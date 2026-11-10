#!/usr/bin/env python3
"""Report small-archive crossovers using an explicit frozen production CLI.

Run through the workspace artifact-retention runner. These are reporting cases,
not many-file ZIP parity gates. The metadata producer is an owning Rust test of
public ArchiveBuilder APIs; the frozen CLI consumes and compacts its result.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import time
import zipfile
import zlib


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def payload(kind, ordinal, size):
    if kind == 'text':
        text = f'function_{ordinal:08}: preserve names, comments, and exact input bytes.\n'.encode()
        return (text * ((size + len(text) - 1) // len(text)))[:size]
    ordinal = 0 if kind == 'repeated' else ordinal
    return hashlib.shake_256(f'sac1-crossover-fixed-v1/{ordinal}/{size}'.encode()).digest(size)


def zip_control(path, files, extra=b''):
    with zipfile.ZipFile(path, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name, data in files:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            info._compresslevel = 6
            info.extra = extra
            archive.writestr(info, data)
    return path.stat().st_size


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', type=Path, required=True)
    parser.add_argument('--metadata-producer', type=Path, required=True)
    parser.add_argument('--profile', choices=['release', 'test/debug'], default='test/debug', help='profile used to compile both supplied executables')
    parser.add_argument('--metadata-only', action='store_true', help='run metadata follow-on without repeating completed crossovers')
    args = parser.parse_args()
    output = Path.cwd()
    cli = output / 'sac-cli'
    producer = output / 'metadata-producer'
    shutil.copy2(args.cli, cli)
    shutil.copy2(args.metadata_producer, producer)
    cli.chmod(0o500)
    producer.chmod(0o500)
    provenance = {'cli_sha256': digest(cli), 'metadata_producer_sha256': digest(producer),
                  'cli_source': str(args.cli.resolve()), 'producer_source': str(args.metadata_producer.resolve()),
                  'profile': args.profile + '; crossover sizes and content; elapsed times remain diagnostic',
                  'generator': 'sac1-crossover-fixed-v1; SHAKE256 distinct/repeated bytes, main qualification text template',
                  'python': platform.python_version(), 'zip': 'stdlib.zipfile DEFLATE6, no comments, Zip64 only when needed',
                  'zlib_compile': zlib.ZLIB_VERSION, 'zlib_runtime': zlib.ZLIB_RUNTIME_VERSION,
                  'scope': '1/2/16/256 archives report overhead and crossover; no ZIP parity gate'}
    (output / 'invocation.json').write_text(json.dumps(provenance, indent=2) + '\n')
    report = (output / 'measurements.jsonl').open('w')
    def record(value):
        report.write(json.dumps(value, sort_keys=True) + '\n'); report.flush()
    def run(*arguments):
        p = subprocess.run([str(cli), *map(str, arguments)], capture_output=True)
        if p.returncode:
            raise RuntimeError(f'CLI failed {arguments}: {p.stderr.decode(errors="replace")}')
        return p.stdout
    for count in ([] if args.metadata_only else [1, 2, 16, 256]):
        for size in [32, 512, 513, 1024, 4096, 8192, 8193, 16384, 65536]:
            for kind in ['incompressible', 'text', 'repeated']:
                for name_length in [8, 128]:
                    case = f'crossover-n{count}-b{size}-{kind}-name{name_length}'
                    work = output / case
                    source = work / 'source'
                    (source / 'd0').mkdir(parents=True)
                    files = []
                    for ordinal in range(count):
                        basename = f'f{ordinal:07}' + 'x' * (name_length - 8)
                        name = 'd0/' + basename
                        data = payload(kind, ordinal, size)
                        (source / name).write_bytes(data)
                        files.append((name, data))
                    archive = work / 'archive.sac'
                    before = time.monotonic_ns()
                    run('pack', source, archive)
                    packed_ns = time.monotonic_ns() - before
                    verification = json.loads(run('verify', archive))
                    assert verification['physical'] == 'verified'
                    for index in sorted({0, count // 2, count - 1}):
                        assert run('read', archive, files[index][0]) == files[index][1]
                    listing = [json.loads(line) for line in run('list', archive).splitlines()]
                    assert sum(row['kind'] == 'file' for row in listing) == count
                    packed = archive.stat().st_size
                    zipped = zip_control(work / 'control.zip', files)
                    logical = count * size
                    record({'case': case, 'scope': 'crossover-report-only', 'resources': count,
                            'file_bytes': size, 'name_bytes': name_length, 'content': kind,
                            'metadata': 'empty extraction facts; ordinary ZIP boilerplate mode/time stated in invocation',
                            'logical_bytes': logical, 'packed_bytes': packed, 'zip_bytes': zipped,
                            'signed_packed_minus_logical_bytes': packed - logical,
                            'signed_overhead_per_resource_bytes': (packed - logical) / count,
                            'sac_minus_zip_bytes': packed - zipped, 'sac_at_or_below_zip': packed <= zipped,
                            'pack_elapsed_ns_diagnostic_only': packed_ns, 'physical_verified': True,
                            'sampled_payloads_checked': len(set([0, count // 2, count - 1])), 'passed': True})
                    shutil.rmtree(work)
        print(json.dumps({'completed_resource_count': count}), flush=True)
    metadata_dir = output / 'metadata'
    metadata_dir.mkdir()
    env = os.environ.copy(); env['SAC1_METADATA_FIXTURE_DIR'] = str(metadata_dir)
    p = subprocess.run([str(producer), '--exact', 'metadata_prevents_inline_placement_and_uses_bounded_extents', '--nocapture'],
                       env=env, capture_output=True, text=True)
    (metadata_dir / 'producer.log').write_text(p.stdout + p.stderr)
    if p.returncode:
        raise RuntimeError('metadata producer regression failed')
    metadata = json.loads((metadata_dir / 'metadata-fixture.json').read_text())
    archive = metadata_dir / 'metadata.sac'
    data = (metadata_dir / 'metadata.expected.bin').read_bytes()
    assert json.loads(run('verify', archive))['physical'] == 'verified'
    listing = [json.loads(line) for line in run('list', archive).splitlines()]
    assert len(listing) == 2
    for row in listing:
        assert row['metadata_cbor_hex'] == metadata['metadata_cbor_hex']
        assert run('read', archive, row['path']) == data
    compact = metadata_dir / 'metadata.compact.sac'
    run('compact', archive, compact)
    assert json.loads(run('verify', compact))['physical'] == 'verified'
    assert run('read', compact, 'added') == data
    original_info = json.loads(run('inspect', archive))
    compact_info = json.loads(run('inspect', compact))
    assert original_info['snapshot'] == compact_info['snapshot']
    encoded_metadata = bytes.fromhex(metadata.pop('metadata_cbor_hex'))
    extra = struct.pack('<HH', 0xCAFE, len(encoded_metadata)) + encoded_metadata
    zipped = zip_control(metadata_dir / 'metadata-control.zip', [('added', data), ('edited', data)], extra)
    metadata.update({'scope': 'metadata-report-only', 'zip_bytes': zipped,
                     'zip_opaque_metadata_extra_id': '0xCAFE',
                     'zip_fixed_metadata_extra_bytes_per_file_local_plus_central': 2 * len(extra),
                     'metadata_mapping': 'opaque identical canonical CBOR preserved in a private ZIP extra field; no parity gate',
                     'compact_bytes': compact.stat().st_size, 'snapshot_preserved': True,
                     'frozen_cli_verified_original_and_compact': True, 'all_payloads_and_metadata_checked': True, 'passed': True})
    record(metadata)
    report.close()
    print(json.dumps({'metadata': 'passed', 'crossovers': 0 if args.metadata_only else 216, 'passed': True}), flush=True)


if __name__ == '__main__':
    main()
