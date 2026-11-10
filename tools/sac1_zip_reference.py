#!/usr/bin/env python3
"""Write the frozen ordinary-ZIP control from the qualification's actual input.

The JSON manifest is an array of {"name": POSIX archive name, "path": source
file}. This tool never discovers additional files or approximates ZIP size.
The caller owns its input/output directory and may retire both after recording
the returned measurements. ZIP bytes include all local/central headers and EOF.
"""

import argparse
import json
from pathlib import Path
import platform
import time
import zipfile
import zlib


def reference(manifest_path: Path, output: Path, level: int) -> dict:
    entries = json.loads(manifest_path.read_text())
    if not isinstance(entries, list):
        raise ValueError("manifest must be an array")
    names = set()
    input_bytes = 0
    started = time.perf_counter_ns()
    # Exclusive creation prevents a mistaken output path from destroying input.
    with output.open("xb") as target:
        with zipfile.ZipFile(
            target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=level,
            allowZip64=True, strict_timestamps=True,
        ) as archive:
            for entry in entries:
                name, source = entry["name"], Path(entry["path"])
                components = name.split("/")
                if not name or any(p in ("", ".", "..") for p in components):
                    raise ValueError(f"invalid archive name: {name!r}")
                if name in names:
                    raise ValueError(f"duplicate archive name: {name!r}")
                names.add(name)
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                # ZipFile.open(ZipInfo) uses the entry's level rather than the
                # archive default. This spelling also works before Python 3.13.
                info._compresslevel = level
                info.extra = b""
                info.comment = b""
                # Set the known length before opening: small entries then use
                # ordinary ZIP rather than an unnecessarily forced Zip64 field.
                info.file_size = source.stat().st_size
                input_bytes += info.file_size
                with source.open("rb") as src, archive.open(info, "w") as dst:
                    while block := src.read(1024 * 1024):
                        dst.write(block)
        target.flush()
        size = target.tell()
    return {
        "format": "ordinary ZIP", "bytes": size, "resources": len(entries),
        "input_bytes": input_bytes,
        "elapsed_ns": time.perf_counter_ns() - started,
        "python": platform.python_version(), "implementation": "stdlib.zipfile",
        "zlib_compile": zlib.ZLIB_VERSION, "zlib_runtime": zlib.ZLIB_RUNTIME_VERSION,
        "level": level, "extra_fields": 0, "comment_bytes": 0,
        "metadata": "1980-01-01T00:00:00, Unix regular file mode 0644",
        "zip64": "only when format limits require it",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--level", type=int, default=6, choices=range(10))
    args = parser.parse_args()
    print(json.dumps(reference(args.manifest, args.output, args.level), sort_keys=True))


if __name__ == "__main__":
    main()
