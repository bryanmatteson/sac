#!/usr/bin/env python3
"""Build and run the SAC1 production qualification, retaining exact logs.

Run this tool through the workspace artifact-retention runner for managed
database-producing comparisons. Cargo compiles the integration test and its
package binaries; CLI consumer tests are separately required for release.
"""

import argparse
import hashlib
import json
import os
import platform
import re
import resource
from pathlib import Path
import subprocess
import shutil
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path.cwd())
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--groups", default="tiny,small,bulk,compressed,native,compaction")
    parser.add_argument("--binary", type=Path, help="reuse an already compiled optimized qualification executable")
    parser.add_argument("--build-provenance", type=Path, help="invocation.json for a reused executable")
    parser.add_argument("--rss", action="store_true", help="measure the invoked test process with the OS time utility")
    parser.add_argument("--rss-limit-bytes", type=int)
    args = parser.parse_args()
    if args.build_provenance and not args.binary:
        parser.error("--build-provenance requires --binary")
    if args.rss_limit_bytes is not None and not args.rss:
        parser.error("--rss-limit-bytes requires --rss")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    checkout = Path(__file__).resolve().parent.parent
    def sources():
        paths = [checkout / "Cargo.toml", checkout / "Cargo.lock", Path(__file__).resolve(),
                 checkout / "tools/sac1_zip_reference.py", checkout / "tests/sac1_qualification.rs"]
        paths.extend((checkout / "src").rglob("*.rs"))
        paths.extend((checkout / "tests/sac1_qualification").rglob("*.rs"))
        return {str(path.relative_to(checkout)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(set(paths))}

    before_sources = sources()
    if args.binary:
        executable = str(args.binary.resolve())
        provenance = {"reused_binary": executable, "full": args.full, "groups": args.groups,
                      "build_provenance": (json.loads(args.build_provenance.read_text())
                                           if args.build_provenance else None)}
    else:
        command = ["cargo", "+1.97.1", "rustc", "--manifest-path", str(checkout / "Cargo.toml"),
                   "--release", "--test", "sac1_qualification", "--message-format=json"]
        started = time.monotonic_ns()
        build = subprocess.run(command, cwd=checkout, capture_output=True, text=True)
        (output / "compile.jsonl").write_text(build.stdout)
        (output / "compile.stderr.log").write_text(build.stderr)
        provenance = {"command": command, "full": args.full, "groups": args.groups,
                      "compile_elapsed_ns": time.monotonic_ns() - started,
                      "compile_returncode": build.returncode,
                      "source_before_build_sha256": before_sources,
                      "source_after_build_sha256": sources()}
        (output / "invocation.json").write_text(json.dumps(provenance, indent=2) + "\n")
        if build.returncode:
            print(build.stderr, file=sys.stderr)
            for line in build.stdout.splitlines():
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if value.get("reason") == "compiler-message":
                    print(value["message"].get("rendered", ""), file=sys.stderr)
            return build.returncode
        executable = None
        for line in build.stdout.splitlines():
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if value.get("reason") == "compiler-artifact" and value.get("target", {}).get("name") == "sac1_qualification":
                executable = value.get("executable") or executable
        if not executable:
            raise RuntimeError("Cargo returned success without the qualification executable")
    frozen = output / "qualification-runner"
    shutil.copy2(executable, frozen)
    frozen.chmod(0o500)
    digest = hashlib.sha256()
    with frozen.open("rb") as binary:
        for chunk in iter(lambda: binary.read(1024 * 1024), b""):
            digest.update(chunk)
    if args.build_provenance and provenance["build_provenance"].get("executable_sha256") != digest.hexdigest():
        raise RuntimeError("reused executable does not match its build provenance")
    provenance["driver_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    provenance.update({"cargo_executable": executable, "executed_executable": str(frozen),
                       "executable_sha256": digest.hexdigest(),
                       "selection": {key: value for key, value in os.environ.items()
                                     if key.startswith("SAC1_QUALIFY_")}})
    (output / "invocation.json").write_text(json.dumps(provenance, indent=2) + "\n")
    env = os.environ.copy()
    env["SAC1_QUALIFY_DIR"] = str(output)
    env["SAC1_QUALIFY_CASES"] = args.groups
    if args.full:
        env["SAC1_QUALIFY_FULL"] = "1"
    else:
        env.pop("SAC1_QUALIFY_FULL", None)
    invocation = [str(frozen), "--ignored", "--exact", "sac1_production_qualification",
                  "--nocapture", "--test-threads=1"]
    if args.rss:
        invocation = ["/usr/bin/time", "-l" if platform.system() == "Darwin" else "-v", *invocation]
    print(f"Running {'full' if args.full else 'diagnostic'} populations: {args.groups}", flush=True)
    with (output / "qualification.log").open("w") as log:
        peak_rss = None
        cpu_before = resource.getrusage(resource.RUSAGE_CHILDREN)
        run_started = time.monotonic_ns()
        load_before = os.getloadavg()
        process = subprocess.Popen(invocation, cwd=checkout, env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            log.write(line)
            log.flush()
            match = re.search(r"(\d+)\s+maximum resident set size", line)
            if match:
                peak_rss = int(match.group(1))
            match = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", line)
            if match:
                peak_rss = int(match.group(1)) * 1024
            marker = "SAC1_MEASUREMENT "
            if marker in line:
                value = json.loads(line.split(marker, 1)[1])
                summary = {k: value[k] for k in (
                    "case", "scope", "passed", "packed_bytes", "limit_bytes", "overhead_bytes",
                    "throughput_ratio", "compact_bytes", "elapsed_ns", "error") if k in value}
                if "timing" in value and isinstance(value["timing"], dict):
                    summary["p95_ns"] = value["timing"].get("p95_ns")
                print(json.dumps(summary, sort_keys=True), flush=True)
            elif "panic" in line or "FAILED" in line:
                print(line, end="", flush=True)
        status = process.wait()
        cpu_after = resource.getrusage(resource.RUSAGE_CHILDREN)
        (output / "process-times.json").write_text(json.dumps({
            "scope": "qualification test process and waited descendants; compiler excluded",
            "elapsed_ns": time.monotonic_ns() - run_started,
            "user_cpu_seconds": cpu_after.ru_utime - cpu_before.ru_utime,
            "system_cpu_seconds": cpu_after.ru_stime - cpu_before.ru_stime,
            "loadavg_before": load_before, "loadavg_after": os.getloadavg(),
            "returncode": status,
        }, indent=2) + "\n")
        if args.rss:
            result = {"case": "process-peak-rss", "groups": args.groups, "peak_bytes": peak_rss,
                      "scope": "whole process; includes test harness, caches and live buffers; no application output exclusions",
                      "limit_bytes": args.rss_limit_bytes,
                      "passed": peak_rss is not None and (args.rss_limit_bytes is None or peak_rss <= args.rss_limit_bytes)}
            (output / "process-peak-rss.json").write_text(json.dumps(result, indent=2) + "\n")
            print(json.dumps(result), flush=True)
            if not result["passed"]:
                status = status or 1
        return status


if __name__ == "__main__":
    sys.exit(main())
