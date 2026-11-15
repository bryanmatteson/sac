#!/usr/bin/env python3
"""Run an already built, explicitly selected trie_workloads release executable.

Alternates backend order, checks logical equivalence, and preserves every sample.
Whole-process user/system CPU includes setup and verification; JSON edit timings
come from ProcessTime inside the binary and exclude setup/publication/verification.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import statistics
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--iterations", type=int, default=8192)
    parser.add_argument("--cadences", type=int, nargs="+", default=[0, 128])
    parser.add_argument("--cases", nargs="+", default=["updates", "inserts-ordered", "inserts-shuffled", "resize"])
    parser.add_argument("--spill", action="store_true")
    parser.add_argument("--backends", nargs="+", default=["map", "trie"], choices=["map", "trie", "dual", "dual-rebuild", "dual-paged", "dual-bucket", "live-map"])
    parser.add_argument("--merge-every", type=int, default=1024)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if (args.output / "samples.jsonl").exists() or (args.output / "summary.json").exists():
        parser.error("choose a fresh output directory to preserve earlier measurements")
    args.output.mkdir(parents=True, exist_ok=True)
    metadata = {"binary": str(binary), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "started": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "host": platform.platform(), "load_start": os.getloadavg(),
                "repeats": args.repeats, "iterations": args.iterations, "spill": args.spill,
                "cadences": args.cadences, "cases": args.cases, "backends": args.backends, "merge_every": args.merge_every}
    (args.output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    samples = []
    with (args.output / "samples.jsonl").open("w") as output:
        for cadence in args.cadences:
            for case in args.cases:
                for repeat in range(args.repeats):
                    pair = []
                    shift = repeat % len(args.backends)
                    for backend in args.backends[shift:] + args.backends[:shift]:
                        env = {**os.environ, "SAC_MAP_ITERATIONS": str(args.iterations),
                               "SAC_MAP_PUBLISH_EVERY": str(cadence), "SAC_MAP_MERGE_EVERY": str(args.merge_every)}
                        env.pop("SAC_MAP_SPILL", None)
                        if args.spill:
                            env["SAC_MAP_SPILL"] = "1"
                        before = resource.getrusage(resource.RUSAGE_CHILDREN)
                        start = time.monotonic()
                        proc = subprocess.run([str(binary), backend, case], env=env, capture_output=True, text=True)
                        after = resource.getrusage(resource.RUSAGE_CHILDREN)
                        if proc.returncode:
                            raise RuntimeError(f"{backend}/{case}: {proc.stdout}\n{proc.stderr}")
                        sample = json.loads(proc.stdout)
                        sample.update(repeat=repeat, process_seconds=time.monotonic() - start,
                                      process_user_seconds=after.ru_utime-before.ru_utime,
                                      process_system_seconds=after.ru_stime-before.ru_stime,
                                      load=os.getloadavg())
                        assert sample["verified"]
                        pair.append(sample)
                        samples.append(sample)
                        output.write(json.dumps(sample) + "\n")
                        output.flush()
                        print(f'{cadence=:3} {case:16} {repeat=} {backend:4} '
                              f'{sample["cpu_ns"]/args.iterations/1000:7.2f} us/edit; '
                              f'{sample["appended_bytes"]/args.iterations:7.0f} bytes/edit', flush=True)
                    assert len({s["logical_digest"] for s in pair}) == 1
    summaries = []
    metrics = ["cpu_ns", "wall_ns", "publication_cpu_ns", "publication_ns", "appended_bytes",
               "sealed_bytes", "read_operations", "lookup_cpu_ns", "lookup_ns", "lookup_count",
               "verification_ns", "process_user_seconds", "process_system_seconds", "merge_cpu_ns", "merge_ns",
               "merges", "overlay_entries", "live_sealed_bytes", "export_cpu_ns", "export_ns",
               "lookup_prepare_cpu_ns", "lookup_prepare_ns", "random_lookup_cpu_ns", "random_lookup_ns",
               "miss_lookup_cpu_ns", "miss_lookup_ns", "miss_lookup_count"]
    for cadence in args.cadences:
        for case in args.cases:
            row = {"case": case, "publish_every": cadence, "spill": args.spill}
            for backend in args.backends:
                group = [s for s in samples if s["backend"] == backend and s["case"] == case and s["publish_every"] == cadence]
                row[backend] = {k: statistics.median(s[k] for s in group) for k in metrics}
                row[backend]["edit_us"] = row[backend]["cpu_ns"] / args.iterations / 1000
                row[backend]["durable_wall_us"] = statistics.median((s["wall_ns"] + s["merge_ns"] + s["publication_ns"]) / args.iterations / 1000 for s in group)
                row[backend]["total_cpu_us"] = statistics.median((s["cpu_ns"] + s["merge_cpu_ns"] + s["publication_cpu_ns"]) / args.iterations / 1000 for s in group)
                row[backend]["with_export_cpu_us"] = statistics.median((s["cpu_ns"] + s["merge_cpu_ns"] + s["publication_cpu_ns"] + s["export_cpu_ns"]) / args.iterations / 1000 for s in group)
                row[backend]["cpu_range_us"] = [min(s["cpu_ns"] for s in group)/args.iterations/1000,
                                                  max(s["cpu_ns"] for s in group)/args.iterations/1000]
            if "map" in args.backends:
                for backend in args.backends:
                    if backend == "map": continue
                    row[backend + "_edit_cpu_reduction_pct"] = 100 * (1 - row[backend]["cpu_ns"] / row["map"]["cpu_ns"])
                    row[backend + "_total_cpu_reduction_pct"] = 100 * (1 - row[backend]["total_cpu_us"] / row["map"]["total_cpu_us"])
                    row[backend + "_append_ratio"] = row[backend]["appended_bytes"] / row["map"]["appended_bytes"]
                    row[backend + "_sealed_ratio"] = row[backend]["sealed_bytes"] / row["map"]["sealed_bytes"]
            summaries.append(row)
    (args.output / "summary.json").write_text(json.dumps(summaries, indent=2) + "\n")
    metadata["load_end"] = os.getloadavg()
    metadata["finished"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (args.output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")


if __name__ == "__main__":
    main()
