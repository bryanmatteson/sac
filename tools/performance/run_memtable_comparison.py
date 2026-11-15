#!/usr/bin/env python3
"""Run paired public-API SAC/memtable measurements in fresh sequential processes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import tempfile
import time

WORKLOADS = {
    "hot-128": (1024, 8192, 128),
    "wide-128": (8192, 8192, 128),
    "wide-1024": (2048, 4096, 1024),
}
BACKENDS = {
    "direct-durable": ("direct-durable", 16 * 1024 * 1024),
    "direct-deferred": ("direct-deferred", 16 * 1024 * 1024),
    "memtable-16MiB": ("memtable", 16 * 1024 * 1024),
    "memtable-1MiB": ("memtable", 1024 * 1024),
}


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else result.stderr.strip()


def time_counters(stderr):
    result = {}
    for name, expression, multiplier in [
        ("wall_seconds", r"(?m)^real\s+([\d.]+)", 1),
        ("user_seconds", r"(?m)^user\s+([\d.]+)", 1),
        ("system_seconds", r"(?m)^sys\s+([\d.]+)", 1),
        ("peak_rss_bytes", r"(\d+)\s+maximum resident set size", 1),
    ]:
        match = re.search(expression, stderr)
        if not match:
            raise ValueError(f"Missing {name} from /usr/bin/time: {stderr}")
        result[name] = float(match.group(1)) * multiplier
    return result


def metrics(sample):
    out = {"rss_open_bytes": sample["rss_open_bytes"], **{
        "process_" + key: value for key, value in sample["process"].items()
    }}
    if sample["phase"] in ("timing", "attribution"):
        write = sample["write"]
        out.update({"updates_per_second": write["updates_per_second"],
                    "write_wall_ms": write["wall_ns"] / 1e6,
                    "write_cpu_ms": write["cpu_ns"] / 1e6,
                    "write_call_p99_us": write["calls"]["p99_ns"] / 1e3,
                    "write_call_max_ms": write["calls"]["max_ns"] / 1e6,
                    "checkpoints": write["statistics"]["checkpoints"],
                    "sac_appended_bytes": write["sac_appended_bytes"]})
        cadence = write["explicit_flushes"]
        if cadence:
            out["cadence_flush_p50_ms"] = cadence["p50_ns"] / 1e6
            out["cadence_flush_max_ms"] = cadence["max_ns"] / 1e6
        for cls, dist in sample.get("reads", {}).items():
            if cls == "residency":
                continue
            for percentile in ("p50", "p99"):
                out[f"read_{cls}_{percentile}_us"] = dist[percentile + "_ns"] / 1e3
        probes = sample.get("checkpoint_probes", [])
        if not probes:
            return out
        out["checkpoint_median_ms"] = statistics.median(p["wall_ns"] for p in probes) / 1e6
        out["checkpoint_max_ms"] = max(p["wall_ns"] for p in probes) / 1e6
        stalls = [p["overlapping_read_latency"]["max_ns"] for p in probes if p["overlapping_read_latency"]]
        out["checkpoint_overlapping_reads"] = sum(p["overlapping_reads"] for p in probes)
        if stalls:
            out["checkpoint_blocked_read_max_ms"] = max(stalls) / 1e6
    elif sample["phase"] == "memory":
        out["rss_dirty_bytes"] = sample["dirty"]["rss_bytes"]
        out["rss_dirty_minus_open_bytes"] = sample["dirty"]["rss_bytes"] - sample["rss_open_bytes"]
        out["rss_flushed_bytes"] = sample["flushed"]["rss_bytes"]
        out["pending_memory_bytes"] = sample["dirty"]["statistics"]["pending_memory_bytes"] or 0
        out["pending_entries"] = sample["dirty"]["statistics"]["pending_entries"] or 0
        out["pressure_checkpoints"] = sample["dirty"]["statistics"]["checkpoints"]
        out["wal_bytes"] = sample["dirty"]["statistics"]["wal_bytes"]
    elif sample["phase"]=="contention":
        probes=sample["contention_probes"]
        out["writes_during_checkpoint"] = sum(p["writes_completed_while_checkpoint"] for p in probes)
        out["checkpoint_median_ms"] = statistics.median(p["wall_ns"] for p in probes)/1e6
        readers=[p["overlapping_read_latency"] for p in probes if p["overlapping_read_latency"]]
        if readers:
            out["checkpoint_read_max_ms"] = max(p["max_ns"] for p in readers)/1e6
        calls=[p["concurrent_write_latency"] for p in probes if p["concurrent_write_latency"]]
        if calls:
            out["concurrent_write_max_ms"] = max(p["max_ns"] for p in calls)/1e6
    else:
        timer = sample["timer"]
        out["timer_publish_ms"] = timer["published_after_first_start_ns"] / 1e6
        out["timer_write_ack_ms"] = timer["accepted_after_first_start_ns"] / 1e6
        out["timer_read_max_ms"] = timer["reader_latency"]["max_ns"] / 1e6
        out["timer_read_p99_us"] = timer["reader_latency"]["p99_ns"] / 1e3
    return out


def summarize(samples):
    groups = {}
    for sample in samples:
        key = (sample["phase"], sample["workload"], sample["batch_size"], sample["backend"])
        groups.setdefault(key, []).append(sample)
    result = []
    for (phase, workload, batch, backend), rows in sorted(groups.items()):
        values = {}
        for row in rows:
            for name, value in metrics(row).items():
                values.setdefault(name, []).append(value)
        result.append({"phase": phase, "workload": workload, "batch_size": batch,
                       "backend": backend, "repetitions": len(rows), "metrics": {
                           name: {"median": statistics.median(v), "min": min(v), "max": max(v)}
                           for name, v in values.items()}})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--memtable-only", action="store_true")
    parser.add_argument("--baseline-binary", type=Path, help="Pair two memtable implementations on identical v1 fixtures")
    parser.add_argument("--phases", nargs="+", choices=["timing", "attribution", "memory", "timer", "contention"], default=["timing", "memory", "timer"])
    parser.add_argument("--workloads", nargs="+", choices=list(WORKLOADS), default=list(WORKLOADS))
    parser.add_argument("--batches", nargs="+", type=int, choices=[1,64], default=[1,64])
    parser.add_argument("--updates", type=int, help="Override update count (256..65536) for a shorter paired experiment")
    parser.add_argument("--smoke", action="store_true", help="one short workload, all paths")
    parser.add_argument("--scratch-directory", type=Path, help="Existing directory on the device under test; logs remain in --output")
    args = parser.parse_args()
    if platform.system() != "Darwin":
        parser.error("This runner uses macOS /usr/bin/time -lp RSS units; port explicitly before running elsewhere")
    if not 1 <= args.repeats <= 20:
        parser.error("--repeats must be 1..20")
    if args.baseline_binary and not args.memtable_only:
        parser.error("--baseline-binary requires --memtable-only")
    if "contention" in args.phases and (args.baseline_binary or not args.memtable_only):
        parser.error("contention requires --memtable-only without a baseline binary")
    if args.updates is not None and not 256 <= args.updates <= 65536:
        parser.error("--updates must be 256..65536")
    binary = args.binary.resolve()
    baseline = args.baseline_binary.resolve() if args.baseline_binary else None
    if baseline and hashlib.sha256(binary.read_bytes()).digest() == hashlib.sha256(baseline.read_bytes()).digest():
        parser.error("baseline and candidate executables have identical SHA-256 hashes")
    backends = {key:(mode,memory,binary) for key,(mode,memory) in BACKENDS.items()
                if not args.memtable_only or mode=="memtable"}
    if baseline:
        backends = {prefix+key:(mode,memory,executable)
                    for key,(mode,memory,_) in backends.items()
                    for prefix,executable in [("before-",baseline),("after-",binary)]}
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    scratch_base = (args.scratch_directory or output).resolve()
    if not scratch_base.is_dir():
        parser.error("scratch directory must exist")
    if (output / "samples.jsonl").exists():
        parser.error("Choose a new output directory; samples.jsonl already exists")
    (output / "logs").mkdir(exist_ok=True)
    environment = {
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": platform.platform(), "machine": platform.machine(),
        "hardware": {key: command("sysctl", "-n", key) for key in
                     ("hw.model", "hw.ncpu", "hw.memsize", "machdep.cpu.brand_string")},
        "rustc": command("rustc", "--version"),
        "git_head": command("git", "rev-parse", "HEAD"),
        "git_status": command("git", "status", "--short"),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "binary": str(binary), "repeats": args.repeats, "load_start": os.getloadavg(),
        "baseline_binary": str(baseline) if baseline else None,
        "baseline_sha256": hashlib.sha256(baseline.read_bytes()).hexdigest() if baseline else None,
        "arguments": vars(args) | {"binary":str(binary),"output":str(output),"scratch_directory":str(scratch_base),"baseline_binary":str(baseline) if baseline else None},
        "method": "sequential fresh processes; rotated backend order; same seeded image; release/native; fully reopened and verified",
    }
    (output / "environment.json").write_text(json.dumps(environment, indent=2) + "\n")
    workloads = {"smoke": (1024, 512, 128)} if args.smoke else {key:WORKLOADS[key] for key in args.workloads}
    if args.updates is not None:
        workloads = {key:(keys,args.updates,size) for key,(keys,_,size) in workloads.items()}
    samples = []
    checksums = {}
    with tempfile.TemporaryDirectory(prefix="memtable-benchmark-", dir=scratch_base) as scratch:
        scratch = Path(scratch)
        seeds = {}
        for name, (keys, _, size) in workloads.items():
            seed = scratch / (name + ".sac")
            subprocess.run([str(baseline or binary), "fixture", str(seed), str(keys), str(size)], check=True,
                           capture_output=True, text=True, timeout=120)
            seeds[name] = seed
        tasks = []
        for repeat in range(args.repeats):
            for name, params in workloads.items():
                for timing_phase in [p for p in args.phases if p in ("timing", "attribution")]:
                    for batch in args.batches:
                        order = list(backends)
                        shift = repeat % len(order)
                        order = order[shift:] + order[:shift]
                        if (repeat // len(order)) % 2:
                            order.reverse()
                        tasks.extend((repeat,timing_phase,name,params,batch,backend) for backend in order)
                if "memory" in args.phases and name!="hot-128":
                    order = [key for key,(mode,_,_) in backends.items() if mode!="direct-durable"]
                    shift = repeat % len(order)
                    order = order[shift:] + order[:shift]
                    tasks.extend((repeat,"memory",name,params,64,backend) for backend in order)
                if "contention" in args.phases:
                    tasks.extend((repeat,"contention",name,params,64,backend) for backend in backends)
            timer_name = "wide-128" if "wide-128" in workloads else next(iter(workloads))
            if "timer" in args.phases:
                for backend,(mode,_,_) in backends.items():
                    if mode=="memtable":
                        tasks.append((repeat,"timer",timer_name,workloads[timer_name],64,backend))
        with (output / "samples.jsonl").open("w") as raw:
            for ordinal, (repeat, phase, name, (keys, updates, size), batch, backend) in enumerate(tasks, 1):
                mode, memory, executable = backends[backend]
                stem = f"{ordinal:03}-{name}-{phase}-b{batch}-{backend}-r{repeat+1}"
                with tempfile.TemporaryDirectory(prefix="case-", dir=scratch) as case:
                    argv = ["/usr/bin/time", "-lp", str(executable), "run", mode, phase,
                            str(seeds[name]), case, str(keys), str(updates), str(size), str(batch), str(memory)]
                    load_before = os.getloadavg()
                    proc = subprocess.run(argv, capture_output=True, text=True, timeout=300)
                    (output / "logs" / (stem + ".stdout.json")).write_text(proc.stdout)
                    (output / "logs" / (stem + ".stderr.txt")).write_text(proc.stderr)
                    if proc.returncode:
                        raise RuntimeError(f"{stem} failed ({proc.returncode}): {proc.stderr}")
                    sample = json.loads(proc.stdout)
                    assert sample["verified"]
                    sample.update({"backend": backend, "workload": name, "repeat": repeat + 1,
                                   "process": time_counters(proc.stderr), "load_before": load_before,
                                   "load_after": os.getloadavg(), "ordinal": ordinal})
                    key = (phase, name, batch)
                    if phase!="contention":
                        previous = checksums.setdefault(key, sample["logical_digest"])
                        assert previous == sample["logical_digest"], f"Logical contents differ for {stem}"
                    raw.write(json.dumps(sample, separators=(",", ":")) + "\n")
                    raw.flush()
                    samples.append(sample)
                    metric = metrics(sample)
                    detail = (f"{metric['updates_per_second']:.0f} updates/s" if phase in ("timing", "attribution") else
                              f"RSS {metric['rss_dirty_bytes']/1048576:.2f} MiB" if phase == "memory" else
                              f"{metric['writes_during_checkpoint']} batches acknowledged during checkpoints" if phase=="contention" else
                              f"published {metric['timer_publish_ms']:.2f} ms")
                    print(f"[{ordinal}/{len(tasks)}] {stem}: {detail}; verified", flush=True)
    (output / "summary.json").write_text(json.dumps(summarize(samples), indent=2) + "\n")
    environment.update({"completed_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "load_end": os.getloadavg(), "samples": len(samples)})
    (output / "environment.json").write_text(json.dumps(environment, indent=2) + "\n")
    print(f"Saved {len(samples)} verified samples to {output}")


if __name__ == "__main__":
    main()
