#!/usr/bin/env python3
"""Separate memtable code cost from same-volume durable-write contention on macOS.

All application consumers retain real F_FULLFSYNC acknowledgements. The injected
load writes only task-owned ring files (8 MiB each); no caches are purged and no
other process is stopped. Every consumer reopens and verifies its complete state.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import threading
import time


def write_all(file, block):
    remaining=memoryview(block)
    while remaining:
        written=file.write(remaining)
        if not written:raise OSError('short durable-load write')
        remaining=remaining[written:]


def distribution(values):
    ordered=sorted(values)
    return {'count':len(values),'total_ns':sum(values),'p50_ns':statistics.median(values),
            'p99_ns':ordered[min(len(ordered)-1,int(len(ordered)*.99))], 'max_ns':max(values)} if values else None


class SyncLoad:
    def __init__(self, directory, workers):
        self.directory=directory; self.workers=workers; self.stop=threading.Event()
        self.threads=[]; self.samples=[[] for _ in range(workers)]; self.counts=[0]*workers
        self.totals=[0]*workers; self.errors=[]
    def __enter__(self):
        ready=[threading.Event() for _ in range(self.workers)]
        block=os.urandom(65536)
        def run(index):
            try:
                with (self.directory/f'load-{index}').open('x+b',buffering=0) as f:
                    while not self.stop.is_set():
                        f.seek((self.counts[index]%128)*len(block))
                        start=time.perf_counter_ns(); write_all(f,block)
                        fcntl.fcntl(f.fileno(),fcntl.F_FULLFSYNC)
                        elapsed=time.perf_counter_ns()-start
                        self.counts[index]+=1; self.totals[index]+=elapsed
                        if len(self.samples[index])<4096:self.samples[index].append(elapsed)
                        ready[index].set()
            except BaseException as error:
                self.errors.append(repr(error)); ready[index].set()
        for i in range(self.workers):
            t=threading.Thread(target=run,args=(i,),name=f'durable-load-{i}');t.start();self.threads.append(t)
        for event in ready:
            if not event.wait(30):
                self.stop.set()
                for thread in self.threads:thread.join()
                raise RuntimeError('injected sync load failed to start')
        if self.errors:
            self.stop.set()
            for thread in self.threads:thread.join()
            raise RuntimeError(self.errors)
        return self
    def __exit__(self,*_):
        self.stop.set()
        for thread in self.threads:thread.join()
        if self.errors:raise RuntimeError(self.errors)
    def statistics(self):
        return {'workers':self.workers,'bytes_per_write':65536,'max_file_bytes_per_worker':8*1024*1024,
                'sync_calls':sum(self.counts),'sync_total_ns':sum(self.totals),
                'sampled_latency':distribution([v for values in self.samples for v in values])}


def sync_control(directory):
    # Same volume, comparable WAL record size, same full device barrier, no SAC.
    block=os.urandom(64*(13+8+1024)+96)
    times=[]
    with (directory/'sync-control').open('w+b',buffering=0) as f:
        for i in range(8):
            f.seek(i*len(block));write_all(f,block)
            start=time.perf_counter_ns();fcntl.fcntl(f.fileno(),fcntl.F_FULLFSYNC)
            times.append(time.perf_counter_ns()-start)
    return distribution(times)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',action='append',required=True,help='NAME=/absolute/path, repeat for variants')
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--repeats',type=int,default=5)
    parser.add_argument('--load-workers',type=int,default=2,help='Bounded durable writers; 0 runs only the no-injection condition')
    parser.add_argument('--conditioning-repeats',type=int,default=2)
    parser.add_argument("--scratch-directory", type=Path, help="Existing directory on the device under test; logs remain in --output")
    args=parser.parse_args()
    if platform.system()!='Darwin':parser.error('F_FULLFSYNC experiment requires macOS')
    if not 1<=args.repeats<=20 or not 0<=args.load_workers<=4 or not 0<=args.conditioning_repeats<=5:parser.error('invalid bounded repetition/load count')
    binaries={name:Path(path).resolve() for name,path in (value.split('=',1) for value in args.binary)}
    if len(binaries)!=len(args.binary) or not any(name!='original' for name in binaries):
        parser.error('unique names and at least one instrumented variant are required')
    binary_records={n:{'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for n,p in binaries.items()}
    hashes=[entry['sha256'] for entry in binary_records.values()]
    if len(set(hashes))!=len(hashes):
        parser.error('variant executables have identical SHA-256 hashes; verify the actual build output paths')
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=True)
    scratch_base=(args.scratch_directory or output).resolve()
    if not scratch_base.is_dir():parser.error("scratch directory must exist")
    if (output/'samples.jsonl').exists():parser.error('use a fresh output directory')
    (output/'logs').mkdir()
    environment={'started_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'platform':platform.platform(),
                 'load_start':os.getloadavg(),'arguments':vars(args)|{'output':str(output),'scratch_directory':str(scratch_base)},
                 'binaries':binary_records,
                 'method':'rotated fresh-process same-fixture consumers; real F_FULLFSYNC; bounded same-volume load; no cache purges',
                 'cwd':str(Path.cwd())}
    (output/'environment.json').write_text(json.dumps(environment,indent=2)+'\n')
    iolog=(output/'iostat.txt').open('w')
    monitor=subprocess.Popen(['/usr/sbin/iostat','-d','-n','16','-w','1'],stdout=iolog,stderr=subprocess.STDOUT)
    rows=[];digests={}
    try:
        with tempfile.TemporaryDirectory(prefix='storage-isolation-',dir=scratch_base) as scratch, (output/'samples.jsonl').open('w') as raw:
            scratch=Path(scratch);seed=scratch/'seed.sac'
            executable=next(iter(binaries.values()))
            subprocess.run([str(executable),'fixture',str(seed),'2048','1024'],check=True,capture_output=True,text=True,timeout=120)
            def run(name,phase='timing',batch=64,memory=16*1024*1024,context='no-injected-load',repeat=1,workers=0):
                ordinal=len(rows)+1;stem=f'{ordinal:03}-{name}-{context}-r{repeat}'
                with tempfile.TemporaryDirectory(prefix='case-',dir=scratch) as case:
                    case=Path(case)
                    with SyncLoad(case,workers) as load:
                        before=sync_control(case);load_before=os.getloadavg()
                        proc=subprocess.run(['/usr/bin/time','-lp',str(binaries[name]),'run','memtable',phase,
                                             str(seed),str(case),'2048','4096','1024',str(batch),str(memory)],capture_output=True,text=True,timeout=300)
                        after=sync_control(case)
                    (output/'logs'/(stem+'.stdout.json')).write_text(proc.stdout)
                    (output/'logs'/(stem+'.stderr.txt')).write_text(proc.stderr)
                    if proc.returncode:raise RuntimeError(f'{stem}: {proc.stderr}')
                    row=json.loads(proc.stdout);assert row['verified']
                    prior=digests.setdefault(phase,row['logical_digest']);assert prior==row['logical_digest']
                    row.update({'variant':name,'context':context,'repeat':repeat,'ordinal':ordinal,
                                'load_before':load_before,'load_after':os.getloadavg(),'sync_control_before':before,
                                'sync_control_after':after,'injected_load':load.statistics()})
                    raw.write(json.dumps(row,separators=(',',':'))+'\n');raw.flush();rows.append(row)
                    w=row['write'];io=w['statistics'].get('io',{})
                    print(f"[{ordinal}] {stem}: {w['updates_per_second']:.0f} updates/s; WAL sync {io.get('wal_sync_total_ns',0)/1e6:.1f} ms; verified",flush=True)
            for repeat in range(1,args.repeats+1):
                names=list(binaries);shift=(repeat-1)%len(names);names=names[shift:]+names[:shift]
                if ((repeat-1)//len(names))%2:names.reverse()
                conditions=([0,args.load_workers] if repeat%2 else [args.load_workers,0]) if args.load_workers else [0]
                for workers in conditions:
                    for name in names:run(name,context='injected-sync-load' if workers else 'no-injected-load',repeat=repeat,workers=workers)
            # Reproduce the original predecessor: 4096 single-record durable
            # writes under the 1 MiB budget, then immediately test 16 MiB/b64.
            instrumented=next(name for name in binaries if name!='original')
            for repeat in range(1,args.conditioning_repeats+1):
                run(instrumented,context='before-conditioning',repeat=repeat)
                run(instrumented,batch=1,memory=1024*1024,context='conditioning-b1-1MiB',repeat=repeat)
                run(instrumented,context='after-conditioning',repeat=repeat)
            for name in binaries:
                if name=='original':continue
                for workers in ([0,args.load_workers] if args.load_workers else [0]):
                    run(name,phase='attribution',context='trace-injected' if workers else 'trace-no-injected',workers=workers)
    finally:
        monitor.terminate()
        try:monitor.wait(timeout=5)
        except subprocess.TimeoutExpired:monitor.kill();monitor.wait()
        iolog.close()
    environment.update({'completed_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'load_end':os.getloadavg(),'samples':len(rows)})
    (output/'environment.json').write_text(json.dumps(environment,indent=2)+'\n')
    print(f'Saved {len(rows)} verified samples to {output}',flush=True)


if __name__=='__main__':main()
