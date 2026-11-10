#!/usr/bin/env python3
"""Run each database workload with a hard two-minute process deadline."""
import argparse,json,os,pathlib,platform,re,subprocess,time
p=argparse.ArgumentParser();p.add_argument('binary');p.add_argument('--repetitions',type=int,default=3);args=p.parse_args()
binary=str(pathlib.Path(args.binary).resolve());results=[]
for repeat in range(args.repetitions):
    cases=['copy-swap','offline','online','online-pinned','online-no-punch','online-reuse']
    if repeat%2: cases.reverse()
    for case in cases:
        directory=pathlib.Path(f'{repeat}-{case}');directory.mkdir()
        host={'load':os.getloadavg(),'platform':platform.platform(),'time':time.time()}
        result=subprocess.run(['/usr/bin/time','-lp',binary,case],cwd=directory,text=True,capture_output=True,timeout=120)
        (directory/'stdout.json').write_text(result.stdout);(directory/'time.txt').write_text(result.stderr)
        if result.returncode: raise RuntimeError(f'{case}: {result.returncode}\n{result.stderr}')
        row=json.loads(result.stdout);row['host']=host;row['repeat']=repeat
        meta=(directory/'benchmark.sac').stat();row['allocated_after_close']=meta.st_blocks*512
        match=re.search(r'(\d+)\s+maximum resident set size',result.stderr)
        row['whole_process_peak_rss_bytes']=int(match[1]) if match else None
        results.append(row);pathlib.Path('results.json').write_text(json.dumps(results,indent=2)+'\n')
        print(json.dumps(row),flush=True)
