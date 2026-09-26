#!/usr/bin/env python3
"""Run each shard in a fresh process. Absolute runner results; no empty-green runs.
Keeps stdout JSON and stderr per shard. Continues failures to preserve coverage.
Use one --runner binary per format. Does NOT compile or modify source.
"""
import argparse,gzip,json,subprocess,sys,struct
from pathlib import Path

def main():
 p=argparse.ArgumentParser();p.add_argument('--runner',required=True,type=Path);p.add_argument('--corpus',required=True,type=Path);p.add_argument('--out',required=True,type=Path);p.add_argument('--timeout',type=float,default=300.0);p.add_argument('runner_args',nargs=argparse.REMAINDER);a=p.parse_args()
 a.runner_args=a.runner_args[1:] if a.runner_args[:1]==['--'] else a.runner_args
 paths=sorted(a.corpus.glob('*.gz')) if a.corpus.is_dir() else [a.corpus]
 if not paths:raise SystemExit('No corpus files: refusing empty run')
 a.out.mkdir(parents=True,exist_ok=True);results=[];failed=False
 for i,path in enumerate(paths):
  raw=gzip.open(path,'rb').read() if path.suffix=='.gz' else path.read_bytes()
  try:
   r=subprocess.run([str(a.runner.resolve()),'-',*a.runner_args],input=raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=a.timeout)
  except subprocess.TimeoutExpired as e:
   r=subprocess.CompletedProcess([str(a.runner)],124,e.stdout or b'',(e.stderr or b'')+b'\nSHARD_TIMEOUT\n')
  (a.out/(path.name+'.stderr')).write_bytes(r.stderr);(a.out/(path.name+'.stdout')).write_bytes(r.stdout)
  try:
   lines=r.stdout.decode().strip().splitlines();summary=json.loads(lines[-1]);valid=summary.get('selected',0)>0 and 'backends'in summary
   if not a.runner_args:valid=valid and summary.get('selected')==struct.unpack('<I',raw[8:12])[0]
  except Exception:summary=None;valid=False
  ok=r.returncode==0 and valid;failed|=not ok
  results.append(dict(shard=path.name,returncode=r.returncode,valid_summary=valid,summary=summary))
  print(f'{i+1}/{len(paths)} {path.name}: rc={r.returncode}',file=sys.stderr)
 report=dict(shards=len(paths),failed_shards=sum(x['returncode']!=0 or not x['valid_summary'] for x in results),results=results)
 (a.out/'summary.json').write_text(json.dumps(report,indent=2));print(json.dumps({k:v for k,v in report.items() if k!='results'}));return int(failed)
if __name__=='__main__':raise SystemExit(main())
