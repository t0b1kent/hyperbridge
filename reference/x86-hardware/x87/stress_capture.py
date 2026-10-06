#!/usr/bin/env python3
"""Original MIT reproducible isolation stress protocol; writes diagnostics only under build/stress/."""
import pathlib,argparse,subprocess,json
p=pathlib.Path(__file__).resolve().parent
ap=argparse.ArgumentParser();ap.add_argument('--runs',type=int,default=100);args=ap.parse_args();assert 1<=args.runs<=1000
b=p/'build'/'stress';b.mkdir(exist_ok=True)
ref=subprocess.check_output([str(p/'build/oracle'),'environment'],stderr=subprocess.DEVNULL)
events=[];filtered_equal=0
for filtered,option in ((True,'--timing'),(False,'--timing-unfiltered')):
 for trial in range(1,args.runs+1):
  result=subprocess.run([str(p/'build/oracle'),'environment',option],capture_output=True,check=True)
  mode='filtered'if filtered else'unfiltered';(b/f'{mode}-{trial}.txt').write_bytes(result.stdout);(b/f'{mode}-{trial}.log').write_bytes(result.stderr)
  if filtered:
   if result.stdout!=ref:raise SystemExit(f'Filtered trial {trial} differs; preserve diagnostics and investigate, do not patch records')
   filtered_equal+=1
  else:
   times={}
   for line in result.stderr.decode().splitlines():
    if line.startswith('timing '):
     t=line.split();kv=dict(x.split('=')for x in t[2:]);times[t[1],kv['cw'],kv['case']]=kv
   for a,z in zip(ref.decode().splitlines(),result.stdout.decode().splitlines()):
    if a==z:continue
    t=z.split();meta=dict(x.split('=',1)for x in t[12:]);events.append(dict(trial=trial,reference_row=a,observed_row=z,timing=times[t[0],t[1],meta['CASE']]))
summary=dict(filtered_trials=args.runs,filtered_identical=filtered_equal,unfiltered_trials=args.runs,unfiltered_differences=events)
(b/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(f'Filtered trials identical: {filtered_equal}/{args.runs}; unfiltered differing rows: {len(events)}; details in build/stress/summary.json')
