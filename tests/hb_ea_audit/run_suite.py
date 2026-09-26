#!/usr/bin/env python3
"""Run both bounded value corpora; --require-clean is the red-before control.
The native oracle is executed on Linux x86-64 with SSE4.1. No AArch64 or Wine
runtime execution is claimed. The source path can select an unmodified snapshot.
"""
import argparse,collections,json,os,platform,shutil,subprocess,sys
from pathlib import Path
T=Path(__file__).resolve().parent

def build(repo,source,out):
 if platform.system()!='Linux' or platform.machine()!='x86_64':
  raise RuntimeError('Requires Linux x86-64; the oracle must be native.')
 if 'sse4_1' not in Path('/proc/cpuinfo').read_text():raise RuntimeError('SSE4.1 is required by the native INSERTPS oracle.')
 if not shutil.which(os.environ.get('CC','clang')):raise RuntimeError('clang not found')
 out.mkdir(parents=True,exist_ok=True)
 env=dict(os.environ,HB_EA_REPO=str(repo),HB_EA_ORACLE=str(out/'oracle.so'))
 subprocess.run(['sh',str(T/'build.sh'),str(out/'emitter'),str(source)],env=env,check=True)
 subprocess.run([os.environ.get('CC','clang'),'-O2','-std=gnu11','-mno-red-zone','-msse4.1','-shared','-fPIC',str(T/'hb_ea_live_oracle.c'),'-o',str(out/'oracle.so')],check=True)
 return env

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--repo',type=Path,default=T.parent.parent)
 p.add_argument('--source',type=Path)
 p.add_argument('--out',type=Path,default=T/'out')
 p.add_argument('--require-clean',action='store_true')
 a=p.parse_args();repo=a.repo.resolve();source=(a.source or repo/'src/hb_arm64_codegen.c').resolve();out=a.out.resolve()
 try:env=build(repo,source,out)
 except (OSError,RuntimeError,subprocess.CalledProcessError) as e:print(str(e),file=sys.stderr);return 2
 combined=collections.Counter();runs={}
 for name,script in [('main','hb_ea_live_test.py'),('extra','hb_ea_extra_test.py')]:
  cmd=[sys.executable,str(T/script),'--emitter',str(out/'emitter'),'--out',str(out/(name+'.json')),'--require-clean']
  with (out/(name+'.log')).open('w') as log:rc=subprocess.run(cmd,env=env,stdout=log,stderr=subprocess.STDOUT).returncode
  if rc not in (0,1):print('Harness error; inspect '+str(out/(name+'.log')),file=sys.stderr);return 2
  try:j=json.loads((out/(name+'.json')).read_text())['summary']
  except (OSError,ValueError):print('Missing results; inspect '+str(out/(name+'.log')),file=sys.stderr);return 2
  runs[name]=j;combined.update(j['counts'])
 summary=dict(source=str(source),counts=dict(combined),runs=runs)
 (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2))
 bad=sum(combined[k] for k in ['fault','mismatch','unsupported','unmodeled-call-route'])
 return 1 if a.require_clean and bad else 0
if __name__=='__main__':raise SystemExit(main())
