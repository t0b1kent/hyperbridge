#!/usr/bin/env python3
"""Build cumulative patch stages; demand red immediately before each fix and green after.
This checks minimal causal witnesses, not the complete corpus. Use run_suite.py
for the full test matrix. Patches must be applied in numeric order.
"""
import argparse,importlib,json,os,shutil,subprocess,sys,tempfile
from pathlib import Path
from run_suite import build
T=Path(__file__).resolve().parent
BASE=dict(op='scalar_rhs',arch=1,lean=0,pinned=1,fused=1,width=4,shape=0,disp=0,scale=1,target=0)
CASES=[{},dict(lean=1),dict(op='xor',shape=1,scale=4,width=8,base=0xfffffff0,index=0x10),dict(pinned=0,fused=0,disp=4096,base=0xfffffff0,index=0x10),dict(op='lock_add',arch=0,lean=1,pinned=0,fused=0,width=8),dict(op='lock_add'),dict(op='lock_sub',fused=0),dict(op='regxor',arch=0,lean=1,pinned=0,fused=0,width=8),dict(op='copy_count',arch=0,lean=0,pinned=0,fused=0,width=1,shape=0,disp=4095,scale=1,target=0,variant='normal')]

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--repo',type=Path,required=True);p.add_argument('--baseline',type=Path,required=True);p.add_argument('--patch-dir',type=Path,required=True);p.add_argument('--out',type=Path,default=T/'out/negative-controls.json');a=p.parse_args()
 patches=sorted(a.patch_dir.resolve().glob('[0-9][0-9]-*.patch'))
 if len(patches)!=9:raise SystemExit('Expected the nine numbered patches.')
 repo=a.repo.resolve();records=[]
 with tempfile.TemporaryDirectory(prefix='hb-ea-negative-') as tmp:
  root=Path(tmp);(root/'src').mkdir();current=root/'src/hb_arm64_codegen.c';shutil.copyfile(a.baseline,current)
  env=build(repo,current,root/'stage00');os.environ['HB_EA_ORACLE']=env['HB_EA_ORACLE']
  t=importlib.import_module('hb_ea_live_test');extra=importlib.import_module('hb_ea_extra_test');before=root/'stage00/emitter'
  av=(0x1122334455667788,0x8877665544332211);bv=(0x23456789abcdef01,0xfedcba9876543210)
  for index,(patch,changes) in enumerate(zip(patches,CASES),1):
   subprocess.run(['patch','--batch','--forward','-p1','-i',str(patch)],cwd=root,check=True,stdout=subprocess.DEVNULL)
   out=root/f'stage{index:02d}';out.mkdir();after=out/'emitter'
   subprocess.run(['sh',str(T/'build.sh'),str(after),str(current)],env=dict(os.environ,HB_EA_REPO=str(repo)),check=True)
   case=dict(BASE,**changes);r=dict(fix=f'F{index:02d}',case=case,stages=[])
   for which,binary in [('before',before),('after',after)]:
    j=t.generate(binary,case['op'],case['shape'],case['disp'],case['arch'],case['lean'],case['pinned'],case['width'],case['scale'],case['target'],case['fused'])
    if not j['emitted']:raise RuntimeError(f'{r["fix"]}: emitter declined witness')
    try:
     errors,details=extra.run(j,case) if index==9 else t.run(j,case,av,bv);status='mismatch' if errors else 'pass'
    except t.Fault as e:status='fault';errors=[str(e)];details={}
    r['stages'].append(dict(stage=which,status=status,errors=errors,details=details,emission=j))
   if r['stages'][0]['status'] not in ('fault','mismatch') or r['stages'][1]['status']!='pass':raise RuntimeError('Invalid negative control: '+json.dumps(r))
   records.append(r);print(r['fix']+': '+r['stages'][0]['status']+' -> pass');before=after
  t.close_servers()
 a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(records,indent=2)+'\n');return 0
if __name__=='__main__':raise SystemExit(main())
