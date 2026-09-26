#!/usr/bin/env python3
"""Unit controls for runner extension and JSON checker; NOT a full ARM runner."""
from pathlib import Path
import argparse,json,subprocess,sys,tempfile
from install_runner_extension import EDITS,transform

def main():
 a=argparse.ArgumentParser();a.add_argument('--include',type=Path,required=True);a.add_argument('--report',type=Path,required=True);args=a.parse_args()
 here=Path(__file__).resolve().parent;report={'full_ARM_runner_executed':False,'controls':[]}
 with tempfile.TemporaryDirectory() as td:
  root=Path(td);exe=root/'extension_test'
  subprocess.run(['clang','-O2','-Wall','-Wextra','-Wno-unused-function','-I'+str(args.include.resolve()),str(here/'runner_extension_test.c'),'-o',str(exe)],check=True)
  output=subprocess.check_output([str(exe)],text=True);report['header_test_log']=output
  # This fixture deliberately only tests the guarded patch machinery and its
  # exact anchors. It is NOT represented as a fetched full runner source file.
  fragment='\n'.join(old for _,old,_ in EDITS)
  fragment+='\nstatic hb_result_t run_backend(int arch, int backend) { return arch + backend; }\nstatic const char* reg_name(int a) { return 0; }\n'
  new=transform(fragment)
  assert 'run_backend_sse_inner' in new and '#include "hb_sse_oracle/runner_extension.h"' in new
  try:transform(new)
  except ValueError:pass
  else:raise AssertionError('double apply must be rejected')
  report['controls'].append({'name':'guarded_patch_fragment_transform_and_double_apply','passed':True,'full_source_compiled':False})
  cases=root/'input.cases';cases.write_text('0 f30f58c1 1 sse-id=1\n0 f30f58c1 1 sse-id=2\n')
  def row(i):return {'ok':True,'sse_oracle':{'id':i,'seed_ok':True,'interp_values_ok':True,'jit_values_ok':True,'mxcsr_expected_exc':0,'interp_mxcsr_exc':63,'jit_mxcsr_exc':1}}
  samples=[]
  samples.append(('positive_exception_diagnostic_only',[row(1),row(2)],[],0))
  q=[row(1),row(2)];q[0]['sse_oracle']['interp_values_ok']=False;q[0]['sse_oracle']['jit_values_ok']=False;q[0]['ok']=False
  samples.append(('both_engines_wrong',q,[],1));samples.append(('intentional_negative_control',q,['--expect-value-failure'],0))
  samples.append(('missing_case',[row(1)],[],1));samples.append(('duplicate_case',[row(1),row(1)],[],1))
  samples.append(('old_runner_missing_oracle_fields',[{'ok':True},{'ok':True}],[],1))
  q=[row(1),row(2)];q[0]['sse_oracle']['seed_ok']=False;samples.append(('lost_seed',q,[],1))
  samples.append(('zero_rows_negative_is_not_success',[],['--expect-value-failure'],1))
  for name,rows,extra,want in samples:
   p=subprocess.run([sys.executable,str(here/'check_runner_output.py'),'--cases',str(cases),*extra],input='\n'.join(json.dumps(x) for x in rows)+'\n',text=True,capture_output=True)
   assert p.returncode==want,(name,p.returncode,p.stdout,p.stderr)
   report['controls'].append({'name':name,'passed':True,'expected_exit':want,'actual_exit':p.returncode,'synthetic_JSON_input':True})
 args.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':True,'controls':len(report['controls'])}))
if __name__=='__main__':main()
