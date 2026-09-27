#!/usr/bin/env python3
"""Reproduce the checkpoint's native regression and decoded-source tests on Apple Silicon."""
import json,os,platform,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'build/source03-checkpoint'
def main():
    if platform.system()!='Darwin' or platform.machine()!='arm64':
        raise SystemExit('This native checkpoint was validated on macOS ARM64.')
    OUT.mkdir(parents=True,exist_ok=True)
    env={k:v for k,v in os.environ.items() if not k.startswith('MACRUNNER_HB_')}
    env.update(MACRUNNER_HB_MEM_SEGV_JIT_DOOR='1',MACRUNNER_HB_STATIC_REGS='0',
               MACRUNNER_HB_SMC_PROTECT='0',MACRUNNER_HB_SMC_EXACT_BYTES='1',
               MACRUNNER_HB_SMC_EXACT_LAZY='1',MACRUNNER_HB_CHAIN_PRUNE_DENIED='1')
    records=[]
    def run(label,args,extra=None):
        e=dict(env);e.update(extra or {})
        with (OUT/(label+'.log')).open('wb') as f:
            r=subprocess.run([str(a) for a in args],cwd=ROOT,env=e,stdout=f,stderr=subprocess.STDOUT,timeout=180)
        records.append({'label':label,'rc':r.returncode})
        if r.returncode:raise RuntimeError(label+' failed; see '+str(OUT/(label+'.log')))
    try:
        run('build',['make','-j1','CC=clang','libhyperbridge.a'])
        for name in ['native_regressions','source_provenance']:
            source=ROOT/'tests/hb_test_runner.c' if name=='native_regressions' else Path(__file__).with_name(name+'.c')
            run('compile-'+name,['clang','-O2','-std=c11','-D_DARWIN_C_SOURCE','-Iinclude','-Isrc',source,'libhyperbridge.a','-lpthread','-lm','-o',OUT/name])
        for source in ['0','1']:
            e={'MACRUNNER_HB_DECODED_SOURCE':source}
            run('native-source'+source,[OUT/'native_regressions'],e)
            for merge in ['0','1']:
                run('provenance-source'+source+'-merge'+merge,[OUT/'source_provenance'],dict(e,MACRUNNER_HB_MERGE_BLOCKS=merge))
    finally:
        (OUT/'RESULT.json').write_text(json.dumps(records,indent=2)+'\n')
    print('Native checkpoint checks passed; logs: '+str(OUT))
if __name__=='__main__':main()
