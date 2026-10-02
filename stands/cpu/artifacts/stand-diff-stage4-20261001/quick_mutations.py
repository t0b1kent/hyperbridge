#!/usr/bin/env python3
"""Exercise the actual five-game quick CLI with six gated ARM64 emitter errors."""
import json
import os
import pathlib
import subprocess
import sys
import time
from mutation_controls import MODES

OWN=pathlib.Path(__file__).resolve().parent
ROOT=OWN.parents[1]


def main():
    stamp=str(time.time_ns());base=OWN/'out'/('quick-mutations-'+stamp)
    runner=OWN/'stand_runner_ec_sparse_rw_mutants'
    rows=[];baseline=None
    for mode in [None,*MODES]:
        prefix=pathlib.Path(str(base)+'-'+(mode or 'baseline'))
        env=os.environ.copy();env.pop('STAND_CODEGEN_MUTATION',None)
        if mode:env['STAND_CODEGEN_MUTATION']=mode
        command=[str(ROOT/'scripts/hb-stand-diff.sh'),'--quick',str(runner),'--out',str(prefix)]
        with prefix.with_suffix('.cli.log').open('x') as stream:
            rc=subprocess.run(command,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,
                              stdout=stream,stderr=stream,timeout=180).returncode
        result=json.loads(prefix.with_suffix('.json').read_text())
        emissions=sum(line.startswith('STAND_MUTATION_EMIT')
                      for path in OWN.glob('out/'+prefix.name+'-*-part*.log') for line in path.open())
        if mode is None:baseline=result;passed=rc==0 and result['status']=='PASS'
        else:passed=(baseline['status']=='PASS' and rc==1 and result['status']=='FAIL' and emissions>0
                     and result['dataset_sha256']==baseline['dataset_sha256']
                     and result['runner_sha256']==baseline['runner_sha256'])
        rows.append(dict(mode=mode or 'baseline',passed=passed,rc=rc,emissions=emissions,
                         report=str(prefix.with_suffix('.json')),seconds=result['seconds'],new=result['new']))
        print(json.dumps(rows[-1],separators=(',',':')),flush=True)
    caught=sum(r['passed'] for r in rows[1:])
    result=dict(total=6,caught=caught,percent=100*caught/6,baseline_passed=rows[0]['passed'],rows=rows,
                seconds=sum(r['seconds'] for r in rows),dataset_sha256=baseline['dataset_sha256'],
                runner_sha256=baseline['runner_sha256'])
    base.with_suffix('.json').write_text(json.dumps(result,indent=2)+'\n')
    print('QUICK_MUTATIONS',caught,'/6',base.with_suffix('.json'))
    return int(caught!=6 or not result['baseline_passed'])


if __name__=='__main__':raise SystemExit(main())
