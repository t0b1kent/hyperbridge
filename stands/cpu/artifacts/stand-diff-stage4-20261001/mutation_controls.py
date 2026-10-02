#!/usr/bin/env python3
"""Six actual ARM64 code-generation mutations, controlled on saved real inputs."""
import argparse
import collections
import concurrent.futures
import json
import os
import pathlib
import subprocess
import sys
import time
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]/'stand-diff-20260930'))
from evidence_io import iter_lines

OWN=pathlib.Path(__file__).resolve().parent
BASE=OWN.parent/'stand-diff-20260930'
sys.path.insert(0,str(OWN))
from real_inputs import sha
from parallel_replay import policy

MODES={
    'flags':lambda r:any(t[2] in ['cmp','test','add','sub'] for t in r['reference']['trace']),
    'sign_extend':lambda r:any(t[2] in ['movsx','movsxd'] for t in r['reference']['trace']),
    'operand_width':lambda r:any(t[2] in ['lea','add','sub'] for t in r['reference']['trace']),
    'store_omitted':lambda r:bool(r['reference']['written_memory']),
    'register_write_omitted':lambda r:any(t[2] in ['xor','pxor','xorps','xorpd'] for t in r['reference']['trace']),
    'sse_rounding':lambda r:any(t[2] in ['cvtss2si','cvtsd2si','cvttss2si','cvttsd2si','cvtps2dq','cvttps2dq','cvtpd2dq','cvttpd2dq'] for t in r['reference']['trace']),
}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--out',type=pathlib.Path,default=OWN/'out/mutations')
    ap.add_argument('--detach',action='store_true')
    ap.add_argument('--workers',type=int);a=ap.parse_args()
    workers,priority=policy(a.workers)
    mutant_runner=OWN/'stand_runner_ec_sparse_rw_mutants'
    if a.detach:
        with a.out.with_suffix('.driver.log').open('x') as stream:
            p=subprocess.Popen([sys.executable,str(pathlib.Path(__file__)),*[x for x in sys.argv[1:] if x!='--detach']],
                               stdin=subprocess.DEVNULL,stdout=stream,stderr=stream,start_new_session=True)
        print('MUTATION_PID',p.pid);return 0
    accepted=json.loads((BASE/'out/STAGE3-FINAL-20261001.json').read_text())
    manifest=json.loads((BASE/'stage3-manifest.json').read_text())
    selections={m:{} for m in MODES}
    for g,result in zip(manifest['games'],accepted['games']):
        raw=(BASE.parents[1]/result['summary']).with_suffix('.jsonl')
        for line in iter_lines(raw):
            r=json.loads(line)
            if r.get('classification')!='EQUAL':continue
            for mode,predicate in MODES.items():
                chosen=selections[mode].setdefault(g['game'],[])
                if len(chosen)<12 and predicate(r):chosen.append(r['state']['sequence'])
    started=time.monotonic()
    def run_mode(mode):
        attempts=[];caught=False;activated=0
        for game in manifest['games']:
            selected=selections[mode].get(game['game'],[])
            if not selected:continue
            stem=pathlib.Path(str(a.out)+'-'+mode+'-'+game['game'])
            sf=pathlib.Path(str(stem)+'-sequences.json');sf.write_text(json.dumps(selected)+'\n')
            common=[sys.executable,str(OWN/'real_inputs_batch.py'),'--states',str(BASE/game['states']),
                    '--image',str(BASE/game['image']),'--capture',str(BASE/game['capture']),
                    '--sequences',str(sf),'--limit','100000','--known-mxcsr-1f80-1fa0']
            summaries={};commands={}
            for kind,runner in [('baseline',str(mutant_runner)),('mutation',str(mutant_runner))]:
                prefix=pathlib.Path(str(stem)+'-'+kind);env=os.environ.copy();env.pop('STAND_CODEGEN_MUTATION',None)
                if kind=='mutation':env['STAND_CODEGEN_MUTATION']=mode
                cmd=[*priority,*common,'--runner',str(OWN/runner),'--out-prefix',str(prefix)]
                commands[kind]=cmd
                with prefix.with_suffix('.driver.log').open('x') as stream:
                    rc=subprocess.run(cmd,env=env,stdin=subprocess.DEVNULL,stdout=stream,stderr=stream,timeout=180).returncode
                d=json.loads(prefix.with_suffix('.json').read_text());summaries[kind]=(prefix,d,rc)
            bp,baseline,brc=summaries['baseline'];mp,mutant,mrc=summaries['mutation']
            good={}
            for line in iter_lines(bp.with_suffix('.jsonl')):
                r=json.loads(line)
                if r.get('classification')=='EQUAL':good[r['state']['sequence']]=r
            emissions=sum(1 for line in mp.with_suffix('.log').open() if line.startswith('STAND_MUTATION_EMIT'))
            activated+=emissions;trigger=None
            for line in iter_lines(mp.with_suffix('.jsonl')):
                r=json.loads(line);seq=r['state']['sequence']
                if seq in good and (r.get('classes') or (r.get('native') and not r['native'].get('state_valid') and
                   r['native'].get('status') not in ['host_code_collision','guest_image_mapping_FAILED','watch_mapping_FAILED'])):
                    trigger=dict(sequence=seq,code=r['code'],classification=r.get('classification'),classes=r.get('classes'),
                                 native_status=r.get('native',{}).get('status'),baseline=str(bp),mutation=str(mp),
                                 reproduce=['env','STAND_CODEGEN_MUTATION='+mode,*commands['mutation'], '--sequence',str(seq)])
                    break
            caught=bool(trigger and emissions and not baseline['new_classes'])
            attempts.append(dict(game=game['game'],baseline_rc=brc,mutation_rc=mrc,
                                 baseline_checked=baseline['counts'].get('checked',0),emissions=emissions,trigger=trigger))
            if caught:break
        print('MUTATION',mode,'CAUGHT' if caught else 'NOT_CAUGHT','emissions',activated,flush=True)
        return dict(mode=mode,caught=caught,emissions=activated,attempts=attempts)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results=list(pool.map(run_mode,MODES))
    caught=sum(r['caught'] for r in results)
    output=dict(total=len(results),caught=caught,percent=100*caught/len(results),results=results,
                seconds=time.monotonic()-started,workers=workers,sha256={str(p):sha(p) for p in [OWN/'stand_runner_ec_sparse_rw',
                mutant_runner,OWN/'fexmac/mutant-JIT.cpp',pathlib.Path(__file__)]},
                boundaries=['Mutations modify emitted ARM64 instructions; oracle and output comparison are unchanged.',
                            'Only a mutation with activation and an EQUAL baseline of the exact trigger counts as caught.',
                            'NOT_CAUGHT/zero activation remain explicit blind spots, not successful controls.'])
    a.out.with_suffix('.json').write_text(json.dumps(output,indent=2)+'\n')
    print('MUTATIONS',caught,'/',len(results),a.out.with_suffix('.json'))
    return int(caught!=len(results))

if __name__=='__main__':raise SystemExit(main())
