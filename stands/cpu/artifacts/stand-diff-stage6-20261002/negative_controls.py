#!/usr/bin/env python3
"""Real runner post-execution status mutations: extra ZE and lost input PE.

The second input is an explicitly derived control, never credited as real corpus.
FEX, product binaries, and raw recordings remain untouched.
"""
import argparse
import hashlib
import json
import os
import pathlib
import struct
import subprocess
import sys

OWN=pathlib.Path(__file__).resolve().parent
ROOT=OWN.parents[1]
sys.path.insert(0,str(OWN.parent/'stand-diff-stage5-20261001'))
import fast_replay
from evidence_io import open_binary,open_text


def main():
    ap=argparse.ArgumentParser();ap.add_argument('runner',type=pathlib.Path)
    ap.add_argument('--out-dir',type=pathlib.Path,default=OWN);a=ap.parse_args()
    a.out_dir.mkdir(parents=True,exist_ok=True)
    dataset=json.loads((OWN.parent/'stand-diff-stage5-20261001/dataset.json').read_text())
    game=dataset['games'][0]
    with open_text(OWN/'quick-accepted-r1-hk.jsonl') as stream:
        example=next(json.loads(line) for line in stream)
    sequence=example['state']['sequence']
    with open_binary(game['states']) as source:
        header=source.read(24);_,size,length,_=struct.unpack_from('<4I',header,8)
        metadata=source.read(length)
        while True:
            raw=source.read(size)
            if not raw:raise ValueError('control entry absent')
            if struct.unpack_from('<Q',raw,8)[0]==sequence:break
    initial=struct.unpack_from('<I',raw,44)[0]
    derived=bytearray(raw);struct.pack_into('<I',derived,44,initial|0x20)
    states=a.out_dir/'CONTROL-DERIVED-INPUT-PE.hbstates'
    with states.open('xb') as stream:stream.write(header+metadata+derived)
    adapter=OWN/'fast_replay_flags.py';rows=[]
    for name,mutation,control in [('mutant-baseline',None,False),('extra-ze','extra_ze',False),
                                  ('sticky-baseline',None,True),('drop-input-pe','drop_input_pe',True)]:
        prefix=a.out_dir/name
        if control:
            command=[sys.executable,str(adapter),'--runner',str(a.runner.resolve()),'--states',str(states),
                     '--image',game['image'],'--capture',game['capture'],'--game','hk','--limit','1',
                     '--out-prefix',str(prefix),'--scan-all']
        else:
            command=[str(ROOT/'scripts/hb-stand-diff.sh'),'--quick',str(a.runner.resolve()),
                     '--adapter',str(adapter),'--out',str(prefix)]
        env=os.environ.copy();env.pop('STAND_DIFF_FLAG_MUTATION',None)
        if mutation:env['STAND_DIFF_FLAG_MUTATION']=mutation
        with prefix.with_suffix('.control.log').open('x') as log:
            result=subprocess.run(command,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=log)
        report=json.loads(prefix.with_suffix('.json').read_text())
        rows.append(dict(control=name,mutation=mutation,rc=result.returncode,report=str(prefix.with_suffix('.json')),
                         new=report.get('new',report.get('new_classes')),known=report.get('known',report.get('known_classes'))))
    passed=[r['rc'] for r in rows]==[0,1,0,1] and all(r['new'].get('mxcsr') for r in rows if r['mutation'])
    receipt=dict(status='PASS' if passed else 'FAIL',detected=2 if passed else None,total=2,rows=rows,
                 runner=str(a.runner.resolve()),runner_sha256=hashlib.sha256(a.runner.read_bytes()).hexdigest(),
                 derived_control=dict(sequence=sequence,source=game['states'],source_sha256=game['sha256'][game['states']],
                                      modification='HBSTATE1 record offset44 MXCSR |=0x20, other bytes unchanged',
                                      path=str(states),sha256=hashlib.sha256(states.read_bytes()).hexdigest()),
                 boundary='Post-execution guest-state mutations in own frontend; no FEX code-generation mutation or product deployment.')
    (a.out_dir/'NEGATIVE-CONTROLS.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt));return int(not passed)


if __name__=='__main__':raise SystemExit(main())
