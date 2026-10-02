#!/usr/bin/env python3
"""Bounded JIT versus Unicorn gates on identical saved real inputs; no Wine."""
import argparse
import collections
import concurrent.futures
import datetime
import json
import os
import pathlib
import subprocess
import sys
import time

OWN=pathlib.Path(__file__).resolve().parent
ROOT=OWN.parents[1]
sys.path.insert(0,str(OWN))
from real_inputs import sha
from evidence_io import exists, open_text
from parallel_replay import policy, tasks_for, run_task, merge

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    mode=ap.add_mutually_exclusive_group(required=True)
    mode.add_argument('--quick',action='store_true');mode.add_argument('--full',action='store_true')
    ap.add_argument('runner',type=pathlib.Path)
    ap.add_argument('--dataset',type=pathlib.Path,default=OWN.parent/'stand-diff-stage5-20261001/dataset.json')
    ap.add_argument('--adapter',type=pathlib.Path,default=OWN.parent/'stand-diff-stage5-20261001/fast_replay.py')
    ap.add_argument('--out',type=pathlib.Path)
    ap.add_argument('--detach',action='store_true')
    ap.add_argument('--workers',type=int,help='Total process workers; daytime max4, nighttime max6')
    ap.add_argument('--batch-size',type=int,default=4096)
    ap.add_argument('--resume',type=pathlib.Path,help='Full only: reuse completed shards with identical candidate/input/source SHA; preserve interrupted evidence')
    a=ap.parse_args()
    parent_engine_env={k:v for k,v in os.environ.items() if k.startswith(('FEX_','MACRUNNER_FEX_','STAND_DIFF_'))}
    if a.quick and a.resume:ap.error('--resume applies only to full')
    workers,priority=policy(a.workers)
    start=time.monotonic()
    out=a.out or OWN/'out'/('gate-'+str(time.time_ns()))
    if a.detach:
        with out.with_suffix('.driver.log').open('x') as stream:
            argv=[*priority,sys.executable,str(pathlib.Path(__file__)),*[x for x in sys.argv[1:] if x!='--detach']]
            if a.out is None:argv+=['--out',str(out)]
            child=subprocess.Popen(argv,cwd=ROOT,stdin=subprocess.DEVNULL,stdout=stream,stderr=stream,start_new_session=True)
        print(json.dumps(dict(gate='HB_STAND_DIFF',status='RUNNING',pid=child.pid,report=str(out))))
        return 0
    rows=[];reason=None;known=collections.Counter();new=collections.Counter();fixed=collections.Counter();flag_counts=collections.Counter();checked=skipped=mapping_skipped=unavailable=flag_unavailable=0
    runner=a.runner.resolve();digest=None;dataset_digest=None;frozen={}
    try:
        dataset_digest=sha(a.dataset)
        for path in [pathlib.Path(__file__).resolve(),OWN/'parallel_replay.py']:
            frozen[str(path)]=sha(path)
        dataset=json.loads(a.dataset.read_text())
        names=[g['game'] for g in dataset['games']]
        if len(set(names))!=len(names) or not {'hk','hedon','abzu','divinity','stardew'}.issubset(names):
            raise ValueError('Dataset must contain all five base games exactly once')
        digest=sha(runner)
        tasks=[]
        for game in dataset['games']:
            prefix=pathlib.Path(str(out)+'-'+game['game'])
            game_tasks=tasks_for(game,runner,prefix,1 if a.quick else workers,quick=a.quick,batch_size=a.batch_size)
            for task in game_tasks:task['adapter']=str(a.adapter.resolve())
            if not a.quick and 'states_count' in game:
                for task in game_tasks:task['expected_states']=(game['states_count']+workers-1-task['shard_index'])//workers
            tasks.extend(game_tasks)
        if a.resume:
            verified={}
            for task in tasks:
                previous=pathlib.Path(str(a.resume)+'-'+task['game']+f"-part{task['shard_index']:02d}")
                saved=previous.with_suffix('.json')
                if not saved.exists():continue
                result=json.loads(saved.read_text())
                if result['counts']['states']!=task.get('expected_states'):raise ValueError('Resume shard count/partition drift')
                if result['runner_batch_size']!=task['batch_size']:raise ValueError('Resume batch size drift')
                for name,expected in result['inputs_sha256'].items():
                    if name not in verified:verified[name]=sha(pathlib.Path(name))
                    if verified[name]!=expected:raise ValueError('Resume input/source drift: '+name)
                if result['inputs_sha256'].get(str(runner))!=digest:raise ValueError('Resume candidate drift')
                for name in ['states','image','capture']:
                    if task[name] not in result['inputs_sha256']:raise ValueError('Resume corpus mismatch')
                if not exists(previous.with_suffix('.jsonl')):raise ValueError('Resume raw evidence absent')
                task.update(reuse_prefix=str(previous),reuse_summary_sha256=sha(saved))
        if a.quick:
            for task in tasks:task['deadline']=start+155
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            completed=list(pool.map(run_task,tasks))
        for game in dataset['games']:
            prefix=pathlib.Path(str(out)+'-'+game['game'])
            parts=[p for p in completed if p['task']['game']==game['game']]
            summary=merge(parts,prefix)
            for p,expected in game['sha256'].items():
                # Large raw inputs were already hashed by the adapter.
                actual=summary['inputs_sha256'].get(p)
                if actual is None:actual=sha(pathlib.Path(p))
                if actual!=expected:raise ValueError('Frozen input drift: '+p)
            counts=summary['counts'];n=counts.get('checked',0)
            k=summary['known_classes'];fresh=summary['new_classes']
            excluded=counts.get('states',0)-n
            status='PASS' if n and not fresh and not any(key.startswith('STOP_') for key in counts) else 'FAIL'
            if not a.quick and game.get('states_count') is not None and counts.get('states')!=game['states_count']:status='FAIL'
            collisions=sum(counts.get(key,0) for key in ['host_code_collision','guest_image_mapping_FAILED'])
            if a.quick and (n!=game['expected_quick'] or excluded!=collisions):status='FAIL'
            required=set(game.get('quick_required_sequences',[])) if a.quick else set()
            seen=set()
            if required:
                with open_text(prefix.with_suffix('.jsonl')) as stream:
                    for line in stream:
                        row=json.loads(line)
                        if row.get('native',{}).get('state_valid'):seen.add(row['state']['sequence'])
                if not required.issubset(seen):status='FAIL'
            if any(p['rc'] not in [0,1] for p in parts):status='FAIL'
            rows.append(dict(game=game['game'],status=status,checked=n,known=k,new=fresh,
                             new_count=counts.get('mismatch',0)-sum(k.values())+sum(v for key,v in fresh.items() if key.startswith('native_')),
                             fixed=summary.get('fixed_classes',{}),reference_unavailable=counts.get('reference_unavailable',0),
                             flags_reference_unavailable=counts.get('flags_reference_unavailable',0),
                             mxcsr_flags={k.removeprefix('mxcsr_flags_'):v for k,v in counts.items() if k.startswith('mxcsr_flags_')},
                             phase_seconds=summary.get('phase_seconds',{}),retry_counts=summary.get('retry_counts',{}),
                             skipped=excluded,mapping_skipped=collisions,coverage=summary['coverage'],summary=str(prefix.with_suffix('.json')),
                             summary_sha256=sha(prefix.with_suffix('.json')),required_sequences_checked=sorted(required&seen),
                             semantic_sha256=summary['semantic_sha256'],
                             argv=[p['argv'] for p in parts],rc=[p['rc'] for p in parts]))
            checked+=n;skipped+=excluded;mapping_skipped+=collisions;known.update(k);new.update(fresh)
            fixed.update(summary.get('fixed_classes',{}));unavailable+=counts.get('reference_unavailable',0)
            flag_unavailable+=counts.get('flags_reference_unavailable',0)
            flag_counts.update({k.removeprefix('mxcsr_flags_'):v for k,v in counts.items() if k.startswith('mxcsr_flags_')})
            if status!='PASS':reason=game['game']+' incomplete or new difference'
        for row in rows:
            for name,value in json.loads(pathlib.Path(row['summary']).read_text())['inputs_sha256'].items():
                if name in frozen and frozen[name]!=value:raise ValueError('global frozen source drift: '+name)
                frozen[name]=value
        for path in [pathlib.Path(__file__).resolve(),OWN/'parallel_replay.py']:
            if sha(path)!=frozen[str(path)]:raise ValueError('Gate source drift during execution: '+str(path))
        if sha(runner)!=digest:raise ValueError('Candidate binary drift during gate')
    except (OSError,ValueError,KeyError,TimeoutError,subprocess.TimeoutExpired) as exc:
        reason=type(exc).__name__+': '+str(exc)
    if a.quick and time.monotonic()-start > 180:reason='quick wall-clock deadline'
    status='PASS' if 'dataset' in locals() and len(rows)==len(dataset['games']) and all(r['status']=='PASS' for r in rows) and reason is None else 'FAIL'
    result=dict(gate='HB_STAND_DIFF',status=status,mode='quick' if a.quick else 'full',games=len(rows),
                checked=checked,known=dict(known),new=dict(new),skipped=skipped,mapping_skipped=mapping_skipped,
                fixed=dict(fixed),reference_unavailable=unavailable,
                flags_reference_unavailable=flag_unavailable,mxcsr_flags=dict(flag_counts),
                parent_engine_env=parent_engine_env,
                known_count=sum(known.values()),fixed_count=sum(fixed.values()),
                new_count=sum(r.get('new_count',0) for r in rows),
                seconds=round(time.monotonic()-start,3),runner=str(runner),runner_sha256=digest,
                dataset=str(a.dataset),dataset_sha256=dataset_digest,reason=reason,rows=rows,workers=workers,
                resumed_from=str(a.resume) if a.resume else None,reused_shards=sum(bool(t.get('reuse_prefix')) for t in tasks) if 'tasks' in locals() else 0,
                boundaries=['Saved entry registers and later memory snapshot have common temporal skew.',
                            'Coverage is the checked subset; skips are never credited.',
                            'GPU ownership and real EC/native transition remain outside this gate.'])
    import hashlib
    canonical=dict(games=[dict(game=r['game'],semantic_sha256=r['semantic_sha256']) for r in rows],
                   frozen_inputs=frozen,
                   runner_sha256=digest,dataset_sha256=dataset_digest,status=status,parent_engine_env=parent_engine_env)
    result['canonical_sha256']=hashlib.sha256(json.dumps(canonical,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    out.with_suffix('.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ['gate','status','mode','games','checked','known','known_count','fixed','fixed_count','new','new_count','reference_unavailable','flags_reference_unavailable','skipped','mapping_skipped','seconds','reason','canonical_sha256']}|
                     {'mxcsr_flags':{k:v for k,v in flag_counts.items() if k in ('states_executed','known','fixed','partial_fixed')}}|
                     {'report':str(out.with_suffix('.json'))},separators=(',',':')))
    return int(status!='PASS')

if __name__=='__main__':raise SystemExit(main())
