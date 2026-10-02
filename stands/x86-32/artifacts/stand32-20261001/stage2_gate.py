#!/usr/bin/env python3
"""STAND32 stage2: explicit known list, deterministic paired batch replay."""
import argparse,collections,datetime,hashlib,json,os,pathlib,shutil,subprocess,time
import batch_replay as batch
import evidence_io as io
import stand32 as s
OWN=pathlib.Path(__file__).resolve().parent
ACCEPTED={'EQUAL','FIXED','KNOWN','REFERENCE_GAP','EMPTY_RAW80'}
INPUT_GAPS={'MEMORY_NOT_PRESENT'}

def failure_counts(counts):
    # Missing source bytes invalidate the replay, but are not engine findings.
    return (sum(n for key,n in counts.items() if key not in ACCEPTED|INPUT_GAPS),
            sum(counts.get(key,0) for key in INPUT_GAPS))

def outcome(counts,complete,mutations,strict=False):
    unknown=sum(n for key,n in counts.items() if key not in ACCEPTED)
    strict_bad=sum(n for key,n in counts.items() if key not in {'EQUAL','FIXED'})
    return complete and mutations and unknown==0 and (not strict or strict_bad==0)

def checked_coverage(cases,rows,translated_blocks=None):
    by_id={case['id']:case['state']['rip'] for case in cases}
    checked={by_id[row['id']] for row in rows if row['id'] in by_id
             and row['classification'] in {'EQUAL','FIXED','KNOWN','EMPTY_RAW80','NEW'}
             and any(attempt.get('status') in {'exit','EXIT_SPAN'} for attempt in row.get('attempts',[]))}
    return dict(checked_block_starts=len(checked),translated_block_starts=translated_blocks,
                percent=100*len(checked)/translated_blocks if translated_blocks else None,
                denominator_status='PRESENT' if translated_blocks else 'NOT_PROVIDED',
                rule='distinct translated RIPs with completed oracle/native comparison; reference gaps and timeouts excluded')

def per_capture_coverage(cases,rows,captures):
    denominators={c['states']:c for c in captures}
    aliases={}
    for capture in captures:
        for source in [capture['states'],*capture.get('aliases',[])]:
            if source in aliases and aliases[source]!=capture['states']:raise ValueError('ambiguous capture alias')
            aliases[source]=capture['states']
    grouped=collections.defaultdict(list)
    for case in cases:
        source=case.get('source',{}).get('states');grouped[aliases.get(source,source)].append(case)
    result=[]
    for source,subset in sorted(grouped.items(),key=lambda item:str(item[0])):
        ids={case['id'] for case in subset};metadata=denominators.get(source,{})
        result.append(dict(states_source=source,states=len(subset),
            **checked_coverage(subset,[r for r in rows if r['id'] in ids],metadata.get('translated_blocks'))))
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--quick',action='store_true');g.add_argument('--full',action='store_true')
    p.add_argument('--runner',type=pathlib.Path,required=True);p.add_argument('--strict',action='store_true')
    p.add_argument('--dataset',type=pathlib.Path,default=OWN/('dataset-stage2.json' if (OWN/'dataset-stage2.json').exists() else 'dataset-low32.json'))
    p.add_argument('--workers',type=int);a=p.parse_args()
    started=time.monotonic();deadline=started+160 if a.quick else None
    harness_files=['stage2_gate.py','batch_replay.py','owned_cpu.py','stand32.py','known_defects.py','adjudicate.py','independent_x87.py','x87_instructions.py','evidence_io.py','memory_store.py','manifest_pack.py']
    harness_sha={name:io.sha(OWN/name) for name in harness_files}
    now=datetime.datetime.now();daytime=(7,0)<=(now.hour,now.minute)<(23,30)
    workers=a.workers or (4 if daytime else 6)
    if not 1<=workers<=(4 if daytime else 6):raise ValueError('worker cap')
    nice=5 if daytime else 0
    if nice>os.getpriority(os.PRIO_PROCESS,0):os.nice(nice-os.getpriority(os.PRIO_PROCESS,0))
    if shutil.disk_usage(OWN).free<40*1024**3:print('STAND32 FAIL known=0 fixed=0 reference_gap=0 new=0 missing=export_volume<40GiB');return 1
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ');out=OWN/'out'/('gate2-'+stamp);out.mkdir(parents=True)
    jobs=[];metadata=[];selected_games={};error=None;replay={};mutations=[];missing=[]
    def add(source,label,cases=None,bases=None):
        source=pathlib.Path(source).resolve();cases=io.read_json(source) if cases is None else cases
        if isinstance(cases,dict):cases=cases['cases']
        for case in cases:
            selected=bases or ['0','0x80000000000']
            if label=='directed' and case['id']==14:selected=['0x80000000000']
            jobs.append(dict(case=case,label=label,source=str(source),bases=selected))
        return cases
    try:
        directed=add(OWN/'fixtures/directed-low32.json','directed')
        add(OWN/'fixtures/x87-two-to-one-env.json','x87-family')
        add(OWN/'fixtures/x87-env-family.json','x87-env-family')
        if a.full:add(OWN/'fixtures/pe-extracted.json','pe')
        dataset=io.read_json(a.dataset)
        for game in dataset['games']:
            source=(a.dataset.parent/game['cases']).resolve();original=io.read_json(source)
            if isinstance(original,dict):original=original['cases']
            if not original or any(c.get('origin')!='GAME_CAPTURE' for c in original):raise ValueError('real capture missing')
            if game.get('cases_sha256') and io.sha(source)!=game['cases_sha256']:raise ValueError('frozen corpus changed')
            recorded_states=len(original);excluded_input_states=0;admission_path=None
            if game.get('admission'):
                admission_path=(a.dataset.parent/game['admission']).resolve()
                if io.sha(admission_path)!=game['admission_sha256']:raise ValueError('source admission changed')
                admission=io.read_json(admission_path)
                recorded_states=admission['recorded_states'];excluded_input_states=admission['excluded_count']
                if admission['admitted_states']!=len(original) or recorded_states!=len(original)+excluded_input_states:
                    raise ValueError('source admission count mismatch')
            if a.quick:
                ids=game.get('quick_case_ids',[c['id'] for c in original[:12]])
                index={c['id']:c for c in original};selected=[index[i] for i in ids]
                if len(selected)>32:raise ValueError('quick cap')
            else:selected=original
            selected_games[game['id']]=selected
            add(source,'game-'+game['id'],selected)
            metadata.append(dict(game=game['id'],available_states=len(original),states=len(selected),
                recorded_states=recorded_states,excluded_input_states=excluded_input_states,admission=str(admission_path) if admission_path else None,
                cases_sha256=game.get('cases_sha256'),
                blocks=len({c['state']['rip'] for c in selected}),recording_grade=game.get('recording_grade'),
                control_grade=game.get('control_grade'),coverage=game.get('coverage'),memory_at_state=game.get('memory_at_state')))
            if game.get('recording_grade')!='PASS' or game.get('memory_at_state')!='COHERENT':missing.append(game['id']+': coherent capture admission')
        replay=batch.replay(jobs,a.runner,out/'replay',workers,nice=nice,deadline=deadline)
        # Instrument controls are fixed owned corrupted builds, not mutations of
        # the supplied runner. Their exact raw outputs remain separate evidence.
        for name,ident in [('base',2),('sign',13),('carry4g',14),('x87_rounding',9),('x87_stack_order',8)]:
            source=OWN/'fixtures/carry-disp8-disp32.json' if name=='carry4g' else OWN/'fixtures/directed-low32.json'
            cases=io.read_json(source) if name=='carry4g' else [c for c in directed if c['id']==ident]
            runner=OWN/('stand_runner32_x87_mutants' if name.startswith('x87_') else 'stand_runner32')
            mjobs=[dict(case=c,label=name,source=str(source),bases=['0x80000000000']) for c in cases]
            control=batch.replay(mjobs,runner,out/('control-'+name),1,nice=nice,admit_known=False,deadline=deadline)
            mutant=batch.replay(mjobs,runner,out/('mutant-'+name),1,nice=nice,mutation=name,admit_known=False,deadline=deadline)
            detected=all(not r['diff'] for r in control['results']) and all(bool(r['diff']) for r in mutant['results'])
            mutations.append(dict(name=name,status='DETECTED' if detected else 'BLIND',sentinels=len(cases),control=str(out/('control-'+name)/'RESULT.json'),mutant=str(out/('mutant-'+name)/'RESULT.json')))
    except Exception as exc:error=repr(exc)
    drift=[name for name,digest in harness_sha.items() if io.sha(OWN/name)!=digest]
    if drift:missing.append('harness changed during run: '+','.join(drift))
    counts=collections.Counter(replay.get('counts',{}));new,input_gaps=failure_counts(counts)
    complete=bool(replay) and replay['executed']==sum(len(j['bases']) for j in jobs) and not missing and len(metadata)>=3
    hits=sum(x['status']=='DETECTED' for x in mutations)
    excluded_input_states=sum(meta['excluded_input_states'] for meta in metadata)
    passed=outcome(counts,complete,hits==5,a.strict) and error is None and (not a.strict or excluded_input_states==0)
    matrix=[]
    for meta in metadata:
        for base in ['0','0x80000000000']:
            rows=[r for r in replay.get('results',[]) if r['label']=='game-'+meta['game'] and r['base']==base]
            capture_coverage=meta.get('coverage') or {}
            measured=checked_coverage(selected_games[meta['game']],rows,capture_coverage.get('translated_blocks'))
            captures=per_capture_coverage(selected_games[meta['game']],rows,capture_coverage.get('captures',[]))
            matrix.append(dict(meta,base=base,counts=dict(collections.Counter(r['classification'] for r in rows)),executed=len(rows),checked_coverage=measured,
                per_capture_checked_coverage=captures))
    seconds=time.monotonic()-started
    report=dict(status='PASS' if passed else 'FAIL',mode='quick' if a.quick else 'full',strict=a.strict,seconds=seconds,
        target_seconds=180 if a.quick else 480,time_target_met=seconds<=(180 if a.quick else 480),workers=workers,nice=os.getpriority(os.PRIO_PROCESS,0),
        runner=str(a.runner.resolve()),runner_sha256=s.sha(a.runner),dataset=str(a.dataset.resolve()),dataset_sha256=io.sha(a.dataset),
        harness_sha256=harness_sha,quick_work_deadline_seconds=160 if a.quick else None,
        known_registry_sha256=io.sha(OWN/'known-defects.json'),counts=dict(counts),new=new,fixed=counts['FIXED'],known=counts['KNOWN'],
        reference_gap=counts['REFERENCE_GAP'],empty_raw80=counts['EMPTY_RAW80'],input_gaps=input_gaps,excluded_input_states=excluded_input_states,game_matrix=matrix,mutations=mutations,
        error=error,missing=missing,semantic_sha256=replay.get('semantic_sha256'),replay=str(out/'replay/RESULT.json'),
        coverage_limits=['host null page synthetic14 excluded in native0; nonnull sibling15 retained',
                         'EMPTY_RAW80 is neither an engine defect nor equality; see F02 corpus audit',
                         'exact source states, independent oracle and both native bases; first-K misses later states'])
    (out/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f'STAND32 {report["status"]} equal={counts["EQUAL"]} known={counts["KNOWN"]} fixed={counts["FIXED"]} reference_gap={counts["REFERENCE_GAP"]} empty_raw80={counts["EMPTY_RAW80"]} input_gaps={input_gaps} excluded_states={excluded_input_states} new={new} games={len(metadata)}/4 mutations={hits}/5 seconds={seconds:.3f} result={out}/RESULT.json')
    return 0 if passed else 1
if __name__=='__main__':raise SystemExit(main())
