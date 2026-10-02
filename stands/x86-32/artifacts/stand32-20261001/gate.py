#!/usr/bin/env python3
"""One-line acceptance gate. Missing game capture or mutation coverage fails closed."""
import argparse,collections,concurrent.futures,datetime,json,os,pathlib,signal,subprocess,sys,time
import stand32 as s
import evidence_io
OWN=pathlib.Path(__file__).resolve().parent
def native_probe_executed(probe):
    # Equality is a separate requirement: a semantic mismatch still proves
    # native execution and must not be hidden by falling back to reference-only.
    rows=probe.get('results',[])
    return (probe.get('status')=='MEASURED' and len(rows)==1 and
            rows[0].get('classification') in ('EQUAL','NEW') and
            'execution' not in rows[0].get('diff',{}))

def main():
    p=argparse.ArgumentParser(description=__doc__);mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--quick',action='store_true');mode.add_argument('--full',action='store_true')
    p.add_argument('--runner',type=pathlib.Path,required=True)
    p.add_argument('--dataset',type=pathlib.Path,default=OWN/'dataset-low32.json');a=p.parse_args()
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    out=OWN/'out'/('gate-'+stamp);out.mkdir(parents=True)
    started=time.monotonic();deadline=started+(165 if a.quick else 3600);runs=[];mutations=[]
    local_now=datetime.datetime.now();daytime=7*60 <= local_now.hour*60+local_now.minute < 23*60+30
    workers=4 if daytime else 6
    inherited_nice=os.getpriority(os.PRIO_PROCESS,0)
    if daytime and inherited_nice<5:os.nice(5-inherited_nice)
    native_base0=False
    def execute(label,cases,base,mutation='',runner=None,force_native=False):
        remaining=deadline-time.monotonic()
        if remaining<=3:return dict(label=label,status='BUDGET_EXHAUSTED')
        selected_runner=(runner or a.runner).resolve()
        target=out/label;cmd=[sys.executable,str(OWN/'stand32.py'),'--runner',str(selected_runner),'--base',base,'--cases',str(cases),'--out',str(target),'--budget',str(max(1,remaining-10))]
        if mutation:cmd+=['--mutation',mutation]
        if base=='0' and not (native_base0 or force_native):cmd+=['--oracle-only']
        with (out/(label+'.log')).open('wb') as log:
            child=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            try:rc=child.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid,signal.SIGTERM);child.wait();return dict(label=label,status='BUDGET_EXHAUSTED')
        file=target/'RESULT.json'
        if not file.exists():return dict(label=label,status='HARNESS_FAILED',rc=rc)
        report=json.loads(file.read_text());complete=report['executed']==report['planned']
        return dict(label=label,status='MEASURED' if complete else 'BUDGET_EXHAUSTED',rc=rc,path=str(file),runner=str(selected_runner),runner_sha256=report['runner_sha256'],counts=report['counts'],results=report['results'])
    def execute_parallel(jobs):
        # Each subprocess owns a distinct result directory and temporary pages.
        # Independent replay is CPU work; respect the day/night worker cap.
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures=[pool.submit(execute,*job) for job in jobs]
            return [future.result() for future in futures]
    error=None;matrix=[];game_grades=[];x87_status='NOT_MEASURED';base0_probe={}
    try:
        capabilities=subprocess.run([str(a.runner.resolve()),'--capabilities'],capture_output=True,text=True,timeout=5)
        caps=json.loads(capabilities.stdout)
        directed_file=OWN/'fixtures/directed-low32.json'
        directed=json.loads(directed_file.read_text())
        probe_file=out/'native-base0-probe.json'
        probe_file.write_text(json.dumps([directed[0]])+'\n')
        base0_probe=execute('native-base0-probe',probe_file,'0',force_native=True)
        native_base0=native_probe_executed(base0_probe)
        # macOS retains the first host page even for entitled processes. Keep
        # its original fixture as an explicit host-limit probe; the non-null
        # wrap sibling proves 32-bit carry semantics in both native modes.
        base0_directed=out/'directed-base0.json'
        base0_directed.write_text(json.dumps([c for c in directed if c['id']!=14])+'\n')
        null_fixture=out/'native-null-page.json'
        null_fixture.write_text(json.dumps([next(c for c in directed if c['id']==14)])+'\n')
        null_page_probe=execute('native-null-page-probe',null_fixture,'0',force_native=True)
        jobs=[]
        for base in ['0','0x80000000000']:
            jobs.extend([('directed-'+base,base0_directed if base=='0' else directed_file,base),
                         ('x87-family-'+base,OWN/'fixtures/x87-two-to-one-env.json',base),
                         ('x87-env-family-'+base,OWN/'fixtures/x87-env-family.json',base)])
            if a.full:jobs.append(('pe-'+base,OWN/'fixtures/pe-extracted.json',base))
        runs.extend(execute_parallel(jobs))
        for name,ident in [('base',2),('sign',13),('carry4g',14),('x87_rounding',9),('x87_stack_order',8)]:
            sentinels=(json.loads((OWN/'fixtures/carry-disp8-disp32.json').read_text()) if name=='carry4g'
                       else [next(c for c in directed if c['id']==ident)])
            fixture=out/(name+'.json');fixture.write_text(json.dumps(sentinels)+'\n')
            # Instrument self-tests use owned, intentionally corrupted FEX builds.
            # They never pretend that the user's supplied engine was mutated.
            mutant_runner=OWN/('stand_runner32_x87_mutants' if name.startswith('x87_') else 'stand_runner32')
            if not mutant_runner.exists():mutations.append(dict(name=name,status='NOT_ENABLED'));continue
            control=execute('mutation-control-'+name,fixture,'0x80000000000',runner=mutant_runner)
            if control.get('rc')!=0 or control.get('counts')!={'EQUAL':len(sentinels)}:
                mutations.append(dict(name=name,status='BLIND_BASELINE_FAILED',control=control));continue
            run=execute('mutation-'+name,fixture,'0x80000000000',name,runner=mutant_runner)
            detected=(run.get('status')=='MEASURED' and len(run.get('results',[]))==len(sentinels)
                      and all(bool(row['diff']) for row in run['results']))
            mutations.append(dict(name=name,status='DETECTED' if detected else 'UNDETECTED',scope='owned_FEX_instrument_self_test',
                                  sentinels=[c['id'] for c in sentinels],control=control,run=run))
        if a.dataset.exists():
            dataset=json.loads(a.dataset.read_text())
            game_jobs=[];game_metadata=[]
            for game in dataset['games']:
                case_file=(a.dataset.parent/game['cases']).resolve()
                original=evidence_io.read_json(case_file)
                if isinstance(original,dict):original=original['cases']
                if not original or any(c.get('origin')!='GAME_CAPTURE' for c in original):
                    raise ValueError('game corpus must contain actual captured states')
                if a.quick and game.get('quick_case_ids'):
                    index={c['id']:c for c in original};selected=[index[i] for i in game['quick_case_ids']]
                    if not 1<=len(selected)<=32:raise ValueError('quick selection cap')
                else:selected=original[:32] if a.quick else original
                selected_file=out/('game-'+game['id']+'.json');evidence_io.write_json(selected_file,selected)
                # Coordinator 2026-10-01 18:52: captured pre-fault states are
                # accepted offline inputs; a failed menu control stays visible.
                game_grades.append(game.get('recording_grade')=='PASS' and game.get('memory_at_state')=='COHERENT')
                for base in ['0','0x80000000000']:
                    game_jobs.append(('game-'+game['id']+'-'+base,selected_file,base))
                    game_metadata.append(dict(game=game['id'],base=base,blocks=len({c['state']['rip'] for c in selected}),states=len(selected),
                        available_states=len(original),
                        backend=('native_FEX32_base0' if native_base0 else 'Unicorn32_reference_only') if base=='0' else 'native_FEX32_shifted',
                        recording_grade=game.get('recording_grade'),control_grade=game.get('control_grade'),
                        memory_at_state=game.get('memory_at_state'),evidence=game.get('evidence',[])))
            for metadata,run in zip(game_metadata,execute_parallel(game_jobs)):
                runs.append(run);counts=run.get('counts',{})
                metadata.update(equal=counts.get('EQUAL',0),reference_exit=counts.get('REFERENCE_EXIT',0),
                                known=counts.get('KNOWN',0),reference_gap=counts.get('REFERENCE_INSN_GAP',0)+counts.get('REFERENCE_GAP',0),
                                new=counts.get('NEW',0),status=run['status'],
                                host_mapping_failed=counts.get('HOST_MAPPING_FAILED',0),executed=len(run.get('results',[])))
                matrix.append(metadata)
            x87_file=(a.dataset.parent/dataset['x87_report']).resolve()
            x87=json.loads(x87_file.read_text());x87_status=x87.get('status','NOT_MEASURED')
    except Exception as exc:error=repr(exc)
    # Real capture is deliberately a separate admission requirement. Extracted PE
    # bytes with generated inputs must never satisfy a game-state acceptance gate.
    if not matrix:
        matrix=[dict(game=g,base=b,blocks=None,states=None,equal=None,known=None,reference_gap=None,new=None,status='NOT_ENABLED')
                for g in ['Heroes III','Diablo Hellfire','UT99','fourth PE32 title'] for b in ['0','0x80000000000']]
    missing=[]
    if len(game_grades)<3 or not all(game_grades):missing.append('3-4 real captures with coherent pre-fault memory')
    if x87_status not in ['MEASURED','MEASURED_CAPTURED_SCOPE']:missing.append('per-block weighted x87 accounting')
    if not native_base0:missing.append('native FEX32 base0 execution unavailable in actual runner probe; Unicorn base0 is reference only')
    if len(mutations)!=5 or any(m['status']!='DETECTED' for m in mutations):missing.append('five detected engine mutants')
    if not runs or any(r.get('status')!='MEASURED' or r.get('rc')!=0 or any(x['classification'] not in ['EQUAL','REFERENCE_EXIT'] for x in r.get('results',[])) for r in runs):missing.append('successful native replay in both bases (reference-only fallback never proves native equality)')
    passed=not missing and error is None
    report=dict(status='PASS' if passed else 'INCOMPLETE',mode='quick' if a.quick else 'full',runner=str(a.runner.resolve()),runner_sha256=s.sha(a.runner) if a.runner.is_file() else None,
        diagnostic_runs=runs,native_base0_executed=native_base0,native_base0_probe=base0_probe,
        mutation_control=mutations,game_matrix=matrix,x87_accounting=x87_status,error=error,missing=missing)
    report.update(seconds=time.monotonic()-started,workers=workers,nice=os.getpriority(os.PRIO_PROCESS,0),
                  dataset=str(a.dataset.resolve()),null_page_probe=locals().get('null_page_probe'),
                  synthetic_base0_exclusions=[dict(id=14,reason='host null page unavailable; nonnull carry sibling15 included')])
    (out/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n')
    totals=collections.Counter()
    for r in runs:totals.update(r.get('counts',{}))
    hits=sum(m['status']=='DETECTED' for m in mutations)
    print(f'STAND32 {"PASS" if passed else "FAIL"} equal={totals["EQUAL"]} known={totals["KNOWN"]} reference_gap={totals["REFERENCE_GAP"]} new={totals["NEW"]} games={sum(game_grades)}/4 mutations={hits}/5 x87={x87_status} result={out}/RESULT.json')
    return 0 if passed else 1
if __name__=='__main__':
    from stage2_gate import main as stage2_main
    raise SystemExit(stage2_main())
