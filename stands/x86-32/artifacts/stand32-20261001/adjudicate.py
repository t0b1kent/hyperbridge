#!/usr/bin/env python3
"""Preserve raw comparisons; attach independent, narrowly scoped witnesses."""
import argparse,collections,hashlib,json,pathlib
import evidence_io as io
import independent_x87 as rules
OWN=pathlib.Path(__file__).resolve().parent

def classify(case,ref,got,row):
    raw=row['classification'];diff=row.get('diff',{})
    if raw=='ENVIRONMENT_NOT_REPLAYABLE':
        return 'KNOWN','ENVIRONMENT_INPUT','спорно',dict(rule='CPUID/time/system interaction lacks captured response; native equality untested')
    if raw!='NEW':return raw,None,None,None
    environment=rules.environment_restore_witness(ref,got,diff)
    if environment:
        return 'REFERENCE_GAP','R02_ENV_RESTORE_POINTERS','пробел эталона',environment
    for event in ref.get('x87_events',[]):
        witness=rules.masked_push_overflow(event)
        if witness and witness['reference_violates_rule']:
            witness['native_correctness']='NOT_PROVEN; full output remains a raw mismatch'
            return 'REFERENCE_GAP','R01_MASKED_STACK_OVERFLOW','пробел эталона',witness
    keys=set(diff)
    if keys and all(k.startswith('fp80_') and ref['ftw']>>(2*int(k[5:]))&3==3 for k in keys):
        return 'KNOWN','F02_EMPTY_RAW80','спорно',dict(rule='all differing raw80 slots have EMPTY tags; strict mismatch retained',
                  independent_check={k:rules.tag(diff[k][1],False) for k in keys},hardware_proof='NOT_PRESENT')
    if keys=={'ftw'} and case['code'].startswith('d9f1'):
        top=case['state']['fsw']>>11&7;expected=rules.pop_mask(case['state']['ftw'],top)
        return 'KNOWN','F03_POP_TAG','дефект движка',dict(rule='FYL2X consumes ST0 and clears its occupied bit',
                 expected_abridged=expected,native_abridged=got['x87_abridged_ftw'])
    if keys=={'fsw'}:
        witness=rules.sticky_ie_witness(case['state']['fsw'],ref['trace'],ref['fsw'],got['x87_fsw'])
        if witness and witness['engine_violates_rule']:
            return 'KNOWN','F04_STICKY_IE','дефект движка',witness
    if case.get('origin')=='DIRECTED_X87_FAMILY' and 'ftw' in diff:
        top=case['state']['fsw']>>11&7
        return 'KNOWN','F03_POP_TAG','дефект движка',dict(rule='FYL2X/FYL2XP1/FPATAN pop clears consumed physical tag',
                 expected_abridged=rules.pop_mask(case['state']['ftw'],top),native_abridged=got['x87_abridged_ftw'])
    if case.get('origin')=='DIRECTED_X87_ENV_FAMILY' and 'data' in diff:
        state=case['state'];expected=sum(rules.tag(state['mm'][i*32:i*32+20],bool(state['ftw']>>i&1))<<(2*i) for i in range(8))
        offset=case['saved_ftw_offset'];actual=int.from_bytes(bytes.fromhex(got['data'])[offset:offset+2],'little')
        reference=int.from_bytes(bytes.fromhex(ref['memory']['0x20000000'])[offset:offset+2],'little')
        return 'KNOWN','F06_SERIALIZED_TAG','дефект движка',dict(rule='full tag reconstructs ZERO/SPECIAL from binary80, not occupancy alone',
                  expected=expected,reference=reference,native=actual)
    return 'NEW','UNCLASSIFIED','спорно',None

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('gate',type=pathlib.Path)
    parser.add_argument('--out',type=pathlib.Path,required=True);args=parser.parse_args()
    original=json.loads((args.gate/'RESULT.json').read_text());runs=[];classes=collections.defaultdict(list)
    for run in original['diagnostic_runs']:
        path=pathlib.Path(run['path']);report=json.loads(path.read_text());rows=[]
        for row in report['results']:
            stem=path.parent/f'{row["id"]:06d}';case=io.read_json(stem.with_suffix('.case.json'));ref=io.read_json(stem.with_suffix('.reference.json'))
            got={}
            if io.stored_path(stem.with_suffix('.stdout')).exists():
                output=[json.loads(line) for line in io.read_text(stem.with_suffix('.stdout')).splitlines() if line.startswith('{')]
                if output:got=output[-1]
            classification,family,verdict,witness=classify(case,ref,got,row)
            item=dict(id=row['id'],raw_classification=row['classification'],classification=classification,family=family,verdict=verdict)
            rows.append(item)
            if family:
                evidence={str(io.stored_path(stem.with_suffix(suffix))):io.sha(stem.with_suffix(suffix))
                          for suffix in ['.case.json','.reference.json','.stdout'] if io.stored_path(stem.with_suffix(suffix)).exists()}
                classes[family].append(dict(**item,run=run['label'],code=case['code'],eip=case['state']['rip'],diff=row.get('diff',{}),
                       witness=witness,input_state=str(io.stored_path(stem.with_suffix('.case.json'))),evidence_logical_sha256=evidence,
                       reproduce=row.get('reproduction')))
        runs.append(dict(label=run['label'],counts=dict(collections.Counter(x['classification'] for x in rows)),results=rows))
    matrix=[]
    for metadata in original['game_matrix']:
        label='game-'+metadata['game']+'-'+metadata['base'];run=next(x for x in runs if x['label']==label);counts=run['counts']
        matrix.append(dict(metadata,raw_counts=next(x['counts'] for x in original['diagnostic_runs'] if x['label']==label),
                           adjudicated_counts=counts,equal=counts.get('EQUAL',0),known=counts.get('KNOWN',0),
                           reference_gap=counts.get('REFERENCE_GAP',0),new=counts.get('NEW',0)))
    report=dict(status='MEASURED_WITH_EXPLICIT_LIMITS',raw_gate=str(args.gate/'RESULT.json'),raw_gate_sha256=io.sha(args.gate/'RESULT.json'),
                classifier_sha256=io.sha(__file__),rules_sha256=io.sha(OWN/'independent_x87.py'),matrix=matrix,
                class_counts={k:len(v) for k,v in classes.items()},classes=classes,runs=runs,
                limits=['KNOWN means recognized mismatch or unavailable environment, never equality',
                        'Independent witnesses are integer tag/stack/status rules; no hardware/Prism was run',
                        'R01 establishes a reference gap, not correctness of the native output',
                        'F02 remains disputed under the required strict raw80 comparison'])
    args.out.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(class_counts=report['class_counts'],rows=len(matrix),path=str(args.out))))

if __name__=='__main__':main()
