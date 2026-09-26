#!/usr/bin/env python3
"""Fail closed on missing absolute checks, omitted/duplicate cases and bad values.
Reads hb_diff_case_runner JSONL from stdin; stderr diagnostics must stay separate.
Guest MXCSR exception differences are counted but do not make values fail.
"""
import argparse,collections,gzip,json,sys
from pathlib import Path

def main():
    a=argparse.ArgumentParser();a.add_argument('--cases',required=True,type=Path)
    a.add_argument('--interp-only',action='store_true');a.add_argument('--expect-value-failure',action='store_true');args=a.parse_args()
    opener=gzip.open if args.cases.suffix=='.gz' else open
    ids=set()
    with opener(args.cases,'rt') as f:
        for line in f:
            if not line.strip() or line.startswith('#'):continue
            fields=dict(x.split('=',1) for x in line.split() if '=' in x)
            n=int(fields['sse-id']);assert n not in ids,'duplicate input case ID';ids.add(n)
    seen=set();stats=collections.Counter();examples=[]
    for line in sys.stdin:
        if not line.strip():continue
        try:
            r=json.loads(line);o=r['sse_oracle'];n=o['id']
            if type(n) is not int or n not in ids or n in seen:raise ValueError('unknown/duplicate case ID')
            seen.add(n);stats['rows']+=1
            if o.get('seed_ok') is not True:stats['bad_seed']+=1
            if o.get('interp_values_ok') is not True:stats['interp_value_failure']+=1
            if args.interp_only:
                if o.get('jit_values_ok') is not None:stats['unexpected_mode']+=1
            elif o.get('jit_values_ok') is not True:stats['jit_value_failure']+=1
            if r.get('ok') is not True:stats['runner_failure']+=1
            if o['interp_mxcsr_exc']!=o['mxcsr_expected_exc']:stats['interp_exception_diagnostic']+=1
            if not args.interp_only and o['jit_mxcsr_exc']!=o['mxcsr_expected_exc']:stats['jit_exception_diagnostic']+=1
            if r.get('ok') is not True and len(examples)<12:examples.append({'id':n,'diff':r.get('diff'),'oracle':o})
        except (ValueError,KeyError,TypeError) as ex:
            stats['malformed_or_unchecked_row']+=1
            if len(examples)<12:examples.append({'error':str(ex),'line':line[:300]})
    stats['expected']=len(ids);stats['missing']=len(ids-seen)
    integrity=sum(stats[k] for k in ['bad_seed','unexpected_mode','malformed_or_unchecked_row','missing'])
    failures=stats['interp_value_failure']+stats['jit_value_failure']
    if args.expect_value_failure:
        ok=not integrity and failures>0
    else:
        ok=not integrity and failures==0 and stats['runner_failure']==0 and len(ids)>0
    print(json.dumps({'ok':ok,'negative_control':args.expect_value_failure,'counts':dict(stats),'examples':examples},indent=2))
    return 0 if ok else 1
if __name__=='__main__':sys.exit(main())
