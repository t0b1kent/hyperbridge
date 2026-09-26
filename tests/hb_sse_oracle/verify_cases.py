#!/usr/bin/env python3
"""Read the exported runner protocol back, execute x86 hardware and HB C.
Independent of export_cases.case_line: verifies actual input/expected fields.
"""
from pathlib import Path
from ctypes import byref
import argparse,collections,gzip,json,os,sys
from binding import Sample,Result,load

def main():
    a=argparse.ArgumentParser();a.add_argument('--cases',required=True,type=Path)
    a.add_argument('--library',type=Path);a.add_argument('--report',required=True,type=Path)
    a.add_argument('--require-clean',action='store_true');a.add_argument('--corrupt-first-expectation',action='store_true');args=a.parse_args()
    if args.library:os.environ['HB_SSE_LIB']=str(args.library.resolve())
    lib=load();programs={};stats=collections.Counter();seen=set();examples=[]
    opener=gzip.open if args.cases.suffix=='.gz' else open
    with opener(args.cases,'rt') as src:
        for text in src:
            if not text.strip() or text.startswith('#'):continue
            fields=text.split();seed=int(fields[0],0);code=bytes.fromhex(fields[1]);count=int(fields[2]);kv=dict(x.split('=',1) for x in fields[3:])
            assert len(kv)==len(fields)-3,'duplicate field';assert kv['sse-version']=='1'
            ident=int(kv['sse-id']);assert ident not in seen;seen.add(ident)
            if code not in programs:programs[code]=lib.oracle_prepare(code,len(code))
            p=programs[code];assert p and lib.oracle_ir_count(p)==count,(code,count)
            s=Sample();s.mxcsr=int(kv['sse-mxcsr'],0);s.flags=int(kv['флаги'],0);s.rax=int(kv['рег-rax'],0)
            assert int(kv['sse-rbx-data'],0)==0x1000
            for j in range(3):s.x[j][:]=bytes.fromhex(kv[f'sse-xmm{j}']+kv[f'sse-ymmhi{j}'])
            s.mem[:]=bytes.fromhex(kv['sse-mem']);expected=bytearray.fromhex(kv['expect-xmm0']+kv['expect-ymmhi0'])
            if args.corrupt_first_expectation and stats['cases']==0:expected[0]^=1
            mask=int(kv['expect-flags-mask'],0);flags=int(kv['expect-flags'],0);rax=int(kv['expect-rax'],0);exc=int(kv['expect-mxcsr-exceptions'],0)
            h=Result();b=Result();lib.oracle_run(p,byref(s),0,byref(h));lib.oracle_run(p,byref(s),1,byref(b))
            vh=bytes(h.x)==expected and h.rax==rax and h.flags&mask==flags and h.host_mxcsr&63==exc
            vb=bytes(b.x)==expected and b.rax==rax and b.flags&mask==flags and b.status==0
            stats['cases']+=1
            if not vh:stats['hardware_expectation_failure']+=1
            if not vb:stats['interpreter_value_failure']+=1
            if b.guest_mxcsr&63!=exc:stats['interpreter_exception_diagnostic']+=1
            if (not vh or not vb) and len(examples)<8:examples.append({'id':ident,'bytes':code.hex(),'mxcsr':hex(s.mxcsr),'hardware_matches':vh,'interp_matches':vb})
    ok=stats['cases']>0 and stats['hardware_expectation_failure']==0 and (not args.require_clean or stats['interpreter_value_failure']==0)
    report={'passed':ok,'executed_native_x86':True,'full_ARM_runner_executed':False,'counts':dict(stats),'examples':examples}
    args.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
    return 0 if ok else 1
if __name__=='__main__':sys.exit(main())
