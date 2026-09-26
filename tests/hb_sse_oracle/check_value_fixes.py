#!/usr/bin/env python3
"""Real x86 native execution + real baseline/fixed interpreter, minimal controls."""
from pathlib import Path
from ctypes import byref
import argparse,json,os,sys
from binding import Sample,Result,load

def main():
    a=argparse.ArgumentParser();a.add_argument('--baseline',type=Path,required=True);a.add_argument('--fixed',type=Path,required=True);a.add_argument('--out',type=Path,required=True);args=a.parse_args()
    os.environ['HB_SSE_LIB']=str(args.baseline.resolve());base=load()
    os.environ['HB_SSE_LIB']=str(args.fixed.resolve());fixed=load()
    results=[]
    # One genuine positive control + independent witnesses, and DAZ vs FTZ isolation.
    tests=[('N01', 'f30f58c1',32,0x7fc00001,0x7fc12345,0x1f80,0x7fc00001,False),
           ('N01-memory','f30f5803',32,0x7fc00001,0x7fc12345,0x1f80,0x7fc00001,False),
           ('N01-double','f20f58c1',64,0x7ff8000000000001,0x7ff8000000012345,0x1f80,0x7ff8000000000001,False),
           ('N02','f30f5dc1',32,0,1,0x9fc0,0,False),
           ('N02-DAZ-only','f30f5dc1',32,0,1,0x1fc0,0,False),
           ('N02-memory','f30f5d03',32,0,1,0x9fc0,0,False),
           ('control-FTZ-only','f30f5fc1',32,0,1,0x9f80,1,True),
           ('control-add-finite','f30f58c1',32,0x3f800000,0x3f800000,0x1f80,0x40000000,True),
           ('control-indefinite','f30f5ec1',32,0,0,0x1f80,0xffc00000,True),
           ('control-min-SNaN','f30f5dc1',32,0x3f800000,0x7f800001,0x1f80,0x7f800001,True)]
    for name,code,bits,lhs,rhs,mx,expect,old_pass in tests:
        size=bits//8;s=Sample();s.flags=0xad7;s.mxcsr=mx;s.rax=0xdefaced5badbeef0
        upper=bytes.fromhex('efcdab89674523011032547698badcfe')
        s.x[0][:]=lhs.to_bytes(size,'little')+bytes(16-size)+upper
        s.x[1][:]=rhs.to_bytes(size,'little')+bytes(16-size)+upper;s.mem[:]=bytes(s.x[1])
        h=Result();b=Result();f=Result();cod=bytes.fromhex(code)
        p=base.oracle_prepare(cod,len(cod));q=fixed.oracle_prepare(cod,len(cod));assert p and q
        base.oracle_run(p,byref(s),0,byref(h));base.oracle_run(p,byref(s),1,byref(b));fixed.oracle_run(q,byref(s),1,byref(f))
        val=lambda r:int.from_bytes(bytes(r.x)[:size],'little')
        assert val(h)==expect,(name,'hardware',hex(val(h)),hex(expect))
        assert (bytes(h.x)==bytes(b.x))==old_pass,(name,'baseline control')
        assert bytes(h.x)==bytes(f.x) and h.rax==f.rax and h.flags&0x8d5==f.flags&0x8d5 and f.status==0,name
        results.append({'test':name,'bytes':code,'input_bits':[f'{lhs:0{size*2}x}',f'{rhs:0{size*2}x}'],'mxcsr':hex(mx),'hardware':f'{val(h):0{size*2}x}','baseline':f'{val(b):0{size*2}x}','fixed':f'{val(f):0{size*2}x}','hardware_exceptions':h.host_mxcsr&63,'before':'pass' if old_pass else 'mismatch','after':'pass'})
    args.out.write_text(json.dumps({'passed':True,'tests':results},indent=2)+'\n')
    print(json.dumps({'passed':True,'tests':len(results)}))
if __name__=='__main__':main()
