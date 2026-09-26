#!/usr/bin/env python3
"""Readable minimal witnesses and finite/indefinite boundary controls."""
from pathlib import Path
from ctypes import byref
import argparse,json,struct
from binding import Sample,Result,load

def main():
 a=argparse.ArgumentParser();a.add_argument('--out',type=Path,required=True);args=a.parse_args();lib=load();jobs=[]
 def add(label,code,bits,lhs,rhs,mx=0x1f80,kind='fp'):jobs.append((label,code,bits,lhs,rhs,mx,kind))
 add('QNaN first small','f30f58c1',32,0x7fc00001,0x7fc12345)
 add('QNaN first large','f30f58c1',32,0x7fc12345,0x7fc00001)
 add('SNaN first, QNaN second','f30f58c1',32,0x7f800001,0x7fc12345)
 add('QNaN first, SNaN second','f30f58c1',32,0x7fc00001,0x7f812345)
 add('negative QNaN first double','f20f58c1',64,0xfff8000000000001,0x7ff8000000012345)
 for mx in [0x1f80,0x9fc0,0x1fc0,0x9f80]:add('MIN +zero,+min-subnormal','f30f5dc1',32,0,1,mx)
 add('MIN source2 SNaN unchanged','f30f5dc1',32,0x3f800000,0x7f800001)
 add('MIN source2 -zero sign','f30f5dc1',32,0,0x80000000)
 add('MAX source2 +zero sign','f30f5fc1',32,0x80000000,0)
 for mx in [0x1f80,0x3f80,0x5f80,0x7f80]:
  add('ADD +zero,-zero RC','f30f58c1',32,0,0x80000000,mx)
  add('ADD 1 + half-ULP RC','f30f58c1',32,0x3f800000,0x33800000,mx)
 add('DAZ arithmetic','f30f58c1',32,0,1,0x9fc0)
 add('DAZ min-subnormal times infinity','f30f59c1',32,1,0x7f800000,0x9fc0)
 add('FTZ exact subnormal result','f30f5ec1',32,0x00800000,0x40000000,0x9f80)
 add('indefinite DIV 0/0','f30f5ec1',32,0,0)
 add('indefinite DIV 0/0 double','f20f5ec1',64,0,0)
 add('indefinite SQRT -1','f30f51c1',32,0,0xbf800000)
 for op,code in [('COMISS','0f2fc1'),('UCOMISS','0f2ec1')]:
  for desc,lhs,rhs,mx in [('QNaN',0x7fc00001,0,0x1f80),('SNaN',0x7f800001,0,0x1f80),('DAZ equal',0,1,0x9fc0)]:add(op+' '+desc,code,32,lhs,rhs,mx,'flags')
 add('CVTSS2SI +subnormal RC-up DAZ','f30f2dc1',32,0,1,0xdfc0,'int')
 bits64=lambda x:int.from_bytes(struct.pack('<d',x),'little')
 for mx in [0x1f80,0x3f80,0x5f80,0x7f80]:
  add('CVTSD2SI r32 2^31-0.5','f20f2dc1',64,0,bits64(2147483647.5),mx,'int')
  add('CVTTSD2SI r32 2^31-0.5','f20f2cc1',64,0,bits64(2147483647.5),mx,'int')
 for desc,v in [('2^31',2147483648.),('-2^31',-2147483648.),('-2^31-1',-2147483649.)]:add('CVTTSD2SI r32 '+desc,'f20f2cc1',64,0,bits64(v),kind='int')
 for desc,v in [('2^63',0x43e0000000000000),('-2^63',0xc3e0000000000000),('2^63-1024',0x43dfffffffffffff),('-2^63-2048',0xc3e0000000000001)]:add('CVTTSD2SI r64 '+desc,'f2480f2cc1',64,0,v,kind='int')
 results=[]
 for label,code,bits,lhs,rhs,mx,kind in jobs:
  width=bits//8;s=Sample();s.flags=0xad7;s.mxcsr=mx;s.rax=0xdefaced5badbeef0
  upper=bytes.fromhex('efcdab89674523011032547698badcfe')
  s.x[0][:]=lhs.to_bytes(width,'little')+bytes(16-width)+upper;s.x[1][:]=rhs.to_bytes(width,'little')+bytes(16-width)+upper;s.mem[:]=bytes(s.x[1])
  cod=bytes.fromhex(code);p=lib.oracle_prepare(cod,len(cod));assert p,(label,lib.oracle_error())
  out=[]
  for mode in range(3):
   r=Result();lib.oracle_run(p,byref(s),mode,byref(r));assert r.status==0
   value=r.rax if kind=='int' else r.flags&0x8d5 if kind=='flags' else int.from_bytes(bytes(r.x)[:width],'little')
   out.append({'value':f'{value:016x}' if kind=='int' else f'{value:03x}' if kind=='flags' else f'{value:0{width*2}x}','xmm0_ymmhi0_le':bytes(r.x).hex(),'rax':f'{r.rax:016x}','status_flags':f'{r.flags&0x8d5:03x}','host_mxcsr':f'{r.host_mxcsr:04x}','guest_mxcsr':f'{r.guest_mxcsr:04x}'})
  results.append({'label':label,'bytes':code,'bits':bits,'kind':kind,'inputs_bits':[f'{lhs:0{width*2}x}',f'{rhs:0{width*2}x}'],'mxcsr':f'{mx:04x}','hardware':out[0],'hb_matched':out[1],'hb_neutral':out[2]})
 args.out.write_text(json.dumps(results,indent=2)+'\n');print('measured',len(results),'focused cases')
if __name__=='__main__':main()
