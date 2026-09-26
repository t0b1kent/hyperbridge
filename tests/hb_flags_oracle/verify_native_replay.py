#!/usr/bin/env python3
"""Read exported HBFL cases and re-execute actual x86 bytes, checking masked outputs.
No HyperBridge or ARM execution. Record one expected-bit mutation as a negative control.
"""
import sys,ctypes as C,mmap,json,argparse,hashlib
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'hb_absolute'))
from corpus import records

def main():
 p=argparse.ArgumentParser();p.add_argument('--native-output',required=True,type=Path);p.add_argument('--corpus',required=True,type=Path);p.add_argument('--out',required=True,type=Path);a=p.parse_args()
 lib=C.CDLL(str(a.native_output/'build/oracle.so'));lib.hb_flags_native.argtypes=[C.c_void_p]*4
 paths=sorted(a.corpus.glob('*.hbfl.gz')) if a.corpus.is_dir() else [a.corpus]
 cm=mmap.mmap(-1,4096,prot=3);ca=C.addressof(C.c_char.from_buffer(cm));libc=C.CDLL(None,use_errno=True);libc.mprotect.argtypes=[C.c_void_p,C.c_size_t,C.c_int]
 last=None;bad=[];cnt=0;first=None;digest=hashlib.sha256()
 for path in paths:
  for r in records(path):
   if r['magic']!=b'HBFL0001':raise ValueError('not HBFL')
   if r['code']!=last:
    if libc.mprotect(ca,4096,3):raise OSError(C.get_errno())
    b=r['code']+b'\xc3';cm[:len(b)]=b
    if libc.mprotect(ca,4096,5):raise OSError(C.get_errno())
    last=r['code']
   ini=(C.c_uint64*7)(*r['inputs']);out=(C.c_uint64*7)();mem=C.create_string_buffer(r['memory']);lib.hb_flags_native(ini,out,ca,mem);got=list(out)
   dif=[i for i in range(7) if (got[i]^r['outputs'][i])&r['masks'][i]]
   if dif and len(bad)<20:bad.append(dict(name=r['name'],fields=dif))
   digest.update(bytes(out));cnt+=1
   if first is None:first=(r,got)
 if not cnt:raise ValueError('empty replay')
 r,got=first;mut=list(r['outputs']);bit=next(i for i,m in enumerate(r['masks']) if m);maskbit=r['masks'][bit]&-r['masks'][bit];mut[bit]^=maskbit
 negative=bool((got[bit]^mut[bit])&r['masks'][bit]);assert negative
 res=dict(executor='native AMD x86-64',exported_records_reexecuted=cnt,masked_mismatches=bad,result_sha256=digest.hexdigest(),expected_bit_mutation_caught=negative,not_a_hyperbridge_run=True)
 a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(res,indent=2));print(json.dumps(res,indent=2));return bool(bad)
if __name__=='__main__':raise SystemExit(main())
