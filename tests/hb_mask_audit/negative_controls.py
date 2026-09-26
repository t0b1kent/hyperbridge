#!/usr/bin/env python3
"""Actual x86 tests of ignored masks, and truly unmapped-page fault suppression.
This is a controlled opcode mutation, NOT a run of pre-patch HyperBridge.
All allocations are prepared before munmap to avoid reusing the test hole.
"""
import ctypes as C, json, mmap, os, struct, argparse
from pathlib import Path
H=Path(__file__).resolve().parent

def main():
 p=argparse.ArgumentParser();p.add_argument('--native-output',required=True,type=Path);p.add_argument('--out',required=True,type=Path);a=p.parse_args()
 lib=C.CDLL(str(a.native_output/'build/oracle.so'));lib.hb_mask_native.argtypes=[C.c_void_p]*7
 if not lib.hb_mask_available():raise SystemExit('AVX-512 unavailable')
 libc=C.CDLL(None,use_errno=True);libc.mprotect.argtypes=[C.c_void_p,C.c_size_t,C.c_int];libc.munmap.argtypes=[C.c_void_p,C.c_size_t]
 forms=[('load-zero','62f17c891003'),('load-merge','62f17c091003'),('store','62f17c09110f'),('pair-load','62f17c09100362f17c081107'),('pair-store','62f17c08100362f17c0a1107')]
 programs=[]
 for n,h in forms:
  b=bytearray.fromhex(h);mut=bytearray(b)
  # Remove the mask from the relevant EVEX instruction only.
  j=6 if n=='pair-store' else 0;mut[j+3]&=~0x87
  programs.extend([(n,bytes(b)+b'\xc3'),(n+'-ignore-mask',bytes(mut)+b'\xc3')])
 code=mmap.mmap(-1,4096,prot=3);ca=C.addressof(C.c_char.from_buffer(code));ofs=[];off=0
 for n,b in programs:ofs.append(off);code[off:off+len(b)]=b;off+=len(b)
 if libc.mprotect(ca,4096,5):raise OSError(C.get_errno())
 vi=bytearray(2048)
 for r in range(32):
  for i in range(16):struct.pack_into('<I',vi,r*64+i*4,0x3f800000+r*16+i)
 # Clear, human-readable source and destination lanes in the minimum witnesses.
 struct.pack_into('<4I',vi,0,0x11111111,0x22222222,0x33333333,0x44444444)
 struct.pack_into('<4I',vi,64,0x3f800000,0x40000000,0x40400000,0x40800000)
 im=bytearray([0xa5]*256);struct.pack_into('<4I',im,0,0x3f800000,0x40000000,0x40400000,0x40800000)
 ib=C.create_string_buffer(bytes(vi));ob=C.create_string_buffer(2048);mb=C.create_string_buffer(bytes(im));ka=(C.c_uint64*8)(*([5]*8));fa=C.c_size_t()
 def go(idx,rd=None,wr=None):
  C.memmove(mb,bytes(im),256);C.memset(ob,0,2048);sig=lib.hb_mask_native(ib,ob,rd or C.addressof(mb),ca+ofs[idx],wr or C.addressof(mb)+128,ka,C.byref(fa))
  return dict(signal=sig,zmm0=ob.raw[:64].hex(),memory=C.string_at(mb,256).hex(),fault=fa.value)
 rows=[]
 for i,(n,h) in enumerate(forms):
  good=go(i*2);bad=go(i*2+1)
  caught=good['zmm0']!=bad['zmm0'] or good['memory']!=bad['memory'] or good['signal']!=bad['signal']
  if not caught or good['signal'] or bad['signal']:raise AssertionError((n,good,bad))
  rows.append(dict(name=n,bytes=h,mask=5,input_zmm0=bytes(vi[:64]).hex(),source_lanes=bytes(im[:16]).hex(),initial_memory=bytes(im).hex(),hardware=good,ignore_mask_opcode=programs[i*2+1][1][:-1].hex(),mutant_hardware=bad,caught=caught))
 # Actual munmap, not merely PROT_NONE. Four simple probes use the same wrapper.
 page=os.sysconf('SC_PAGESIZE');region=mmap.mmap(-1,2*page,prot=3);base=C.addressof(C.c_char.from_buffer(region));edge=base+page
 C.memmove(edge-4,struct.pack('<I',0x3f800000),4)
 # Preallocate all buffers/return holders before unmapping the page.
 probes=[('load-all-disabled',0,0,edge,edge,0),('load-first-lane',0,1,edge-4,edge,0),('load-active-hole',0,3,edge-4,edge,11),('store-all-disabled',4,0,edge,edge,0),('store-first-lane',4,1,edge,edge-4,0),('store-active-hole',4,3,edge,edge-4,11)]
 prepared=[(n,idx,(C.c_uint64*8)(*([mask]*8)),C.c_void_p(rd),C.c_void_p(wr),want,C.c_size_t()) for n,idx,mask,rd,wr,want in probes]
 if libc.munmap(edge,page):raise OSError(C.get_errno())
 res=[]
 for n,idx,kk,rd,wr,want,ff in prepared:
  sig=lib.hb_mask_native(ib,ob,rd,ca+ofs[idx],wr,kk,C.byref(ff))
  res.append((n,sig,want,ff.value))
 guard=[]
 for n,sig,want,addr in res:
  passed=(sig==0 if want==0 else sig in (7,11) and edge<=addr<edge+page)
  if not passed:raise AssertionError((n,sig,want,hex(addr)))
  guard.append(dict(name=n,signal=sig,expect_fault=bool(want),fault_in_unmapped_page=bool(sig and edge<=addr<edge+page),pass_=passed))
 a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(dict(executor='native AMD x86-64',not_a_hyperbridge_execution=True,mask_mutations=rows,unmapped_page=guard),indent=2));print('5 ignored-mask controls and 6 truly unmapped-page probes passed')
if __name__=='__main__':main()
