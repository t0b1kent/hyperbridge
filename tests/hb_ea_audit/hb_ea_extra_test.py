#!/usr/bin/env python3
"""Address/liveness contracts for stack and composite consumers.
Expected addresses use hardware x86 LEA; scalar updates and masks use the native
oracle. These are not executions of an entire x86 program or Wine helpers.
"""
import argparse,json,struct,collections,ctypes
from pathlib import Path
import hb_ea_live_test as t
from a64_eval import CPU,Fault,Unsupported,MASK
class Sparse:
 def __init__(self):self.d={};self.access=[]
 def map(self,a,b):self.d.update({a+i:v for i,v in enumerate(b)})
 def read(self,a,n):
  if any(a+i not in self.d for i in range(n)):raise Fault(f'unmapped access {a:#x}+{n}')
  self.access.append(('r',a,n));return bytes(self.d[a+i] for i in range(n))
 def write(self,a,b):
  if any(a+i not in self.d for i in range(len(b))):raise Fault(f'unmapped write {a:#x}+{len(b)}')
  self.access.append(('w',a,len(b)));self.map(a,b)
 def get(self,a,n):return int.from_bytes(self.read(a,n),'little')
 def put(self,a,v,n):self.write(a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))
CONFIGS=[(0,0,0,0),(0,1,0,0)]+[(1,l,p,f) for l in (0,1) for p in (0,1) for f in (0,1)]
DISPS=(0,4095,-4095,4096,-4096)
SHAPES=[(0,d,1) for d in DISPS]+[(1,d,s) for s in (1,2,4,8) for d in DISPS]+[(2,0x23456000,1),(2,0x180313320,1),(2,0x087E00000000,1)]+[(3,0x23456000,s) for s in (1,2,4,8)]
OPS=['bitsource','setcc_store','stack_push','stack_pop','push_mem','ret_stack','hot_scan','bounded_scan','copy_body','copy_count','store_count','zero_backedge']
def run(j,c):
 arch=c['arch'];n=4 if arch else 8;mask=(1<<(n*8))-1;op=c['op'];shape=c['shape'];width=c['width'];target=c['target'];g32=0x500000000 if arch else 0
 base=0x400000 if arch else 0x600000000;idx=0x13
 if c['variant']=='wrap':base=0xfffffff0;idx=0x10
 ptr_is_base=not(shape&2);initial=base if ptr_is_base else idx
 scanning=op in ('hot_scan','bounded_scan');counting=op in ('store_count','copy_count')
 ptr_off=j['rbx_off'] if ptr_is_base else j['rcx_off']
 def ea(step=0,delta=0):
  b=base+(step if ptr_is_base else 0);i=idx+(step if not ptr_is_base else 0)
  return t.O.ea_native(0 if shape&2 else b,i if shape&1 else 0,c['scale'],c['disp']+delta,arch)+g32
 ctx=bytearray(j['ctx_size']);fmt='<I' if arch else '<Q';value=0x8877665544332211
 vals={'rax_off':value,'rbx_off':base,'rcx_off':idx,'rdx_off':0 if op=='store_count' else initial+2 if op=='bounded_scan' else 2}
 if scanning:vals['rbx_off' if ptr_is_base else 'rcx_off']=(initial-1)&mask
 sp=(0 if op in ('stack_push','push_mem') else 0xfffffffc) if arch and c['variant']=='wrap' else 0x900000
 vals['rsp_off']=sp
 for k,v in vals.items():struct.pack_into(fmt,ctx,j[k],v&mask)
 struct.pack_into('<Q',ctx,j['g32_off'],g32)
 m=Sparse();m.map(t.CTX,ctx)
 for step in range(4):
  m.map(ea(step),bytes([0x21+step])*max(width,8));m.map(ea(step,64),bytes([0xc9])*max(width,8))
 # Terminal after two reads for the scan forms; multi-byte scan values remain valid.
 if scanning:m.map(ea(1),bytes(width))
 stackold=sp+g32;stacknew=t.O.ea_native(sp,0,1,-n,arch)+g32
 for address in (stackold,stacknew):m.map(address,bytes([0x7b])*n)
 old_source=m.read(ea(),width);source0=int.from_bytes(old_source,'little')
 # Native x86 MOVZX/MOV/LEA form the value and address oracle for these contracts.
 source0=t.O.extend_native(0,width,source0,0)
 expected_dst=[]
 if op in ('copy_body','copy_count'):
  for step in range(1 if op=='copy_body' else 2):expected_dst.append((ea(step,64),m.read(ea(step),width)))
 regs=[0xd00d000000000000+x*0x10101 for x in range(32)];regs[j['ctx_reg']]=t.CTX
 if c['pinned']:regs[24]=g32
 def helper(cpu,address):
  targets={int(v,16):k for k,v in j['helpers'].items()}
  if targets.get(address)!='store':raise Unsupported('extra unmodeled helper '+hex(address))
  rr=cpu.r
  if rr[0]!=t.CTX or rr[3] not in (1,2,4,8):raise Fault('wrong copy helper ABI')
  cpu.m.put(rr[1],rr[2],rr[3])
  for reg in range(19):rr[reg]=0xbadc0de000000000+reg
  rr[0]=0;cpu.nzcv=(1,0,1,1)
 cpu=CPU(regs,m,helper);cpu.run(bytes.fromhex(j['code']));errors=[]
 def eq(what,a,b):
  if a!=b:errors.append(f'{what}: {a!r} != {b!r}')
 def guest(k):return m.get(t.CTX+j[k],n)
 if op=='bitsource':eq('bit scan input',regs[j['rmap'][20]],source0)
 elif op=='setcc_store':eq('setcc memory',m.get(ea(),1),target&1)
 elif op in ('stack_push','push_mem'):
  eq('pushed',m.get(stacknew,n),(source0 if op=='push_mem' else value)&mask)
  eq('SP after push',guest('rsp_off'),t.O.ea_native(sp,0,1,-n,arch))
 elif op in ('stack_pop','ret_stack'):
  eq('popped',regs[j['rmap'][20]],int.from_bytes(bytes([0x7b])*n,'little'))
  eq('SP after pop/ret',guest('rsp_off'),t.O.ea_native(sp,0,1,n+(target if op=='ret_stack' else 0),arch))
  if op=='ret_stack':eq('ret target',m.get(t.CTX+j['pc_off'],8),int.from_bytes(bytes([0x7b])*n,'little'))
 elif scanning:
  eq('scan pointer',m.get(t.CTX+ptr_off,n),(initial+1)&mask)
  eq('scan PC',m.get(t.CTX+j['pc_off'],8),0x9000100c)
 elif op in ('copy_body','copy_count'):
  for address,b in expected_dst:eq('copied',m.read(address,len(b)),b)
  eq('copy pointer',m.get(t.CTX+ptr_off,n),(initial+(1 if op=='copy_body' else 2))&mask)
  if op=='copy_count':eq('remaining count',guest('rdx_off'),0)
  eq('copy PC',m.get(t.CTX+j['pc_off'],8),0x90001014 if op=='copy_body' else 0x9000101c)
 elif op=='store_count':
  for step in range(3):eq('fill byte',m.get(ea(step),1),0x5a)
  eq('fill count',guest('rdx_off'),3);eq('fill pointer',m.get(t.CTX+ptr_off,n),(initial+3)&mask)
 elif op=='zero_backedge':
  eq('zero byte',m.get(ea(),1),0);eq('ptr2',guest('rbx_off'),base+2);eq('index',guest('rcx_off'),idx+1);eq('count',guest('rdx_off'),1)
  eq('backedge PC',m.get(t.CTX+j['pc_off'],8),0x90001000)
 else:raise Unsupported('missing expectation for '+op)
 if c['pinned']:eq('pinned X24',regs[24],g32)
 return errors,dict(ea=hex(ea()),steps=len(cpu.trace))
def main():
 p=argparse.ArgumentParser();p.add_argument('--emitter',type=Path,default=t.HERE/'emitter');p.add_argument('--out',type=Path,default=t.HERE/'extra-results.json');p.add_argument('--require-clean',action='store_true');args=p.parse_args()
 rows=[];codes=[]
 for arch,lean,pinned,fused in CONFIGS:
  for op in OPS:
   if arch and op in ('hot_scan','copy_body','store_count','zero_backedge'):continue # fixtures require x64-sized guest GPRs
   if not arch and op in ('stack_push','stack_pop'):continue
   widths=[2,4]+([] if arch else [8]) if op=='bitsource' else [1,2] if op in ('hot_scan','copy_body','copy_count') else [4 if arch else 8] if op in ('stack_push','stack_pop','push_mem','ret_stack') else [1]
   for width in widths:
    for shape,disp,scale in ([(0,0,1)] if op in ('stack_push','stack_pop','ret_stack') else SHAPES):
     if arch and shape&2 and disp>0xffffffff:continue
     targets=[0,1] if op=='setcc_store' else [0,32,4095,4096] if op=='ret_stack' else [0]
     for target in targets:
      c=dict(op=op,arch=arch,lean=lean,pinned=pinned,fused=fused,width=width,shape=shape,disp=disp,scale=scale,target=target)
      j=t.generate(args.emitter,op,shape,disp,arch,lean,pinned,width,scale,target,fused,extra={'MACRUNNER_HB_INDIRECT_IC_RET':'0'})
      if not j['emitted']:rows.append(dict(**c,status='declined'));continue
      if lean and j['emitted_call']:rows.append(dict(**c,status='production-reemits-with-frame'));continue
      codes.append(dict(case=c,emission=j))
      for variant in (['normal','wrap'] if arch and not(shape&2) else ['normal']):
       cc=dict(c,variant=variant)
       try:errors,details=run(j,cc);status='mismatch' if errors else 'pass'
       except (Fault,Unsupported) as e:status='fault' if isinstance(e,Fault) else 'unsupported';errors=[str(e)];details={}
       rows.append(dict(**cc,status=status,errors=errors,**details))
 summary=dict(counts=dict(collections.Counter(r['status'] for r in rows)),total=len(rows),emissions=len(codes))
 args.out.write_text(json.dumps(dict(summary=summary,cases=rows),indent=2)+'\n');args.out.with_suffix('.code.json').write_text(json.dumps(codes,indent=2)+'\n');print(json.dumps(summary,indent=2))
 for st in ('mismatch','fault','unsupported'):print(st,dict(collections.Counter((r['op'],r['errors'][0].split(':')[0]) for r in rows if r['status']==st)))
 return int(args.require_clean and any(r['status'] in ('fault','mismatch','unsupported','unmodeled-call-route') for r in rows))
if __name__=='__main__':raise SystemExit(main())
