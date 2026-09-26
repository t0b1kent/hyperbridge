#!/usr/bin/env python3
"""Actual C emitter + fail-closed A64 data evaluator + native x86 oracle.
Negative control: any known-broken selected source must fail --require-clean.
Every unsupported word is reported separately, never accepted as a pass.
"""
import argparse,ctypes,json,os,struct,subprocess,random,collections,atexit,tempfile
from pathlib import Path
from a64_eval import CPU,Memory,Fault,Unsupported,MASK
HERE=Path(__file__).resolve().parent;CTX=0x100000000000
O=ctypes.CDLL(os.environ.get('HB_EA_ORACLE',str(HERE/'out/oracle.so')))
O.ea_native.argtypes=[ctypes.c_uint64,ctypes.c_uint64,ctypes.c_int,ctypes.c_int64,ctypes.c_int];O.ea_native.restype=ctypes.c_uint64
O.vector_native.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_int]
O.scalar_native.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_uint64,ctypes.c_uint64,ctypes.POINTER(ctypes.c_uint64)];O.scalar_native.restype=ctypes.c_uint64
O.extend_native.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_uint64,ctypes.c_int];O.extend_native.restype=ctypes.c_uint64
SERVERS={}
def close_servers():
 for p,f in SERVERS.values():
  p.stdin.close();p.wait(timeout=15);f.close()
 SERVERS.clear()
atexit.register(close_servers)
class HelperRoute(Exception):
 def __init__(self,details):self.details=details

VOP={'xor':0,'regxor':0,'and':1,'andn':2,'or':3,'unpackhi':4,'unpacklo':5,'load':6,'movload':6,'xmm_pair':6,'insert':7,'extract':8,'regunpack':9}
SOP={'add':0,'sub':1,'and':2,'or':3,'xor':4}
OPS=list(VOP)+['movstore','scalar_rhs','scalar_lhs','rmw_add','rmw_sub','rmw_and','rmw_or','rmw_xor','lock_add','lock_sub','lock_and','lock_or','lock_xor','adj_load','adj_store','adj_alias','scalar_pair','insert','insert_mem','extract','extract_mem','vexxor','vexload','rmw_adc','rmw_sbb']+[a+'_'+b for a in ('cmp','test') for b in ('rhs','lhs')]+['binary_'+x for x in SOP]+['dispatch_'+x for x in ('cmpxchg','cmpxchg8b','cmpxchg16b','x87_fld','x87_fadd','x87_fstp','insert_mem','extract_mem','vexxor','avxxor')]
OPS=list(dict.fromkeys(OPS+['tso_load','tso_store','extend_signed','extend_zero','branch_mem']+[a+'_'+b for a in ('cmp','test') for b in ('memreg','memimm','simple')]))
OPS += ['ir_xmm_load','ir_xmm_store','ir_narrow_load','ir_narrow_store','ir_movd_load','ir_movd_store','ir_scalar_mov_load']
def vector(op,a,b,imm=0):
 out=ctypes.create_string_buffer(16);O.vector_native(VOP[op],a,b,out,imm);return out.raw

def generate(binary,op,shape,disp,arch,lean,pinned,width=8,scale=4,target=0,fused=0,extra=None):
 env={k:v for k,v in os.environ.items() if not k.startswith('MACRUNNER_')}
 env.update(MACRUNNER_HB_JIT_DIRECT_MEM='1',MACRUNNER_HB_JIT_DIRECT_SCALAR_MEM='1',MACRUNNER_HB_NATIVE_MEM_I386='1',MACRUNNER_HB_EA_FUSED_UXTW=str(fused),MACRUNNER_HB_PIN_GUEST32_BASE=str(pinned),MACRUNNER_HB_GUEST32_HOST_PERM='1',MACRUNNER_HB_DIRECT_BYTE_STORE='1',MACRUNNER_HB_NATIVE_MEM_BYTE_LOADS='1',MACRUNNER_HB_JCC_FUSE_FULL='1')
 if extra:env.update(extra)
 key=(str(binary),arch,lean,pinned,fused,tuple(sorted((extra or {}).items())))
 if key not in SERVERS:
  log=tempfile.TemporaryFile(mode='w+t')
  proc=subprocess.Popen([str(binary),'--server'],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,text=True,bufsize=1)
  SERVERS[key]=(proc,log)
 proc,log=SERVERS[key]
 line=' '.join(map(str,[op,shape,disp,arch,lean,pinned,width,scale,target]))+'\n'
 proc.stdin.write(line);proc.stdin.flush();out=proc.stdout.readline()
 if not out:
  log.seek(0);raise RuntimeError('emitter server failed: '+log.read()[-3000:])
 return json.loads(out)

def run(j,c,a,b):
 arch=c['arch'];op=c['op'];width=c['width'];pinned=c['pinned'];shape=c['shape'];disp=c['disp'];scale=c['scale']
 base=c.get('base',0x400000 if arch else 0x600000000);index=c.get('index',0x13)
 if arch:base&=0xffffffff;index&=0xffffffff
 g32=0x500000000 if arch else 0
 ea=O.ea_native(0 if shape&2 else base,index if shape&1 else 0,scale,disp,arch)+g32
 dst=O.ea_native(0 if shape&2 else base,index if shape&1 else 0,scale,disp+64,arch)+g32
 ctx=bytearray(j['ctx_size']);ab=struct.pack('<QQ',*a);bb=struct.pack('<QQ',*b)
 ctx[j['xmm_off']:j['xmm_off']+16]=ab;ctx[j['xmm1_off']:j['xmm1_off']+16]=bb
 fmt='<I' if arch else '<Q';gm=0xffffffff if arch else MASK
 for key,v in [('rax_off',a[0]),('rdx_off',a[1]),('rbx_off',base),('rcx_off',index)]:struct.pack_into(fmt,ctx,j[key],v&gm)
 struct.pack_into('<Q',ctx,j['g32_off'],g32)
 mem=Memory();mem.map(CTX,ctx);mem.map(ea,bb+bytes([0xA7])*32)
 mem.map(dst,bytes([0xC9])*48)
 regs=[0xD00D000000000000+r*0x10101 for r in range(32)];regs[j['ctx_reg']]=CTX
 if pinned:regs[24]=g32
 helpers={int(v,16):k for k,v in j['helpers'].items()};calls=[]
 def helper(cpu,addr):
  kind=helpers.get(addr)
  if kind is None:raise Unsupported('unmodeled helper target '+hex(addr))
  rr=cpu.r;calls.append({'kind':kind,'args':[hex(x) for x in rr[:5]]})
  if rr[0]!=CTX:raise Fault('bad helper ctx '+hex(rr[0]))
  if kind in ('interp','atomic'):
   if rr[1]!=int(j['ir_ptr'],16):raise Fault('bad IR helper pointer')
   expected='atomic' if 'cmpxchg' in op else 'interp'
   if kind!=expected:raise Fault('wrong helper family '+kind+' expected '+expected)
   raise HelperRoute({'kind':kind,'args':[hex(x) for x in rr[:3]],'steps':len(cpu.trace)})
  if kind=='store_u128':cpu.m.write(rr[1],struct.pack('<QQ',rr[2],rr[3]))
  elif kind=='store':
   if rr[3] not in (1,2,4,8):raise Fault('bad store width')
   cpu.m.put(rr[1],rr[2],rr[3])
  elif kind=='load':
   if rr[2]!=0:raise Unsupported('helper guest reg other than RAX')
   val=cpu.m.get(rr[1],rr[3]);off=CTX+j['rax_off'];n=4 if arch or rr[3]==4 else 8
   old=cpu.m.get(off,n);bits=rr[3]*8;shift=rr[4]*8
   result=(old&~(((1<<bits)-1)<<shift))|(val<<shift)
   cpu.m.put(off,result,n)
  for r in range(19):rr[r]=(0xBADC0DE000000000+r)&MASK
  rr[0]=0
 cpu=CPU(regs,mem,helper);cpu.run(bytes.fromhex(j['code']))
 failures=[]
 def eq(label,got,expected):
  if got!=expected:failures.append(label+': '+(got.hex() if isinstance(got,bytes) else hex(got))+' != '+(expected.hex() if isinstance(expected,bytes) else hex(expected)))
 if op in VOP and op!='extract': eq('xmm0',mem.read(CTX+j['xmm_off'],16),vector(op,ab,bb,c.get('target',0)))
 if op=='ir_xmm_load':eq('IR XMM load',mem.read(CTX+j['xmm_off'],16),vector('load',ab,bb))
 if op=='ir_xmm_store':eq('IR XMM store',mem.read(ea,16),ab)
 if op in ('ir_narrow_load','ir_movd_load'):eq('IR narrow XMM load',mem.read(CTX+j['xmm_off'],16),struct.pack('<QQ',O.extend_native(0,width,b[0],0),0))
 if op in ('ir_narrow_store','ir_movd_store'):eq('IR narrow XMM store',mem.get(ea,width),O.extend_native(0,width,a[0],0))
 if op=='ir_scalar_mov_load':eq('IR scalar MOV load',mem.get(CTX+j['rax_off'],width),O.extend_native(0,width,b[0],0))
 if op=='movstore':eq('store128',mem.read(ea,16),ab)
 if op=='xmm_pair':eq('pair128',mem.read(dst,16),bb)
 if op in ('scalar_rhs','scalar_lhs'):
  v=b[0]&((1<<(width*8))-1);u=a[0]&((1<<(width*8))-1)
  eq('scalar operands',mem.read(CTX+j['xmm_off'],16),struct.pack('<QQ',*( (u,v) if op=='scalar_rhs' else (v,u))))
 if op.startswith(('rmw_','lock_')):
  q=ctypes.c_uint64();expect=O.scalar_native(SOP[op.split('_')[1]],width,b[0],a[0],ctypes.byref(q))
  eq('RMW memory',mem.get(ea,width),expect)
 if op=='adj_load':
  eq('first adjacent load',mem.get(CTX+j['rax_off'],8),b[0]);eq('second adjacent load',mem.get(CTX+j['rdx_off'],8),b[1])
 if op=='adj_alias':
  eq('first alias load',mem.get(CTX+j['rbx_off'],8),b[0]);eq('second alias load',mem.get(CTX+j['rdx_off'],8),b[1])
 if op=='adj_store':eq('adjacent stores',mem.read(ea,16),ab)
 if op=='scalar_pair':eq('scalar pair store',mem.get(dst,width),b[0]&((1<<(width*8))-1))
 if op=='extract':eq('extract',mem.read(CTX+j['rax_off'],4),vector(op,ab,bb,c.get('target',0))[:4])
 if op.startswith(('cmp_','test_')):
  lhs,rhs=(a[0],b[0]) if op.endswith('rhs') else (b[0],a[0]);flags=ctypes.c_uint64()
  if 'memimm' in op:rhs=0x35
  O.scalar_native(SOP['sub' if op.startswith('cmp') else 'and'],width,lhs,rhs,ctypes.byref(flags))
  f=flags.value;z=bool(f&64);sf=bool(f&128);cf=bool(f&1);of=bool(f&2048);pf=bool(f&4)
  choices=[z,not z,sf,not sf,not z and sf==of,sf==of,sf!=of,z or sf!=of,not cf and not z,not cf,cf,cf or z,of,not of,pf,not pf]
  eq('compare branch PC',mem.get(CTX+j['pc_off'],8),0x90001010 if choices[c['target']] else 0x9000100a)
 if op.startswith('binary_'):
  flags=ctypes.c_uint64();value=O.scalar_native(SOP[op[7:]],width,a[0],a[1],ctypes.byref(flags))
  eq('scalar X22 result',regs[j['rmap'][22]]&((1<<(width*8))-1),value)
 if op.startswith('extend_'):
  n=4 if arch else 8;eq('extended register',mem.get(CTX+j['rax_off'],n),O.extend_native(op=='extend_signed',width,b[0],arch))
 if op=='branch_mem':eq('indirect target',regs[j['rmap'][20]],b[0]&(0xffffffff if arch else MASK))
 if op=='tso_load':eq('TSO load',mem.get(CTX+j['rax_off'],width),b[0]&((1<<(width*8))-1))
 if op=='tso_store':eq('TSO store',mem.get(ea,width),a[0]&((1<<(width*8))-1))
 eq('source canary',mem.read(ea+16,32),bytes([0xA7])*32)
 eq('destination canary',mem.read(dst+16,32),bytes([0xC9])*32)
 if pinned:eq('pinned X24',regs[24],g32)
 return failures,{'ea':hex(ea),'dst':hex(dst),'calls':calls,'steps':len(cpu.trace),'words':sorted(cpu.words)}

def main():
 p=argparse.ArgumentParser();p.add_argument('--emitter',type=Path,default=HERE/'emitter');p.add_argument('--out',type=Path,default=HERE/'results.json');p.add_argument('--quick',action='store_true');p.add_argument('--require-clean',action='store_true');args=p.parse_args()
 configs=[(1,0,0,1),(1,1,0,1),(0,0,0,0),(0,1,0,0),(1,0,0,0),(1,1,0,0),(1,0,1,0),(1,1,1,0),(1,0,1,1),(1,1,1,1)]
 # Cartesian scales x boundary displacements; absolute forms are post-lifter RIP.
 disps=(0,4095,-4095,4096,-4096)
 shapes=[(0,d,1) for d in disps]+[(1,d,s) for s in (1,2,4,8) for d in disps]+[(2,0x23456000,1),(2,0x180313320,1),(2,0x087E00000000,1)]+[(3,0x23456000,s) for s in (1,2,4,8)]
 if args.quick:shapes=[(0,0,1),(1,4096,4)]
 records=[];rng=random.Random(20260926);codes=[]
 for arch,lean,pinned,fused in configs:
  for op in OPS:
   if arch and (op.startswith('adj_') or op=='dispatch_cmpxchg16b'):continue # CMPXCHG16B and mem64 GPR pairs require x64
   widths=[1,2,4]+([] if arch else [8]) if op.startswith(('scalar','rmw_','cmp_','test_','binary_','tso_','extend_')) else [4] if op.startswith('lock_') else [8]
   if not arch and op.startswith('lock_'):widths=[4,8]
   if op.startswith(('ir_narrow','ir_movd')):widths=[4,8]
   if op=='ir_scalar_mov_load':widths=[1,2,4]+([] if arch else [8])
   if op in ('insert_mem','extract_mem','dispatch_insert_mem','dispatch_extract_mem'):widths=[4]
   if op=='dispatch_cmpxchg':widths=[1,2,4]+([] if arch else [8])
   if args.quick:widths=widths[-1:]
   for width in widths:
    for shape,disp,scale in shapes:
     if arch and shape&2 and disp>0xffffffff:continue
     if (op in ('insert','extract','regxor','regunpack') or op.startswith('binary_')) and (shape,disp,scale)!=(0,0,1):continue
     targets=range(256) if op=='insert' else range(4) if op=='extract' else [x+h for h in (0,256) for x in (1,2,4,8)] if op=='regunpack' else [0,2,6,10] if op.startswith(('cmp_','test_')) else [0]
     if args.quick:targets=list(targets)[:2]
     for target in targets:
      c=dict(op=op,arch=arch,lean=lean,pinned=pinned,fused=fused,width=width,shape=shape,disp=disp,scale=scale,target=target)
      j=generate(args.emitter,op,shape,disp,arch,lean,pinned,width,scale,target,fused=fused)
      if not j['emitted']:
       records.append(dict(**c,status='declined',size=j['size']));continue
      if lean and j['emitted_call']:
       records.append(dict(**c,status='production-reemits-with-frame',size=j['size']));continue
      codes.append(dict(case=c,emission=j))
      variants=[('normal',{})]
      if arch and not(shape&2) and not args.quick and op not in ('insert','extract','regxor','regunpack') and not op.startswith(('binary_','dispatch_')):variants.append(('wrap',dict(base=0xfffffff0,index=0x10)))
      for variant,over in variants:
       c1=dict(c,**over,variant=variant);a=(rng.getrandbits(64),rng.getrandbits(64));b=(rng.getrandbits(64),rng.getrandbits(64))
       try:
        err,details=run(j,c1,a,b);status='mismatch' if err else 'pass'
       except HelperRoute as e:status='helper-route';err=[];details=e.details
       except Unsupported as e:status='unsupported';err=[str(e)];details={}
       except Fault as e:status='fault';err=[str(e)];details={}
       records.append(dict(**c1,status=status,errors=err,a=[hex(x) for x in a],b=[hex(x) for x in b],**details))
 summary=dict(counts=dict(collections.Counter(r['status'] for r in records)),total=len(records),emissions=len(codes),source='actual compiled codegen, see manifest',limitations='A64 bounded evaluator, not Mac; helper ABI contracts modeled only for three transfer helpers; no memory-order or multi-thread atomic claims')
 args.out.write_text(json.dumps(dict(summary=summary,cases=records),indent=2)+'\n');args.out.with_suffix('.code.json').write_text(json.dumps(codes,indent=2)+'\n');print(json.dumps(summary,indent=2))
 for st in ('mismatch','fault','unsupported'):
  print(st,dict(collections.Counter((r['op'],r['errors'][0].split(':')[0]) for r in records if r['status']==st)))
 if args.require_clean and any(r['status'] in ('mismatch','fault','unsupported') for r in records):return 1
 return 0
if __name__=='__main__':raise SystemExit(main())
