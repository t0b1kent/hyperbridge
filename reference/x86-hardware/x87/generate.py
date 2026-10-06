#!/usr/bin/env python3
# Original code, MIT License. No downloaded sources.
import pathlib,json,struct
P=pathlib.Path(__file__).resolve().parent; B=P/'build';B.mkdir(exist_ok=True)
forms=[]
def add(cls,name,asm,mode='unary',mb=0,out=0,flags=0,n=1,meta=0):
 forms.append(dict(cls=cls,name=name,asm=asm,mode=mode,mb=mb,out=out,flags=flags,n=n,meta=meta))
for bits in (32,64,80):
 typ={32:'dword',64:'qword',80:'tbyte'}[bits]
 add('load-store',f'FLD_m{bits}',f'fld {typ} ptr [rsi]',f'f{bits}',bits//8)
 for pop in (False,True):
  if bits==80 and not pop:continue
  op='fstp' if pop else 'fst';add('load-store',f'{op.upper()}_m{bits}',f'{op} {typ} ptr [rsi]','unary',0,bits//8)
for bits in (16,32,64):
 typ={16:'word',32:'dword',64:'qword'}[bits]
 add('load-store',f'FILD_m{bits}',f'fild {typ} ptr [rsi]',f'i{bits}',bits//8)
 for op in ('fist','fistp','fisttp'):
  if bits==64 and op=='fist':continue
  add('load-store',f'{op.upper()}_m{bits}',f'{op} {typ} ptr [rsi]','unary',0,bits//8)
add('load-store','FBLD_m80','fbld tbyte ptr [rsi]','bcd',10)
add('load-store','FBSTP_m80','fbstp tbyte ptr [rsi]','unary',0,10)
for op in ('fld1','fldz','fldpi','fldl2t','fldl2e','fldlg2','fldln2'):add('load-store',op.upper(),op,'constant',n=0)
for op in ('fld','fst','fstp'):add('load-store',op.upper()+'_ST1',op+' st(1)','binary',n=2)
for op in ('fadd','fsub','fsubr','fmul','fdiv','fdivr'):
 for d in (0,1):add('arithmetic',f'{op.upper()}_ST{d}_ST{1-d}',f'{op} st({d}), st({1-d})','binary',n=2)
 add('arithmetic',op.upper()+'P_ST1_ST0',op+'p st(1), st(0)','binary',n=2)
 for bits in (32,64):add('arithmetic',f'{op.upper()}_m{bits}',f'{op} '+{32:'dword',64:'qword'}[bits]+' ptr [rsi]',f'pair_f{bits}',bits//8)
 for bits in (16,32):add('arithmetic',f'FI{op[1:].upper()}_m{bits}',f'fi{op[1:]} '+{16:'word',32:'dword'}[bits]+' ptr [rsi]',f'pair_i{bits}',bits//8)
for op in ('fsqrt','fabs','fchs','frndint'):add('arithmetic',op.upper(),op)
for op in ('fcom','fcomp','fucom','fucomp'):
 add('comparison',op.upper()+'_ST1',op+' st(1)','binary',n=2)
 if not op.startswith('fu'):
  for bits in (32,64):add('comparison',f'{op.upper()}_m{bits}',op+' '+{32:'dword',64:'qword'}[bits]+' ptr [rsi]',f'pair_f{bits}',bits//8)
for op in ('fcompp','fucompp'):add('comparison',op.upper(),op,'binary',n=2)
for op in ('fcomi','fcomip','fucomi','fucomip'):add('comparison',op.upper()+'_ST1',op+' st, st(1)','binary',flags=1,n=2)
for op in ('ficom','ficomp'):
 for bits in (16,32):add('comparison',f'{op.upper()}_m{bits}',op+' '+{16:'word',32:'dword'}[bits]+' ptr [rsi]',f'pair_i{bits}',bits//8)
for op in ('ftst','fxam'):add('comparison',op.upper(),op)
for op in ('fprem','fprem1','fscale'):add('remainder-scale',op.upper(),op,'binary',n=2)
add('remainder-scale','FXTRACT','fxtract')
for op in ('fprem','fprem1'):add('remainder-scale',op.upper()+'_ITER',op,'iter',n=2)
for op in ('fsin','fcos','fsincos','fptan','f2xm1'):add('transcendental',op.upper(),op,'trans')
for op in ('fpatan','fyl2x','fyl2xp1'):add('transcendental',op.upper(),op,'transpair',n=2)
# Every stack operation has independent clean-state inputs over all 9 occupancy depths.
for op,asm in [('FLD1','fld1'),('FSTP_ST0','fstp st(0)'),('FADDP_ST1_ST0','faddp st(1), st(0)'),('FCOMPP','fcompp'),('FFREE_ST0','ffree st(0)'),('FFREE_ST3','ffree st(3)'),('FINCSTP','fincstp'),('FDECSTP','fdecstp'),('FXCH_ST1','fxch st(1)'),('FXCH_ST7','fxch st(7)'),('FNINIT','fninit'),('FNCLEX','fnclex')]:add('stack',op+'_DEPTH',asm,'stack',meta=1)
# Marked environment input pointers are symbolic constants; all machine addresses normalized.
for name,asm,mode,out in [('FNSTENV','fnstenv [rsi]','env',28),('FLDENV','fldenv [rsi]','envload',0),('FNSAVE','fnsave [rsi]','env',108),('FRSTOR','frstor [rsi]','restore',0),('FXSAVE64','fxsave64 [rsi]','env',512),('FXRSTOR64','fxrstor64 [rsi]','fxrestore',0),('FXSAVE','fxsave [rsi]','env',512),('FXRSTOR','fxrstor [rsi]','fxrestore',0)]:add('environment',name,asm,mode,{'envload':28,'restore':108,'fxrestore':512}.get(mode,0),out,meta=2)
for name,asm in [('FNOP','fnop'),('FLD1','fld1'),('FADD_ST0_ST1','fadd st, st(1)'),('FLD_m32','fld dword ptr [rsi]'),('FST_m64','fst qword ptr [rsi]'),('FCOMI_ST1','fcomi st, st(1)'),('FNCLEX','fnclex'),('FNINIT','fninit'),('FLDCW','fldcw [rsi]')]:add('environment','TRACE_'+name,asm,'envtrace',4 if name=='FLD_m32' else 0,8 if name=='FST_m64' else 0,name.startswith('FCOMI'),meta=1)
# Deferred exception snapshots include probe location and pre-probe FXSAVE state.
triggers=[('IE','fsqrt',0),('DE','fadd st, st(1)',1),('ZE','fdiv st, st(1)',2),('OE','fmul st, st(1)',3),('UE','fmul st, st(1)',4),('PE','fdiv st, st(1)',5),('STACK_UNDERFLOW','fadd st, st(1)',0),('STACK_OVERFLOW','fld1',0)]
for label,asm,bit in triggers:
 for probe in ('FWAIT','FLD1'):add('traps',label+'_'+probe,asm,'trap',n=bit,meta=3 if probe=='FWAIT' else 4)
# Values: first 30 form a complete all-pairs special cross product; the rest are rounding/integer boundaries.
v=[]
def val(name,se,sig):v.append((name,se,sig))
for name,se,sig in [('pzero',0,0),('nzero',0x8000,0),('pone',0x3fff,0x8000000000000000),('none',0xbfff,0x8000000000000000),('pinf',0x7fff,0x8000000000000000),('ninf',0xffff,0x8000000000000000),('qnan_a',0x7fff,0xc000000000001111),('qnan_b',0xffff,0xc000000000003333),('snan_a',0x7fff,0x8000000000002222),('snan_b',0xffff,0x8000000000004444),('denorm_min',0,1),('denorm_max',0,0x7fffffffffffffff),('ndenorm_min',0x8000,1),('ndenorm_max',0x8000,0x7fffffffffffffff),('normal_min',1,0x8000000000000000),('normal_max',0x7ffe,0xffffffffffffffff),('nnormal_min',0x8001,0x8000000000000000),('nnormal_max',0xfffe,0xffffffffffffffff),('pseudo_denorm',0,0x8000000000000001),('npseudo_denorm',0x8000,0x8000000000000001),('unnormal',0x4000,0x4000000000000101),('nunnormal',0xc000,0x4000000000000202),('pseudo_nan_a',0x7fff,0x4000000000005555),('pseudo_nan_b',0xffff,0x0000000000006666),('pseudo_inf',0x7fff,0),('npseudo_inf',0xffff,0),('two',0x4000,0x8000000000000000),('half',0x3ffe,0x8000000000000000),('three',0x4000,0xc000000000000000),('nhalf',0xbffe,0x8000000000000000)]:val(name,se,sig)
SPECIAL=len(v)
# Explicit half-way and adjacent encodings at PC=24,53,64; both signs.
for p in (24,53,64):
 for sign in (0,0x8000):
  for delta in (-1,0,1):
   # At p=64 use exact halfway near 0.5 as arithmetic input; true tie produced by add 2^-64.
   sig=0x8000000000000000+(1<<(63-p) if p<64 else 1)+delta
   val(f'p{p}_tie_{sign}_{delta}',0x3fff|sign,sig)
  val(f'p{p}_half_ulp_{sign}',(0x3fff-p)|sign,0x8000000000000000)
for bits in (16,32,64):
 for sign in (0,0x8000):
  for delta in (-1,0,1):
   # Around +/- 2^(bits-1), steps are exact binary80 ulps.
   val(f'i{bits}_edge_{sign}_{delta}',(0x3fff+bits-1)|sign,0x8000000000000000+delta if delta>=0 else 0xffffffffffffffff)
   if delta<0:v[-1]=(v[-1][0],(0x3fff+bits-2)|sign,v[-1][2])
for num in (1,3,5,65535,65537,4294967295,4294967297):
 for sign in (0,0x8000):
  e=num.bit_length()-1;val(f'halfint_{num}_{sign}',(0x3fff+e-1)|sign,num<<(63-e))
# Cast exact integer to binary80, all done via integer code, not host FP.
def enc_dyadic(n,e=0):
 s=0x8000 if n<0 else 0;n=abs(n)
 if not n:return (s,0)
 k=n.bit_length()-1;return (0x3fff+k+e|s,n<<(63-k))
# Several hundred exact rational/dyadic arguments plus pi-adjacent representable inputs.
trans=[]
for i in range(-192,193):trans.append((f'grid_{i}',*enc_dyadic(i,-5)))
for e in (-16445,-16400,-1000,-100,-65,-64,-63,-33,-20,-10,10,20,30,40,50,60,62,63,64,65,100):
 for s in (0,0x8000):
  se=0x3fff+e
  if se>0:trans.append((f'pow2_{e}_{s}',se|s,0x8000000000000000))
  else:trans.append((f'pow2_{e}_{s}',s,1<<(e+16445)))
# Pi constants are inputs with explicitly specified binary80 bits, not asserted transcendental answers.
for k,se,sig in [('pi2',0x3fff,0xc90fdaa22168c235),('pi',0x4000,0xc90fdaa22168c235),('pi2big',0x403c,0xc90fdaa22168c235)]:
 for sign in (0,0x8000):
  for d in range(-4,5):trans.append((f'{k}_{sign}_{d}',se|sign,sig+d))
F32=[0,0x80000000,0x3f800000,0xbf800000,0x7f800000,0xff800000,0x7fc01111,0xffc03333,0x7f802222,0xff804444,1,0x7fffff,0x800000,0x7f7fffff,0x80000001,0x807fffff,0x80800000,0xff7fffff,0x40000000,0x3f000000,0x40400000,0xbf000000,0x3f800001,0x3f7fffff,0x4b000000,0x4f000000,0x5f000000,0x3fc00000]
F64=[0,0x8000000000000000,0x3ff0000000000000,0xbff0000000000000,0x7ff0000000000000,0xfff0000000000000,0x7ff8000000001111,0xfff8000000003333,0x7ff0000000002222,0xfff0000000004444,1,0xfffffffffffff,0x10000000000000,0x7fefffffffffffff,0x8000000000000001,0x800fffffffffffff,0x8010000000000000,0xffefffffffffffff,0x4000000000000000,0x3fe0000000000000,0x4008000000000000,0xbfe0000000000000,0x3ff0000000000001,0x3fefffffffffffff,0x4330000000000000,0x41e0000000000000,0x43e0000000000000,0x3ff8000000000000]
ints={bits:[0,1,2,3,(1<<bits)-1,(1<<bits)-2,(1<<(bits-1))-1,1<<(bits-1),(1<<(bits-1))+1,(1<<(bits-2))-1,1<<(bits-2),(1<<bits)-(1<<(bits-2))] for bits in (16,32,64)}
bcd=[0,0x80000000000000000000,1,0x999999999999999999,0x80999999999999999999,0x123456789012345678,0x80123456789012345678,0x0000000000000000000a,0x000000000000000000af,0x00ffffffffffffffffff,0x7f123456789012345678,0xff123456789012345678]
modeid={m:i for i,m in enumerate(dict.fromkeys(f['mode'] for f in forms))}
S=['.intel_syntax noprefix','.text'];H=['/* Generated from original generate.py, MIT */']
for i,f in enumerate(forms):
 f['index']=i;fn='op_'+str(i);H.append(f'extern void {fn}(void*,void*,void*,void*,uint64_t*); extern char {fn}_insn, {fn}_probe, {fn}_resume;')
 S += [f'.global {fn}, {fn}_insn, {fn}_probe, {fn}_resume',f'.type {fn},@function',f'{fn}:','  fxrstor64 [rdi]','  push 0xad7','  popfq',f'{fn}_insn:',f"  {f['asm']}"]
 if f['mode']=='trap':S += ['  fxsave64 [rdx+512]',f'{fn}_probe:', '  fwait' if f['meta']==3 else '  fld1']
 else:S += [f'{fn}_probe:']
 S += [f'{fn}_resume:','  pushfq','  pop rax','  mov [r8], rax','  fxsave64 [rdx]','  fnstenv [rcx]','  fninit','  ret',f'.size {fn},.-{fn}']
S+=['.section .note.GNU-stack,"",@progbits']
H+=['static const struct form forms[]={']
for f in forms:H.append('{"%s","%s",%d,%d,%d,%d,%d,%d,%d,op_%d,&op_%d_insn,&op_%d_probe,&op_%d_resume},'%(f['cls'],f['name'],modeid[f['mode']],f['mb'],f['out'],f['flags'],f['n'],f['meta'],f['index'],f['index'],f['index'],f['index'],f['index']))
H+=['};']
for k,i in modeid.items():H+=['#define MODE_'+k.upper()+' '+str(i)]
H+=['#define SPECIAL '+str(SPECIAL),'static const struct value vals[]={']+[f'{{"{n}",0x{sig:016x}ULL,0x{se:04x}}},' for n,se,sig in v]+['};','static const struct value transvals[]={']+[f'{{"{n}",0x{sig:016x}ULL,0x{se:04x}}},' for n,se,sig in trans]+['};']
for name,arr in [('f32',F32),('f64',F64)]+[(f'i{k}',a) for k,a in ints.items()]:H += [f'static const uint64_t {name}[]={{'+','.join(f'0x{x:x}ULL' for x in arr)+'};']
H+=['static const struct value bcd[]={']+[f'{{"bcd{i}",0x{x&((1<<64)-1):016x}ULL,0x{x>>64:04x}}},'for i,x in enumerate(bcd)]+['};']
(B/'forms.S').write_text('\n'.join(S)+'\n');(B/'forms.h').write_text('\n'.join(H)+'\n')
(P/'forms.json').write_text(json.dumps(forms,indent=2)+'\n')
(P/'inputs.json').write_text(json.dumps(dict(special_count=SPECIAL,values=[dict(name=n,hex=f'{se:04x}{sig:016x}')for n,se,sig in v],transcendental=[dict(name=n,hex=f'{se:04x}{sig:016x}')for n,se,sig in trans],f32=[f'{x:08x}'for x in F32],f64=[f'{x:016x}'for x in F64],integers={k:[f'{x:0{k//4}x}'for x in a]for k,a in ints.items()},bcd=[f'{x:020x}'for x in bcd]),indent=2)+'\n')
print('forms',len(forms),'special',SPECIAL,'values',len(v),'trans',len(trans))
