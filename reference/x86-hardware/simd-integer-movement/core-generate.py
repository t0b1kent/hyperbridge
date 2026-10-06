#!/usr/bin/env python3
# Original code under MIT License. Generates assembly instructions and metadata, not results.
import json,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parent
B=ROOT/'core-build';B.mkdir(exist_ok=True)
F=[]
def add(cls,op,width=128,enc='SSE',arity=2,imm=-1,lane=1,mode='normal',mem=True,feature='avx2'):
    variants=['reg','mem-aligned','mem-unaligned'] if mem else ['reg']
    for loc in variants:
        F.append(dict(cls=cls,op=op,width=width,enc=enc,arity=arity,imm=imm,lane=lane,mode=mode,loc=loc,feature=feature))
def standard(cls,ops,arity=2,imm=False,lane=1,only128=False,mode='normal'):
    for op in ops.split():
        for enc,width in [('SSE',128),('VEX',128),*([] if only128 else [('VEX',256)])]:
            for i in (range(256) if imm else [-1]):add(cls,op,width,enc,arity,i,lane,mode)
# 2. Permutes, shuffles, blends: all immediate byte values, including ignored high bits.
for op,l in [('pshufd',4),('pshuflw',2),('pshufhw',2)]:standard('permutation',op,1,True,l)
for op,l in [('shufps',4),('shufpd',8),('palignr',1),('blendps',4),('blendpd',8),('pblendw',2)]:standard('permutation',op,2,True,l)
standard('permutation','pshufb',2,lane=1)
for op,l in [('unpcklps',4),('unpckhps',4),('unpcklpd',8),('unpckhpd',8),('punpcklbw',1),('punpckhbw',1),('punpcklwd',2),('punpckhwd',2),('punpckldq',4),('punpckhdq',4),('punpcklqdq',8),('punpckhqdq',8)]:standard('permutation',op,lane=l)
for op,l in [('blendvps',4),('blendvpd',8),('pblendvb',1)]:standard('permutation',op,lane=l,mode='blendvar')
for width in (128,256):
    for op,l in [('pblendd',4),('permilps',4),('permilpd',8)]:
        for i in range(256):add('permutation',op,width,'VEX',2 if op=='pblendd' else 1,i,l)
    for op,l in [('permilps',4),('permilpd',8)]:add('permutation',op,width,'VEX',2,-1,l,'permvar')
for op in ('perm2f128','perm2i128'):
    for i in range(256):add('permutation',op,256,'VEX',2,i,16)
for op in ('permd','permps'):add('permutation',op,256,'VEX',2,-1,4,'permfull')
for op in ('permq','permpd'):
    for i in range(256):add('permutation',op,256,'VEX',1,i,8)
# 3. Integer arithmetic, saturating and wrapping.
for suf,l in [('b',1),('w',2),('d',4),('q',8)]:standard('arithmetic','padd'+suf+' psub'+suf,lane=l)
for suf,l in [('sb',1),('sw',2),('usb',1),('usw',2)]:standard('arithmetic','padd'+suf+' psub'+suf,lane=l)
for op,l in [('pmullw',2),('pmulhw',2),('pmulhuw',2),('pmulld',4),('pmuludq',4),('pmuldq',4),('pmulhrsw',2),('pmaddwd',2),('pmaddubsw',1),('pavgb',1),('pavgw',2),('psadbw',1)]:standard('arithmetic',op,lane=l)
for op in ['pmin','pmax']:
    for suf,l in [('sb',1),('sw',2),('sd',4),('ub',1),('uw',2),('ud',4)]:standard('arithmetic',op+suf,lane=l)
for suf,l in [('b',1),('w',2),('d',4)]:
    standard('arithmetic','pabs'+suf,1,lane=l)
    standard('arithmetic','psign'+suf,2,lane=l)
for op in ('phaddw','phaddd','phaddsw','phsubw','phsubd','phsubsw'):standard('arithmetic',op,lane=4 if op.endswith('d') else 2)
standard('arithmetic','phminposuw',1,lane=2,only128=True)
standard('arithmetic','mpsadbw',2,True,lane=1)
# 4. Logic, compare, flag tests.
standard('logic','pand pandn por pxor andps andnps orps xorps andpd andnpd orpd xorpd',lane=1)
for suf,l in [('b',1),('w',2),('d',4),('q',8)]:standard('logic','pcmpeq'+suf+' pcmpgt'+suf,lane=l)
standard('logic','ptest',2,lane=1,mode='flags')
for op,l in [('testps',4),('testpd',8)]:
    for w in (128,256):add('logic',op,w,'VEX',2,-1,l,'flags')
# 5. Packed shifts, all imm8, scalar register counts, and per-element counts.
for op,l in [('psllw',2),('pslld',4),('psllq',8),('psrlw',2),('psrld',4),('psrlq',8),('psraw',2),('psrad',4)]:
    # Immediate forms cannot read memory with legacy SSE; VEX has reg source only too.
    for enc,w in [('SSE',128),('VEX',128),('VEX',256)]:
        for i in range(256):add('shifts',op,w,enc,1,i,l,'shiftimm',False)
        add('shifts',op,w,enc,2,-1,l,'shiftcount',True)
for op in ('pslldq','psrldq'):
    for enc,w in [('SSE',128),('VEX',128),('VEX',256)]:
        for i in range(256):add('shifts',op,w,enc,1,i,1,'shiftbytes',False)
for op,l in [('psllvd',4),('psllvq',8),('psrlvd',4),('psrlvq',8),('psravd',4)]:
    for w in (128,256):add('shifts',op,w,'VEX',2,-1,l,'shiftvar')
# 6. Packing, lane-local in 256-bit forms.
for op,l in [('packsswb',2),('packssdw',4),('packuswb',2),('packusdw',4)]:standard('pack',op,lane=l)
# Each kernel loads full YMMs. YMM4 is destination, YMM1/YMM2 operands, YMM0 blend mask.
S=['.text'];H=[];R=[]
for i,f in enumerate(F):
    f['id']=i;name='core_'+str(i);reg='xmm' if f['width']==128 else 'ymm';v=f['enc']=='VEX';mem=f['loc']!='reg';op=('v' if v else '')+f['op'];d='%'+reg+'4';a='%'+reg+'1';b='%'+reg+'2';ma='(%rdx)';im='$'+str(f['imm'])
    if f['mode'] in ('shiftimm','shiftbytes'):
        asm=f'{op} {im}, {a}, {d}' if v else f'{op} {im}, {d}'
    elif f['mode']=='shiftcount':
        count=ma if mem else '%xmm2';asm=f'{op} {count}, {a}, {d}' if v else f'{op} {count}, {d}'
    elif f['mode']=='flags':
        # Tests use destination-before as first operand, never write a vector destination.
        asm=f'{op} {ma if mem else a}, {d}'
    elif f['mode']=='blendvar':
        asm=f'{op} %{reg}0, {ma if mem else b}, {a}, {d}' if v else f'{op} {ma if mem else a}, {d}'
    elif f['mode']=='permfull':
        # VPERMD/PS use first source as indices and second as data.
        asm=f'{op} {ma if mem else b}, {a}, {d}'
    elif f['arity']==1:
        asm=f'{op} '+(im+', ' if f['imm']>=0 else '')+f'{ma if mem else a}, {d}'
    else:
        asm=f'{op} '+(im+', ' if f['imm']>=0 else '')+(f'{ma if mem else b}, {a}, {d}' if v else f'{ma if mem else a}, {d}')
    f['asm']=asm;f['memslot']=2 if f['mode']=='shiftcount' or (v and f['arity']==2 and f['mode']!='flags') else 1
    f['memsize']=16 if f['mode']=='shiftcount' else f['width']//8
    if f['imm']>=0:f['cases']=4 if f['cls']!='shifts' else 8
    elif f['mode']=='shiftcount':f['cases']=f['lane']*8+6
    else:f['cases']=24
    f['expected_rows']=f['cases']
    S.extend([f'.globl {name}',f'.type {name},@function',name+':','vmovdqu 0(%rdi), %ymm4','vmovdqu 32(%rdi), %ymm1','vmovdqu 64(%rdi), %ymm2','vmovdqu 96(%rdi), %ymm0','pushq $0xad7','popfq','pushfq','popq %rax','movq %rax, 40(%rsi)',f'.globl {name}_fault',name+'_fault:',asm,f'.globl {name}_resume',name+'_resume:','vmovdqu %ymm4, 0(%rsi)','pushfq','popq %rax','movq %rax, 32(%rsi)','vzeroupper','ret',f'.size {name},.-{name}'])
    H.append(f'extern void {name}(const struct input *,struct output *,const void *);\nextern char {name}_fault,{name}_resume;')
    fields=[json.dumps(f[x]) for x in ('cls','op','enc','loc','mode')]+[str(f[x]) for x in ('width','arity','imm','lane','cases','memslot','memsize')]+[name,'&'+name+'_fault','&'+name+'_resume']
    R.append('{'+','.join(fields)+'},')
S+=['.section .note.GNU-stack,"",@progbits']
(B/'core.S').write_text('\n'.join(S)+'\n');(B/'forms.h').write_text('\n'.join(H)+'\nstatic const struct form forms[]={\n'+'\n'.join(R)+'\n};\n')
(ROOT/'core-inventory.json').write_text(json.dumps(F,indent=2)+'\n')
print('Generated',len(F),'forms;',sum(f['cases'] for f in F),'rows')
