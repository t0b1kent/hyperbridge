#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
D=Path(__file__).resolve().parent
ops=[]
def add(name,enc,ins,kind,w=16,e=1,aux=0,mem=0,imm=-1,align=1):
 ops.append(dict(name=name,enc=enc,ins=ins,kind=kind,w=w,e=e,aux=aux,mem=mem,imm=imm,align=align))
# mem: 0 register, 1 load, 2 store; exact accessible length is aux for scalar operations.
for vex in [0,1]:
 pre='v' if vex else ''; enc='VEX128' if vex else 'SSE'
 for bits in [32,64]:
  m=pre+('movd' if bits==32 else 'movq'); reg='eax' if bits==32 else 'rax'
  add(m+'.gpr_to_xmm',enc,f'{m} xmm0, {reg}','gprload',e=bits//8)
  add(m+'.xmm_to_gpr',enc,f'{m} {reg}, xmm1','gprstore',e=bits//8)
  add(m+'.load',enc,f'{m} xmm0, [rsi]','scalarload',e=bits//8,mem=1)
  add(m+'.store',enc,f'{m} [rsi], xmm1','scalarstore',e=bits//8,mem=2)
 add(pre+'movq.reg',enc,f'{pre}movq xmm0, xmm1','scalarload',e=8)
 add(pre+'movq.store_opcode_reg',enc,'.byte '+('0xc5,0xf9,0xd6,0xc8' if vex else '0x66,0x0f,0xd6,0xc8'),'scalarload',e=8)
 for root in ['movdqa','movdqu','movaps','movups','movapd','movupd']:
  for w in ([16,32] if vex else [16]):
   r='xmm' if w==16 else 'ymm'; ee=f'VEX{w*8}' if vex else 'SSE'; m=pre+root
   add(m+'.reg',ee,f'{m} {r}0, {r}1','copy',w=w)
   for mode in [1,2]:
    ins=f'{m} {r}0, [rsi]' if mode==1 else f'{m} [rsi], {r}1'
    add(m+('.load' if mode==1 else '.store'),ee,ins,'copy' if mode==1 else 'store',w=w,mem=mode,align=w if root in ['movdqa','movaps','movapd'] else 1)
 for bits in [32,64]:
  m=pre+('movss' if bits==32 else 'movsd')
  add(m+'.reg',enc,f'{m} xmm0, xmm1, xmm2' if vex else f'{m} xmm0, xmm1','scalarmix',e=bits//8)
  add(m+'.store_opcode_reg',enc,'.byte '+(('0xc5,0xf2,0x11,0xd0' if bits==32 else '0xc5,0xf3,0x11,0xd0') if vex else ('0xf3,0x0f,0x11,0xc8' if bits==32 else '0xf2,0x0f,0x11,0xc8')),'scalarmix',e=bits//8)
  add(m+'.load',enc,f'{m} xmm0, [rsi]','scalarload',e=bits//8,mem=1)
  add(m+'.store',enc,f'{m} [rsi], xmm1','scalarstore',e=bits//8,mem=2)
 for root,hi in [('movlps',0),('movhps',1),('movlpd',0),('movhpd',1)]:
  m=pre+root
  add(m+'.load',enc,f'{m} xmm0, xmm1, [rsi]' if vex else f'{m} xmm0, [rsi]','halfload',e=8,aux=hi,mem=1)
  add(m+'.store',enc,f'{m} [rsi], xmm1','halfstore',e=8,aux=hi,mem=2)
 for root,aux in [('movlhps',0),('movhlps',1)]:
  m=pre+root
  add(m,enc,f'{m} xmm0, xmm1, xmm2' if vex else f'{m} xmm0, xmm1','halfmix',e=8,aux=aux)
 for root,e,odd in [('movddup',8,0),('movsldup',4,0),('movshdup',4,1)]:
  for w in ([16,32] if vex else [16]):
   r='xmm' if w==16 else 'ymm'; m=pre+root; ee=f'VEX{w*8}' if vex else 'SSE'
   for mem in [0,1]: add(m+('.load' if mem else '.reg'),ee,f'{m} {r}0, '+('[rsi]' if mem else f'{r}1'),'duplicate',w=w,e=e,aux=odd,mem=mem,align=16 if (not vex and root!='movddup' and mem) else 1)
 for sx in [0,1]:
  for suf,i,o in [('bw',1,2),('bd',1,4),('bq',1,8),('wd',2,4),('wq',2,8),('dq',4,8)]:
   for w in ([16,32] if vex else [16]):
    r='xmm' if w==16 else 'ymm'; m=pre+'pmov'+('sx' if sx else 'zx')+suf; ee=f'VEX{w*8}' if vex else 'SSE'
    for mem in [0,1]: add(m+('.load' if mem else '.reg'),ee,f'{m} {r}0, '+('[rsi]' if mem else 'xmm1'),'extend',w=w,e=i,aux=o|(sx<<8),mem=mem)
 for root,e in [('movmskps',4),('movmskpd',8),('pmovmskb',1)]:
  for w in ([16,32] if vex else [16]):
   r='xmm' if w==16 else 'ymm'; m=pre+root
   add(m,f'VEX{w*8}' if vex else 'SSE',f'{m} eax, {r}1','movmask',w=w,e=e)
 add(pre+'maskmovdqu',enc,f'{pre}maskmovdqu xmm1, xmm2','maskstore',w=16,e=1,mem=2)
 for kind in ['extract','insert']:
  for root,e in [('b',1),('w',2),('d',4),('q',8)]:
   m=pre+('pextr' if kind=='extract' else 'pinsr')+root
   for mem in [0,1]:
    for imm in range(256):
     if kind=='extract':
      dst='[rsi]' if mem else ('rax' if e==8 else 'eax'); ins=f'{m} {dst}, xmm1, {imm}'
      # Force SSE4.1 encoding for PEXTRW register form; the SSE2 form is covered separately.
      if root=='w' and not mem:
       ins=('.byte 0xc4,0xe3,0x79,0x15,0xc8,' if vex else '.byte 0x66,0x0f,0x3a,0x15,0xc8,')+str(imm)
      add(m+('.mem' if mem else '.gpr'),enc,ins,'extract',e=e,mem=2 if mem else 0,imm=imm)
     else:
      src='[rsi]' if mem else ('rax' if e==8 else 'eax'); ins=f'{m} xmm0, '+('xmm1, ' if vex else '')+f'{src}, {imm}'
      add(m+('.mem' if mem else '.gpr'),enc,ins,'insert',e=e,mem=mem,imm=imm)
  # SSE2 PEXTRW register-only encoding, distinct from SSE4.1 above.
  for imm in (range(256) if kind=='extract' else []):
   ins=('.byte 0xc5,0xf9,0xc5,0xc1,' if vex else '.byte 0x66,0x0f,0xc5,0xc1,')+str(imm)
   add(pre+'pextrw.sse2_gpr',enc,ins,'extract',e=2,imm=imm)
 for mem in [0,1]:
  for imm in range(256):
   m=pre+'extractps'; dst='[rsi]' if mem else 'eax'
   add(m+('.mem' if mem else '.gpr'),enc,f'{m} {dst}, xmm1, {imm}','extract',e=4,mem=2 if mem else 0,imm=imm)
   m=pre+'insertps'; src='[rsi]' if mem else ('xmm2' if vex else 'xmm1')
   add(m+('.mem' if mem else '.reg'),enc,f'{m} xmm0, '+('xmm1, ' if vex else '')+f'{src}, {imm}','insertps',e=4,mem=mem,imm=imm)
for root,e,ws,reg in [('vbroadcastss',4,[16,32],True),('vbroadcastsd',8,[32],True),('vbroadcastf128',16,[32],False),('vbroadcasti128',16,[32],False),('vpbroadcastb',1,[16,32],True),('vpbroadcastw',2,[16,32],True),('vpbroadcastd',4,[16,32],True),('vpbroadcastq',8,[16,32],True)]:
 for w in ws:
  r='xmm' if w==16 else 'ymm'
  for mem in ([0,1] if reg else [1]): add(root+('.load' if mem else '.reg'),f'VEX{w*8}',f'{root} {r}0, '+('[rsi]' if mem else 'xmm1'),'broadcast',w=w,e=e,mem=mem)
for root in ['f128','i128']:
 for imm in range(256):
  for mem in [0,1]:
   add('vextract'+root+('.mem' if mem else '.reg'),'VEX256',f'vextract{root} '+('[rsi]' if mem else 'xmm0')+f', ymm1, {imm}','extract128',w=32,e=16,mem=2 if mem else 0,imm=imm)
   add('vinsert'+root+('.mem' if mem else '.reg'),'VEX256',f'vinsert{root} ymm0, ymm1, '+('[rsi]' if mem else 'xmm2')+f', {imm}','insert128',w=32,e=16,mem=mem,imm=imm)
for root,e in [('vmaskmovps',4),('vmaskmovpd',8),('vpmaskmovd',4),('vpmaskmovq',8)]:
 for w in [16,32]:
  r='xmm' if w==16 else 'ymm'
  add(root+'.load',f'VEX{w*8}',f'{root} {r}0, {r}2, [rsi]','maskload',w=w,e=e,mem=1)
  add(root+'.store',f'VEX{w*8}',f'{root} [rsi], {r}2, {r}1','maskstore',w=w,e=e,mem=2)
# Each separately assembled immediate is part of the form inventory.
kinds=list(dict.fromkeys(o['kind'] for o in ops))
head=['/* SPDX-License-Identifier: MIT; generated by generate.py */','enum Kind { '+', '.join('K_'+k.upper() for k in kinds)+' };','typedef void (*Fn)(struct Ctx *);','struct Op {const char *name,*enc; Fn fn; int kind,w,e,aux,mem,imm,align;};']
asm=['# SPDX-License-Identifier: MIT','.intel_syntax noprefix','.text']
for i,o in enumerate(ops):
 head.append(f'extern void movement_{i}(struct Ctx *);')
 asm+=['.p2align 4',f'.globl movement_{i}',f'.type movement_{i}, @function',f'movement_{i}:','  mov r11, rdi','  mov rsi, QWORD PTR [r11+160]','  mov rax, QWORD PTR [r11+168]','  vmovdqu ymm0, [r11]','  vmovdqu ymm1, [r11+32]','  vmovdqu ymm2, [r11+64]']
 if 'maskmovdqu' in o['name']: asm+=['  mov rdi, rsi']
 asm+=['  '+o['ins']]+(['  sfence'] if 'maskmovdqu' in o['name'] else [])+['  vmovdqu [r11+96], ymm0','  vmovdqu [r11+128], ymm2','  mov QWORD PTR [r11+176], rax','  vzeroupper','  ret',f'.size movement_{i}, .-movement_{i}']
head+=['static const struct Op ops[] = {']
for i,o in enumerate(ops): head.append('{"%s","%s",movement_%d,K_%s,%d,%d,%d,%d,%d,%d},'%(o['name'],o['enc'],i,o['kind'].upper(),o['w'],o['e'],o['aux'],o['mem'],o['imm'],o['align']))
head+=['};']
asm+=['.section .note.GNU-stack,"",@progbits']
(D/'movement-generated.h').write_text('\n'.join(head)+'\n'); (D/'movement-generated.S').write_text('\n'.join(asm)+'\n')
import csv
with (D.parent/'movement-manifest.tsv').open('w') as f:
 wr=csv.writer(f,delimiter='\t');wr.writerow(['symbol','name','encoding','width','element_bytes','aux','memory','immediate','alignment','instruction'])
 for i,o in enumerate(ops):wr.writerow([f'movement_{i}',o['name'],o['enc'],o['w']*8,o['e'],o['aux'],o['mem'],o['imm'],o['align'],o['ins']])
print(f'generated {len(ops)} movement forms')
