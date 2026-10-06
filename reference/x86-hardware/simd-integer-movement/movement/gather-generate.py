#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
import csv
p=Path(__file__).resolve().parent;ops=[]
for name,de,ie in [('vgatherdps',4,4),('vgatherqps',4,8),('vgatherdpd',8,4),('vgatherqpd',8,8),('vpgatherdd',4,4),('vpgatherqd',4,8),('vpgatherdq',8,4),('vpgatherqq',8,8)]:
 for w in [16,32]:
  n=w//max(de,ie);dr='ymm' if n*de==32 else 'xmm';ir='ymm' if n*ie==32 else 'xmm'
  for scale in [1,2,4,8]:ops.append((name,w,de,ie,n,scale,f'{name} {dr}0, [rsi+{ir}1*{scale}], {dr}2'))
h=['/* SPDX-License-Identifier: MIT; generated */','typedef void (*Fn)(struct Ctx*);','struct Op {const char *name; Fn fn; int w,e,ie,n,scale;};']
a=['# SPDX-License-Identifier: MIT','.intel_syntax noprefix','.text']
for i,o in enumerate(ops):
 h.append(f'extern void gather_{i}(struct Ctx*);')
 a+=['.p2align 4',f'.globl gather_{i}',f'.type gather_{i}, @function',f'gather_{i}:','mov r11,rdi','mov rsi,[r11+160]','vmovdqu ymm0,[r11]','vmovdqu ymm1,[r11+32]','vmovdqu ymm2,[r11+64]',o[6],'vmovdqu [r11+96],ymm0','vmovdqu [r11+128],ymm2','vzeroupper','ret',f'.size gather_{i},.-gather_{i}']
h+=['static const struct Op ops[]={']
for i,(name,w,e,ie,n,s,ins) in enumerate(ops):h.append(f'{{"{name}",gather_{i},{w},{e},{ie},{n},{s}}},')
h+=['};'];a+=['.section .note.GNU-stack,"",@progbits']
(p/'gather-generated.h').write_text('\n'.join(h)+'\n');(p/'gather-generated.S').write_text('\n'.join(a)+'\n')
with (p.parent/'gather-manifest.tsv').open('w') as f:
 wr=csv.writer(f,delimiter='\t');wr.writerow(['symbol','name','encoding_width','element_bytes','index_bytes','lanes','scale','instruction'])
 for i,o in enumerate(ops):wr.writerow([f'gather_{i}',*o])
print('generated',len(ops),'gather forms')
