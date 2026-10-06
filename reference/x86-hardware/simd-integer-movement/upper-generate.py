#!/usr/bin/env python3
# Original code, MIT License.
from pathlib import Path
b=Path(__file__).resolve().parent/'core-build';b.mkdir(exist_ok=True)
s=['.text']
for op in ('vzeroupper','vzeroall'):
 s+=['.globl upper_'+op,'.type upper_'+op+',@function','upper_'+op+':']
 s += [f'vmovdqu {i*32}(%rdi), %ymm{i}' for i in range(16)]
 s += [op]
 s += [f'vmovdqu %ymm{i}, {i*32}(%rsi)' for i in range(16)]
 s += ['vzeroupper','ret','.size upper_'+op+',.-upper_'+op]
s+=['.section .note.GNU-stack,"",@progbits'];(b/'upper.S').write_text('\n'.join(s)+'\n')
