#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
p=Path(__file__).resolve().parent
asm=['.text']; decl=[]; forms=[]
for vex in (0,1):
 for op in ('pcmpestri','pcmpestrm','pcmpistri','pcmpistrm'):
  for imm in range(256):
   for mem in range(3):
    label=f's_{vex}_{op}_{imm}_{mem}'
    asm += [f'.globl {label}',f'.type {label},@function',f'{label}:',
     ' mov %rdi,%r8',' mov 216(%r8),%r9',' vmovdqu 0(%r8),%ymm0',' vmovdqu 32(%r8),%ymm1',' vmovdqu 64(%r8),%ymm2',
     ' mov 192(%r8),%eax',' mov 196(%r8),%edx',' mov 200(%r8),%ecx',' pushq $0x202',' popfq',
     f' {"v" if vex else ""}{op} ${imm},{"(%r9)" if mem else "%xmm2"},%xmm1',' pushfq',' pop %rax',' mov %ax,208(%r8)',
     ' mov %ecx,204(%r8)',' vmovdqu %ymm0,96(%r8)',' vmovdqu %ymm1,128(%r8)',' vmovdqu %ymm2,160(%r8)',' vzeroupper',' ret',f'.size {label},.-{label}']
    decl.append(f'extern void {label}(Ctx*);')
    forms.append(f'{{"{"v" if vex else ""}{op}",{imm},{vex},{int("estr" in op)},{int(op[-1]=="m")},{mem},{label}}}')
asm += ['.section .note.GNU-stack,"",@progbits']
(p/'ops.S').write_text('\n'.join(asm)+'\n')
(p/'forms.h').write_text('\n'.join(decl)+'\nstatic Form forms[]={\n'+',\n'.join(forms)+'\n};\n')
