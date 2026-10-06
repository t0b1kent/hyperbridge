#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
p=Path(__file__).resolve().parent
asm=['.text']; decl=[]; forms=[]; idx=0
ops=[('aesenc',0,[0,1,2],False),('aesenclast',1,[0,1,2],False),('aesdec',2,[0,1,2],False),('aesdeclast',3,[0,1,2],False),('aesimc',4,[0,1],False),('aeskeygenassist',5,[0,1],True),('pclmulqdq',6,[0,1,2],True),('sha1rnds4',7,[0],True),('sha1nexte',8,[0],False),('sha1msg1',9,[0],False),('sha1msg2',10,[0],False),('sha256rnds2',11,[0],False),('sha256msg1',12,[0],False),('sha256msg2',13,[0],False)]
def emit(name,kind,enc,imm,mem,bits,code,feature=0):
 global idx
 label=f'crypto_op_{idx}';idx+=1
 asm.extend([f'.globl {label}',f'.type {label},@function',f'{label}:',' mov %rdi,%r8']+code+[' ret',f'.size {label},.-{label}'])
 decl.append(f'extern void {label}(Ctx*);')
 forms.append(f'{{"{name}",{kind},{enc},{imm},{mem},{bits},{feature},{label}}}')
for op,kind,encs,immed in ops:
 for enc in encs:
  for imm in range(256) if immed else [-1]:
   for mem in range(3):
    reg='ymm' if enc==2 else 'xmm';src='(%r9)' if mem else '%'+reg+'2';dst='%'+reg+'1';vop=('v' if enc else '')+op
    code=[' vmovdqu 0(%r8),%ymm1',' vmovdqu 32(%r8),%ymm2',' vmovdqu 64(%r8),%ymm0',' mov 184(%r8),%r9']
    if kind in (4,5):line=f' {vop} '+(f'${imm},' if immed else '')+f'{src},{dst}'
    elif enc:line=f' {vop} '+(f'${imm},' if immed else '')+f'{src},{dst},{dst}'
    else:line=f' {vop} '+(f'${imm},' if immed else '')+f'{src},{dst}'
    code += [line,' vmovdqu %ymm1,96(%r8)',' vmovdqu %ymm0,128(%r8)',' vmovdqu %ymm2,288(%r8)',' vzeroupper']
    feature=2 if kind>=7 else (3 if enc==2 and kind==6 else (1 if enc==2 else 0))
    emit(vop,kind,enc,imm,mem,256 if enc==2 else 128,code,feature)
for bits,destbits in [(8,32),(16,32),(32,32),(8,64),(64,64)]:
 for mem in range(3):
  suff={8:'b',16:'w',32:'l',64:'q'}[bits];src={8:'%dl',16:'%dx',32:'%edx',64:'%rdx'}[bits] if not mem else '(%r9)';dst='%rax' if destbits==64 else '%eax'
  emit(f'crc32_r{destbits}_m{bits}' if mem else f'crc32_r{destbits}_r{bits}',14,destbits,-1,mem,bits,[' mov 160(%r8),%rax',' mov 168(%r8),%rdx',' mov 184(%r8),%r9',f' crc32{suff} {src},{dst}',' mov %rax,176(%r8)'])
for bits in (16,32,64):
 for store in (0,1):
  for mem in (1,2):
   suff={16:'w',32:'l',64:'q'}[bits];reg={16:'%ax',32:'%eax',64:'%rax'}[bits]
   ins=f' movbe{suff} {reg},(%r9)' if store else f' movbe{suff} (%r9),{reg}'
   emit('movbe_store' if store else 'movbe_load',16 if store else 15,0,-1,mem,bits,[' mov 160(%r8),%rax',' mov 184(%r8),%r9',ins,' mov %rax,176(%r8)'])
asm.append('.section .note.GNU-stack,"",@progbits')
(p/'ops.S').write_text('\n'.join(asm)+'\n')
(p/'forms.h').write_text('\n'.join(decl)+'\nstatic Form forms[]={\n'+',\n'.join(forms)+'\n};\n')
