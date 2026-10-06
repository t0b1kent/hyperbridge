#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
p=Path(__file__).resolve().parent
ctx=0x20000000
regs=['eax','ecx','edx','ebx','esp','ebp','esi','edi']
ops=[]
s=['/* SPDX-License-Identifier: MIT */','.text','.code32']
def gen(name,w,ins,kind,imm=-1,reg=-1,seg=-1,frame=0):
    idx=len(ops); label=f'op_{idx}'
    ops.append((name,w,kind,imm,reg,seg,label,frame))
    s.extend([f'.globl {label}',f'{label}:'])
    for i,r in enumerate(regs):
        if r!='esp':s.append(f' movl {ctx+i*4}, %{r}')
    s.extend([f' movl {ctx+16}, %esp',f' pushl {ctx+32}',' popfl',' pushfl',f' popl {ctx+36}'])
    s.extend(' '+x for x in ins)
    s.extend([' pushfl',f' popl {ctx+40}'])
    for i,r in enumerate(regs):s.append(f' movl %{r}, {ctx+44+i*4}')
    if kind=='POPSEG':
        s.extend([f' movw %{segs[seg]}, %ax',' movzwl %ax,%eax',f' movl %eax,{ctx+76}'])
    if frame:
        for j in range(8):
            if frame==16:s.extend([f' movzwl {j*2}(%esp), %eax',f' movl %eax, {ctx+76+j*4}'])
            else:s.extend([f' movl {j*4}(%esp), %eax',f' movl %eax, {ctx+76+j*4}'])
    s.append(' jmp leave32')
for name,opcode,w in [('DAA',0x27,8),('DAS',0x2f,8),('AAA',0x37,16),('AAS',0x3f,16)]:gen(name+'.al' if w==8 else name+'.ax',w,[f'.byte {opcode}'],name)
for name,opcode in [('AAM',0xd4),('AAD',0xd5)]:
    for k in range(256):gen(name+'.imm',16,[f'.byte {opcode},{k}'],name,k)
for name,opcode,w in [('PUSHA',0x60,16),('PUSHAD',0x60,32),('POPA',0x61,16),('POPAD',0x61,32)]:gen(name+'.regs',w,[f'.byte '+('0x66,' if w==16 else '')+f'{opcode}'],name,frame=w if opcode==0x60 else 0)
for w in [16,32]:gen('BOUND.mem',w,[f'.byte '+('0x66,' if w==16 else '')+'0x62,0x05',f'.long {ctx+128}'],'BOUND')
gen('INTO.of',32,['.byte 0xce'],'INTO')
gen('SALC.al',8,['.byte 0xd6'],'SALC')
for kind,start in [('INC',0x40),('DEC',0x48)]:
    for w in [16,32]:
        for i,r in enumerate(regs):gen(kind+'.'+(r[1:] if w==16 else r),w,[f'.byte '+('0x66,' if w==16 else '')+f'{start+i}'],kind,reg=i)
segs=['es','cs','ss','ds','fs','gs']; push=[[0x06],[0x0e],[0x16],[0x1e],[0x0f,0xa0],[0x0f,0xa8]];pop=[[0x07],None,[0x17],[0x1f],[0x0f,0xa1],[0x0f,0xa9]]
for w in [16,32]:
    for i,name in enumerate(segs):
        gen('PUSH.'+name,w,['.byte '+','.join(map(str,([0x66] if w==16 else [])+push[i]))],'PUSHSEG',seg=i,frame=w)
        if pop[i]:gen('POP.'+name,w,['.byte '+','.join(map(str,([0x66] if w==16 else [])+pop[i]))],'POPSEG',seg=i)
gen('LAHF.ah',16,['lahf'],'LAHF')
gen('SAHF.ah',16,['sahf'],'SAHF')
gen('ARPL.ax_bx',16,['arpl %bx,%ax'],'ARPL')
for kind,ins in [('ADD',['addl %edx,%eax']),('SUB',['subl %edx,%eax']),('SHL',['shll %cl,%eax'])]:gen(kind+'.compat',32,ins,kind)
s.extend(['.code64','.globl control64','control64:',f' movl {ctx},%eax',f' movl {ctx+8},%edx',f' movl {ctx+4},%ecx',' cmp $0,%edi',' je control_add',' cmp $1,%edi',' je control_sub',' jmp control_shl'])
for label,ins in [('add','addl %edx,%eax'),('sub','subl %edx,%eax'),('shl','shll %cl,%eax')]:
    s.extend([f'control_{label}:',f' movl {ctx+32},%esi',' pushq %rsi',' popfq',' pushfq',' popq %rsi',f' movl %esi,{ctx+36}',' '+ins,' pushfq',' popq %rsi',f' movl %esi,{ctx+40}',f' movl %eax,{ctx+44}',f' movl %edx,{ctx+52}',' ret'])
s.append('.section .note.GNU-stack,"",@progbits')
(p/'build'/'ops.S').write_text('\n'.join(s)+'\n')
kinds=[]
for op in ops:
    if op[2] not in kinds:kinds.append(op[2])
h=['/* SPDX-License-Identifier: MIT */','enum Kind { '+', '.join('K_'+x for x in kinds)+' };','struct Op { const char *name; int width,kind,imm,reg,seg; void (*fn)(void); int frame; };']
for *_,label,frame in ops:h.append(f'extern void {label}(void);')
h.append('static const struct Op ops[]={')
for name,w,kind,imm,reg,seg,label,frame in ops:h.append(f'{{"{name}",{w},K_{kind},{imm},{reg},{seg},{label},{frame}}},')
h.append('};')
(p/'build'/'ops.h').write_text('\n'.join(h)+'\n')
import json
(p/'inventory.json').write_text(json.dumps([dict(name=n,width=w,kind=k,immediate=i,register=r,segment=g,symbol=l,frame=f) for n,w,k,i,r,g,l,f in ops],indent=2)+'\n')
