#!/usr/bin/env python3
# Original code, MIT License.
import json,pathlib
P=pathlib.Path(__file__).resolve().parent
(P/'build').mkdir(exist_ok=True)
forms=[]; asm=['.text']; decl=[]
regs={8:('al','bl','cl','dl'),16:('ax','bx','cx','dx'),32:('eax','ebx','ecx','edx'),64:('rax','rbx','rcx','rdx')}
suf={8:'b',16:'w',32:'l',64:'q'}
def add(cls,op,w,mode='reg',c=-1,code=None):
 i=len(forms); name=f'core_{i}'; forms.append(dict(cls=cls,op=op,w=w,mode=mode,c=c,symbol=name))
 a,b,x,d=regs.get(w,regs[64]); s=suf.get(w,'q')
 if code is None:
  if cls in ('shifts','rotates'): code=f'{op.lower()}{s} '+(f'${c}' if mode=='imm' else '%cl')+f', %{a}'
  elif cls=='double': code=f'{op.lower()}{s} '+(f'${c}' if mode=='imm' else '%cl')+f', %{b}, %{a}'
  elif op in ('MUL','IMUL1','DIV','IDIV'): code=f'{op.lower().replace("1", "")}{s} %{b}'
  elif op=='IMUL2': code=f'imul{s} %{b}, %{a}'
  elif op=='IMUL3': code=f'imul{s} ${c}, %{b}, %{a}'
  elif cls=='bitscan': code=f'{op.lower()}{s} %{b}, %{a}'
  elif cls=='bittest': code=f'{op.lower()}{s} '+(f'${c}' if mode.endswith('imm') else f'%{b}')+', '+('(%rsi)' if mode.startswith('mem') else f'%{a}')
  elif cls=='logic': code=f'{op.lower()}{s} %{b}, %{a}'
  elif op=='BSWAP16': code='.byte 0x66,0x0f,0xc8'
  elif op=='CMPXCHG': code=f'cmpxchg{s} %{x}, %{b}'
  elif op=='XADD': code=f'xadd{s} %{b}, %{a}'
  elif op=='CMPXCHG8B': code='cmpxchg8b (%rsi)'
  elif op=='CMPXCHG16B': code='cmpxchg16b (%rsi)'
 asm.extend([f'.globl {name}',f'.type {name},@function',f'{name}:','push %rbx','mov 0(%rdi),%rax','mov 8(%rdi),%rbx','mov 16(%rdi),%rcx','mov 24(%rdi),%rdx','mov 40(%rdi),%rsi','pushq 32(%rdi)','popfq','pushfq','popq 48(%rdi)',code,'pushfq','popq 56(%rdi)','mov %rax,64(%rdi)','mov %rdx,72(%rdi)','mov %rbx,80(%rdi)','mov %rcx,88(%rdi)','pop %rbx','ret',f'.size {name},.-{name}'])
 decl.append(f'extern void {name}(Ctx*);')
for cls,ops in [('shifts',['SHL','SAL','SHR','SAR']),('rotates',['ROL','ROR','RCL','RCR'])]:
 for op in ops:
  for w in regs:
   for c in range(2*w+2):
    for mode in ('imm','cl'): add(cls,op,w,mode,c)
for op in ('SHLD','SHRD'):
 for w in (16,32,64):
  for c in range(64):
   for mode in ('imm','cl'): add('double',op,w,mode,c)
for w in regs:
 for op in ('MUL','IMUL1'):add('multiply',op,w)
 if w>8:
  add('multiply','IMUL2',w)
  for c in ((-128,-2,-1,0,1,2,3,127,-32768,32767,128,255) if w==16 else (-128,-2,-1,0,1,2,3,127,-2147483648,2147483647,-32768,32767,128,255)):add('multiply','IMUL3',w,'imm',c)
 for op in ('DIV','IDIV'): add('divide',op,w)
for w in (16,32,64):
 for op in ('BSF','BSR','TZCNT','LZCNT','POPCNT'):add('bitscan',op,w)
 for op in ('BT','BTS','BTR','BTC'):
  add('bittest',op,w,'reg-reg');add('bittest',op,w,'mem-reg')
  for c in sorted(set([0,1,w//2,w-1,w,w+1,255])):
   add('bittest',op,w,'reg-imm',c);add('bittest',op,w,'mem-imm',c)
for w in regs:
 for op in ('AND','OR','XOR','TEST'):add('logic',op,w)
 for op in ('CMPXCHG','XADD'):add('misc',op,w)
add('misc','BSWAP16',16)
add('misc','CMPXCHG8B',64,'mem')
add('misc','CMPXCHG16B',128,'mem')
asm.append('.section .note.GNU-stack,"",@progbits')
(P/'build/core.S').write_text('\n'.join(asm)+'\n')
(P/'build/forms.h').write_text('\n'.join(decl)+'\nstatic const Form forms[]={\n'+''.join('{"%s","%s",%d,"%s",%d,%s},\n'%(f['cls'],f['op'],f['w'],f['mode'],f['c'],f['symbol']) for f in forms)+'};\n')
(P/'core-inventory.json').write_text(json.dumps(forms,indent=2)+'\n')
print(f'{len(forms)} native instruction forms')
