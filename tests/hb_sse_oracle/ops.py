"""Canonical byte encodings are assembled, not supplied by the HB decoder."""
from pathlib import Path
import subprocess,json

def operations():
 out=[]
 def add(name,family,bits,kind,form,asm,vex=False,intbits=0):
  out.append(dict(id=len(out),name=name,family=family,bits=bits,kind=kind,form=form,asm=asm,vex=vex,intbits=intbits))
 for suffix,bits,scalar in [('ss',32,True),('sd',64,True),('ps',32,False),('pd',64,False)]:
  for op in ['add','sub','mul','div','min','max']+(['sqrt'] if scalar else []):
   for form in ['reg','mem']:
    operand='xmm1' if form=='reg' else ('DWORD PTR [rbx]' if scalar and bits==32 else 'QWORD PTR [rbx]' if scalar else 'XMMWORD PTR [rbx]')
    add(op+suffix,op,bits,'scalar' if scalar else 'packed',form,f'{op+suffix} xmm0, {operand}')
 for suffix,bits in [('ss',32),('sd',64)]:
  for op in ['comi','ucomi']:
   for form in ['reg','mem']:
    rhs='xmm1' if form=='reg' else ('DWORD' if bits==32 else 'QWORD')+' PTR [rbx]'
    add(op+suffix,op,bits,'flags',form,f'{op+suffix} xmm0, {rhs}')
 for name,bits in [('cvtss2sd',32),('cvtsd2ss',64),('cvtdq2ps',32),('cvttps2dq',32)]:
  for form in ['reg','mem']:
   mem='XMMWORD' if name in ['cvtdq2ps','cvttps2dq'] else 'DWORD' if bits==32 else 'QWORD'
   rhs='xmm1' if form=='reg' else mem+' PTR [rbx]'
   add(name,name,bits,'packconvert' if mem=='XMMWORD' else 'convert',form,f'{name} xmm0, {rhs}')
 for suffix,bits in [('ss',32),('sd',64)]:
  for width in [32,64]:
   for form in ['reg','mem']:
    rhs=('eax' if width==32 else 'rax') if form=='reg' else ('DWORD' if width==32 else 'QWORD')+' PTR [rbx]'
    add('cvtsi2'+suffix+'_'+str(width),'itof',bits,'itof',form,f'cvtsi2{suffix} xmm0, {rhs}',intbits=width)
   for trunc in [False,True]:
    name=('cvtt' if trunc else 'cvt')+suffix+'2si'
    for form in ['reg','mem']:
     rhs='xmm1' if form=='reg' else ('DWORD' if bits==32 else 'QWORD')+' PTR [rbx]'
     add(name+'_'+str(width),'ftoi_t' if trunc else 'ftoi',bits,'ftoi',form,f'{name} '+('eax' if width==32 else 'rax')+', '+rhs,intbits=width)
 for op in ['padd','psub']:
  for suffix,bits in [('b',8),('w',16),('d',32),('q',64)]:
   for form in ['reg','mem']:
    add(op+suffix,op,bits,'intpack',form,f'{op+suffix} xmm0, '+('xmm1' if form=='reg' else 'XMMWORD PTR [rbx]'))
 # Second-priority VEX.128 scalar operations, including scalar conversions.
 for suffix,bits in [('ss',32),('sd',64)]:
  for op in ['add','sub','mul','div','min','max','sqrt']:
   for form in ['reg','mem']:
    rhs='xmm2' if form=='reg' else ('DWORD' if bits==32 else 'QWORD')+' PTR [rbx]'
    add('v'+op+suffix,op,bits,'scalar',form,f'v{op+suffix} xmm0, xmm1, {rhs}',vex=True)
 for name,bits in [('vcvtss2sd',32),('vcvtsd2ss',64)]:
  for form in ['reg','mem']:
   rhs='xmm2' if form=='reg' else ('DWORD' if bits==32 else 'QWORD')+' PTR [rbx]'
   add(name,name[1:],bits,'convert',form,f'{name} xmm0, xmm1, {rhs}',vex=True)
 return out

def assemble(root):
 out=operations();lines=['.intel_syntax noprefix','.text']
 for op in out:
  name=f'case_{op["id"]}';lines.extend([f'.global {name}',f'{name}:',op['asm'],f'.size {name}, .-{name}'])
 (root/'opcodes.S').write_text('\n'.join(lines)+'\n')
 subprocess.run(['clang','-c',str(root/'opcodes.S'),'-o',str(root/'opcodes.o')],check=True)
 subprocess.run(['objcopy','-O','binary','--only-section=.text',str(root/'opcodes.o'),str(root/'opcodes.bin')],check=True)
 data=(root/'opcodes.bin').read_bytes();symbols={}
 for line in subprocess.check_output(['nm','-S',str(root/'opcodes.o')],text=True).splitlines():
  addr,size,kind,name=line.split();symbols[name]=(int(addr,16),int(size,16))
 for op in out:
  start,size=symbols[f'case_{op["id"]}'];op['bytes']=data[start:start+size].hex()
 (root/'opcodes.json').write_text(json.dumps(out,indent=2))
 (root/'opcodes.disasm.txt').write_text(subprocess.check_output(['objdump','-d','-Mintel',str(root/'opcodes.o')],text=True))
 return out
if __name__=='__main__':assemble(Path(__file__).resolve().parent/'out')
