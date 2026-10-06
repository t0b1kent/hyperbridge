# SPDX-License-Identifier: MIT
"""Independent GNU-as verification of all scalar/vector byte encodings."""
import pathlib,subprocess,tempfile
import scalar,vector
P={1:'BYTE',2:'WORD',4:'DWORD',8:'QWORD',16:'XMMWORD',32:'YMMWORD'}
R={1:'bl',2:'bx',4:'ebx',8:'rbx'}
def signed(v,n):return v-(1<<(n*8)) if v>>(n*8-1) else v
def asm(f):
 n=f['name'];w=f['width'];mem=f'{P[w]} PTR [rdi]'
 if f.get('string'):
  op='movs' if 'movs' in n else 'stos'
  return ('rep ' if n.startswith('rep_') else '')+op+{1:'b',2:'w',4:'d',8:'q'}[w]
 if n.startswith('movnti'):return f'movnti {mem}, {R[w]}'
 if n.startswith('mov') and f['group']=='scalar':
  if n.endswith('_reg'):return f'mov {mem}, {R[w]}'
  raw=bytes.fromhex(f['code']);nb=min(w,4);value=signed(int.from_bytes(raw[-nb:],'little'),nb)
  return f'mov {mem}, {value}'
 if n.startswith('push'):
  if n.endswith('_reg'):return f'push {R[w]}'
  if n.endswith('_mem'):return f'push {P[w]} PTR [rsi]'
  nb=1 if n.endswith('imm8') else min(w,4);value=signed(int.from_bytes(bytes.fromhex(f['code'])[-nb:],'little'),nb)
  return f'.att_syntax\npush{"w" if w==2 else "q"} ${value}\n.intel_syntax noprefix'
 if n.startswith('call'):return 'call .+5'
 if n.startswith('maskmov'):return 'maskmovdqu xmm0, xmm1'
 op=n.split('_')[0]
 if n.startswith('pextr'):return f'{op} {mem}, xmm0, {n.split("_")[-1]}'
 return f'{op} {mem}, {"ymm0" if op=="vmovdqu" else "xmm0"}'
rows=[]
for g,mod in [('scalar',scalar),('vector',vector)]:
 for f in mod.forms():f['group']=g;rows.append(f)
with tempfile.TemporaryDirectory(prefix='new0035-encoding-') as d:
 p=pathlib.Path(d);s=['.intel_syntax noprefix','.text']
 for i,f in enumerate(rows):s += [f'.globl case_{i}',f'case_{i}:',asm(f)]
 s+=['.globl case_end','case_end:'];(p/'a.s').write_text('\n'.join(s)+'\n')
 subprocess.run(['as','--64','-o',str(p/'a.o'),str(p/'a.s')],check=True)
 subprocess.run(['objcopy','-O','binary','-j','.text',str(p/'a.o'),str(p/'a.bin')],check=True)
 raw=(p/'a.bin').read_bytes();pos={n:int(a,16) for a,t,n in (x.split() for x in subprocess.check_output(['nm','-n',str(p/'a.o')],text=True).splitlines())}
 errors=[];prefix_equivalent=0
 for i,f in enumerate(rows):
  end=f'case_{i+1}' if i+1<len(rows) else 'case_end';b=raw[pos[f'case_{i}']:pos[end]]
  if b.hex()!=f['code']:
   if b.startswith(bytes.fromhex('66f3')) and f['code'].startswith('f366') and b[2:].hex()==f['code'][4:]:prefix_equivalent+=1
   else:errors.append((f['name'],f['code'],b.hex(),asm(f)))
 assert not errors,errors
 print(f'Verified {len(rows)} scalar/vector forms: {len(rows)-prefix_equivalent} byte-exact, {prefix_equivalent} differ only by interchangeable 66/F3 prefix order; zero semantic/operand-width mismatches')
