# SPDX-License-Identifier: MIT
"""Independent GNU-as specification of every scalar/string form."""
import json,pathlib,re,subprocess
root=pathlib.Path(__file__).resolve().parent
forms=[x for x in json.loads((root.parent/'probe35/forms.json').read_text()) if x['group']=='scalar']
src=['.text'];specs=[]
for i,f in enumerate(forms):
 n=f['name'];w=f['width'];suffix={1:'b',2:'w',4:'l',8:'q'}[w];rbx={1:'%bl',2:'%bx',4:'%ebx',8:'%rbx'}[w]
 if 'stos' in n or 'movs' in n:
  asm=('rep ' if n.startswith('rep_') else '')+('stos' if 'stos' in n else 'movs')+suffix
 elif n.startswith('push'):
  operand=rbx if n.endswith('_reg') else '(%rsi)' if n.endswith('_mem') else '$-61' if n.endswith('_imm8') else '$-18779' if w==2 else '$-658000219'
  asm='push'+suffix+' '+operand
 elif n=='call_rel32':asm='call .+5'
 elif n.startswith('movnti'):asm='movnti '+rbx+', (%rdi)'
 elif n.endswith('_reg'):asm='mov'+suffix+' '+rbx+', (%rdi)'
 elif n.endswith('_imm'):
  immediate={1:-91,2:-18779,4:-658000219,8:-658000219}[w]
  asm='mov'+suffix+' $'+str(immediate)+', (%rdi)'
 else:raise ValueError(n)
 specs.append(asm);src += [f'.global case_{i}',f'case_{i}:',asm]
src+=['.global case_end','case_end:'];(root/'scalar-spec.S').write_text('\n'.join(src)+'\n')
subprocess.run(['as','--64','-o',str(root/'scalar-spec.o'),str(root/'scalar-spec.S')],check=True)
subprocess.run(['objcopy','-O','binary','-j','.text',str(root/'scalar-spec.o'),str(root/'scalar-spec.bin')],check=True)
binary=(root/'scalar-spec.bin').read_bytes();nm=subprocess.check_output(['nm','-n',str(root/'scalar-spec.o')],text=True)
positions={s[2]:int(s[0],16) for line in nm.splitlines() if len(s:=line.split())==3}
def normalized(code):
 p=[]
 while code and code[0] in [0x66,0xf3]:p.append(code[0]);code=code[1:]
 return bytes(sorted(p))+code
results=[]
for i,f in enumerate(forms):
 end='case_end' if i==len(forms)-1 else f'case_{i+1}'
 actual=binary[positions[f'case_{i}']:positions[end]];wanted=bytes.fromhex(f['code'])
 results.append({'form':f['name'],'asm':specs[i],'captured_encoding':wanted.hex(),'independent_as_encoding':actual.hex(),'exact':actual==wanted,'same_legacy_prefix_order_independent':normalized(actual)==normalized(wanted)})
(root/'SCALAR-BYTE-VALIDATION.json').write_text(json.dumps(results,indent=2)+'\n')
print('Scalar forms:',len(results),'exact:',sum(r['exact'] for r in results),'equivalent allowing 66/F3 prefix order:',sum(r['same_legacy_prefix_order_independent'] for r in results))
assert all(r['same_legacy_prefix_order_independent'] for r in results),[r for r in results if not r['same_legacy_prefix_order_independent']]
