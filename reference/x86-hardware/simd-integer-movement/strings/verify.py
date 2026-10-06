#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independently inspect built opcode bytes, widths, immediates and memory forms."""
import subprocess,re,json,hashlib
from pathlib import Path
p=Path(__file__).resolve().parent
family=p.name
text=subprocess.check_output(['objdump','-d','-w',str(p/'build/oracle')],text=True)
functions={};label=None
for line in text.splitlines():
 m=re.match(r'^[0-9a-f]+ <([^>]+)>:',line)
 if m:label=m.group(1);functions[label]=[];continue
 if label:
  m=re.match(r'^\s*[0-9a-f]+:\s+((?:[0-9a-f]{2}\s+)+)\s*(\S+)\s*(.*)',line)
  if m:functions[label].append((bytes.fromhex(m[1]),m[2],m[3]))
count=0;immcount=0;encs={};digest=hashlib.sha256()
for line in (p/'forms.h').read_text().splitlines():
 if not line.startswith('{"'):continue
 row=line.strip().rstrip(',').strip('{}').split(',');name=row[0].strip('"');label=row[-1]
 if family=='strings':
  imm,enc,explicit,mask,mem=map(int,row[1:6]);bits=128;kind=None
  match=lambda mnemonic:mnemonic==name
 else:
  kind,enc,imm,mem,bits,feature=map(int,row[1:7])
  stem='crc32' if kind==14 else 'movbe' if kind>=15 else name
  match=lambda mnemonic:mnemonic.startswith(stem) or (kind==6 and mnemonic.startswith('vpclmul' if enc else 'pclmul'))
 ops=[x for x in functions[label] if match(x[1])]
 assert len(ops)==1,(label,ops)
 raw,mnemonic,args=ops[0]
 assert ('(' in args)==bool(mem),(label,args,mem)
 if imm>=0:
  assert raw[-1]==imm,(label,raw.hex(),imm);immcount+=1
 if family=='strings' or kind<14:
  assert (raw[0] in (0xc4,0xc5))==bool(enc),(label,raw.hex(),enc)
  assert ('%ymm' in args)==(bits==256),(label,args,bits)
  if enc:
   vex_l=((raw[2] if raw[0]==0xc4 else raw[1])>>2)&1
   assert vex_l==(bits==256),(label,raw.hex(),bits)
  typ='legacy' if not enc else f'VEX{bits}'
 else:typ='scalar'
 encs[typ]=encs.get(typ,0)+1;digest.update(label.encode()+b'\0'+raw);count+=1
result={'family':family,'forms_checked':count,'immediate_forms_checked':immcount,'encodings':encs,'opcode_bytes_sha256':digest.hexdigest(),'checks':['unique target opcode in each symbol','legacy versus VEX prefix','VEX L bit and displayed register width','register versus memory operand','all immediate bytes match declaration']}
(p.parent/f'{family}-encoding-validation.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,sort_keys=True))

# The inventory is regenerated from the same declared forms and includes a priori row counts.
manifest=[]
for line in (p/'forms.h').read_text().splitlines():
 if not line.startswith('{"'):continue
 v=line.strip().rstrip(',').strip('{}').split(',');name=v[0].strip('"')
 if family=='strings':
  imm,enc,expl,mask,mem=map(int,v[1:6]);n=88 if expl else 72
  row=dict(symbol=v[-1],mnemonic=name,imm8=imm,encoding='VEX128' if enc else 'legacy128',memory=mem,destination_bits=128 if mask else 32,rows=n)
 else:
  kind,enc,imm,mem,bits,feature=map(int,v[1:7]);n=8
  row=dict(symbol=v[-1],mnemonic=name,kind=kind,imm8=imm,encoding=('scalar' if kind>=14 else 'legacy128' if not enc else 'VEX'+str(bits)),memory=mem,operand_bits=bits,destination_bits=enc if kind==14 else bits,destination='memory' if kind==16 else 'register',cpuid_feature=feature,rows=n)
 manifest.append(row)
(p.parent/f'{family}-manifest.json').write_text(json.dumps({'family':family,'forms':manifest,'expected_forms':len(manifest),'expected_rows_on_recorded_cpu':sum(r['rows'] for r in manifest)},indent=2)+'\n')
