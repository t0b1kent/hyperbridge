#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check standard destination slots/widths directly in native output."""
import gzip,re,json
from pathlib import Path
p=Path(__file__).resolve().parent;family=p.name;count=0;scalar=0;faults=0
for line in gzip.open(p.parent/f'out-{family}.txt.gz','rt'):
 if line.startswith('#'):continue
 t=line.split();name=t[0].split('[')[0];w=int(t[1]);assert t[5]=='->'
 md=dict(v.split('=',1) for v in t[7:] if '=' in v)
 if family=='strings':
  is_index=name.endswith('i');assert w==(32 if is_index else 128)
  assert len(t[2])==len(t[6])==(8 if is_index else 64)
  assert len(t[3])==len(t[4])==64
  assert re.fullmatch('[0-9a-f]{4}',md['FLAGS'])
  if is_index:
   assert t[2]==md['ECX0'];assert len(md['YMM0_BEFORE'])==len(md['YMM0_AFTER'])==64
  else:assert len(md['ECX_AFTER'])==8
 elif name.startswith(('crc32','movbe')):
  scalar+=1;assert len(t[2])==len(t[6])==w//4;assert t[4]=='-'
  assert len(t[3])==int(md['SRC_BITS'])//4
  assert len(md['GPR64_BEFORE'])==len(md['GPR64_AFTER'])==16
  if name.startswith('crc32'):
   assert w==int(re.search(r'crc32_r(32|64)',name)[1])
  if name!='movbe_store':
   assert t[2]==md['GPR64_BEFORE'][-w//4:];assert t[6]==md['GPR64_AFTER'][-w//4:]
  else:
   assert t[3]==md['GPR64_BEFORE'][-w//4:];assert t[6]==md['MEM_AFTER']
 else:
  assert w in (128,256);assert len(t[2])==len(t[6])==64
  ternary=name.startswith('v') and name not in ('vaesimc','vaeskeygenassist')
  if ternary:
   assert t[3]==t[2];assert len(t[4])==(w//4 if md['MEM']!='0' else 64)
  else:
   assert len(t[3])==(w//4 if md['MEM']!='0' else 64)
   assert len(t[4])==64 if name=='sha256rnds2' else t[4]=='-'
  assert len(md['YMM0_BEFORE'])==len(md['YMM0_AFTER'])==len(md['SOURCE_YMM2_BEFORE'])==len(md['SOURCE_YMM2_AFTER'])==64
  if 'FAULT' in md:
   faults+=1;assert len(md['SOURCE_AFTER'])==64;assert md['TRAP']=='13' and md['ERROR']=='0'
 assert all(re.fullmatch('[0-9a-f]+',t[i]) for i in (2,3,6));count+=1
assert count==({'strings':491520,'crypto':37560}[family])
if family=='crypto':assert scalar==216 and faults==4136
result=dict(family=family,rows_checked=count,scalar_rows=scalar,fault_rows=faults,standard_destination_slots='PASS')
(p.parent/f'{family}-format-validation.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,sort_keys=True))
