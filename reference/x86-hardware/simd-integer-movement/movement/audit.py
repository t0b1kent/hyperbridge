#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import csv,re,subprocess
from pathlib import Path
p=Path(__file__).resolve().parent.parent
rows=list(csv.DictReader((p/'movement-manifest.tsv').open(),delimiter='\t'))
dis=subprocess.check_output(['objdump','-d','-M','intel',str(p/'movement/movement-runner')],text=True)
blocks={};current=None
for line in dis.splitlines():
 m=re.match(r'[0-9a-f]+ <(movement_\d+)>:',line)
 if m:current=m.group(1);blocks[current]=[];continue
 if current:
  if not line.strip():current=None;continue
  m=re.match(r'\s*[0-9a-f]+:\s+((?:[0-9a-f]{2} )+)\s*(.+)',line)
  if m:blocks[current].append((m.group(1).strip(),m.group(2)))
with (p/'movement-opcode-audit.tsv').open('w') as f:
 wr=csv.writer(f,delimiter='\t');wr.writerow(['symbol','instruction','bytes','disassembly'])
 for r in rows:
  b=blocks[r['symbol']];idx=7 if 'maskmovdqu' in r['name'] else 6;raw,decoded=b[idx];mnemonic=decoded.split()[0];want=r['name'].split('.')[0]
  assert mnemonic==want,(r,mnemonic)
  assert (raw.startswith(('c4 ','c5 ')))==(r['encoding']!='SSE'),(r,raw)
  b=bytes.fromhex(raw)
  if r['encoding']!='SSE':
   vex_l=(b[1]>>2)&1 if b[0]==0xc5 else (b[2]>>2)&1
   assert vex_l==(r['encoding']=='VEX256'),(r,raw)
  if int(r['immediate'])>=0:assert b[-1]==int(r['immediate']),(r,raw)
  assert ('[' in decoded)==(int(r['memory'])!=0 and 'maskmovdqu' not in r['name']),(r,decoded)
  wr.writerow([r['symbol'],r['instruction'],raw,decoded])
print('movement opcode audit: verified',len(rows),'target mnemonics, legacy/VEX bytes, L bits, immediate bytes and memory/register locations')
