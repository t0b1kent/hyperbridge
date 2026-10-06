#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import csv,re,subprocess
from pathlib import Path
p=Path(__file__).resolve().parent.parent
rows=list(csv.DictReader((p/'gather-manifest.tsv').open(),delimiter='\t'))
dis=subprocess.check_output(['objdump','-d','-M','intel',str(p/'movement/gather-runner')],text=True)
blocks={};cur=None
for line in dis.splitlines():
 m=re.match(r'[0-9a-f]+ <(gather_\d+)>:',line)
 if m:cur=m.group(1);blocks[cur]=[];continue
 if cur:
  if not line.strip():cur=None;continue
  m=re.match(r'\s*[0-9a-f]+:\s+((?:[0-9a-f]{2} )+)\s*(.+)',line)
  if m:blocks[cur].append((m.group(1).strip(),m.group(2)))
with (p/'gather-opcode-audit.tsv').open('w') as f:
 wr=csv.writer(f,delimiter='\t');wr.writerow(['symbol','instruction','bytes','disassembly'])
 for r in rows:
  raw,decoded=blocks[r['symbol']][5];b=bytes.fromhex(raw)
  assert decoded.split()[0]==r['name'],(r,decoded)
  assert b[0]==0xc4 and ((b[2]>>2)&1)==(int(r['encoding_width'])==32),(r,raw)
  assert ((b[2]>>7)&1)==(int(r['element_bytes'])==8),(r,raw)
  assert len(b)==6 and (b[4]&7)==4,(r,raw) # VEX3 + opcode + ModRM + VSIB
  assert (1<<(b[5]>>6))==int(r['scale']),(r,raw)
  wr.writerow([r['symbol'],r['instruction'],raw,decoded])
print('gather opcode audit: verified',len(rows),'target mnemonics, VEX L/W bits and VSIB scale bits')
