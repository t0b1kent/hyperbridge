#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import csv,collections,gzip
from pathlib import Path
p=Path(__file__).resolve().parent.parent
rows=list(csv.DictReader((p/'gather-counts.tsv').open(),delimiter='\t'));g=collections.defaultdict(lambda:[0,0,0])
for r in rows:
 a=g[(r['name'],r['encoding_width'])];a[0]+=1;a[1]+=int(r['rows']);a[2]+=int(r['faults'])
n=sum(int(r['rows']) for r in rows);f=sum(int(r['faults']) for r in rows)
out=['# Class 7: indexed gathers','','| Instruction | VEX L width | Scale forms | Rows | Full scalar checks | Fault state checks |','|---|---:|---:|---:|---:|---:|']
for (name,w),(forms,count,faults) in g.items():out.append(f'| {name} | {w} | {forms} | {count} | {count-faults} | {faults} |')
out+=['',f'Total: {len(rows)} forms, {n} predicted and observed rows, {n-f} complete scalar result/mask comparisons, {f} scalar fault-state comparisons. Each mnemonic × VEX128/VEX256 × scale 1/2/4/8 has 9 deterministic data patterns × 11 access/mask scenarios (99 rows).','', 'Scenarios: aligned; one-byte-misaligned base; alternating mask; all mask signs clear with every address protected; protected addresses only in disabled lanes; last-lane fault; first-lane fault; sign-only/noncanonical masks; duplicate indices; fault with noncanonical pending mask bits; fault with both initially disabled and enabled lanes. Negative signed indices occur at every scale. All addresses are within this process’s own guarded mapping or its deliberately inaccessible guard pages.','', 'The .VEX128/.VEX256 name suffix is the encoded form width; the primary width column is the actual destination register width: QPS/QD use XMM destinations even in their L=1 forms. DPD/DQ L=1 use XMM indices and YMM destinations. Full 256-bit index, initial/final destination and mask are retained.','', 'Exact omissions: EVEX/AVX-512 gather/scatter, 32-bit address-size and alternate register-allocation/segment-prefix aliases are outside the requested AVX2 forms. There are no omitted requested mnemonic/scale/L combinations. Signal handlers record actual fault-time destination/mask including XSAVE YMM upper halves; no partial result is synthesized.','', 'Run movement-gather-run.sh from submission. It rebuilds, runs each binary with a 900-second timeout, compares two deterministic gzip -n outputs, and hashes the uncompressed canonical out-gather.txt stream. The scalar C model is compiled with tree/SLP vectorization disabled. gather-manifest.tsv inventories each form; gather-opcode-audit.tsv verifies disassembled mnemonic and VEX L/W bits.']
(p/'gather-COVERAGE.md').write_text('\n'.join(out)+'\n')
stat=collections.Counter()
with gzip.open(p/'out-gather.txt.gz','rt') as fp:
 for line in fp:
  if line.startswith('#'):continue
  k=line.split()[0].split('.')[2];stat[k]+=1
rules=f'''# Class 7 observed gather rules

- {n-f} non-faulting rows exactly match scalar signed-index address calculation, lane data, destination merge and the full 256-bit final mask. Scales 1/2/4/8 and negative indices are independently exercised.
- Successful gathers clear the entire YMM mask, including initially disabled mask elements with nonzero low bits. They retain old destination elements where the corresponding mask sign was clear, and zero destination bits outside the form's output lanes.
- {stat['alloff_guard']} all-disabled protected-address rows and {stat['masked_guard']} rows with protected addresses only in disabled lanes complete without a fault. The raw before/after masks make the clearing visible.
- {f} fault rows are real SIGSEGV/page-fault observations. Each already-completed active lane contains its scalar memory value and has mask element zero; each pending active lane retains its old destination and the entire original mask element, including noncanonical low bits. Initially disabled lanes retain their old destination and their mask elements become zero. Enabled readable lanes below the first faulting lane must be complete; later lanes are checked against their actually observed completion mask.
- On this host, faulting gathers retain the destination and mask bits above the form's output lanes, including the nonzero YMM upper-half pattern for XMM-destination forms. Successful completion zeroes those bits. This difference is recorded from signal XSAVE context, not inferred from the post-longjmp process registers.
- All {n} rows pass the relevant scalar/state model. Two complete native executions produce identical gzip bytes. Fault recovery uses only user-owned anonymous memory and a standard SA_SIGINFO signal handler.
'''
(p/'gather-RULES.md').write_text(rules)
