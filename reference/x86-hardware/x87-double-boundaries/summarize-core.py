#!/usr/bin/env python3
# SPDX-License-Identifier: MIT. Tables computed solely from hardware-generated CSV.
import csv
from collections import defaultdict
from pathlib import Path
base=Path(__file__).resolve().parent
rows=list(csv.DictReader((base/'raw/core-counts.csv').open()))
data=defaultdict(dict)
for r in rows:data[(r['operation'],r['pc'],r['rounding'])][r['class']]=int(r['total'])
with (base/'CORE-RESULT.md').open('w') as f:
 f.write('# Arithmetic and square root: measured hardware results\n\n')
 f.write('AMD EPYC 9V74, native x86-64 guest; FTZ=DAZ=0, masked exceptions. Each row has exactly 1,000,000 random pairs plus the fixed edges. PC24: binary32 inputs and SSE single; PC53/64: binary64 inputs and SSE double. These are measured samples, not a proof of universal equivalence.\n\n')
 f.write('## Register result versus SSE\n\n| Operation | PC | RC | Cases | Equal value | Unequal value | Unequal exception bits | Above target max exponent | Below target normal exponent | NaN result |\n|---|---:|---|---:|---:|---:|---:|---:|---:|---:|\n')
 for (op,pc,rc),d in data.items():
  f.write(f'| {op} | {pc} | {rc} | {d["ALL"]} | {d["ALL"]-d["VALUE_MISMATCH"]} | {d["VALUE_MISMATCH"]} | {d["FLAGS_MISMATCH"]} | {d["EXCEEDS_BASELINE_MAX_EXP"]} | {d["BELOW_BASELINE_MIN_NORMAL_EXP"]} | {d["NAN_PRESENT"]} |\n')
 f.write('\nException comparison is FSW & 0x3f versus MXCSR & 0x3f. It is not a comparison of C0/C1/C2/C3, TOP or trap timing. Category counts overlap.\n\n## Candidate finite-normal guarded domain\n\nSource operands finite normal or zero; x87 result finite normal or zero in the source format. Input representation precondition is mandatory.\n\n| Operation | PC | RC | Guarded cases | Value failures | Exception-bit failures |\n|---|---:|---|---:|---:|---:|\n')
 for (op,pc,rc),d in data.items():f.write(f'| {op} | {pc} | {rc} | {d["GUARDED_DOMAIN"]} | {d["GUARDED_VALUE_MISMATCH"]} | {d["GUARDED_FLAGS_MISMATCH"]} |\n')
 f.write('\n## Explicit narrowing store\n\nFSTP m64 for PC53/64, FSTP m32 for PC24, same RC. Store exceptions were cleared before the store, and are recorded separately.\n\n| Operation | PC | RC | Stored-value differences from direct SSE | Finite stored-value differences | Underflow double-rounding candidates | Store OE | Store UE | Store PE |\n|---|---:|---|---:|---:|---:|---:|---:|---:|\n')
 for (op,pc,rc),d in data.items():f.write(f'| {op} | {pc} | {rc} | {d["MEMORY_VALUE_MISMATCH"]} | {d["MEMORY_FINITE_DIFFERENCE"]} | {d["UNDERFLOW_DOUBLE_ROUNDING_CANDIDATE"]} | {d["STORE_OVERFLOW"]} | {d["STORE_UNDERFLOW"]} | {d["STORE_INEXACT"]} |\n')
 f.write('\n## Native witnesses\n\nEach row below is copied from the generated examples CSV, without editing numeric results. Full raw examples have FSW before/after and MXCSR.\n\n| Operation | PC | RC | Class | A bits | B bits | x87 register 80 | SSE extended 80 | x87 stored bits | SSE native bits | FSW after | MXCSR | FSW store |\n|---|---:|---|---|---|---|---|---|---|---|---|---|---|\n')
 seen=set()
 for r in csv.DictReader((base/'raw/core-examples.csv').open()):
  key=(r['operation'],r['pc'],r['rounding'],r['class'])
  if key in seen or r['pc']!='53' or r['rounding']!='RN' or r['class'] not in ['EXCEEDS_BASELINE_MAX_EXP','UNDERFLOW_DOUBLE_ROUNDING_CANDIDATE','NAN_PAYLOAD_DIFFERENCE']:continue
  seen.add(key);f.write('| '+' | '.join(r[k] for k in ['operation','pc','rounding','class','a_hex','b_hex','x87_80_hex','sse_as_80_hex','x87_memory_hex','sse_native_hex','fsw_after','mxcsr','fsw_memory_after'])+' |\n')
 f.write('\n## Per-operation conclusion\n\n')
 for op in dict.fromkeys(k[0] for k in data):
  f.write(f'- {op}: unconditional double replacement is invalid. PC53/24 observed guarded-domain equivalence must be qualified by representable input format, normal result range and complete state semantics; see per-mode failure counts. PC64 intentionally retains extra precision and is not a double operation.\n')
 f.write('\nFSQRT differs from binary operations: input B is an unused deterministic draw and excluded from its input categories. NaN selection/quieting and exception priority remain separate from finite arithmetic. FADD/FSUB non-overflow normal behavior does not permit discarding extended exponent range in later chain steps.\n')
print('wrote CORE-RESULT.md')
