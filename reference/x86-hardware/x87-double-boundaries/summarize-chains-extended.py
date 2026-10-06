#!/usr/bin/env python3
# SPDX-License-Identifier: MIT. Summarizes only measured CSV output.
from pathlib import Path
from collections import defaultdict
import csv,json,hashlib
b=Path(__file__).resolve().parent

def load(name,keys):
 d=defaultdict(dict)
 for r in csv.DictReader((b/'raw'/f'{name}-counts.csv').open()):d[tuple(r[k]for k in keys)][r['class']]=r
 return d

def validate(name,d,configs,edges):
 assert len(d)==configs
 for k,rows in d.items():
  assert int(rows['ALL']['random'])==1000000
  assert int(rows['ALL']['edge'])==edges
  for r in rows.values():assert int(r['total'])==int(r['random'])+int(r['edge'])
 hashes={}
 for suffix in ['counts','examples']:
  filename=f'{name}-{suffix}.csv';data=(b/'raw'/filename).read_bytes();repeat=(b/'validation'/f'{name}-repeat'/filename).read_bytes();assert data==repeat
  hashes[filename]={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'repeat_byte_identical':True}
 return {'status':'PASS','configurations':len(d),'random_cases':sum(int(v['ALL']['random'])for v in d.values()),'total_cases':sum(int(v['ALL']['total'])for v in d.values()),'files':hashes}

chains=load('chains',['family','length','pc','rounding']);extended=load('extended',['operation','pc','rounding'])
validation={'chains':validate('chains',chains,112,400),'extended':validate('extended',extended,48,256)}
(b/'validation/chains-extended-validation.json').write_text(json.dumps(validation,indent=2)+'\n')
with (b/'CHAINS-RESULT.md').open('w')as f:
 f.write('# Register-resident chains, lengths 2–8\n\n')
 f.write('Two families: (a*b)/b*a/b… and (a+b)-b+b-b…; every prefix length 2 through 8 is measured. x87 intermediates remain in ST0, SSE intermediates in xmm0; no intermediate floating-point stores. A separate diagnostic execution of the first operation records the first-step x87 value. That witness is not inserted into the measured chain.\n\n')
 f.write('PC53 uses binary64 source values and SSE double. PC24 uses binary32 source values and SSE float. Four matched rounding modes, FTZ=DAZ=0, masked exceptions. Each of 112 configurations has 1,000,000 deterministic random pairs and 400 edge pairs. Total 112,044,800 cases. Full raw CSV repeat is byte-identical.\n\n')
 f.write('## Results\n\n| Family | Length | PC | RC | Value mismatch | Flags mismatch | First above target exponent range | First below target normal | Recovered normal after high first | Recovered normal after low first |\n|---|---:|---:|---|---:|---:|---:|---:|---:|---:|\n')
 fields=['VALUE_MISMATCH','FLAGS_MISMATCH','FIRST_ABOVE_BASELINE_RANGE','FIRST_BELOW_BASELINE_NORMAL','RECOVERED_NORMAL_AFTER_HIGH_FIRST','RECOVERED_NORMAL_AFTER_LOW_FIRST']
 for k,d in chains.items():f.write('| '+' | '.join((*k,*(d[x]['total']for x in fields)))+' |\n')
 f.write('\nBelow normal exponent range includes subnormal-representable values. It is not the same as below the least nonzero IEEE value. Recovered-normal counts describe the x87 path; they are not all necessarily mismatches. Consult value/flags columns and individual examples. Odd-length chains end on multiplication/addition; even-length chains end on division/subtraction. Categories overlap.\n\n')
 f.write('## Native witnesses\n\n| Family | Length | PC | RC | Class | A bits | B bits | Final x87 80 | Final SSE 80 | First x87 80 (separate execution) | FSW after | MXCSR |\n|---|---:|---:|---|---|---|---|---|---|---|---|---|\n')
 seen=set()
 for r in csv.DictReader((b/'raw/chains-examples.csv').open()):
  key=(r['family'],r['pc'],r['class'])
  if key in seen or r['rounding']!='RN' or r['length']!='2' or r['class']not in ['RECOVERED_NORMAL_AFTER_HIGH_FIRST','RECOVERED_NORMAL_AFTER_LOW_FIRST']:continue
  seen.add(key);fields=['family','length','pc','rounding','class','a_hex','b_hex','x87_80_hex','sse_as_80_hex','separate_first_step_x87_hex','fsw_after','mxcsr'];f.write('| '+' | '.join(r[x]for x in fields)+' |\n')
 f.write('\nConclusion: unconditional double/float replacement of register chains is invalid even when the final x87 result is normal and representable. An intermediate overflow/underflow or loss of subnormal precision in the SSE path can survive or become irreversible; final-range checking alone is insufficient. These two chain families are measured counterexamples, not exhaustive coverage of every possible sequence.\n\nBuild/run: bash run-chains.sh. Source chains.c is original MIT C/asm. Fixed seed 0x434841494e533031; random full IEEE source-format bit patterns, distinct NaN payloads, zeros, infinities, minimum subnormal/normal and maximum finite. Compiler flags match core; see run-chains.sh.\n')
with (b/'EXTENDED-RESULT.md').open('w')as f:
 f.write('# Existing extended-register input: lossy IEEE-storage model\n\n')
 f.write('This is a separate input domain from core.c. Original inputs are m80 values with full 64-bit significands and full x87 exponent range. Path A loads both m80 operands and executes x87 register FADD/FSUB/FMUL/FDIV. Path B first narrows each original operand through actual hardware FSTP m32/m64 at the selected RC, then executes SSE. This is explicitly a lossy replacement proposal, not two operations with already-identical representable inputs. Narrowing FSW values are retained separately from operation FSW/MXCSR.\n\n')
 f.write('Three PC settings × four RC × four operations = 48 configurations, each 1,000,000 random pairs plus 256 explicit edge pairs: 48,012,288 cases. Random m80 inputs are finite normal across all exponents 1..32766, with independent full significands/signs; exact zeros, ext subnormal, infinity and distinct quiet/signaling NaNs are supplied as edges. Fixed seed 0x455854454e444544. Full repeated raw CSV is byte-identical.\n\n')
 f.write('| Operation | PC | RC | Value mismatch | Operation flags mismatch | Input narrowing exception | Normal-final mismatch | Normal-exponent source narrowing inexact |\n|---|---:|---|---:|---:|---:|---:|---:|\n')
 fields=['VALUE_MISMATCH','OPERATION_FLAGS_MISMATCH','SOURCE_NARROWING_EXCEPTION','FINITE_NORMAL_FINAL_MISMATCH','SOURCE_EXTRA_PRECISION_IN_TARGET_RANGE']
 for k,d in extended.items():f.write('| '+' | '.join((*k,*(d[x]['total']for x in fields)))+' |\n')
 f.write('\nThe last class is defined mechanically: both source exponents are in the target normal exponent interval and narrowing raises PE. It is not an exclusive causal attribution; a boundary overflow can also set PE. Operation flag comparison intentionally excludes input-narrowing flags, which are printed in separate columns.\n\n## Targeted input-precision witness\n\n')
 targeted=list(csv.DictReader((b/'raw/extended-targeted.csv').open()))
 for r in targeted:
  if(r['operation'],r['pc'],r['rounding'],r['pair'])==('FSUB','53','RN','0'):
   f.write('Native PC53/RN subtraction: A m80 '+r['a_80_hex']+', B m80 '+r['b_80_hex']+'. Original-register x87 result '+r['x87_80_hex']+'; narrowed-input SSE result '+r['sse_80_hex']+'. Narrowed A/B: '+r['a_narrow_hex']+' / '+r['b_narrow_hex']+'. This is (1+2^-63)-1: the result survives in x87 even though PC=53, because loading a register did not truncate the original operand. Actual narrowing A flags '+r['a_narrow_fsw']+'; original subtraction FSW '+r['fsw_after']+'.\n')
 f.write('\nConclusion for FADD/FSUB/FMUL/FDIV: CW PC53 alone is not sufficient permission to store every x87 stack value as double. Values must carry a verified representability/state precondition or use an extended fallback. PC24 has the analogous source-representation requirement. Exponent guards alone are insufficient when the original input has additional significand bits.\n\nBuild/run: bash run-extended.sh. Targeted witness: gcc -O2 -std=c11 -Wall -Wextra -Werror -fno-strict-aliasing -fno-fast-math -ffp-contract=off extended-selftest.c -o extended-selftest && ./extended-selftest > raw/extended-targeted.csv.\n')
print(json.dumps(validation,indent=2))
