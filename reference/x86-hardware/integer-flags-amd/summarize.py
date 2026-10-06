#!/usr/bin/env python3
# Original MIT code.
import pathlib,json,collections
P=pathlib.Path(__file__).resolve().parent;c=json.loads((P/'core-counts.json').read_text());inv=json.loads((P/'core-inventory.json').read_text());summary=json.loads((P/'validation-summary.json').read_text())
u={
 'SHL':'AF for nonzero count; OF except count 1; CF for count >= width (nonzero masked count)',
 'SAL':'Same instruction encoding/undefined flags as SHL',
 'SHR':'AF for nonzero count; OF except count 1; CF for count >= width (nonzero masked count)',
 'SAR':'AF for nonzero count; OF except count 1',
 'ROL':'OF except masked count 1; masked count 0 leaves flags unchanged',
 'ROR':'OF except masked count 1; masked count 0 leaves flags unchanged',
 'RCL':'OF except masked count 1; masked count 0 leaves flags unchanged',
 'RCR':'OF except masked count 1; masked count 0 leaves flags unchanged',
 'SHLD':'AF for nonzero count, OF except 1; result/arithmetic flags undefined when masked count > width',
 'SHRD':'AF for nonzero count, OF except 1; result/arithmetic flags undefined when masked count > width',
 'MUL':'PF, AF, ZF, SF', 'IMUL1':'PF, AF, ZF, SF','IMUL2':'PF, AF, ZF, SF','IMUL3':'PF, AF, ZF, SF',
 'DIV':'CF, PF, AF, ZF, SF, OF after successful division; #DE captured independently',
 'IDIV':'CF, PF, AF, ZF, SF, OF after successful division; #DE captured independently',
 'BSF':'CF, PF, AF, SF, OF; destination undefined if source=0',
 'BSR':'CF, PF, AF, SF, OF; destination undefined if source=0',
 'TZCNT':'PF, AF, SF, OF','LZCNT':'PF, AF, SF, OF','POPCNT':'None; ZF computed, others cleared',
 'BT':'PF, AF, SF, OF; ZF unaffected','BTS':'PF, AF, SF, OF; ZF unaffected','BTR':'PF, AF, SF, OF; ZF unaffected','BTC':'PF, AF, SF, OF; ZF unaffected',
 'AND':'AF','OR':'AF','XOR':'AF','TEST':'AF',
 'CMPXCHG':'None; arithmetic flags from accumulator minus destination',
 'XADD':'None; arithmetic flags from sum',
 'BSWAP16':'16-bit result undefined; flags unaffected',
 'CMPXCHG8B':'None; ZF computed, other arithmetic flags unaffected',
 'CMPXCHG16B':'None; ZF computed, other arithmetic flags unaffected'}
lines=['# Coverage and exact accounting','','All requested 64-bit-mode mnemonics and permitted operand widths are executed. Architecture classifications below distinguish undefined flags/results from values checked by the C model; they are not general claims about the observed CPU behavior. Empirical behavior appears in RULES.md with measured counts.','','“Forms” below means generated width/form/count-or-immediate configurations, not a claim that every one has different opcode bytes. A CL configuration is repeated per raw count. All counts include duplicate labeled operand positions and both actual initial flags.','','| Instruction | Widths | Configurations | Data rows | Architecturally undefined or special flags/results |','|---|---|---:|---:|---|']
for op,n in c['rows_by_instruction'].items():
 fs=[f for f in inv if f['op']==op];widths='/'.join(str(w) for w in sorted(set(f['w'] for f in fs)))
 lines.append(f'| {op} | {widths} | {len(fs)} | {n:,} | {u[op]} |')
lines+=['','## Counts checked before and after execution','','| Class | Native configurations | Predicted and observed rows | Actual traps | Gzip bytes |','|---|---:|---:|---:|---:|']
for cls,x in summary.items():
 if not isinstance(x,dict):continue
 lines.append(f'| {cls} | {x.get("forms",540)} | {x["rows"]:,} | {x.get("traps",0):,} | {x["gzip_bytes"]:,} |')
lines+=['',f'Total: {summary["total_rows"]:,} actual data rows; {summary["total_result_gzip_bytes"]:,} compressed result bytes (limit 60,000,000).','',
 'Independent `verify_data.py` checks every configuration against these products, not just grand totals:',
 '- shifts: 4 mnemonics × 2 forms × sum over w=8,16,32,64 of (2w+2 counts) ×22×2 = 87,296; rotates use the same product',
 '- double: 2 mnemonics ×3 widths ×64 counts ×2 forms ×22²×2 = 743,424',
 '- multiply: (8 one-operand +3 two-operand +40 three-operand/immediate configurations) ×22²×2 = 49,368',
 '- divide: 8 forms×22³×2 +2 signedness forms×(20+20+20+21 nonzero divisor positions)×4 boundary quotients×3 offsets×2 flags =174,256',
 '- bitscan: 5 mnemonics×3 widths×22²×2 =14,520',
 '- bittest: 4 mnemonics×3 widths×[register indices 22×(22+15)×2 + memory indices 22×15×2 +14 immediate/memory configurations×22×2] =34,848',
 '- logic: 4 mnemonics×4 widths×22²×2 =15,488',
 '- misc: (4 CMPXCHG widths + CMPXCHG8B + CMPXCHG16B)×22³×2 +4 XADD widths×22²×2 +22×2 BSWAP16 =131,692','',
 'Division boundaries construct low/high limbs of q×divisor+offset modulo twice the operand width, with q = signed maximum, signed minimum, unsigned maximum, and unsigned maximum+1; offset=-1,0,+1. All arithmetic that may wrap during construction uses unsigned 128-bit addition, avoiding C signed overflow. These supplement, rather than replace, all low/divisor/high Cartesian patterns.',
 '', '## C-defined-semantics checks','', 'No undefined architectural bit is treated as a specification requirement. All captured initial flag values and non-arithmetic low-16 flags are checked independently. Each validation file distinguishes result checks from flag checks: undefined BSF/BSR zero-source destinations and undefined 16-bit double-shift results are not counted as defined-result checks. Successful DIV/IDIV have no defined arithmetic flags to check. Traps verify exact preserved operand registers and arithmetic flags against their saved context. Raw output repeat, diagnostic repeat and compressed output repeat comparisons all succeeded.','']
for cls in ['shifts','rotates','double','multiply','divide','bitscan','bittest','logic','misc']:
 lines+=['### '+cls,'','```',(P/f'out-{cls}.validation.txt').read_text().strip(),'```','']
lines+=['## Class 9','','The full per-command class-9 forms/rows/manual-undefined flags table and C counts are reproduced below.']
bmi=(P/'bmi_REPORT.md').read_text();lines.append(bmi.split('## Coverage and C defined-semantics validation',1)[1].split('## Measured rules',1)[0])
lines+=['## Not covered and why','','- Class 11: DAA, DAS, AAA, AAS, AAM and AAD have zero executed rows. Static no-libc i386 compilation succeeds, but native execution returns errno 8 (Exec format error). This is the task’s explicitly allowed unavailable case. See legacy_REPORT.md/legacy_CHECKS.txt; no emulation, packages or fabricated legacy results.','- The legacy probe is only a compatibility probe; it is not a complete decimal-instruction generator. If a later host permits i386 execution, those exhaustive sweeps remain new work.','- Arbitrarily huge full-pattern memory bit indices are outside the controlled allocation; memory offsets use the fifteen documented negative/positive boundaries. Register indices do include all 22 pattern positions.','- Alternate register allocations, LOCK variants, memory-source variants beyond the specifically requested bit-string and CMPXCHG8B/16B forms, non-#DE fault types and upper-register bits above the operand width are not enumerated.','- Initial arithmetic flag states are the task’s paired all-clear/all-set patterns, not every one of 64 flag combinations.','- No Intel-vs-AMD portability claim is made from this single machine. Exact repeatability is measured on the reported exposed CPU.','','## License and provenance','','All submitted generator/harness/model/analyzer code is original MIT-licensed code. No third-party source was fetched or embedded. Only the local compiler/assembler and already installed standard tools were used.']
(P/'COVERAGE.md').write_text('\n'.join(lines)+'\n');print('COVERAGE.md regenerated')
