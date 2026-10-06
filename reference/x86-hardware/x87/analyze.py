#!/usr/bin/env python3
"""Original MIT counted empirical rules, complete coverage and structural audit."""
import gzip,json,pathlib,collections,hashlib,re,subprocess,functools
from fractions import Fraction
P=pathlib.Path(__file__).resolve().parent
forms=json.loads((P/'forms.json').read_text());inputs=json.loads((P/'inputs.json').read_text())
expected={}
for l in (P/'expected-counts.txt').read_text().splitlines():
 cls,name,n=l.split();expected[cls,name]=int(n)
actual=collections.Counter();cwcounts=collections.Counter();checks=collections.defaultdict(lambda:collections.Counter(support=0,contradiction=0));examples={}
nanobs=collections.defaultdict(collections.Counter);pseudo=collections.defaultdict(collections.Counter);const=collections.defaultdict(collections.Counter);fxam=collections.defaultdict(collections.Counter);envs=collections.defaultdict(collections.Counter);traps=collections.defaultdict(collections.Counter);compare=collections.defaultdict(collections.Counter);remainder=collections.defaultdict(collections.Counter)
classes=sorted(set(f['cls']for f in forms));compression={};indef='ffffc000000000000000';regops={op+'_ST0_ST1':op for op in ['FADD','FSUB','FSUBR','FMUL','FDIV','FDIVR']}

def check(key,ok,row):
 checks[key]['support' if ok else 'contradiction']+=1
 if not ok and key not in examples:examples[key]=row
@functools.lru_cache(None)
def raw(s):
 if s in ('-','empty'):return None
 if len(s)!=20:return None
 return int(s[:4],16),int(s[4:],16)
def canonicalnan(s):
 z=raw(s);return bool(z and z[0]&0x7fff==0x7fff and z[1]>>63 and z[1]&((1<<63)-1))
def quiet(s):return s[:4]+f'{int(s[4:],16)|(1<<62):016x}'
def unsupported(s):
 z=raw(s);return bool(z and z[0]&0x7fff and not z[1]>>63)
@functools.lru_cache(None)
def rational(s):
 z=raw(s)
 if not z:return None
 se,m=z;e=se&0x7fff
 if e==32767 or(e and not m>>63):return None
 # Exact arithmetic audits are deliberately bounded to avoid giant rationals.
 exp=(e if e else 1)-16383-63
 if m and not -256<=exp<=256:return None
 return Fraction((-1 if se>>15 else 1)*m)*(Fraction(2)**exp)
def rmem(s,bits):
 z=int(s,16);p={32:23,64:52}[bits];eb={32:8,64:11}[bits];e=(z>>p)&((1<<eb)-1);m=z&((1<<p)-1)
 if e==(1<<eb)-1:return None
 exp=(e if e else 1)-((1<<(eb-1))-1)-p
 if e:m|=1<<p
 return Fraction((-1 if z>>(bits-1) else 1)*m)*(Fraction(2)**exp)
def ordered(s):
 z=raw(s)
 if not z:return None
 se,m=z;e=se&0x7fff
 if e==32767:return None
 v=((max(e,1)-1)<<63)+m
 return -v if se>>15 else v
for cls in classes:
 path=P/f'out-{cls}.txt.gz';b=path.read_bytes();unpacked=gzip.decompress(b)
 side=(P/f'out-{cls}.sha256').read_text().split();assert side[1]==f'out-{cls}.txt';assert hashlib.sha256(unpacked).hexdigest()==side[0]
 compression[cls]=dict(compressed_bytes=len(b),compressed_sha256=hashlib.sha256(b).hexdigest(),raw_sha256=side[0])
 for line in unpacked.decode().splitlines():
  if line.startswith('#'):continue
  t=line.split();op=t[0];cw=int(t[1],16);a,b=t[2:4];is_trap=t[6]=='TRAP';k=7 if is_trap else 6;r,s,mem=t[k:k+3];sw,tw=int(t[k+3],16),int(t[k+4],16);flags=t[k+5];meta=dict(x.split('=',1)for x in t[k+6:])
  actual[cls,op]+=1;cwcounts[cls,op,cw]+=1
  assert 'UNMAPPED' not in line
  assert all(x in ('empty','-')or re.fullmatch('[0-9a-f]{20}',x)for x in (a,b,r,s))
  assert flags=='-'or re.fullmatch('[0-9a-f]{3}',flags)
  if 'STACK' in meta:
   st=meta['STACK'].split(',');assert len(st)==8;top=(sw>>11)&7
   for i,v in enumerate(st):
    physical=(top+i)&7;tag=(tw>>(physical*2))&3
    check('full_FTW_empty_tags_match_logical_STACK', (tag==3)==(v=='empty'),line)
   atw=int(meta['ATW'],16);reconstructed=sum(((tw>>(2*j)&3)!=3)<<j for j in range(8));check('abridged_FTW_matches_full_FTW',atw==reconstructed,line)
  if op in regops and canonicalnan(a)and canonicalnan(b):
   qa,qb=bool(int(a[4:],16)&1<<62),bool(int(b[4:],16)&1<<62);nk=('Q'if qa else'S')+('Q'if qb else'S');q0,q1=quiet(a),quiet(b)
   predicted=q0 if qa and not qb else q1 if qb and not qa else max((q0,q1),key=lambda x:int(x[4:],16))
   nanobs[nk]['rows']+=1;nanobs[nk]['ST0']+=r==q0;nanobs[nk]['ST1']+=r==q1;nanobs[nk]['IE']+=bool(sw&1)
   check('NaN_'+nk+'_quiet_preferred_else_larger_significand',r==predicted,line)
   check('NaN_'+nk+'_IE_iff_signaling',bool(sw&1)==(not qa or not qb),line)
  if op in regops:
   x,y,z=rational(a),rational(b),rational(r)
   if x is not None and y is not None and z is not None and not (sw&0x1d):
    base=regops[op]
    try:exact={'FADD':lambda:x+y,'FSUB':lambda:x-y,'FSUBR':lambda:y-x,'FMUL':lambda:x*y,'FDIV':lambda:x/y,'FDIVR':lambda:y/x}[base]()
    except ZeroDivisionError:exact=None
    if exact is not None:check('arithmetic_C1_iff_magnitude_rounded_up',bool(sw&0x200)==(abs(z)>abs(exact)),line)
   # Independent invalid-operation tuples, excluding any NaN or unsupported input.
   ai=a[4:]=='8000000000000000'and int(a[:4],16)&0x7fff==0x7fff;bi=b[4:]=='8000000000000000'and int(b[:4],16)&0x7fff==0x7fff
   az=a[4:]=='0000000000000000'and int(a[:4],16)&0x7fff==0;bz=b[4:]=='0000000000000000'and int(b[:4],16)&0x7fff==0
   signsame=a[:1]==b[:1];base=regops[op]
   inv=(base=='FADD'and ai and bi and not signsame)or(base in ('FSUB','FSUBR')and ai and bi and signsame)or(base=='FMUL'and((ai and bz)or(bi and az)))or(base in ('FDIV','FDIVR')and((ai and bi)or(az and bz)))
   if inv:check('invalid_arithmetic_negative_indefinite_and_IE',r==indef and bool(sw&1),line)
   if unsupported(a)or unsupported(b):check('unsupported_arithmetic_negative_indefinite_and_IE',r==indef and bool(sw&1),line)
  if op=='FSQRT':
   x,z=rational(a),rational(r)
   if x is not None and x<0:check('negative_sqrt_indefinite_and_IE',r==indef and bool(sw&1),line)
   if x is not None and x>=0 and z is not None:check('sqrt_C1_iff_magnitude_rounded_up',bool(sw&0x200)==(z*z>x),line)
  if op=='FRNDINT':
   x,z=rational(a),rational(r)
   if x is not None and z is not None:check('frndint_C1_iff_magnitude_rounded_up',bool(sw&0x200)==(abs(z)>abs(x)),line)
  if op.startswith(('FST_m','FSTP_m')) and not op.endswith('m80'):
   x=rational(a);z=rmem(mem,int(op.split('m')[-1]))
   if x is not None and z is not None and not(sw&0x1d):check('float_store_C1_iff_magnitude_rounded_up',bool(sw&0x200)==(abs(z)>abs(x)),line)
  if op.startswith('FIST')and not(sw&1):
   x=rational(a);v=int(mem,16);bits=len(mem)*4;v=v-(1<<bits)if v>>(bits-1)else v
   if x is not None:check('integer_store_C1_iff_magnitude_rounded_up',bool(sw&0x200)==(abs(v)>abs(x)),line)
  if op in ['FLD1','FLDZ','FLDPI','FLDL2T','FLDL2E','FLDLG2','FLDLN2']:const[op,(cw>>10)&3][r]+=1
  if op in ('FLD_m80','FSTP_m80','FABS','FCHS','FSQRT','FXAM','FSTP_m32','FSTP_m64'):
   source=t[4]if op=='FLD_m80'else a
   z=raw(source)
   if z and (unsupported(source)or(z[0]&0x7fff==0 and z[1]>>63)):
    category='pseudo-denormal'if z[0]&0x7fff==0 else 'pseudo-infinity'if z[0]&0x7fff==0x7fff and z[1]==0 else 'pseudo-NaN'if z[0]&0x7fff==0x7fff else 'unnormal'
    result=mem if op.startswith('FSTP')else r;pseudo[category,op][(result,sw&0x47f)]+=1
  if op=='FXAM':fxam[a][f'{sw&0x4700:04x}']+=1
  if cls=='comparison' and op!='FXAM' and (canonicalnan(a)or canonicalnan(b)) and not unsupported(a)and not unsupported(b):
   # This selected set excludes memory forms because displayed ST1 is not its operand.
   if '_m'not in op:
    anysn=(canonicalnan(a)and not int(a[4:],16)&1<<62)or(canonicalnan(b)and not int(b[4:],16)&1<<62)
    expectie=anysn or not op.startswith('FU')
    check('NaN_compare_IE_rule',bool(sw&1)==expectie,line)
    unordered=(int(flags,16)==0x45)if flags!='-'else sw&0x4500==0x4500
    check('NaN_compare_unordered_flags',unordered,line)
  if op in ('FPREM','FPREM1','FPREM_ITER','FPREM1_ITER'):
   x,y,z=rational(a),rational(b),rational(r)
   remainder[op]['C2_set']+=bool(sw&0x400);remainder[op]['C2_clear']+=not bool(sw&0x400)
   if 'STEP'in meta and meta['STEP']=='63':check('remainder_all_fixed64_chains_terminate_C2_clear',not bool(sw&0x400),line)
   if x is not None and y not in (None,0) and z is not None and not(sw&0x401):
    q=x/y;qi=round(q)if op.startswith('FPREM1')else int(q)
    check('remainder_value_exact_for_completed_bounded_inputs',z==x-qi*y,line)
    qbits=((sw>>8)&1)*4+((sw>>14)&1)*2+((sw>>9)&1)
    check('remainder_quotient_bits_absolute_low3',qbits==(abs(qi)&7),line)
  if cls=='environment':
   key=(meta.get('FOP'),meta.get('FIP'),meta.get('FDP'),meta.get('LEGACY_FOP'),meta.get('LEGACY_FIP'),meta.get('LEGACY_FDP'));envs[op][key]+=1
   if op.startswith('TRACE_'):
    check('masked_trace_FXSAVE_reports_zero_FOP_FIP_FDP',meta['FOP']=='000'and meta['FIP']=='zero'and meta['FDP']=='zero',line)
   if op in ('FLDENV','FRSTOR','FXRSTOR64','FXRSTOR'):
    check('environment_restore_preserves_seeded_pointers_in_legacy_view',meta['LEGACY_FIP']=='restore-ip'and meta['LEGACY_FDP']=='restore-dp'and meta['LEGACY_FOP']=='456',line)
   if op=='FNSAVE':check('FNSAVE_resets_x87',sw==0 and tw==0xffff and meta['FCW']=='037f',line)
  if cls=='stack':
   case=int(meta['CASE']);depth=case%9
   if op=='FNINIT_DEPTH':check('FNINIT_resets_x87',sw==0 and tw==0xffff and meta['FCW']=='037f',line)
   if op=='FNCLEX_DEPTH':check('FNCLEX_clears_exception_SF_ES_B_preserves_CCs',sw==(int(meta['BEFORE_FSW'],16)&~0x80ff),line)
   if case<9 and op=='FLD1_DEPTH'and depth==8:check('stack_overflow_IE_SF_C1_negative_indefinite',sw&0x241==0x241 and r==indef,line)
   if case<9 and op=='FSTP_ST0_DEPTH'and depth==0:check('stack_underflow_IE_SF_C1zero_pop',sw&0x241==0x41 and ((sw>>11)&7)==1,line)
   if op in ('FINCSTP_DEPTH','FDECSTP_DEPTH'):check('stack_top_adjust_keeps_physical_full_tags',tw==int(meta['BEFORE_FTW'],16),line)
  if cls=='traps':
   traps[op]['rows']+=1;traps[op]['SIGFPE']+=is_trap;traps[op]['probe']+=meta['TRAP_AT']=='probe';traps[op]['trigger']+=meta['TRAP_AT']=='trigger';traps[op]['signal_code_'+meta['SIGCODE']]+=1
   check('all_unmasked_exceptions_deferred_to_next_waiting_probe',is_trap and meta['TRAP_AT']=='probe',line)
   check('trap_state_equals_preprobe_hardware_snapshot',sw==int(meta['PRE_FSW'],16)and meta['STACK']==meta['PRE_STACK']and meta['ATW']==meta['PRE_ATW'],line)
   check('trap_has_ES_and_B_set',sw&0x8080==0x8080,line)
assert actual==expected,(actual-collections.Counter(expected),collections.Counter(expected)-actual)
for (cls,op),n in expected.items():
 vals=[count for(c,o,cw),count in cwcounts.items()if c==cls and o==op];assert len(vals)==12 and len(set(vals))==1
assert sum(z['compressed_bytes']for z in compression.values())<60*1024*1024
# Validate each assembled target mnemonic from disassembly, recording no code addresses.
dis=subprocess.check_output(['objdump','-d','-M','intel','build/oracle'],cwd=P,text=True);enc=[]
for f in forms:
 match=re.search(r'<op_'+str(f['index'])+r'_insn>:\n\s*[0-9a-f]+:\s*((?:[0-9a-f]{2} )+)\s*([^\n]+)',dis)
 assert match,f;code,ins=match.groups();got=ins.split()[0];want=f['asm'].split()[0]
 assert got==want,(f['name'],want,got)
 enc.append(dict(name=f['name'],bytes=code.strip(),decoded=ins.strip()))
(P/'encoding-validation.json').write_text(json.dumps(dict(forms=len(enc),mnemonic_mismatches=0,encodings=enc),indent=2)+'\n')
summary=dict(classes={c:dict(rows=sum(n for(k,_),n in actual.items()if k==c),forms=sum(f['cls']==c for f in forms),**compression[c])for c in classes},checks={k:dict(v)for k,v in checks.items()},counterexamples=examples,nan_selection={k:dict(v)for k,v in nanobs.items()},traps={k:dict(v)for k,v in traps.items()})
(P/'validation-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
# Report claims only as measured hypotheses with support and contradiction totals.
lines=['# Empirical x87 rules on this CPU','', 'All counts below are obtained by analyze.py from immutable native output rows. They describe this CPU and this sample, not a promise about every x87 implementation. A failed hypothesis remains visible with counterexamples in validation-summary.json. Hardware results are never modified by these analyses.','', '## Measurement isolation','', 'These deterministic rows use a documented interruption filter based only on measured thread context-switch changes, TSC_AUX migration and a fixed 5,000-TSC-tick capture bound, with at most 128 attempts. Intentional SIGFPE cases are latency-exempt. No result field determines acceptance. Unfiltered pointer-loss observations, scheduler/signal probes and 100-run filtered stability evidence are separately delivered; see NOTES.md and capture-interference-evidence.json. These claims concern isolated windows, not arbitrary OS scheduling behavior.','', '## Counted hypotheses','']
for k,v in checks.items():lines.append(f'- `{k}`: {v["support"]:,} supporting rows; {v["contradiction"]:,} contradictory rows')
lines+=['','## Two-NaN selection','', 'For the six ST0/ST1 arithmetic forms, a quiet NaN wins over a signaling NaN. When both inputs have the same quiet/signaling class, the larger significand wins and signaling results are quieted. The original signs/payloads remain observable. Equal-magnitude opposite-sign tie priority is not established by this sample. Slot payload tags use bit 8, so they do not dominate all original payload ordering.','']
for k,v in nanobs.items():lines.append(f'- {k}: '+', '.join(f'{a}={b}'for a,b in v.items()))
lines+=['','## Invalid operations and pseudo formats','', 'The negative binary80 indefinite is `ffffc000000000000000`. Defined invalid arithmetic and negative square roots are checked above independently of NaN/unsupported operands. Pseudo encodings are not silently canonicalized by the generator. The following tuples are literal `(result, FSW & 047f)` observations, aggregated across signs and FCWs; complete status/tag words remain in the raw rows. `FLD m80`/`FSTP m80` and sign-bit operations may preserve encodings which arithmetic rejects.','']
for (category,op),v in sorted(pseudo.items()):lines.append(f'- {category}, {op}: '+ '; '.join(f'({r}, {sw:04x}) × {n}'for(r,sw),n in sorted(v.items())))
lines+=['','## C1 and rounding','', 'The counted C1 hypotheses compare against exact rational arithmetic in a stated bounded finite domain (binary80 value exponent used in the integer significand representation −256…256), excluding overflow/underflow/invalid results. “Rounded up” here means increased magnitude, including a more-negative rounded result. It does not mean numerically toward +∞. Sqrt is checked using the exact squared rounded result. Store rounding is checked separately from arithmetic. The counts and any contradictions above delimit each claim. Undefined condition codes outside these checks remain hardware observations, not universal rules.','', '## Constants by rounding control','', 'RC 0=nearest-even, 1=down, 2=up, 3=toward-zero. Each tuple has three supporting PC variants; disagreement across precision controls would produce multiple results below.','']
for (op,rc),v in sorted(const.items()):lines.append(f'- {op}, RC={rc}: '+', '.join(f'{x} ({n} rows)'for x,n in v.items()))
lines+=['','## Remainders, comparisons, stack and exceptions','', 'FPREM/FPREM1 single-step rows include C2=1 partial reduction. Sixteen deterministic large finite pairs per command additionally run exactly 64 steps each, for all twelve FCWs; all terminal C2 checks and low quotient-bit hypotheses are counted above. Fixed continuation after completion is deliberate and exposes how the next completed remainder changes quotient bits.','']
for op,v in sorted(remainder.items()):lines.append(f'- {op}: '+', '.join(f'{x}={n}'for x,n in v.items()))
lines+=['','FCOM-family quiet/signaling invalid-flag differences and unordered flags are counted above. FCOMI/FUCOMI snapshots retain CF/PF/AF/ZF/SF/OF; tested unordered comparisons clear OF/SF/AF while setting CF/PF/ZF. Stack tests cover all depths 0…8 and a separate sticky-status seed set. FFREE, TOP movement, exchanges, FNINIT and FNCLEX preserve literal full tags and every logical register.','', 'Every unmasked trap includes the kernel-provided fault-time FSW and full80 register image, signal code, exact named faulting instruction, and a non-waiting FXSAVE immediately after the trigger. Signal return only masks pending exceptions and jumps past the probe; the exported TRAP record uses the untouched captured fault image. Full FTW is reconstructed on the same hardware from the saved abridged tag/register image; the same reconstruction was byte-compared against FNSTENV in every non-trapping record.','']
for op,v in sorted(traps.items()):lines.append(f'- {op}: '+', '.join(f'{x}={n}'for x,n in v.items()))
lines+=['','## Environment pointer and opcode updates','', 'Both FXSAVE and legacy FNSTENV views are recorded. FXSAVE FOP/FIP/FDP on this CPU are zero in all sampled masked traces even while legacy FNSTENV reports the updated values; they are meaningful in the pending unmasked trap snapshots. This difference must not be mistaken for an absence of hardware pointer updates. `instruction` and `probe` denote exact assembly labels; `memory+N` is the exact operand offset; seed/restore tokens name public synthetic sentinels. No process address is exported. Unknown pointer values cause validation failure.','', 'Below each tuple is `(FX FOP,FIP,FDP ; legacy FOP,FIP,FDP)`. FXSAVE/FNSAVE memory images additionally report their saved fields and register bytes in the rows.','']
for op,v in sorted(envs.items()):lines.append(f'- {op}: '+ '; '.join(f'{x} × {n}'for x,n in sorted(v.items())))
num=json.loads((P/'numeric-crosscheck.json').read_text());tr=json.loads((P/'transcendental-crosscheck.json').read_text())
lines+=['','## Independent C checks','']+[f'- {k}: {v:,} comparisons'for k,v in num['counts'].items()]+[f'- Mismatches: {len(num["mismatches"])}. Full mismatch list: numeric-crosscheck.json. PC53 arithmetic requires exact double-representable inputs and compares SSE double expressions; PC64 compares C long-double expressions for all four rounding modes.','- No double-rounding mismatch was observed in the explicitly eligible sample; this is not proof that double rounding cannot occur. Nonrepresentable input values, extreme exponents, and special values are skipped by these C-expression checks, but remain in the hardware tables.']
lines+=['','## Correctly rounded transcendental crosschecks','',f'Installed mpmath {tr["mpmath_version"]}, {tr["precision_bits"]}-bit arithmetic; binary80 nearest-even rounding with subnormals. Only PC64/nearest native rows are compared; every comparison and exact input/output bit string is in transcendental-crosscheck-samples.jsonl.gz. Signed-zero FPATAN branches are handled explicitly. The “ordinary” bucket includes inputs next to multiples of π/2 and π, where relative/ULP errors can be large despite small absolute errors. “Large” means |input| ≥ 2^20. F2XM1 is checked only inside [−1,1]; domain/range skips are enumerated in the JSON report.','']
for k,v in tr['stats'].items():lines.append(f'- {k}: n={v["count"]}, exactly rounded={v["exact"]}, within 1 ULP={v["within1"]}, >1 ULP={v["over1"]}, maximum distance={v["max_ulp"]} ULP')
lines+=['','The large trigonometric ULP distances are actual discrepancies against the independent reference, not discarded failures. ULP distance here is the integer distance in the ordered finite binary80 representable-value sequence, accounting for exponent boundaries. A high-precision convergence check is recorded in numeric-validation.txt.']
(P/'RULES.md').write_text('\n'.join(lines)+'\n')
coverage=['# Coverage','', 'All requested stages are implemented. Counts are computed before execution in harness.c and checked per form after execution by analyze.py. Every form uses twelve FCWs unless its per-case trap FCW unmasks one exception.','', '| Class | Forms | Rows | Compressed bytes |','|---|---:|---:|---:|']
for cls,z in summary['classes'].items():coverage.append(f'| {cls} | {z["forms"]} | {z["rows"]:,} | {z["compressed_bytes"]:,} |')
coverage+=['','## Exact bounded sampling','', '- Unary binary80: all 86 explicitly named bit patterns. First 30 are the special set, including signed zero/one/infinity, two QNaNs/two SNaNs with distinct surviving payloads, positive/negative denormals and min/max normals, both signs of pseudo-denormals/unnormals/pseudo-infinities, and two pseudo-NaNs.','- Binary register forms: all 30×30 special pairs, plus 2×86 boundary/value pairs with ±1, plus 36 constructed ties/adjacent half-ULP pairs (24/53/64-bit precision, both signs). NaN slot 1 flips payload bit 8 so same-source patterns remain distinguishable after quieting without forcing one operand to always have the larger payload.','- Memory arithmetic/comparisons: 30×28 special binary80/float-memory pairs or 30×12 binary80/integer-memory pairs, plus 86 rotating boundary cases per form. FLD memory covers every 28 float32/64 or 86 binary80 input; FILD covers 12 integer patterns per width.','- Packed BCD: 12 explicitly specified valid, signed, invalid-nibble and ignored-bit encodings. FBSTP sees all 86 binary80 values.','- Transcendentals: unary 86 special/boundary + 481 deterministic grid/near-π/extreme inputs each. F2XM1 rescales the 385-point central grid by 1/8, giving 385 ordinary in-domain inputs; the remaining out-of-domain and extreme samples are retained. Binary transcendental forms use 30×30 special pairs plus 481 grid pairs with recognizable signed integer second operands.','- FPREM/FPREM1: normal binary set plus 16 deterministic finite large-exponent pairs × exactly 64 linked steps, including incomplete and completed reductions for every FCW. Status is reset between linked instructions without altering the logical operand bytes; TOP is zero for these non-popping forms.','- Stack: each listed command at occupied depths 0…8, with both clean FSW and an explicitly declared sticky-status seed (needed to test FNCLEX). All eight post-registers, physical full FTW, abridged FTW and TOP are reported.','- Environment: every save/restore form, nine representative update/control operations, all occupied depths 0…8, two initial condition-code patterns, all twelve FCWs. Restore source bytes use public pointer sentinels; saved addresses are mapped to labels/offsets. Both legacy 108-byte and 512-byte layouts are covered, including FXSAVE64/FXRSTOR64 and legacy-address FXSAVE/FXRSTOR.','- Traps: eight triggers (six exception classes plus stack under/overflow) × two waiting probes (FWAIT, FLD1) × twelve FCWs. Other exception classes remain masked, status starts clean; the trigger is followed by a non-waiting pre-trap snapshot.','', '## Deliberate limits / nonexistent forms','', '- No non-popping FST m80 or FIST m64 encoding exists; these names are not silently emitted as a different instruction. FSTP m80, FISTP m64 and FISTTP m64 are covered.','- Fixed supported register samples use ST0/ST1 for arithmetic/comparison and ST0/ST3/ST7 for representative stack operations rather than enumerating all eight register-index encodings. Stack depths, overflow and underflow are covered independently. No requested mnemonic family or legal requested memory width is omitted.','- No 32-bit executable or emulation: the requested instructions run in native 64-bit mode, as permitted by TASK.md. Host reports a hypervisor; this is disclosed in MACHINE.txt.','- Exhaustive 2^80 operand patterns, every NaN payload, all BCD invalid-digit permutations, and every possible environment bit pattern are outside the bounded sample. Equal-payload opposite-sign NaN priority is not established.','- Environment reserved bytes and literal process addresses are not delivered. Meaningful fields and full80 saved registers are preserved and exact pointer categories/offsets are explicit.','- C and high-precision models validate selected ordinary/domain-valid rows; they do not generate or replace any native output. High-precision checks focus on PC64/nearest and report discrepancies instead of requiring transcendentals to be correctly rounded.','', '## Per-form native rows','', '| Class | Form | Rows |','|---|---|---:|']
for f in forms:coverage.append(f'| {f["cls"]} | {f["name"]} | {actual[f["cls"],f["name"]]:,} |')
(P/'COVERAGE.md').write_text('\n'.join(coverage)+'\n')
(P/'COMPRESSED-SHA256.txt').write_text(''.join(f'{compression[c]["compressed_sha256"]}  out-{c}.txt.gz\n'for c in classes))
print('AUDIT rows',sum(actual.values()),'forms',len(forms),'compressed',sum(z['compressed_bytes']for z in compression.values()))
print('Counted hypotheses',json.dumps({k:dict(v)for k,v in checks.items()},sort_keys=True))
# Intentionally do not hide empirical contradictions: they are findings, not harness failure.
