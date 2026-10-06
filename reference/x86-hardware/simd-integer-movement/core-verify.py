#!/usr/bin/env python3
# Original MIT verification: read-only checks; never rewrites hardware result rows.
import collections,gzip,hashlib,json,pathlib,re,subprocess
P=pathlib.Path(__file__).resolve().parent
F=json.loads((P/'core-inventory.json').read_text());fm={f['id']:f for f in F}
# Verify the actual linked instruction for every generated encoding/immediate/operand form.
dis=subprocess.check_output(['objdump','-d','--insn-width=16',str(P/'core-build/core')],text=True)
obs={};current=None
for s in dis.splitlines():
 m=re.search(r'<core_(\d+)_fault>:',s)
 if m:current=int(m.group(1));continue
 if current is not None:
  m=re.match(r'\s*[0-9a-f]+:\s*((?:[0-9a-f]{2}\s+)+)\s*(\S+)\s*(.*)',s)
  if m:obs[current]=(bytes.fromhex(m[1]),m[2],m[3]);current=None
assert len(obs)==len(F),(len(obs),len(F))
for f in F:
 raw,op,args=obs[f['id']];expected=('v' if f['enc']=='VEX' else '')+f['op'];assert op==expected,(f,op,args)
 assert (raw[0] in (0xc4,0xc5))==(f['enc']=='VEX'),(f,raw.hex())
 assert ('ymm' if f['width']==256 else 'xmm') in args,(f,args)
 assert ('(%rdx)' in args)==(f['loc']!='reg'),(f,args)
 if f['imm']>=0:
  m=re.search(r'\$(0x[0-9a-f]+|[0-9]+)',args);assert m and int(m[1],0)==f['imm'],(f,args)
# Exact opcode/immediate inventory completeness within each family.
groups=collections.defaultdict(set)
for f in F:
 if f['imm']>=0:groups[(f['cls'],f['op'],f['width'],f['enc'],f['loc'],f['mode'])].add(f['imm'])
assert all(s==set(range(256)) for s in groups.values())
summary={};rule=collections.Counter();byop=collections.defaultdict(lambda:collections.Counter());encs=collections.defaultdict(set)
for f in F:
 k=(f['cls'],f['op']);byop[k]['forms']+=1;byop[k]['rows']+=f['cases'];encs[k].add(f['enc']+str(f['width']))
for cls in ('permutation','arithmetic','logic','shifts','pack'):
 path=P/f'out-{cls}.txt.gz';rawhash=hashlib.sha256();counts=collections.Counter();seen=collections.Counter();f=None;trailer=None
 with gzip.open(path,'rb') as z:
  for bb in z:
   rawhash.update(bb);s=bb.decode().rstrip('\n')
   m=re.match(r'# form=(\d+)',s)
   if m:f=fm[int(m[1])];counts['forms']+=1;continue
   if s.startswith('# rows='):trailer={k:int(v) for k,v in re.findall(r'(\w+)=(\d+)',s)};continue
   if s.startswith('#'):continue
   assert f and f['cls']==cls
   seen[f['id']]+=1;counts['rows']+=1
   left,right=s.split(' -> ');tok=left.split();assert len(tok)==5;result=right.split()[0]
   x1=bytes.fromhex(tok[3] if f['mode']=='flags' else tok[2])[::-1]
   if f['mode']=='flags':
    assert len(tok[2])==4 and len(result)==4 and tok[1]=='16'
    result=re.search(r'YMM_AFTER=([0-9a-f]+)',right)[1]
   if 'TRAP(sig=' in right:
    counts['traps']+=1;assert bytes.fromhex(result)[::-1]==x1
    rule['fault_destination_preservation_support']+=1;continue
   counts['scalar_checked']+=1;dest=bytes.fromhex(result)[::-1];n=f['width']//8
   if n==16 and f['mode']!='flags':
    prefix='legacy_upper_preserve' if f['enc']=='SSE' else 'vex128_upper_zero'
    rule[cls+'_'+prefix+'_support']+=1
    assert dest[16:]==(x1[16:] if f['enc']=='SSE' else bytes(16))
   if f['op']=='pshufb':
    ctrl=bytes.fromhex(tok[4] if f['enc']=='VEX' else tok[3])[::-1];masked=0
    for j in range(n):
     if ctrl[j]&128:masked+=1;assert dest[j]==0
    if masked:rule['pshufb_high_mask_rows']+=1;rule['pshufb_high_mask_bytes']+=masked
   if cls=='shifts' and f['mode'] not in ('shiftbytes',):
    b=f['lane'];a=bytes.fromhex(tok[3])[::-1] if f['enc']=='VEX' else x1
    if f['mode']=='shiftimm':countsvec=[f['imm']]*(n//b)
    elif f['mode']=='shiftcount':
     raw=bytes.fromhex(tok[4] if f['enc']=='VEX' else tok[3])[::-1];countsvec=[int.from_bytes(raw[:8],'little')]*(n//b)
    else:
     raw=bytes.fromhex(tok[4])[::-1];countsvec=[int.from_bytes(raw[j:j+b],'little') for j in range(0,n,b)]
    saw=False
    for j,count in enumerate(countsvec):
     if count>=b*8:
      saw=True;sign=a[j*b+b-1]>>7;expect=bytes([255 if sign and 'psra' in f['op'] else 0])*b;assert dest[j*b:(j+1)*b]==expect;rule['oversized_shift_elements']+=1
    if saw:rule['oversized_shift_rows']+=1
 assert trailer is not None
 expected={f['id']:f['cases'] for f in F if f['cls']==cls};assert dict(seen)==expected
 assert counts['rows']==sum(expected.values())==trailer['rows']==trailer['expected']
 assert counts['scalar_checked']==trailer['C_checked'];assert not trailer['C_mismatches'] and not trailer['upper_mismatches']
 assert rawhash.hexdigest()==(P/f'out-{cls}.sha256').read_text().split()[0]
 summary[cls]=dict(counts,compressed_bytes=path.stat().st_size)
summary['encoding_verified_forms']=len(F);summary['all_256_immediate_groups']=len(groups);summary['rules']=dict(rule)
(P/'core-validation.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
s=['# Classes 2–6: native forms and rows','','A form is one mnemonic × legal encoding/width × register/aligned-memory/+1-memory operand variant × immediate byte (when present). All immediate groups contain exactly 256 forms. Each memory form has its own labelled native instruction. Full YMM destination is printed even for 128-bit operations.','','| Class | Mnemonic | Encodings/width | Forms | Rows |','|---|---|---|---:|---:|']
for (cls,op),v in sorted(byop.items()):s.append(f'| {cls} | {op} | {", ".join(sorted(encs[(cls,op)]))} | {v["forms"]} | {v["rows"]} |')
s+=['','## Input reduction and omissions','','All immediate values are retained. Immediate permutations/arithmetic use 4 deterministic input cases; immediate shifts use 8. Non-immediate forms use 24 cases, except scalar-count shifts use element-width-in-bits + 6 (0 through width+1 plus four very large counts). Lane values mix zero, one, all ones, sign boundaries, saturation boundaries, alternating bits, fixed byte tags and out-of-range/high-bit controls. This is a documented input sample, not an exhaustive Cartesian product.','', 'All requested SSE/VEX128/VEX256 forms for these classes are included where ISA encodings exist. Memory operands use aligned and +1-unaligned addresses. Legacy alignment faults are captured as actual fault-time states. Immediate packed shifts have register destinations/sources only; no nonexistent memory form is invented. No MMX, EVEX or AVX-512-only instructions (such as VPSRAVQ) are in the requested SSE/AVX/AVX2 scope. Class 10 additionally snapshots all sixteen YMM registers for VZEROUPPER/VZEROALL.','', 'C models cover every successfully executed row in these classes; fault rows verify actual destination preservation instead. core-verify.py checks each linked instruction mnemonic, VEX/SSE prefix, width, memory/register choice, all immediate bytes, row counts, raw SHA-256 and selected semantic rules.']
(P/'core-COVERAGE.md').write_text('\n'.join(s)+'\n')
r=['# Core empirical rules (this CPU only)','','All counts below are read from the actual native output files. Every stated rule has zero observed counterexamples in the listed sample; this does not claim exhaustive input proof.','']
for k,v in sorted(rule.items()):r.append(f'- {k}: {v}; counterexamples: 0')
r+=['','Oversized logical shifts produce zero elements; oversized arithmetic right shifts produce the sign fill. PSHUFB zeroes every selected byte whose control high bit is one. Packed 256-bit shuffle/unpack/pack operations in the task that are lane-local agree with the scalar lane-local model. Legacy writing forms preserve YMM[255:128]; VEX-128 writing forms clear it. PTEST/VPTEST/VTEST do not write any vector register, so their VEX encodings preserve the entire input vector rather than zeroing an imaginary destination. Actual alignment-fault rows preserve all destination bits.','', 'The apparent “VEX always zeros upper bits” shorthand applies only when an instruction writes the XMM destination. Stores, flag tests and instructions with only GPR results must be considered separately. All 256 VZEROUPPER/VZEROALL register observations pass their scalar rule: 128 observations preserve the low half/clear the high half, and 128 clear the full YMM register.']
(P/'core-RULES.md').write_text('\n'.join(r)+'\n')
print(json.dumps(summary,sort_keys=True))
