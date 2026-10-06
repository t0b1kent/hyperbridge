#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read measured streams; count candidate rules. Never edit native result rows."""
from pathlib import Path
from collections import Counter, defaultdict
import gzip, json
ROOT=Path(__file__).resolve().parent
FM=0x8d5
counts=defaultdict(Counter)
formcounts=Counter()
traps=Counter()
ruletext={
 'DAA.undefined_OF':'OF equals 8-bit ADD overflow for old AL + d, where d = (low-nibble > 9 or input AF ? 6 : 0) + (old AL > 0x99 or input CF ? 0x60 : 0)',
 'DAS.undefined_OF':'OF equals 8-bit SUB overflow for old AL - d, with the same d condition as DAA',
 'AAA.undefined_OSZP':'OF, SF, ZF and PF equal flags of 16-bit AX + d BEFORE AL is masked to four bits; d = 0x106 when adjustment is selected, otherwise zero',
 'AAS.undefined_OSZP':'OF, SF, ZF and PF equal flags of 16-bit AX - d BEFORE AL is masked to four bits; d = 0x106 when adjustment is selected, otherwise zero',
 'AAM.undefined_OAC':'On successful AAM, OF = AF = CF = 0',
 'AAD.undefined_OAC':'OF, AF and CF equal flags of an 8-bit ADD of old AL and ((old AH * immediate) & 0xff)',
 'AAM.zero_trap':'AAM immediate zero traps and preserves input AX and all six arithmetic flags in the saved fault context',
 'SALC.observed':'SALC gives AL = input CF ? 0xff : 0, preserving all six arithmetic flags',
 'PUSHSEG32.upper':'32-bit segment PUSH zeroes the upper 16 bits of its four-byte stack slot, overwriting the initial 0xa5a5 high half',
 'STACK.flags':'PUSHA/PUSHAD/POPA/POPAD preserve all six arithmetic flags',
 'SEGMENT.flags':'PUSH/POP of measured segment registers preserve all six arithmetic flags',
 'INCDEC.CF':'All measured INC/DEC register forms preserve CF',
 'BOUND.flags':'BOUND preserves all six arithmetic flags, including saved out-of-range fault contexts',
 'INTO.flags':'INTO preserves all six arithmetic flags, including saved overflow trap contexts',
 'ARPL.preserved':'ARPL preserves CF, PF, AF, SF and OF (ZF alone is the architecturally modified arithmetic flag)',
 'LAHF.flags':'LAHF preserves all six arithmetic flags',
 'SAHF.OF':'SAHF preserves OF',
 'SHL.undefined_AF':'SHL in compatibility mode: count zero preserves AF; every nonzero masked count sets AF',
 'SHL.undefined_OF':'SHL in compatibility mode, masked count > 1: OF equals sign(final result) XOR output CF',
}
def record(key,ok):
 counts[key].setdefault('supporting',0);counts[key].setdefault('contradicting',0)
 counts[key]['supporting' if ok else 'contradicting']+=1
 counts[key]['total']+=1

def alu_flags(a,b,w,sub=False):
 m=(1<<w)-1;sign=1<<(w-1);r=(a-b if sub else a+b)&m
 cf=a<b if sub else a+b>m
 of=bool(((a^b)&(a^r)&sign) if sub else ((~(a^b))&(a^r)&sign))
 return int(cf)|((not ((r&255).bit_count()&1))*4)|(bool((a^b^r)&16)*16)|((r==0)*64)|(bool(r&sign)*128)|(of*2048)
for group in ['bcd','extra','control']:
 with gzip.open(ROOT/f'out-{group}.txt.gz','rt') as stream:
  for line in stream:
   if line.startswith('#'):continue
   f=line.split();name=f[0];op=name.split('.')[0];w=int(f[1]);before=int(f[2],16);a=int(f[3],16);c=None if f[5]=='-' else int(f[5],16);is_trap=f[7]=='TRAP';r=int(f[8] if is_trap else f[7],16);after=int(f[-1],16)
   formcounts[(name,w,c if op in ('AAM','AAD') else -1)]+=1
   if is_trap:traps[op]+=1
   adjust=(a&15)>9 or bool(before&16)
   if op in ('DAA','DAS'):
    d=(6 if adjust else 0)+(0x60 if a>0x99 or before&1 else 0)
    record(op+'.undefined_OF',(after&0x800)==(alu_flags(a,d,8,op=='DAS')&0x800))
   elif op in ('AAA','AAS'):
    d=0x106 if adjust else 0
    record(op+'.undefined_OSZP',(after&0x8c4)==(alu_flags(a,d,16,op=='AAS')&0x8c4))
   elif op=='AAM':
    if is_trap:record('AAM.zero_trap',c==0 and r==a and after&FM==before&FM)
    else:record('AAM.undefined_OAC',(after&0x811)==0)
   elif op=='AAD':record('AAD.undefined_OAC',after&0x811==alu_flags(a&255,((a>>8)*c)&255,8)&0x811)
   elif op=='SALC':record('SALC.observed',r==(255 if before&1 else 0) and before&FM==after&FM)
   if op in ('PUSHA','PUSHAD','POPA','POPAD'):record('STACK.flags',before&FM==after&FM)
   if op in ('PUSH','POP'):
    record('SEGMENT.flags',before&FM==after&FM)
    if op=='PUSH' and w==32:record('PUSHSEG32.upper',r>>16==0)
   if op in ('INC','DEC'):record('INCDEC.CF',before&1==after&1)
   if op=='BOUND':record('BOUND.flags',before&FM==after&FM)
   if op=='INTO':record('INTO.flags',before&FM==after&FM)
   if op=='ARPL':record('ARPL.preserved',before&(FM^64)==after&(FM^64))
   if op=='LAHF':record('LAHF.flags',before&FM==after&FM)
   if op=='SAHF':record('SAHF.OF',before&0x800==after&0x800)
   if name=='SHL.compat':
    n=c&31
    record('SHL.undefined_AF',after&16==(before&16 if n==0 else 16))
    if n>1:record('SHL.undefined_OF',bool(after&0x800)==bool(((r>>31)^(after&1))&1))
report={'rules':{key:dict(counts[key],description=ruletext[key]) for key in ruletext},'forms':[{'name':n,'width':w,'immediate':i,'rows':v} for (n,w,i),v in sorted(formcounts.items())],'traps':dict(traps)}
(ROOT/'rule-counts.json').write_text(json.dumps(report,indent=2)+'\n')
lines=['# Measured rules on this exposed AMD EPYC 9V74','', 'These are empirical choices for this CPU, not portable architectural guarantees. Counts are recomputed from native result files. Undefined flags are never substituted into the raw output. CF/PF/AF/ZF/SF/OF mask: 0x08d5.','', '## BCD undefined flags and fault behavior','']
for key in ruletext:
 if key=='SALC.observed':lines+=['','## Extra legacy instructions and mode-control flags','']
 q=counts[key]
 lines += [f'- **{key}:** {ruletext[key]}. Supporting rows: **{q["supporting"]}**; contradicting rows: **{q["contradicting"]}**; applicable rows: {q["total"]}.']
lines += ['', '## Formula conventions','', 'For an n-bit addition r = (a + b) mod 2^n: OF = ((~(a XOR b) AND (a XOR r)) >> (n-1)) AND 1; AF = ((a XOR b XOR r) >> 4) AND 1; CF = (a + b) >= 2^n. For subtraction, OF = (((a XOR b) AND (a XOR r)) >> (n-1)) AND 1. SF is bit n-1, ZF means the entire n-bit intermediate is zero, PF is even parity of its low byte. These are formulas used for counting observations, not a claim that the CPU internally executes those exact micro-operations.', '', 'AAA/AAS adjustment is selected by (old AL & 15) > 9 OR input AF. Thus their measured undefined ZF/SF refer to the full 16-bit intermediate, not the final four-bit AL. AAM rules exclude immediate-zero fault rows. AAD includes immediate zero.','', 'PUSH/POP segment measurements use valid existing user selectors only: ES/SS/DS=0x2b, CS=0x23, FS/GS=0. POP CS has no valid legacy encoding and is intentionally absent. Segment loads are normal per-process instructions; FS/GS bases are restored before returning to libc.','', 'See bcd-CHECKS.txt, extra-CHECKS.txt and control-CHECKS.txt for separately executed C checks of defined result/flag semantics. The SALC equation is observational, because SALC is undocumented.']
(ROOT/'RULES.md').write_text('\n'.join(lines)+'\n')
if any(q['contradicting'] for q in counts.values()):raise SystemExit('Some candidate rules have counterexamples; read RULES.md and do not assert them as exact.')
print('All empirical rule counts computed from raw native rows; zero contradictions.')
