#!/usr/bin/env python3
# Original MIT code. Reads real observations, never edits result bytes.
import gzip,json,collections,pathlib,re
P=pathlib.Path(__file__).resolve().parent
flags={'CF':0,'PF':2,'AF':4,'ZF':6,'SF':7,'OF':11}
classes=['shifts','rotates','double','multiply','divide','bitscan','bittest','logic','misc']
counts=collections.Counter();forms=collections.defaultdict(set);stats={};extras={};before=collections.Counter();rawsha={}
def arithmetic(a,b,w,subtract=False):
 mask=(1<<w)-1;r=(a-b if subtract else a+b)&mask
 cf=int(a<b) if subtract else int(a+b>mask)
 of=(((a^b)&(a^r)) if subtract else ((~(a^b)&(a^r))))>>(w-1)&1
 return cf|int((r&255).bit_count()%2==0)*4|((a^b^r)&16)|int(r==0)*64|((r>>(w-1))&1)*128|of*2048
def tally(key,candidates,actual):
 d=stats.setdefault(key,{'n':0,'candidate':collections.Counter()});d['n']+=1
 for name,value in candidates.items():d['candidate'][name]+=int(value==actual)
def extra(key,value):
 d=extras.setdefault(key,[0,0]);d[0]+=bool(value);d[1]+=not bool(value)
for cls in classes:
 with gzip.open(P/f'out-{cls}.txt.gz','rt') as f:
  for line in f:
   if line.startswith('#'):continue
   t=line.split();op,mode=t[0].split('.',1);w=int(t[1]);fb=int(t[2],16);a=int(t[3],16);b=int(t[4],16);c=None if t[5]=='-' else int(t[5],16);trap=t[7]=='TRAP';j=8 if trap else 7;r=int(t[j],16);r2=None if t[j+1]=='-' else int(t[j+1],16);fa=int(t[j+2],16)
   if op=='POPCNT':extra((op,w,mode,'ZF = (B == 0); CF=PF=AF=SF=OF=0'),(fa&0x8d5)==(64 if b==0 else 0))
   if op=='CMPXCHG':extra((op,w,mode,'CF/PF/AF/ZF/SF/OF equal subtraction flags of C - A (accumulator - old destination)'),(fa&0x8d5)==arithmetic(c,a,w,True))
   if op=='XADD':extra((op,w,mode,'CF/PF/AF/ZF/SF/OF equal addition flags of A + B'),(fa&0x8d5)==arithmetic(a,b,w))
   if op in ['CMPXCHG8B','CMPXCHG16B']:extra((op,w,mode,'ZF = (A == B); CF/PF/AF/SF/OF preserved'),(fa&0x8d5)==((fb&0x895)|(64 if a==b else 0)))
   counts[op]+=1;forms[op].add((w,mode,c if cls in ['shifts','rotates','double'] or op=='IMUL3' or mode.endswith('imm') else None));before[fb]+=1
   mask=(1<<w)-1;n=(c or 0)&(63 if w==64 else 31);cond='all executions';unknown=[]
   if cls=='shifts':
    cond='masked count = 0' if not n else 'masked count = 1' if n==1 else 'masked count > 1, less than width' if n<w else 'masked count >= width'
    if n:unknown=['AF']+(['OF'] if n>1 else [])+(['CF'] if n>=w and op!='SAR' else [])
   elif cls=='rotates':
    cond='masked count = 0' if not n else 'masked count = 1' if n==1 else 'masked count > 1'
    if n>1:unknown=['OF']
   elif cls=='double':
    cond='masked count = 0' if not n else 'masked count = 1' if n==1 else 'masked count = width' if n==w else '1 < masked count < width' if n<w else 'masked count > width'
    if n:unknown=['AF']+(['OF'] if n>1 else [])
    if n>w:unknown=list(flags)
    if w==16 and n>w:
     if op=='SHLD':v=(a<<16)|b;rr=((v<<n)|(v>>(32-n)))>>16&mask
     else:v=(b<<16)|a;rr=((v>>n)|(v<<(32-n)))&mask
     extra((op,w,mode,'REJECTED candidate: result equals '+('high16(ROL32((A << 16) | B, n))' if op=='SHLD' else 'low16(ROR32((B << 16) | A, n))')),r==rr)
     k=n-16; rr=(((b<<k)|(b>>(16-k))) if op=='SHLD' else ((b>>k)|(b<<(16-k))))&mask
     extra((op,w,mode,'for masked count 17..31, undefined result equals '+('ROL16(B, n - 16)' if op=='SHLD' else 'ROR16(B, n - 16)')+' (independent of A)'),r==rr)
   elif cls=='multiply':unknown=['PF','AF','ZF','SF']
   elif cls=='divide':
    cond='trap context' if trap else 'successful division';unknown=list(flags)
    extra((op,w,mode,cond+': '+('REJECTED candidate: ' if not trap else '')+'arithmetic flags preserved: (after & 0x8d5) = (before & 0x8d5)'),(fa&0x8d5)==(fb&0x8d5))
   elif cls=='bitscan':
    if op in ['BSF','BSR']:
     cond='source = 0' if b==0 else 'source != 0';unknown=['CF','PF','AF','SF','OF']
     if not b:extra((op,w,mode,'zero source leaves destination unchanged: R1 = A'),r==a)
    elif op in ['TZCNT','LZCNT']:unknown=['PF','AF','SF','OF']
   elif cls=='bittest':unknown=['PF','AF','SF','OF']
   elif cls=='logic':unknown=['AF']
   elif op=='BSWAP16':extra((op,w,mode,'undefined 16-bit result is zero: R1 = 0'),r==0);extra((op,w,mode,'arithmetic flags preserved'),(fa&0x8d5)==(fb&0x8d5))
   for flag in unknown:
    candidates={'0':0,'1':1,'preserved (same bit in FLAGS_before)':(fb>>flags[flag])&1}
    if flag=='PF':candidates['even parity of R1 low byte']=int((r&255).bit_count()%2==0)
    if flag=='SF':candidates['MSB(R1)']=(r>>(w-1))&1
    if flag=='ZF':candidates['R1 == 0']=int(r==0)
    if flag=='CF':
     candidates['LSB(R1)']=r&1;candidates['MSB(R1)']=(r>>(w-1))&1
     if cls=='shifts':candidates['last shifted bit of zero-extended input (0 beyond width)']=(0 if n>w else ((a>>(w-n))&1) if op in ['SHL','SAL'] else ((a>>(n-1))&1))
    if flag=='OF':
     candidates['CF_after']=fa&1
     candidates['MSB(A) XOR MSB(R1)']=((a^r)>>(w-1))&1
     candidates['MSB(R1) XOR CF_after']=((r>>(w-1))^(fa&1))&1
     candidates['top two bits of A XOR']=((a>>(w-1))^(a>>(w-2)))&1
     candidates['top two bits of R1 XOR']=((r>>(w-1))^(r>>(w-2)))&1
     candidates['MSB(A) XOR CF_before']=((a>>(w-1))^(fb&1))&1
    tally((op,w,mode,cond,flag),candidates,(fa>>flags[flag])&1)
lines=['# Measured integer rules on this machine','','These are empirical observations on the CPU named in MACHINE.txt, not architectural guarantees. Every supporting/contradicting count below is computed from the unmodified native rows by analyze_core.py. Counts include both initial flag patterns and duplicate labeled input positions. A zero contradiction count applies only to the stated sample.','','Notation: n is COUNT masked with 31 (8/16/32-bit operands) or 63 (64-bit operands); MSB/LSB refer to the operand width. `preserved` compares the same flag before and after. Defined semantics are independently checked by the C model in core.c; exact check counts are in each class validation file.','','## Per-command coverage and rules','']
for op in counts:
 lines+=['### '+op,f'{counts[op]:,} measured rows; {len(forms[op]):,} width/form/immediate configurations.','']
 for key,(yes,no) in extras.items():
  if key[0]==op:lines.append(f'- {key[1]}-bit {key[2]}: {key[3]}. Supporting {yes}; contradicting {no}.')
 last=None;found=False
 for key,d in stats.items():
  if key[0]!=op:continue
  found=True;_,w,mode,cond,fl=key;head=(w,mode,cond)
  if head!=last:lines.append(f'- {w}-bit {mode}, {cond} ({d["n"]} rows):');last=head
  perfect=[name for name,n in d['candidate'].items() if n==d['n']]
  if perfect:lines.append(f'  - {fl} = {"; also matches ".join(perfect)}. Supporting {d["n"]}; contradicting 0.')
  else:
   name,n=max(d['candidate'].items(),key=lambda kv:kv[1]);lines.append(f'  - {fl}: no tested simple rule fits all rows. Best candidate `{name}`: supporting {n}; contradicting {d["n"]-n}. See core-rule-counts.json for every candidate.')
 if not found and op!='BSWAP16' and not any(k[0]==op for k in extras):lines.append('- No architecturally undefined arithmetic flags in this instruction/form; see the C-defined-semantics validation counts. All its emitted rows are checked by the applicable C model.')
 lines.append('')
lines+=['## Class 9 and class 11','', 'See bmi_REPORT.md for class 9 measured rules and legacy_REPORT.md for the native i386 execution blocker. No class 11 result or CPU rule is fabricated.']
bmi=(P/'bmi_REPORT.md').read_text()
lines+=['','## Class 9 measured rules (included here)','',bmi.split('## Measured rules, with support and contradiction counts',1)[1]]
(P/'RULES.md').write_text('\n'.join(lines)+'\n')
(P/'core-rule-counts.json').write_text(json.dumps({'before_flag_counts':{f'{k:04x}':v for k,v in before.items()},'rows_by_instruction':dict(counts),'rule_candidates':[{'op':k[0],'width':k[1],'mode':k[2],'condition':k[3],'flag':k[4],'rows':v['n'],'counts':{a:{'supporting':b,'contradicting':v['n']-b} for a,b in v['candidate'].items()}} for k,v in stats.items()],'result_rules':[dict(op=k[0],width=k[1],mode=k[2],rule=k[3],supporting=v[0],contradicting=v[1]) for k,v in extras.items()]},indent=2)+'\n')
(P/'core-counts.json').write_text(json.dumps({'total_rows':sum(counts.values()),'rows_by_instruction':dict(counts),'forms_by_instruction':{k:len(v) for k,v in forms.items()}},indent=2)+'\n')
print(json.dumps(dict(counts),indent=2));print('Total rows',sum(counts.values()),'measured rule groups',len(stats))
