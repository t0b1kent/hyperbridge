#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent structural/count and empirical-rule audit of captured class 9 rows."""
import collections, gzip, re, sys
path = sys.argv[1] if len(sys.argv)>1 else 'out-09-bmi.txt.gz'
count=collections.Counter(); rules=collections.Counter(); contradictions=collections.Counter()
with gzip.open(path,'rt',encoding='ascii') as f:
 for line in f:
  if line.startswith('#'): continue
  t=line.split(); assert len(t)==10 and t[6]=='->',line
  op=t[0];w=int(t[1]);pre=int(t[2],16);post=int(t[9],16)
  assert w in (32,64) and pre in (0x202,0xad7),line
  assert re.fullmatch('[0-9a-f]{4}',t[2]) and re.fullmatch('[0-9a-f]{4}',t[9]),line
  for k in (3,4,5,7,8):assert t[k]=='-' or re.fullmatch('[0-9a-f]{%d}'%(w//4),t[k]),line
  a=int(t[3],16);b=0 if t[4]=='-' else int(t[4],16);c=0 if t[5]=='-' else int(t[5],16);r=int(t[7],16)
  mask=(1<<w)-1; pf=4 if (r&255).bit_count()%2==0 else 0
  sz=(64 if r==0 else 0)|(128 if r>>(w-1) else 0)
  pred=pre
  if op in ('ANDN','BLSI','BLSMSK','BLSR','BZHI'):
   cf=0
   if op=='BLSI':cf=int(a!=0)
   if op in ('BLSMSK','BLSR'):cf=int(a==0)
   if op=='BZHI':cf=int((c&255)>=w)
   pred=0x202|sz|pf|cf
  elif op=='BEXTR':pred=0x202|16|pf|(64 if r==0 else 0)
  elif op in ('ADCX','ADOX'):
   bit=1 if op=='ADCX' else 2048
   carry=int(a+b+int(bool(pre&bit))>mask)
   pred=(pre&~bit)|(bit if carry else 0)
  count[op,w]+=1;rules[op]+=int(post==pred);contradictions[op]+=int(post!=pred)
ops=['ANDN','BEXTR','BLSI','BLSMSK','BLSR','BZHI','MULX','PDEP','PEXT','RORX','SARX','SHLX','SHRX','ADCX','ADOX']
for op in ops:
 for w in (32,64):
  n=44 if op in ('BLSI','BLSMSK','BLSR') else 22*256*2 if op=='RORX' else 22*22*2
  if op=='BEXTR':n+=(w+2)**2*22*2
  assert count[op,w]==n,(op,w,count[op,w],n)
 assert contradictions[op]==0,(op,contradictions[op])
 print('%s rows=%d rule_support=%d rule_contradictions=%d' % (op,sum(count[op,w] for w in (32,64)),rules[op],contradictions[op]))
assert sum(count.values())==286616
print('TOTAL rows=286616; expected count, operand widths, initial flags, empirical rule checks: PASS')
