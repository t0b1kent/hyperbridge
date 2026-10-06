#!/usr/bin/env python3
# Original MIT canonical destination/source format verification, no row edits.
import collections,csv,gzip,json,re
from pathlib import Path
p=Path(__file__).resolve().parent.parent
forms={}
for r in csv.DictReader((p/'movement-manifest.tsv').open(),delimiter='\t'):forms[(r['name'],r['encoding'],int(r['immediate']))]=r
seen=collections.Counter();counts=collections.Counter()
for line in gzip.open(p/'out-movement.txt.gz','rt'):
 if line.startswith('#'):continue
 left,right=line.rstrip().split(' -> ');t=left.split();assert len(t)==5;tout=right.split();value=tout[0];md=dict(s.split('=',1) for s in tout[1:] if '=' in s)
 m=re.fullmatch(r'(.+?)(?:\[(\d+)\])?\.(SSE|VEX128|VEX256)\.([^.]+)\.p(\d+)',t[0]);assert m,t[0]
 key=(m[1],m[3],int(m[2]) if m[2] else -1);r=forms[key];seen[key]+=1
 root=r['name'].split('.')[0];root=root[1:] if root.startswith('v') else root;e=int(r['element_bytes']);w=int(r['width'])//8;mem=int(r['memory'])
 gp=(root in ('movmskps','movmskpd','pmovmskb') or '.xmm_to_gpr' in r['name'] or ((root.startswith('pextr') or root=='extractps') and mem==0))
 if gp:kind='GPR';n=4 if root in ('movmskps','movmskpd','pmovmskb') else 8 if e==8 else 4
 elif mem==2:
  kind='MEM';n=8 if root in ('movlps','movhps','movlpd','movhpd') else 16 if root in ('extractf128','extracti128') else e if root in ('movd','movq','movss','movsd','extractps') or root.startswith('pextr') else w
 else:kind='YMM';n=16 if root in ('extractf128','extracti128') else w
 assert md['DEST_KIND']==kind and int(t[1])==8*n,(key,t[1],kind,n)
 if kind=='GPR':
  assert t[2]==md['GPR_BEFORE_FULL64'][-2*n:] and value==md['GPR_AFTER_FULL64'][-2*n:]
 elif kind=='YMM':assert t[2]==md['YMM0_BEFORE'] and value==md['YMM0_AFTER'];assert len(value)==64
 else:
  a=int(md['ACCESSIBLE_BYTES'])
  if a<n:assert t[2]==value=='UNKNOWN';counts['unknown_full_memory_values']+=1
  else:assert t[2]==md['MEM_BEFORE'][-2*n:] and value==md['MEM_AFTER'][-2*n:]
 if t[2]!='UNKNOWN':assert re.fullmatch('[0-9a-f]+',t[2]) and re.fullmatch('[0-9a-f]+',value)
 for s in t[3:]:assert s in ('-','UNKNOWN') or re.fullmatch('[0-9a-f]+',s)
 assert all(len(md[k])==64 for k in ['YMM0_BEFORE','YMM0_AFTER','SOURCE_YMM1','INPUT_YMM2','MASK_AFTER'])
 a=int(md['ACCESSIBLE_BYTES']);assert md['MEM_BEFORE']==md['MEM_AFTER']=='-' if not a else len(md['MEM_BEFORE'])==len(md['MEM_AFTER'])==a*2
 counts[kind]+=1;counts['rows']+=1
for key,r in forms.items():assert seen[key]==9*(7 if 'maskmov' in r['name'] else 2 if int(r['memory']) else 1),(key,seen[key])
assert counts['rows']==174861
counts['gather_rows']=0
for line in gzip.open(p/'out-gather.txt.gz','rt'):
 if line.startswith('#'):continue
 left,right=line.split(' -> ');t=left.split();assert len(t)==5
 name=t[0].split('[')[0];encoded=int(re.search(r'\.VEX(128|256)',t[0])[1]);expect=128 if name.endswith(('qps','qd')) else encoded
 assert int(t[1])==expect and all(len(x)==64 for x in t[2:]);assert len(right.split()[0])==64 and len(right.split()[1])==64
 counts['gather_rows']+=1
assert counts['gather_rows']==6336
(p/'movement-format-validation.json').write_text(json.dumps(dict(counts),indent=2,sort_keys=True)+'\n')
print(json.dumps(dict(counts),sort_keys=True))
