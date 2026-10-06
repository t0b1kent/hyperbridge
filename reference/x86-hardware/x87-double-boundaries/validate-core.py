#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import csv,hashlib,json
from collections import defaultdict
from pathlib import Path
b=Path(__file__).resolve().parent
rows=list(csv.DictReader((b/'raw/core-counts.csv').open()));g=defaultdict(dict)
for r in rows:g[(r['operation'],r['pc'],r['rounding'])][r['class']]=r
assert len(g)==84
for k,v in g.items():
 assert int(v['ALL']['random'])==1000000,k
 assert int(v['ALL']['total'])==int(v['ALL']['random'])+int(v['ALL']['edge']),k
 assert int(v['ALL']['edge'])==(3056 if k[1]=='24' else 17392),k
 for q in v.values():assert int(q['total'])==int(q['random'])+int(q['edge'])
examples=list(csv.DictReader((b/'raw/core-examples.csv').open()));seen=defaultdict(int)
for r in examples:
 k=(r['operation'],r['pc'],r['rounding'],r['class']);seen[k]+=1
 assert int(r['value_equal'])==int(r['x87_80_hex']==r['sse_as_80_hex'])
 assert int(r['exception_flags_equal'])==int(((int(r['fsw_after'],16)^int(r['mxcsr'],16))&63)==0)
 assert (int(r['mxcsr'],16)&0x8040)==0
 assert (int(r['mxcsr'],16)>>13)&3==['RN','RD','RU','RZ'].index(r['rounding'])
for k,n in seen.items():assert n<=20,k
for k,v in g.items():
 for cls,r in v.items():assert seen[(*k,cls)]==min(20,int(r['total'])),(k,cls)
checks={}
for name in ['core-counts.csv','core-examples.csv']:
 a=(b/'raw'/name).read_bytes();repeat=(b/'validation/core-repeat'/name).read_bytes();assert a==repeat
 checks[name]={'sha256':hashlib.sha256(a).hexdigest(),'bytes':len(a),'repeat_byte_identical':True}
result={'status':'PASS','configurations':len(g),'random_cases':sum(int(v['ALL']['random'])for v in g.values()),'total_cases':sum(int(v['ALL']['total'])for v in g.values()),'example_rows':len(examples),'source_sha256':hashlib.sha256((b/'core.c').read_bytes()).hexdigest(),'files':checks,'all_pc24_pc53_guarded_value_and_flag_failures':sum(int(v[c]['total'])for k,v in g.items()if k[1]!='64'for c in ['GUARDED_VALUE_MISMATCH','GUARDED_FLAGS_MISMATCH'])}
(b/'validation/core-validation.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
