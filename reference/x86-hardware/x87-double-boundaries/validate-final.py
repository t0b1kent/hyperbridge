#!/usr/bin/env python3
# SPDX-License-Identifier: MIT. Structural/hash QA; never computes FP answers.
import csv,json,hashlib
from pathlib import Path
from collections import defaultdict,Counter
b=Path(__file__).resolve().parent
results={};total=0;random=0
for name,expect,edges in [('core',84,None),('chains',112,400),('extended',48,256),('remainder',24,361),('scale',12,1920),('format',48,1937)]:
 rows=list(csv.DictReader((b/'raw'/f'{name}-counts.csv').open()));keys=['family','length','pc','rounding']if name=='chains'else['operation','pc','rounding'];g=defaultdict(dict)
 for r in rows:g[tuple(r[k]for k in keys)][r['class']]=r
 assert len(g)==expect,(name,len(g))
 examples=list(csv.DictReader((b/'raw'/f'{name}-examples.csv').open()));hits=Counter(tuple(r[k]for k in keys)+(r['class'],)for r in examples)
 for key,d in g.items():
  expected_edges=3056 if name=='core'and key[1]=='24'else 17392 if name=='core'else edges
  assert int(d['ALL']['random'])==1000000
  assert int(d['ALL']['edge'])==expected_edges,(name,key,d['ALL'])
  for cls,r in d.items():
   assert int(r['total'])==int(r['random'])+int(r['edge'])
   assert hits[(*key,cls)]==min(20,int(r['total'])),(name,key,cls,hits[(*key,cls)],r['total'])
 hashes={}
 for kind in ['counts','examples']:
  fn=f'{name}-{kind}.csv';raw=(b/'raw'/fn).read_bytes();again=(b/'validation'/f'{name}-repeat'/fn).read_bytes();assert raw==again,fn
  hashes[fn]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'byte_identical_repeat':True}
 n=sum(int(x['ALL']['total'])for x in g.values());total+=n;random+=expect*1000000
 results[name]={'configurations':expect,'cases':n,'random':expect*1000000,'examples':len(examples),'files':hashes}
rows=list(csv.DictReader((b/'raw/aux-summary.csv').open()));assert len(rows)==372
for r in rows:
 n=int(r['random_count'])+int(r['edge_count']);assert int(r['random_count'])==1000000 and int(r['edge_count'])==1937
 assert int(r['compared'])+int(r['unsupported'])==n
 assert int(r['value_equal'])+int(r['value_diff'])==int(r['compared'])
 assert int(r['value_and_exception_equal'])<=int(r['value_equal'])
auxc=list(csv.DictReader((b/'raw/aux-classes.csv').open()));auxe=list(csv.DictReader((b/'raw/aux-examples.csv').open()));hits=Counter((r['operation'],r['pc'],r['rc'],r['class'])for r in auxe)
for r in auxc:
 assert int(r['examples_saved'])==min(20,int(r['count']))
 assert hits[(r['operation'],r['pc'],r['rc'],r['class'])]==int(r['examples_saved'])
hashes={}
for kind in ['summary','classes','examples']:
 fn=f'aux-{kind}.csv';a=(b/'raw'/fn).read_bytes();again=(b/'validation/aux-repeat'/fn).read_bytes();assert a==again
 hashes[fn]={'sha256':hashlib.sha256(a).hexdigest(),'bytes':len(a),'byte_identical_repeat':True}
auxn=sum(int(r['random_count'])+int(r['edge_count'])for r in rows);total+=auxn;random+=372000000
results['aux']={'configurations':372,'cases':auxn,'random':372000000,'examples':len(auxe),'files':hashes}
assert random==700000000 and total==701961852,(random,total)
for fn,repeat in [('double-rounding-witnesses.csv','double-rounding-repeat.csv'),('extended-targeted.csv','extended-targeted-repeat.csv')]:
 a=(b/'raw'/fn).read_bytes();other=(b/'validation'/repeat).read_bytes();assert a==other
results['status']='PASS';results['random_trials_per_complete_suite']=random;results['total_cases_per_complete_suite']=total
results['source_hashes']={p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(b.glob('*.c'))}
(b/'validation/FINAL-VALIDATION.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps({'status':'PASS','configurations':700,'random_trials':random,'cases':total,'all_seven_suites_repeat_byte_identical':True},indent=2))
