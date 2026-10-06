# SPDX-License-Identifier: MIT
import csv,gzip,json,pathlib,collections,hashlib
root=pathlib.Path(__file__).resolve().parent;out=root.parent/'results/0035-write-fault-atomicity-hardware/amd-epyc-9v74-linux';counts=collections.Counter();errors=[]
forms={x['name']:x for x in json.loads((root.parent/'probe35/forms.json').read_text())}
for group in ['scalar','rmw','vector']:
 raw={}
 for line in gzip.open(out/f'{group}.run1.jsonl.gz','rt'):
  r=json.loads(line);raw[(r['form'],r['layout'],r['cross_offset'],r['continuation'])]=r
 seen=set()
 for row in csv.DictReader((out/f'{group}.csv').open()):
  key=(row['form'],row['layout'],int(row['cross_offset_bytes_in_first_page']));counts['csv_rows']+=1
  if key in seen:errors.append(['duplicate',key])
  seen.add(key)
  if row['status'].startswith('N/A'):
   counts['na_rows']+=1;f=forms[row['form']]
   if group!='vector' or f.get('alignment')!=16 or not row['layout'].startswith('cross') or not 1<=key[2]<16:errors.append(['na',key])
   continue
  counts['measured_rows']+=1
  for c in (1,2,3):
   r=raw[(*key,c)]
   for attr in ['final_pages','final_regs']:
    field=f'c{c}_{attr}'
    if row[field]=='N/A':
     if r['status']==0:errors.append(['false-na',key,field])
    elif json.loads(row[field])!=r[attr]:errors.append(['cell-mismatch',key,field])
   faultfield='faults_c1' if c==1 else f'c{c}_faults';ff=json.loads(row[faultfield])
   expected=[{k:v for k,v in f.items() if k!='fpstate'} for f in r['faults']]
   observed=[{k:v for k,v in f.items() if k!='six_flags'} for f in ff]
   if observed!=expected:errors.append(['fault-mismatch',key,c])
  if json.loads(row['initial_pages'])!=raw[(*key,1)]['initial']:errors.append(['initial',key])
  if row['encoding_hex']!=forms[key[0]]['code']:errors.append(['encoding',key])
 if (out/f'{group}.csv').read_bytes()!=gzip.open(out/f'{group}.csv.gz','rb').read():errors.append(['csv-gzip',group])
 if len(seen)!=len(raw)//3+(300 if group=='vector' else 0):errors.append(['row-count',group])
result={'pass':not errors,'counts':dict(counts),'errors':errors};(root/'CSV-VALIDATION.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2));raise SystemExit(bool(errors))
