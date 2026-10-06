#!/usr/bin/env python3
# Original MIT read-only result integrity/count verification; never edits data rows.
import collections,csv,gzip,hashlib,json,pathlib,re
p=pathlib.Path(__file__).resolve().parent
expected=collections.Counter()
for f in json.loads((p/'core-inventory.json').read_text()):expected[f['cls']]+=f['cases']
movement=list(csv.DictReader((p/'movement-manifest.tsv').open(),delimiter='\t'))
expected['movement']=sum(9*(7 if 'maskmov' in r['name'] else 2 if int(r['memory']) else 1) for r in movement)
gather=list(csv.DictReader((p/'gather-manifest.tsv').open(),delimiter='\t'))
expected['gather']=len(gather)*9*11
for cls in ['strings','crypto']:
 m=json.loads((p/(cls+'-manifest.json')).read_text());assert len(m['forms'])==m['expected_forms'];expected[cls]=sum(f['rows'] for f in m['forms']);assert expected[cls]==m['expected_rows_on_recorded_cpu']
expected['upper']=2*8*16
summary={};total_bytes=0
for cls,e in sorted(expected.items()):
 file=p/f'out-{cls}.txt.gz';h=hashlib.sha256();count=0;faults=0;uncompressed=0
 with gzip.open(file,'rb') as f:
  for b in f:
   h.update(b);uncompressed+=len(b)
   if b.startswith(b'#'):continue
   assert b.strip(),(cls,'blank data line');assert b' -> ' in b,(cls,b[:60]);prefix,result=b.split(b' -> ',1);tokens=prefix.split();assert len(tokens)==5,(cls,tokens);assert int(tokens[1]) in (8,16,32,64,128,256);assert re.fullmatch(rb'[0-9a-f]+|UNKNOWN',tokens[2]);assert re.fullmatch(rb'[0-9a-f]+|UNKNOWN',result.split()[0]);count+=1
   if b'TRAP(sig=' in b or re.search(rb'\bFAULT=(?:[1-9][0-9]*)\b',b) or b' FAULT=SEGV ' in b:faults+=1
 assert count==e,(cls,count,e)
 digest,name=(p/f'out-{cls}.sha256').read_text().split();assert name==f'out-{cls}.txt';assert digest==h.hexdigest(),cls
 raw_header=file.read_bytes()[:10];assert raw_header[:3]==bytes([31,139,8]);assert raw_header[4:8]==bytes(4),'gzip timestamp'
 total_bytes+=file.stat().st_size
 summary[cls]={'rows':count,'expected_rows':e,'raw_sha256':digest,'raw_bytes':uncompressed,'gzip_bytes':file.stat().st_size}
assert total_bytes<=60*1000*1000,total_bytes
summary['totals']={'rows':sum(expected.values()),'gzip_bytes':total_bytes,'budget_bytes':60*1000*1000,'forms_core':39375,'forms_movement':len(movement),'forms_gather':len(gather),'forms_strings':6144,'forms_crypto':4695,'upper_instructions':2}
(p/'validation-summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
print(json.dumps(summary['totals'],sort_keys=True))
