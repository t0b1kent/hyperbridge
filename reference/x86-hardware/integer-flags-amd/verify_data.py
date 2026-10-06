#!/usr/bin/env python3
# Original MIT code. Audit existing bytes, never mutate observations.
import pathlib,gzip,hashlib,json,collections,re
P=pathlib.Path(__file__).resolve().parent
inv=json.loads((P/'core-inventory.json').read_text());classes=list(dict.fromkeys(f['cls'] for f in inv));summary={}
for cls in classes:
 z=P/f'out-{cls}.txt.gz';raw=gzip.decompress(z.read_bytes());linecounts=collections.Counter();before=collections.Counter();n=0;trap=0
 for line in raw.decode().splitlines():
  if line.startswith('#'):continue
  t=line.split();op,mode=t[0].split('.',1);w=int(t[1]);is_trap=t[7]=='TRAP';j=8 if is_trap else 7
  assert len(t)==j+3 and t[6]=='->',(cls,line)
  assert len(t[2])==4 and len(t[-1])==4
  assert int(t[2],16)==(0x202 if n%2==0 else 0xad7)
  for k in [3,4,5,j,j+1]:
   if t[k]!='-': assert len(t[k])==w//4,(cls,t[k],w)
  formc=int(t[5],16) if cls in ['shifts','rotates','double'] or op=='IMUL3' or mode.endswith('imm') else None
  linecounts[(op,w,mode,formc)]+=1;before[t[2]]+=1;n+=1;trap+=is_trap
 expected=collections.Counter()
 for f in inv:
  if f['cls']!=cls:continue
  op,w,mode,c=f['op'],f['w'],f['mode'],f['c'];key=(op,w,mode,c&((1<<w)-1) if c>=0 or op=='IMUL3' else None)
  if cls in ['shifts','rotates'] or op=='BSWAP16':rows=44
  elif cls=='bittest':rows=44 if c>=0 else 660+(968 if mode=='reg-reg' else 0)
  elif cls=='divide':rows=22**3*2+(21 if w==64 else 20)*4*3*2
  elif op in ['CMPXCHG','CMPXCHG8B','CMPXCHG16B']:rows=22**3*2
  else:rows=22**2*2
  expected[key]+=rows
 assert linecounts==expected, (cls,'exact per-form count mismatch',linecounts-expected,expected-linecounts)
 sha=hashlib.sha256(raw).hexdigest();record=(P/f'out-{cls}.sha256').read_text().split()[0];assert sha==record
 summary[cls]={'forms':sum(f['cls']==cls for f in inv),'rows':n,'traps':trap,'before_flags':dict(before),'gzip_bytes':z.stat().st_size,'sha256_raw':sha,'sha256_gzip':hashlib.sha256(z.read_bytes()).hexdigest(),'per_form_counts':'all exact; independent expected products','field_widths':'all exact'}
bmi=P/'out-09-bmi.txt.gz';bmi_raw=gzip.decompress(bmi.read_bytes());assert hashlib.sha256(bmi_raw).hexdigest()==(P/'out-09-bmi.sha256').read_text().split()[0]
summary['09-bmi']={'rows':sum(not l.startswith(b'#') for l in bmi_raw.splitlines()),'sha256_raw':hashlib.sha256(bmi_raw).hexdigest(),'gzip_bytes':bmi.stat().st_size,'sha256_gzip':hashlib.sha256(bmi.read_bytes()).hexdigest(),'detail':'bmi_RULE_CHECKS.txt'}
summary['total_rows']=sum(v['rows'] for v in summary.values() if isinstance(v,dict));summary['total_result_gzip_bytes']=sum(v['gzip_bytes'] for v in summary.values() if isinstance(v,dict));assert summary['total_result_gzip_bytes']<=60_000_000
(P/'validation-summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2))
