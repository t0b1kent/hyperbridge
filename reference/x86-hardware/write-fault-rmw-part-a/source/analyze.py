# SPDX-License-Identifier: MIT
"""Validate captured rows, reconstruct snapshots, emit three CSVs and measured counts."""
import csv,gzip,hashlib,json,pathlib,sys,collections,itertools
root=pathlib.Path(__file__).resolve().parent
out=pathlib.Path(sys.argv[1]) if len(sys.argv)>1 else root.parent/'results/0035-write-fault-atomicity-hardware/amd-epyc-9v74-linux'
forms={f['name']:f for f in json.loads((root/'forms.json').read_text())}
def load(group,run):
 with gzip.open(out/f'{group}.run{run}.jsonl.gz','rt') as f:
  yield from map(json.loads,f)
def unpack(p):
 if p is None:return None
 b=bytearray.fromhex(p['fill'])*p['size']
 for off,h in p['patches']:b[off:off+len(h)//2]=bytes.fromhex(h)
 return b[:8192 if p['page2_mapped'] else 4096]
def six(regs):
 v=int(regs['rflags'],16)
 return {k:(v>>b)&1 for k,b in [('CF',0),('PF',2),('AF',4),('ZF',6),('SF',7),('OF',11)]}
def faultsmall(f):
 return {k:v for k,v in f.items() if k!='fpstate'}|{'six_flags':six(f['gregs'])}
def j(x):return json.dumps(x,separators=(',',':'),sort_keys=True)
summary={'groups':{},'integrity_errors':[],'repeat_identical':{},'notes':[]}
examples=[]; allc1=[]
for group in ['scalar','rmw','vector']:
 runs=[]
 for run in [1,2]:
  h=hashlib.sha256()
  with gzip.open(out/f'{group}.run{run}.jsonl.gz','rb') as f:
   for b in iter(lambda:f.read(1<<20),b''):h.update(b)
  runs.append(h.hexdigest())
 summary['repeat_identical'][group]={'run1_sha256_uncompressed':runs[0],'run2_sha256_uncompressed':runs[1],'identical':runs[0]==runs[1]}
 rr=list(load(group,1));bycell=collections.defaultdict(list)
 for r in rr:bycell[(r['form'],r['layout'],r['cross_offset'])].append(r)
 c1=[r for r in rr if r['continuation']==1];allc1.extend(c1)
 expected=set()
 for form in forms.values():
  if form['group']!=group:continue
  for lay in ['inside_rw','cross_rw_rw','cross_rw_ro','cross_ro_rw','cross_ro_ro','cross_rw_unmapped','inside_ro']:
   footprint=form['width']*form.get('count',1)
   if lay.startswith('cross') and group=='vector' and form.get('alignment'):continue
   for off in range(1,footprint) if lay.startswith('cross') else [0]:expected.add((form['name'],lay,off))
 missing=expected-set(bycell);extra=set(bycell)-expected
 if missing or extra:summary['integrity_errors'].append(['coverage',group,sorted(missing),sorted(extra)])
 g={'forms':len({r['form'] for r in rr}),'cells':len(c1),'continuation_rows':len(rr),'completion_rows':sum(r['status']==0 for r in rr),'terminal_traps':dict(collections.Counter(str(r['terminal_trap']) for r in rr if r['status']==2)),'fault_cells_c1':sum(bool(r['faults']) for r in c1),'faults_c1':len([f for r in c1 for f in r['faults']]),'partial_cells_c1':sum(any(f['partial_write'] for f in r['faults']) for r in c1),'clean_reference_c1_c3_comparisons':sum(r['status']==0 and r['continuation'] in [1,3] for r in rr),'clean_reference_c1_c3_mismatches':sum(r['status']==0 and r['continuation'] in [1,3] and not r['clean_equal'] for r in rr),'c2_differs_from_original_clean':sum(r['status']==0 and r['continuation']==2 and not r['clean_equal'] for r in rr),'c3_memory_differs_from_first':sum(r['status']==0 and r['continuation']==3 and r['first_pages']!=r['final_pages'] for r in rr),'fault_traps_c1':dict(collections.Counter(str(f['trap']) for r in c1 for f in r['faults']))}
 summary['groups'][group]=g
 fields=['form','width_bits','footprint_bytes','layout','cross_offset_bytes_in_first_page','destination_offset','status','expected_legal','encoding_hex','faults_c1','partial_c1','initial_pages','c1_final_pages','c1_final_regs','c1_six_flags','c1_equals_one_clean','c2_faults','c2_handler_overwrite','c2_final_pages','c2_final_regs','c2_six_flags','c2_equals_original_clean','c3_faults','c3_first_pages','c3_first_regs','c3_final_pages','c3_final_regs','c3_six_flags','c3_equals_two_clean','full_context_source']
 with (out/f'{group}.csv').open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
  for key,rs in bycell.items():
   rs=sorted(rs,key=lambda r:r['continuation'])
   if [r['continuation'] for r in rs]!=[1,2,3]:summary['integrity_errors'].append(['continuations',key]);continue
   a,b,c=rs;form=forms[a['form']];row=dict(form=a['form'],width_bits=a['width']*8,footprint_bytes=a['width']*form.get('count',1),layout=a['layout'],cross_offset_bytes_in_first_page=a['cross_offset'],destination_offset=a['destination_offset'],status='completed' if a['status']==0 else f'terminal_trap_{a["terminal_trap"]}',expected_legal=a['expected_legal'],encoding_hex=form['code'],faults_c1=j([faultsmall(f) for f in a['faults']]),partial_c1=any(f['partial_write'] for f in a['faults']),initial_pages=j(a['initial']),c1_final_pages=j(a['final_pages']),c1_final_regs=j(a['final_regs']) if a['status']==0 else 'N/A',c1_six_flags=j(six(a['final_regs'])) if a['status']==0 else 'N/A',c1_equals_one_clean=a['clean_equal'] if a['status']==0 else 'N/A',c2_faults=j([faultsmall(f) for f in b['faults']]),c2_handler_overwrite='0x3c across full destination footprint after mapping/protection repair, before sigreturn' if b['status']==0 and b['faults'] else 'not performed',c2_final_pages=j(b['final_pages']),c2_final_regs=j(b['final_regs']) if b['status']==0 else 'N/A',c2_six_flags=j(six(b['final_regs'])) if b['status']==0 else 'N/A',c2_equals_original_clean=b['clean_equal'] if b['status']==0 else 'N/A',c3_faults=j([faultsmall(f) for f in c['faults']]),c3_first_pages=j(c['first_pages']),c3_first_regs=j(c['first_regs']) if c['first_completed'] else 'N/A',c3_final_pages=j(c['final_pages']),c3_final_regs=j(c['final_regs']) if c['status']==0 else 'N/A',c3_six_flags=j(six(c['final_regs'])) if c['status']==0 else 'N/A',c3_equals_two_clean=c['clean_equal'] if c['status']==0 else 'N/A',full_context_source=f'{group}.run1.jsonl.gz: matching form/layout/cross_offset/continuation')
   w.writerow(row)
   for r in rs:
    if r['wait_status']!=0 or not r['done'] or r['status'] not in [0,2] or (r['status']==2 and r['terminal_trap'] not in [6,13,17]):summary['integrity_errors'].append(['child',key,r['continuation'],r['wait_status'],r['status']])
    for fault in r['faults']:
     if fault['gregs']['rip']!='code+0':summary['integrity_errors'].append(['rip',key,r['continuation'],fault['gregs']['rip']])
     if len(bytes.fromhex(fault['fpstate']))!=fault['fpstate_size']:summary['integrity_errors'].append(['fp_size',key])
     # Verify sparse patches are ordered, in bounds, nonoverlapping, and contain no fill bytes.
     for p in [fault['pages'],r['initial'],r['first_pages'],r['final_pages'],r['clean_pages']]:
      if p is None:continue
      prev=0;lim=8192 if p['page2_mapped'] else 4096
      for off,h in p['patches']:
       if off<prev or off+len(h)//2>lim or 0x11 in bytes.fromhex(h):summary['integrity_errors'].append(['sparse',key])
       prev=off+len(h)//2
    if r['continuation']==1 and any(x['partial_write'] for x in r['faults']) and not form.get('string'):summary['integrity_errors'].append(['nonstring_partial',key])
  # Explicit N/A rows for aligned vectors: cannot cross a 4 KiB page legally.
  if group=='vector':
   for form in forms.values():
    if form['group']=='vector' and form.get('alignment'):
     for lay in ['cross_rw_rw','cross_rw_ro','cross_ro_rw','cross_ro_ro','cross_rw_unmapped']:
      for off in range(1,form['width']):
       w.writerow(dict(form=form['name'],width_bits=form['width']*8,footprint_bytes=form['width'],layout=lay,cross_offset_bytes_in_first_page=off,destination_offset=4096-off,status='N/A: 16-byte-aligned 16-byte operand cannot cross a 4096-byte boundary',expected_legal=True,encoding_hex=form['code']))
 with (out/f'{group}.csv').open('rb') as src,(out/f'{group}.csv.gz').open('wb') as dest:
  with gzip.GzipFile(filename='',mode='wb',fileobj=dest,mtime=0) as gz:
   for b in iter(lambda:src.read(1<<20),b''):gz.write(b)
# Row-derived detailed rule denominators.
summary['rules']={}
for label,pred in [
 ('nonrep_scalar_pf',lambda r:r['group']=='scalar' and not r['form'].startswith('rep_')),
 ('rmw_pf',lambda r:r['group']=='rmw'),('vector_pf',lambda r:r['group']=='vector'),
 ('simple_scalar_cross_second_fault',lambda r:r['group']=='scalar' and not r['form'].startswith('rep_') and r['layout']=='cross_rw_ro'),
 ('rep_pf',lambda r:r['form'].startswith('rep_')),
 ('cmpxchg16b_cross',lambda r:r['form'].startswith('cmpxchg16b') and r['layout'].startswith('cross')),
 ('invalid_lock',lambda r:not r['expected_legal']),
 ('legal_lock_or_xchg_cross',lambda r:r['expected_legal'] and ('_lock' in r['form'] or r['form'].startswith('xchg_')) and r['layout'].startswith('cross') and not r['form'].startswith('cmpxchg16b'))]:
 rows=[r for r in allc1 if pred(r)];fs=[f for r in rows for f in r['faults']];pf=[f for f in fs if f['trap']==14]
 summary['rules'][label]={'cells':len(rows),'pf_faults':len(pf),'pf_partial':sum(f['partial_write'] for f in pf),'trap_counts':dict(collections.Counter(str(f['trap']) for f in fs)),'rip_at_instruction_start':sum(f['gregs']['rip']=='code+0' for f in fs),'all_faults':len(fs)}
summary['partial_form_counts']=dict(collections.Counter(r['form'] for r in allc1 if any(f['partial_write'] for f in r['faults'])))
summary['error_code_counts']=dict(collections.Counter(str(f['error']) for r in allc1 for f in r['faults'] if f['trap']==14))
summary['maskmov_masks']={}
for name in [x for x in forms if x.startswith('maskmov')]:
 rr=[r for r in allc1 if r['form']==name];summary['maskmov_masks'][name]={'cells':len(rr),'fault_cells':sum(bool(r['faults']) for r in rr),'protected_cells':sum(r['layout'] not in ['inside_rw','cross_rw_rw'] for r in rr),'protected_no_fault':sum(not r['faults'] and r['layout'] not in ['inside_rw','cross_rw_rw'] for r in rr)}
(out/'SUMMARY.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
print(json.dumps(summary,indent=2,sort_keys=True))
if summary['integrity_errors'] or not all(x['identical'] for x in summary['repeat_identical'].values()):sys.exit(1)
