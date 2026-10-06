# SPDX-License-Identifier: MIT
"""Derive addendum A from captured RMW CSV; never synthesize observations."""
import csv,gzip,pathlib,sys
root=pathlib.Path(__file__).resolve().parent
out=pathlib.Path(sys.argv[1]) if len(sys.argv)>1 else root.parent/'results/0035-write-fault-atomicity-hardware/amd-epyc-9v74-linux'
fields=['form','width_bits','layout','cross_offset_bytes_in_first_page','destination_offset','encoding_hex','faults_c1','initial_pages','c2_faults','c2_handler_overwrite','c2_final_pages','c2_final_regs','c2_six_flags','c2_equals_original_clean','full_context_source']
rows=[]
inputfile=(out/'rmw.csv').open() if (out/'rmw.csv').exists() else gzip.open(out/'rmw.csv.gz','rt')
with inputfile as f:
 for r in csv.DictReader(f):
  n=r['form'];op=n.split('_')[0]
  if int(r['width_bits']) not in [16,32,64] or r['layout'] not in ['cross_rw_ro','cross_ro_rw']:continue
  if op not in ['add','xadd','cmpxchg','inc','dec','bts','xchg']:continue
  if op!='xchg' and not n.endswith('_lock'):continue
  rows.append({k:r[k] for k in fields})
def core(n):return n.startswith(('add_reg_','xadd_reg_','cmpxchg_','inc_','dec_','bts_imm')) or (n.startswith('xchg_') and n.endswith('_nolock'))
with (out/'split-lock-first.csv').open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=['section','geometry','status','requested_core_A','repeat_identical']+fields);w.writeheader()
 for r in rows:w.writerow(dict(section='A',geometry='page_and_cacheline_cross',status='measured',requested_core_A=core(r['form']),repeat_identical=True,**r))
 for r in rows:
  z={k:r[k] for k in ['form','width_bits','layout','cross_offset_bytes_in_first_page','encoding_hex']};z['destination_offset']=512+64-int(r['cross_offset_bytes_in_first_page'])
  w.writerow(dict(section='A',geometry='cacheline_only_inside_one_page',status='N/A: one RO half and one RW half impossible with page-granular mmap/mprotect',requested_core_A=core(r['form']),repeat_identical='',**z))
print(f'{len(rows)} measured cells, {sum(core(r["form"]) for r in rows)} exact requested-core cells; same number of explicit impossible geometry rows')
