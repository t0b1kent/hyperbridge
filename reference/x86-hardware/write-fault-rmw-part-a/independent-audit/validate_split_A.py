# SPDX-License-Identifier: MIT
import csv,json,pathlib,collections
root=pathlib.Path(__file__).resolve().parent;out=root.parent/'results/0035-write-fault-atomicity-hardware/amd-epyc-9v74-linux'
base={(r['form'],r['layout'],r['cross_offset_bytes_in_first_page']):r for r in csv.DictReader((out/'rmw.csv').open())}
rows=list(csv.DictReader((out/'split-lock-first.csv').open()));errors=[];core=set();measured=0;na=0
expected=set()
for w in (16,32,64):
 for form in [f'add_reg_{w}_lock',f'xadd_reg_{w}_lock',f'xchg_reg_{w}_nolock',f'cmpxchg_match_{w}_lock',f'cmpxchg_mismatch_{w}_lock',f'inc_{w}_lock',f'dec_{w}_lock',f'bts_imm3_{w}_lock']:
  for layout in ('cross_rw_ro','cross_ro_rw'):
   for offset in range(1,w//8):expected.add((form,layout,str(offset)))
for row in rows:
 key=tuple(row[x] for x in ['form','layout','cross_offset_bytes_in_first_page'])
 if row['status']=='measured':
  measured+=1
  for field in ['encoding_hex','faults_c1','initial_pages','c2_faults','c2_handler_overwrite','c2_final_pages','c2_final_regs','c2_six_flags','c2_equals_original_clean','full_context_source']:
   if row[field]!=base[key][field]:errors.append(['copy-mismatch',key,field])
  if row['requested_core_A']=='True':core.add(key)
  if row['repeat_identical']!='True':errors.append(['repeat',key])
  ff=json.loads(row['c2_faults'])
  if len(ff)!=1 or ff[0]['trap']!=14 or ff[0]['partial_write'] or ff[0]['gregs']['rip']!='code+0':errors.append(['fault',key])
 else:
  na+=1
  if row['geometry']!='cacheline_only_inside_one_page' or not row['status'].startswith('N/A'):errors.append(['na',key])
if core!=expected:errors.append(['core-grid',{'missing':sorted(expected-core),'extra':sorted(core-expected)}])
if (measured,na)!=(264,264):errors.append(['counts',measured,na])
result={'pass':not errors,'measured_rows':measured,'na_rows':na,'requested_core_measured_rows':len(core),'core_coverage_complete':core==expected,'errors':errors};(root/'SPLIT-A-VALIDATION.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2));raise SystemExit(bool(errors))
