#!/usr/bin/env python3
"""Emit a review queue from the ACTUAL code generator in a user's checkout.
This is conservative source triage, NOT a proof that a check dominates all exits.
Known vector write primitives seed a transitive reverse-call closure. Unclassified
native-emitter candidates are printed and make exit=1, never silently marked safe.
"""
import argparse,csv,json,re,sys
from pathlib import Path
KNOWN={
'emit_native_xmm_mov':'zero_ymm_upper guard; after M01 explicit EVEX mask guard',
'emit_native_xmm_logic':'zero_ymm_upper guard',
'emit_native_insertps':'zero_ymm_upper guard; no legal EVEX opmask encoding',
'emit_native_punpck_qdq':'zero_ymm_upper guard',
'emit_native_sse_fp':'zero_ymm_upper guard before subfamilies',
'emit_native_ymm_load':'target != 0 guard',
'emit_native_ymm_store':'target != 0 guard',
'emit_xmm_load_store_pair':'M01 requires explicit guards on BOTH instructions',
'emit_native_extractps':'no vector destination, no legal EVEX writemask',
}
def stripped(s):
 return re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',lambda m:'\n'*m.group().count('\n') if '\n'in m.group() else ' ',s,flags=re.S)
def functions(s):
 clean=stripped(s);out={}
 for m in re.finditer(r'\b(emit_[A-Za-z_0-9]+)\s*\([^;{}]*\)\s*\{',clean):
  start=m.end();depth=1;i=start
  while i<len(clean) and depth:
   depth+=(clean[i]=='{')-(clean[i]=='}');i+=1
  if not depth:out[m.group(1)]=dict(line=clean.count('\n',0,m.start())+1,body=clean[start:i-1])
 return out
def main():
 p=argparse.ArgumentParser();p.add_argument('source',type=Path);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
 s=a.source.read_text();fs=functions(s)
 if len(fs)<100:raise SystemExit('not a full code generator; refusing partial inventory')
 roots={'emit_store_x20_x22_to_xmm','emit_str_q','emit_fp_ldst','emit_zero_ymm_hi_if_vex','emit_ymm_q_pair'}
 closure=set(n for n in roots if n in fs)
 for n,f in fs.items():
  if re.search(r'\b(?:xmm_reg_off|ymm_reg_off)\s*\(|\b(?:ymm_hi|zmm_hi|xmm_ext)\b',f['body']):closure.add(n)
 while True:
  new={n for n,f in fs.items() if any(re.search(r'\b'+re.escape(c)+r'\s*\(',f['body'])for c in closure)}-closure
  if not new:break
  closure|=new
 rows=[];unknown=[]
 for n in sorted(closure):
  f=fs[n];native=n.startswith('emit_native_') or n=='emit_xmm_load_store_pair'
  if native and n not in KNOWN:unknown.append(n)
  rows.append(dict(emitter=n,line=f['line'],role='architectural candidate' if native else 'primitive / inherited caller check',review_status=KNOWN.get(n,'REVIEW_REQUIRED' if native else 'callsite responsibility'),mentions_zero_ymm_upper='zero_ymm_upper'in f['body'],mentions_mask_guard='jit_evex_write_masked'in f['body'],mentions_evex='HB_EVEX_TARGET'in f['body']))
 a.out.parent.mkdir(parents=True,exist_ok=True)
 with a.out.open('w',newline='')as f:w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
 print(json.dumps(dict(functions_scanned=len(fs),vector_reference_closure=len(rows),unclassified_native=unknown,manual_review_required=True,dispatch_load_store_must_be_reviewed_separately=True),indent=2));return bool(unknown)
if __name__=='__main__':raise SystemExit(main())
