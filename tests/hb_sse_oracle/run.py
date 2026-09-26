#!/usr/bin/env python3
"""Native SSE/AVX oracle versus actual HB C interpreter, two host policies."""
import argparse,json,gzip,collections,time,hashlib
from pathlib import Path
from ctypes import byref
from binding import Sample,Result,load
from ops import assemble
from corpus import *
def pack_result(o):return [bytes(o.x).hex(),f'{o.rax:016x}',f'{o.flags&0x8d5:03x}',f'{o.host_mxcsr:04x}',f'{o.guest_mxcsr:04x}',o.status,o.reads]
def same(a,b):return bytes(a.x)==bytes(b.x) and a.rax==b.rax and ((a.flags^b.flags)&0x8d5)==0 and b.status==0
def fpclass(v,bits):
 m=23 if bits==32 else 52;e=255 if bits==32 else 2047;ex=(v>>m)&e;frac=v&((1<<m)-1)
 return 'nan' if ex==e and frac else 'inf' if ex==e else 'subnormal' if ex==0 and frac else 'zero' if ex==0 else 'normal'
def category(op,h,i,s):
 if i.status:return 'interpreter_status'
 if (h.flags^i.flags)&0x8d5:return 'comi_flags'
 if h.rax!=i.rax:return 'integer_conversion'
 bits=op['bits'];size=bits//8
 if op['family']=='cvtss2sd':bits=64;size=8
 if op['family']=='cvtsd2ss':bits=32;size=4
 active=16 if op['kind'] in ['packed','packconvert','intpack'] else size
 if op['kind'] in ['flags','ftoi']:active=0
 if bytes(h.x)[active:]!=bytes(i.x)[active:]:return 'destination_upper_bits'
 if op['family']=='cvttps2dq':return 'packed_integer_conversion'
 if op['kind']=='intpack':return 'integer_packed_value'
 for k in range(0,active,size):
  a=int.from_bytes(bytes(h.x)[k:k+size],'little');b=int.from_bytes(bytes(i.x)[k:k+size],'little')
  if a!=b:
   ca,cb=fpclass(a,bits),fpclass(b,bits)
   if ca=='nan' and cb=='nan':return 'nan_selection_or_sign'
   if ca=='nan' or cb=='nan':return 'nan_vs_non_nan'
   if s.mxcsr&0x8040:return 'denormal_or_ftz_daz'
   return 'rounding_or_finite'
 return 'unclassified'
def main():
 a=argparse.ArgumentParser();a.add_argument('--out',type=Path,default=Path(__file__).parent/'out/results');a.add_argument('--random',type=int,default=256);a.add_argument('--op',default='');a.add_argument('--limit',type=int,default=0);a.add_argument('--negative-control',action='store_true');a.add_argument('--require-clean',action='store_true',help='exit nonzero on matched-policy value mismatches');args=a.parse_args()
 args.out.mkdir(parents=True,exist_ok=True);root=Path(__file__).resolve().parent;ops=assemble(root/'out');lib=load()
 n=0;stats=collections.defaultdict(collections.Counter);witness={};form_ref={};form_bad=[];t=time.time();native_digest=hashlib.sha256()
 corpus=gzip.open(args.out/'measurements.jsonl.gz','wt',compresslevel=4);fails=gzip.open(args.out/'failures.jsonl.gz','wt',compresslevel=4)
 for op in ops:
  if args.op and args.op not in op['name']:continue
  code=bytes.fromhex(op['bytes']);p=lib.oracle_prepare(code,len(code))
  if not p:raise RuntimeError((op,lib.oracle_error()))
  op['ir_count']=lib.oracle_ir_count(p);op['ir_opcode']=lib.oracle_ir_opcode(p)
  records=list(inputs(op,args.random));digest=hashlib.sha256()
  for j,(label,lhs,rhs,ival) in enumerate(records):
   if args.limit and j>=args.limit:break
   s=Sample();s.flags=0xad7;s.rax=ival;s.mxcsr=0x1f80
   upper=bytes.fromhex('efcdab89674523011032547698badcfe')
   s.x[0][:]=lhs+upper;s.x[1][:]=rhs+upper;s.x[2][:]=rhs+upper
   if op['vex']:
    s.x[0][:]=bytes.fromhex('efbeadde0df0ad0b2143658798badcfe')+upper;s.x[1][:]=lhs+upper
   s.mem[:]=rhs+bytes.fromhex('0102030405060708090a0b0c0d0e0f10')
   if op['kind']=='itof':s.mem[:op['intbits']//8]=ival.to_bytes(op['intbits']//8,'little')
   for mx in MXCSRS:
    s.mxcsr=mx;h=Result();i=Result();z=Result();lib.oracle_run(p,byref(s),0,byref(h));lib.oracle_run(p,byref(s),1,byref(i));lib.oracle_run(p,byref(s),2,byref(z))
    if args.negative_control and n==0:i.x[0]^=1
    if (h.host_mxcsr&~63)!=mx:raise AssertionError('oracle changed MXCSR controls')
    if i.status or z.status:raise AssertionError((op,label,mx,i.status,z.status))
    expected_reads=(op['form']=='mem');assert (i.reads>0)==expected_reads,(op,i.reads);assert (z.reads>0)==expected_reads
    row={'id':n,'op':op['id'],'label':label,'mxcsr':mx,'x':[bytes(x).hex() for x in s.x],'mem':bytes(s.mem).hex(),'rax':f'{s.rax:016x}','flags':f'{s.flags:03x}','hw':pack_result(h),'matched':pack_result(i),'neutral':pack_result(z)}
    bad=[]
    for policy,r in [('matched',i),('neutral',z)]:
     key=(op['name'],op['form'],f'{mx:04x}',policy);stats[key]['cases']+=1
     if not same(h,r):
      c=category(op,h,r,s);bad.append(policy+':'+c);stats[key]['value_mismatch']+=1;stats[key][c]+=1
      wk=(policy,c,op['name'],f'{mx:04x}')
      if wk not in witness:witness[wk]=row.copy()
     if ((r.guest_mxcsr^h.host_mxcsr)&63):stats[key]['guest_mxcsr_flags_mismatch']+=1
     if ((r.host_mxcsr^h.host_mxcsr)&63):stats[key]['host_exception_flags_mismatch']+=1
    row['bad']=bad;corpus.write(json.dumps(row,separators=(',',':'))+'\n')
    if bad:fails.write(json.dumps(row,separators=(',',':'))+'\n')
    signature=bytes(h.x)+h.rax.to_bytes(8,'little')+(h.flags&0x8d5).to_bytes(8,'little')+h.host_mxcsr.to_bytes(4,'little')
    digest.update(signature);native_digest.update(signature);n+=1
  if op['form']=='reg':form_ref[op['name']]=digest.hexdigest()
  elif form_ref[op['name']]!=digest.hexdigest():form_bad.append(op['name'])
  count=sum(v['value_mismatch'] for k,v in stats.items() if k[0]==op['name'] and k[1]==op['form'] and k[3]=='matched')
  print(json.dumps({'op':op['name'],'form':op['form'],'rows_total':n,'matched_failures':count,'elapsed_s':round(time.time()-t,1)}),flush=True)
 corpus.close();fails.close()
 report={'seed':hex(SEED),'source_commit':'8a1020c38ff163cc5712a216aebd4240233f81b8','cases':n,'native_x86_instructions_executed':n,'interpreter_executions':n*2,'elapsed_seconds':time.time()-t,'mxcsr_controls':[hex(x) for x in MXCSRS],'random_cases_per_operation_form':args.random,'register_memory_oracle_disagreement':form_bad,'oracle_output_sha256':native_digest.hexdigest(),'stats':[dict(zip(['op','form','mxcsr','host_policy'],k),**v) for k,v in stats.items()]}
 (args.out/'summary.json').write_text(json.dumps(report,indent=2));(args.out/'witnesses.json').write_text(json.dumps([dict(policy=k[0],category=k[1],name=k[2],mxcsr_hex=k[3],case=v) for k,v in witness.items()],indent=2));(args.out/'opcodes.json').write_text(json.dumps(ops,indent=2))
 totals={p:sum(v['value_mismatch'] for k,v in stats.items() if k[3]==p) for p in ['matched','neutral']}
 print('DONE',json.dumps(dict(cases=n,mismatches=totals,form_disagreement=form_bad)),flush=True)
 if args.negative_control and sum(totals.values())==0:raise AssertionError('negative control failed')
 if args.require_clean and (totals['matched'] or form_bad):raise SystemExit(1)
if __name__=='__main__':main()
