# SPDX-License-Identifier: MIT
import pathlib,gzip,json,sys,collections
root=pathlib.Path(__file__).resolve().parent
out=pathlib.Path(sys.argv[1]) if len(sys.argv)>1 else root.parent/'results/0035-write-fault-atomicity-hardware/amd-epyc-9v74-linux'
forms={x['name']:x for x in json.loads((root/'forms.json').read_text())}
names='rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split()
vals=[0x1122334455667788,0xa1b2c3d4e5f60718,3,0x99aabbccddeeff00,0,0,0x778899aabbccddee,0,0x0808080808080808,0x0909090909090909,0x1010101010101010,0x1212121212121212,0x1313131313131313,0x1414141414141414,0x1515151515151515,0x1616161616161616]
base={'data':0x500000000000,'source':0x510000000000,'stack':0x520000000000,'code':0x530000000000,'altstack':0x540000000000}
def addr(s):
 if s.startswith('0x'):return int(s,16)
 for k,v in base.items():
  if s.startswith(k):return v+int(s[len(k):])
 raise ValueError(s)
def pages(p):
 b=bytearray([17])*8192
 for i,h in p['patches']:b[i:i+len(h)//2]=bytes.fromhex(h)
 return b[:8192 if p['page2_mapped'] else 4096]
c=collections.Counter();errs=[]
for group in ['scalar','rmw','vector']:
 for line in gzip.open(out/f'{group}.run1.jsonl.gz','rt'):
  r=json.loads(line)
  if r['continuation']!=1 or not r['faults']:continue
  f=r['faults'][0];form=forms[r['form']];expected=dict(zip(names,vals));expected.update(form.get('regs',{}));w=form['width'];n=form.get('count',1);sgn=-1 if form.get('df') else 1;expected['rsi']=base['source']+256+((n-1)*w if form.get('string') and form.get('df') else 0);expected['rdi']=base['data']+r['destination_offset'];expected['rsp']=base['data']+r['destination_offset']+w if form.get('stack') else base['stack']+32768
  done=n-addr(f['gregs']['rcx']) if r['form'].startswith('rep_') else 0
  initialrdi=expected['rdi'];initialrsi=expected['rsi']
  if r['form'].startswith('rep_'):
   if done<0 or done>=n:errs.append(['bad_rep_count',r['form'],r['layout'],r['cross_offset'],done])
   expected['rcx']-=done;expected['rdi']+=sgn*done*w
   if 'movs' in r['form']:expected['rsi']+=sgn*done*w
  for k,v in expected.items():
   if addr(f['gregs'][k])!=v:errs.append(['register',r['form'],r['layout'],r['cross_offset'],k,f['gregs'][k],hex(v)])
  flag=form.get('flags',0x203)|(0x400 if form.get('df') else 0)
  if (addr(f['gregs']['rflags'])^flag)&0x8d5:errs.append(['six_flags',r['form'],r['layout'],r['cross_offset']])
  actual=pages(f['pages']);ex=pages(r['initial'])[:len(actual)]
  for i in range(done):
   off=initialrdi-base['data']+sgn*i*w
   if 'movs' in r['form']:
    so=initialrsi-base['source']+sgn*i*w;b=bytes(0x40+(x&63) for x in range(so,so+w))
   else:b=expected['rax'].to_bytes(8,'little')[:w]
   ex[off:off+w]=b
  if actual!=ex:errs.append(['fault_memory',r['form'],r['layout'],r['cross_offset'],done])
  c['fault_cells_checked']+=1;c['page_fault_cells_checked']+=f['trap']==14;c['rep_fault_cells_checked']+=r['form'].startswith('rep_');c['rep_fault_cells_with_completed_iterations']+=done>0
result={'counts':dict(c),'errors':errs};(out/'FAULT-STATE-CHECK.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2));sys.exit(bool(errs))
