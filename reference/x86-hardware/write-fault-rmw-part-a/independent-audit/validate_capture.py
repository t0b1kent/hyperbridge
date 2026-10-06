# SPDX-License-Identifier: MIT
"""Independent validation of raw 0035 evidence; no imports from probe modules."""
import collections, gzip, hashlib, json, pathlib, re
ROOT=pathlib.Path(__file__).resolve().parent.parent
OUT=ROOT/'results/0035-write-fault-atomicity-hardware/amd-epyc-9v74-linux'
FORMS=json.loads((ROOT/'probe35/forms.json').read_text()); FD={f['name']:f for f in FORMS}
BASE={'data':0x500000000000,'source':0x510000000000,'stack':0x520000000000,'code':0x530000000000,'altstack':0x540000000000}
NAMES='rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 rflags'.split()
DEFAULT=dict(zip(NAMES,[0x1122334455667788,0xa1b2c3d4e5f60718,3,0x99aabbccddeeff00,0,0,0x778899aabbccddee,0,0x0808080808080808,0x0909090909090909,0x1010101010101010,0x1212121212121212,0x1313131313131313,0x1414141414141414,0x1515151515151515,0x1616161616161616,0x203]))
ERR=[]; COUNTS=collections.Counter(); HASHES={}
def check(ok,tag,key=None):
 if not ok:ERR.append([tag,key])
def num(s):
 if s.startswith('0x'):return int(s,16)
 for k,v in BASE.items():
  if s.startswith(k):return v+int(s[len(k):])
 raise ValueError(s)
def regs(r):return {k:num(v) for k,v in r.items()}
def page(p,key):
 if p is None:return None
 check(p['size']==8192 and p['fill']=='11','page-header',key)
 length=8192 if p['page2_mapped'] else 4096
 b=bytearray([0x11])*length;end=0
 for start,h in p['patches']:
  v=bytes.fromhex(h)
  check(start>=end and start+len(v)<=length and len(v)>0 and 0x11 not in v,'page-patches',key)
  b[start:start+len(v)]=v;end=start+len(v)
 return b
def input_regs(f,r):
 v=DEFAULT|f.get('regs',{});v['rflags']=f.get('flags',DEFAULT['rflags'])|(0x400 if f.get('df') else 0)
 v['rsi']=BASE['source']+256+(f.get('count',1)-1)*f['width']*bool(f.get('string') and f.get('df'))
 v['rdi']=BASE['data']+r['destination_offset'];v['rsp']=BASE['data']+r['destination_offset']+f['width'] if f.get('stack') else BASE['stack']+32768
 return v
def after_one_scalar(f,r,startregs,startmem,completed=0):
 """Independent scalar/string/stack byte and register model; no RMW flags inference."""
 v=startregs.copy();b=bytearray(startmem);w=f['width'];off=r['destination_offset'];n=f.get('count',1);df=f.get('df',0);name=f['name']
 def put(at,val):b[at:at+w]=(val&((1<<(8*w))-1)).to_bytes(w,'little')
 if f.get('string'):
  delta=-w if df else w
  for i in range(completed,n):
   if 'movs' in name:
    src=256+(n-1)*w*df+i*delta
    b[off+i*delta:off+i*delta+w]=bytes(0x40+((src+j)&63) for j in range(w))
   else:put(off+i*delta,v['rax'])
  v['rdi']+=n*delta
  if 'movs' in name:v['rsi']+=n*delta
  if name.startswith('rep_'):v['rcx']=0
 elif name.startswith('push'):
  if '_reg' in name:val=v['rbx']
  elif '_mem' in name:val=int.from_bytes(bytes(range(0x40,0x40+w)),'little')
  elif '_imm8' in name:val=-61
  else:val=-0x495b if w==2 else -0x2738495b
  put(off,val);v['rsp']-=w
 elif name=='call_rel32':put(off,BASE['code']+5);v['rsp']-=w
 elif name.startswith('mov'):
  if '_imm' in name:val={1:0xa5,2:0xb6a5,4:0xd8c7b6a5,8:-0x2738495b}[w]
  else:val=v['rbx']
  put(off,val)
 else:raise ValueError(name)
 return v,b
expected={}
for f in FORMS:
 cells={}
 for lay in ['inside_rw','inside_ro','cross_rw_rw','cross_rw_ro','cross_ro_rw','cross_ro_ro','cross_rw_unmapped']:
  if lay.startswith('cross') and f['group']=='vector' and f.get('alignment'):continue
  offsets=range(1,f['width']*f.get('count',1)) if lay.startswith('cross') else [0]
  for off in offsets:
   for c in (1,2,3):expected[(f['name'],lay,off,c)]=1
seen=set()
for group in ['scalar','rmw','vector']:
 hs=[]
 for run in (1,2):
  h=hashlib.sha256()
  with gzip.open(OUT/f'{group}.run{run}.jsonl.gz','rb') as stream:
   for x in iter(lambda:stream.read(1<<20),b''):h.update(x)
  hs.append(h.hexdigest())
 check(hs[0]==hs[1],'repeat',group);HASHES[group]=hs
 with gzip.open(OUT/f'{group}.run1.jsonl.gz','rt') as stream:
  for line in stream:
   r=json.loads(line);f=FD[r['form']];key=(r['form'],r['layout'],r['cross_offset'],r['continuation'])
   check(key not in seen,'duplicate',key);seen.add(key);COUNTS['rows']+=1;COUNTS[group+'_rows']+=1
   check(r['wait_status']==0 and r['done']==1,'child-completion',key)
   check(r['group']==f['group'] and r['width']==f['width'] and r['expected_legal']==f['legal'],'catalog-fields',key)
   dest=4096-r['cross_offset']+(f.get('count',1)-1)*f['width']*bool(f.get('string') and f.get('df')) if r['layout'].startswith('cross') else 256
   check(r['destination_offset']==dest,'placement',key)
   low=dest-(f.get('count',1)-1)*f['width']*bool(f.get('string') and f.get('df'));high=low+f['width']*f.get('count',1)
   initial=page(r['initial'],key);expectedinitial=bytearray([0x11])*8192;iv=bytes.fromhex(f.get('initial',''));expectedinitial[dest:dest+len(iv)]=iv
   check(initial==expectedinitial,'initial-image',key)
   for nm in ['first_pages','final_pages','clean_pages']:
    pp=page(r[nm],key)
    if pp is not None:check(pp[:low]==initial[:low] and pp[high:]==initial[high:len(pp)],'outside-footprint-'+nm,key)
   ir=input_regs(f,r)
   for ft in r['faults']:
    COUNTS['faults']+=1;ph=ft['execution_phase'];check(ph in (1,2),'reference-fault',key)
    g=regs(ft['gregs']);b=page(ft['pages'],key);before=initial if ph==1 else page(r['first_pages'],key)
    check(ft['partial_write']==(b!=before[:len(b)]),'partial-recomputed',key)
    check(b[:low]==initial[:low] and b[high:]==initial[high:len(b)],'outside-footprint-fault',key)
    check(g['rip']==BASE['code'],'fault-rip',key)
    check(ft['uc_stack']=={'sp':'altstack+0','size':65536,'flags':0},'altstack',key)
    check(ft['fpstate_size']==len(bytes.fromhex(ft['fpstate']))==2436,'fp-image',key)
    fp=bytes.fromhex(ft['fpstate']);check(fp[160:176]==bytes(range(0x80,0x90)),'xmm0-fault',key)
    check(fp[176:192]==bytes.fromhex(f.get('mask','ff'*16)),'xmm1-fault',key)
    check(fp[576:592]==bytes(range(0x90,0xa0)),'ymm0-upper-fault',key)
    check(len(ft['gregs'])==23 and g['trapno']==ft['trap'] and g['err']==ft['error'],'full-gregs',key)
    check(ft['pages']['page2_mapped']==(r['layout']!='cross_rw_unmapped'),'unmapped-unread',key)
    er=ir.copy()
    if ph==2:
     er=regs(r['first_regs']);er['rdi']=ir['rdi'];er['rsi']=ir['rsi'];er['rsp']=ir['rsp']
     if f.get('string'):er['rcx']=ir['rcx']
    progress=0
    if f['name'].startswith('rep_'):
     progress=er['rcx']-g['rcx'];check(0<=progress<f['count'],'rep-progress',key)
     delta=(-1 if f.get('df') else 1)*f['width'];er['rcx']-=progress;er['rdi']+=delta*progress
     if 'movs' in f['name']:er['rsi']+=delta*progress
     COUNTS['faults-with-rep-progress']+=bool(progress)
    expected_fault=bytearray(before[:len(b)])
    if f['name'].startswith('rep_'):
     delta=(-1 if f.get('df') else 1)*f['width']
     for i in range(progress):
      at=dest+i*delta
      if 'movs' in f['name']:
       source_at=256+(f['count']-1)*f['width']*bool(f.get('df'))+i*delta
       value=bytes(0x40+((source_at+j)&63) for j in range(f['width']))
      else:value=(er['rax']&((1<<(8*f['width']))-1)).to_bytes(f['width'],'little')
      expected_fault[at:at+f['width']]=value
    check(b==expected_fault,'fault-bytes-equal-completed-elements-only',key)
    for k in NAMES:
     check((g[k]&~0x10000)==er[k] if k=='rflags' else g[k]==er[k],'fault-register-'+k,key)
    if ft['trap']==14:
     check(ft['signal']==11 and ft['error']==(6 if r['layout']=='cross_rw_unmapped' else 7),'pf-class',key)
     check(g['cr2']==num(ft['address']),'cr2-siaddr',key)
    elif ft['trap']==6:check(not f['legal'] and ft['signal']==4,'ud-class',key)
    elif ft['trap']==13:check(f['name'].startswith('cmpxchg16b') and r['layout'].startswith('cross'),'gp-class',key)
    else:check(False,'unexpected-trap',key)
   if r['status']==0:
    actualregs=regs(r['final_regs']);actualpages=page(r['final_pages'],key);cleanpages=page(r['clean_pages'],key)
    check(r['clean_equal']==(actualregs==regs(r['clean_regs']) and actualpages==cleanpages[:len(actualpages)]),'clean-equality-recomputed',key)
    if r['continuation'] in (1,3):check(r['clean_equal'],'clean-reference-mismatch',key);COUNTS['one-two-clean-comparisons']+=1
    check(r['first_completed'] and r['second_completed']==(r['continuation']==3),'continuation-completion',key)
    if group=='scalar':
     m=bytearray(initial);progress=0
     if r['continuation']==2 and r['faults']:
      m[low:high]=bytes([0x3c])*(high-low)
      if f['name'].startswith('rep_'):progress=f['count']-num(r['faults'][0]['gregs']['rcx'])
     v,m=after_one_scalar(f,r,ir,m,progress)
     check(v==regs(r['first_regs']) and m==page(r['first_pages'],key),'scalar-first-model',key)
     if r['continuation']==3:
      v['rdi']=ir['rdi'];v['rsi']=ir['rsi'];v['rsp']=ir['rsp']
      if f.get('string'):v['rcx']=ir['rcx']
      v,m=after_one_scalar(f,r,v,m)
     check(v==actualregs and m==actualpages,'scalar-final-model',key);COUNTS['scalar-modeled']+=1
    if group=='vector':
     b=bytearray(initial)
     if r['continuation']==2 and r['faults']:b[low:high]=bytes([0x3c])*(high-low)
     if f['name'].startswith('maskmov'):
      for j,mask in enumerate(bytes.fromhex(f['mask'])):
       if mask&0x80:b[dest+j]=0x80+j
     else:
      idx=0
      if f['name'].startswith('movhps'):idx=8
      elif f['name'].startswith('pextr'):idx=int(f['name'].rsplit('_',1)[1])*f['width']
      b[dest:dest+f['width']]=bytes(range(0x80+idx,0x80+idx+f['width']))
     check(b==actualpages and ir==actualregs,'vector-final-model',key);COUNTS['vector-modeled']+=1
   else:check(r['status']==2 and r['terminal_trap'] in (6,13) and len(r['faults'])==1,'terminal-result',key)
check(seen==set(expected),'full-grid',{'missing':len(set(expected)-seen),'extra':len(seen-set(expected))})
result={'counts':dict(COUNTS),'uncompressed_sha256':HASHES,'errors':ERR,'pass':not ERR}
(pathlib.Path(__file__).parent/'CAPTURE-VALIDATION.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2));raise SystemExit(bool(ERR))
