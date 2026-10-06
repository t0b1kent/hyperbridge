# SPDX-License-Identifier: MIT
"""Independent RMW arithmetic, destination bytes, GPR, and defined-flag checks."""
import collections,gzip,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parent.parent;OUT=ROOT/'results/0035-write-fault-atomicity-hardware/amd-epyc-9v74-linux'
FORMS={f['name']:f for f in json.loads((ROOT/'probe35/forms.json').read_text())}
NAMES='rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 rflags'.split()
DEFAULT=dict(zip(NAMES,[0x1122334455667788,0xa1b2c3d4e5f60718,3,0x99aabbccddeeff00,0,0,0x778899aabbccddee,0,0x0808080808080808,0x0909090909090909,0x1010101010101010,0x1212121212121212,0x1313131313131313,0x1414141414141414,0x1515151515151515,0x1616161616161616,0x203]))
BASE={'data':0x500000000000,'source':0x510000000000,'stack':0x520000000000,'code':0x530000000000,'altstack':0x540000000000}
def num(s):
 if s.startswith('0x'):return int(s,16)
 for k,v in BASE.items():
  if s.startswith(k):return v+int(s[len(k):])
 raise ValueError(s)
def regs(v):return {k:num(x) for k,x in v.items()}
def page(p):
 b=bytearray([0x11])*8192
 for off,h in p['patches']:b[off:off+len(h)//2]=bytes.fromhex(h)
 return b
CF,PF,AF,ZF,SF,OF=1,4,16,64,128,2048;SIX=CF|PF|AF|ZF|SF|OF

def model(f,r,v,mem):
 v=v.copy();mem=bytearray(mem);w=f['width'];n=8*w;mask=(1<<n)-1;sign=1<<(n-1);off=r['destination_offset'];a=int.from_bytes(mem[off:off+w],'little');b=v['rbx']&mask;flags=v['rflags'];dm=(1<<64)-1;name=f['name'];op=name.split('_')[0];z=a
 def setflag(bit,value):
  nonlocal flags
  flags=(flags&~bit)|(bit if value else 0)
 def szp(value):
  setflag(SF,bool(value&sign));setflag(ZF,value==0);setflag(PF,(value&255).bit_count()%2==0)
 def write_reg(reg,value,width=w):
  mm=(1<<(8*width))-1
  v[reg]=(value&mm) if width>=4 else (v[reg]&~mm)|(value&mm)
 def signed(value):return value-(1<<n) if value&sign else value
 def addsub(x,y,carry,sub=False):
  nonlocal flags
  raw=x-y-carry if sub else x+y+carry;val=raw&mask
  setflag(CF,raw<0 if sub else raw>mask);setflag(AF,bool((x^y^val)&0x10));szp(val)
  sval=signed(x)-signed(y)-carry if sub else signed(x)+signed(y)+carry
  setflag(OF,sval < -sign or sval>=sign)
  return val
 if '_imm' in name and op in ('add','adc','sub','sbb','and','or','xor'):
  b=int(f['asm'].rsplit(',',1)[1])&mask
 if op in ('add','adc','sub','sbb','xadd'):
  z=addsub(a,b,int(bool(flags&CF)) if op in ('adc','sbb') else 0,op in ('sub','sbb'))
  if op=='xadd':write_reg('rbx',a)
 elif op in ('and','or','xor'):
  z={'and':lambda:a&b,'or':lambda:a|b,'xor':lambda:a^b}[op]();setflag(CF,False);setflag(OF,False);szp(z);dm&=~AF
 elif op in ('inc','dec'):
  oldcf=flags&CF;z=addsub(a,1,0,op=='dec');flags=(flags&~CF)|oldcf
 elif op=='neg':z=addsub(0,a,0,True)
 elif op=='not':z=(~a)&mask
 elif op=='xchg':z=b;write_reg('rbx',a)
 elif op=='cmpxchg':
  acc=v['rax']&mask;addsub(acc,a,0,True)
  if acc==a:z=b
  else:write_reg('rax',a)
 elif op in ('cmpxchg8b','cmpxchg16b'):
  half=w//2;hm=(1<<(8*half))-1;acc=((v['rdx']&hm)<<(8*half))|(v['rax']&hm);same=acc==a;setflag(ZF,same)
  if same:z=((v['rcx']&hm)<<(8*half))|(v['rbx']&hm)
  else:write_reg('rax',a&hm,half);write_reg('rdx',a>>(8*half),half)
 elif op in ('bts','btr','btc'):
  setflag(CF,bool(a&8));z=a|8 if op=='bts' else a&~8 if op=='btr' else a^8;dm&=~(OF|SF|AF|PF)
 elif op in ('shl','shr','sar','shld','shrd'):
  count=1 if '_one_' in name or '_imm1_' in name else 3
  if op=='shl':z=(a<<count)&mask;cf=(a>>(n-count))&1;of=bool((z&sign))^bool(cf)
  elif op=='shr':z=a>>count;cf=(a>>(count-1))&1;of=bool(a&sign)
  elif op=='sar':z=(signed(a)>>count)&mask;cf=(a>>(count-1))&1;of=False
  elif op=='shld':z=((a<<count)|(b>>(n-count)))&mask;cf=(a>>(n-count))&1;of=bool((a^z)&sign)
  else:z=(a>>count)|((b<<(n-count))&mask);cf=(a>>(count-1))&1;of=bool((a^z)&sign)
  szp(z);setflag(CF,cf);dm&=~AF
  if count==1:setflag(OF,of)
  else:dm&=~OF
 elif op in ('rol','ror','rcl','rcr'):
  count=1 if '_one_' in name else 3
  nn=n+1 if op in ('rcl','rcr') else n;mm=(1<<nn)-1;x=a|((flags&CF)<<n) if nn==n+1 else a
  zz=((x<<count)|(x>>(nn-count)))&mm if op in ('rol','rcl') else ((x>>count)|(x<<(nn-count)))&mm;z=zz&mask
  cf=(zz>>n)&1 if nn==n+1 else z&1 if op=='rol' else z>>(n-1)
  setflag(CF,cf)
  if count==1:setflag(OF,bool(z&sign)^bool(cf) if op in ('rol','rcl') else bool(((z>>(n-1))^(z>>(n-2)))&1))
  else:dm&=~OF
 else:raise ValueError(name)
 mem[off:off+w]=z.to_bytes(w,'little');v['rflags']=flags
 return v,mem,dm
errors=[];counts=collections.Counter()
for line in gzip.open(OUT/'rmw.run1.jsonl.gz','rt'):
 r=json.loads(line)
 if r['status']!=0:continue
 f=FORMS[r['form']];key=(r['form'],r['layout'],r['cross_offset'],r['continuation']);iv=DEFAULT|f.get('regs',{});iv['rflags']=f.get('flags',0x203);iv['rsi']=BASE['source']+256;iv['rdi']=BASE['data']+r['destination_offset'];iv['rsp']=BASE['stack']+32768
 m=page(r['initial']);off=r['destination_offset'];w=f['width']
 if r['continuation']==2 and r['faults']:m[off:off+w]=bytes([0x3c])*w
 v,m,dm=model(f,r,iv,m)
 def verify(label,v,m,dm,observed_regs,observed_page):
  actual=regs(observed_regs);bad=[k for k in NAMES if (v[k]&dm != actual[k]&dm) if k=='rflags']
  bad+=[k for k in NAMES if k!='rflags' and v[k]!=actual[k]]
  if m!=page(observed_page):bad+=['memory']
  if bad:errors.append({'key':key,'phase':label,'different':bad,'expected':{k:hex(v[k]) for k in bad if k!='memory'},'observed':{k:hex(actual[k]) for k in bad if k!='memory'},'defined_flag_mask':hex(dm)})
  counts[label]+=1
 verify('first',v,m,dm,r['first_regs'],r['first_pages'])
 if r['continuation']==3:
  # Undefined output flags are observations, not promises. Carry them through
  # just as hardware does; every defined first-execution result was checked.
  v['rflags']=num(r['first_regs']['rflags']);v['rdi']=iv['rdi'];v['rsi']=iv['rsi'];v['rsp']=iv['rsp'];v,m,dm=model(f,r,v,m)
 verify('final',v,m,dm,r['final_regs'],r['final_pages']);counts['mode'+str(r['continuation'])]+=1
result={'pass':not errors,'counts':dict(counts),'errors':errors};(pathlib.Path(__file__).parent/'RMW-MODEL-VALIDATION.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2));raise SystemExit(bool(errors))
