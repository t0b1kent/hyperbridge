"""Fail-closed, single-thread A64 evaluator for actual emitted probe words.
It is intentionally not an ARM runtime: no concurrency, MMU, exception machinery,
FP arithmetic, or general-purpose x86 helper implementation is simulated.
"""
import struct
MASK=(1<<64)-1
class Unsupported(RuntimeError):pass
class Fault(RuntimeError):pass
class Memory:
 def __init__(self):self.regions=[];self.access=[]
 def map(self,a,b):
  b=bytearray(b)
  for x,c in self.regions:
   if max(a,x)<min(a+len(b),x+len(c)):raise ValueError('overlapping test mappings')
  self.regions.append((a,b))
 def view(self,a,n):
  for x,b in self.regions:
   if x<=a and a+n<=x+len(b):return b,a-x
  raise Fault(f'unmapped access {a:#x}+{n}')
 def read(self,a,n):
  b,o=self.view(a,n);self.access.append(('r',a,n));return bytes(b[o:o+n])
 def write(self,a,d):
  b,o=self.view(a,len(d));self.access.append(('w',a,len(d)));b[o:o+len(d)]=d
 def get(self,a,n):return int.from_bytes(self.read(a,n),'little')
 def put(self,a,v,n):self.write(a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))
def sx(v,n):return v-(1<<n) if v&(1<<(n-1)) else v
def ror(v,n,width):
 n%=width;m=(1<<width)-1;return ((v>>n)|(v<<(width-n)))&m
class CPU:
 def __init__(self,regs,mem,helper=None):
  self.r=regs;self.v=[0]*32;self.m=mem;self.helper=helper;self.nzcv=(0,0,0,0);self.trace=[];self.words=set();self.sp=0
 def get(self,n):return 0 if n==31 else self.r[n]
 def put(self,n,v,width=64):
  if n!=31:self.r[n]=v&((1<<width)-1)
 def flags(self,a,b,result,width,sub=False):
  m=(1<<width)-1;a&=m;b&=m;result&=m;s=1<<(width-1)
  c=int(a>=b) if sub else int(a+b>m)
  v=int(bool(((a^b)&(a^result)&s) if sub else ((~(a^b))&(a^result)&s)))
  self.nzcv=(int(bool(result&s)),int(result==0),c,v)
 def logicalflags(self,v,width):self.nzcv=(int(bool(v&(1<<(width-1)))),int(v==0),0,0)
 def cond(self,c):
  n,z,k,v=self.nzcv
  t=[z,k,n,v,k and not z,n==v,(n==v) and not z,True][c>>1]
  return not t if (c&1) and c!=15 else bool(t)
 def run(self,code,limit=10000):
  words=[w[0] for w in struct.iter_unpack('<I',code)];pc=0;steps=0
  while pc<len(code):
   if pc<0 or pc%4:raise Fault(f'invalid PC {pc:#x}')
   steps+=1
   if steps>limit:raise Fault('instruction budget exceeded')
   w=words[pc//4];self.trace.append((pc,w));self.words.add(w)
   rd=w&31;rn=(w>>5)&31;rm=(w>>16)&31;size=64 if w>>31 else 32;m=(1<<size)-1;nextpc=pc+4
   a=self.get(rn)&m;b=self.get(rm)&m
   if w in (0xd50339bf,0xd5033bbf,0xd5033abf,0xd503201f):pass
   elif (w&0x3b000000)==0x39000000: # unsigned-offset scalar or vector memory
    vec=bool(w&(1<<26));opc=(w>>22)&3;sz=(w>>30)&3
    if vec:
     if opc not in (2,3) or sz!=0:raise Unsupported(f'non-Q vector load/store {w:08x}')
     n=16;load=opc==3
    else:
     n=1<<sz;load=bool(opc&1)
     if opc>=2:raise Unsupported(f'signed immediate load {w:08x}')
    addr=((self.sp if rn==31 else self.get(rn))+((w>>10)&4095)*n)&MASK
    if load:
     val=self.m.get(addr,n)
     if vec:self.v[rd]=val
     else:self.put(rd,val)
    else:self.m.put(addr,self.v[rd] if vec else self.get(rd),n)
   elif (w&0x3b200c00)==0x38200800: # register-offset integer memory
    opc=(w>>22)&3;n=1<<((w>>30)&3);opt=(w>>13)&7
    if w&(1<<26) or opc not in (0,1):raise Unsupported('register memory variant')
    offset=self.get(rm)
    if opt==2:offset&=0xffffffff
    elif opt==6:offset=sx(offset&0xffffffff,32)
    elif opt!=3:raise Unsupported('unsupported address extend')
    if w&(1<<12):offset*=n
    addr=(self.get(rn)+offset)&MASK
    if opc:self.put(rd,self.m.get(addr,n))
    else:self.m.put(addr,self.get(rd),n)
   elif (w&0x3b200c00)==0x38000000: # LDUR/STUR integer
    opc=(w>>22)&3;n=1<<((w>>30)&3)
    if opc not in (0,1) or w&(1<<26):raise Unsupported('unscaled memory variant')
    addr=(self.get(rn)+sx((w>>12)&511,9))&MASK
    if opc:self.put(rd,self.m.get(addr,n))
    else:self.m.put(addr,self.get(rd),n)
   elif (w&0x3f208c00)==0x38200000: # LSE atomic RMW, single-thread data semantics
    n=1<<((w>>30)&3);op=(w>>12)&7;src=self.get(rm)&((1<<(n*8))-1);addr=self.get(rn);old=self.m.get(addr,n)
    if op==0:new=old+src
    elif op==1:new=old&~src
    elif op==2:new=old^src
    elif op==3:new=old|src
    else:raise Unsupported('LSE operation')
    self.m.put(addr,new,n);self.put(rd,old)
   elif (w&0x3ffffc00) in (0x08dffc00,0x089ffc00): # LDAR/STLR
    n=1<<((w>>30)&3);addr=self.get(rn)
    if w&(1<<22):self.put(rd,self.m.get(addr,n))
    else:self.m.put(addr,self.get(rd),n)
   elif (w&0x3a000000)==0x28000000: # pair integer offset
    if w&(1<<26):raise Unsupported('vector pair')
    n=8 if w>>31 else 4;mode=(w>>23)&3;off=sx((w>>15)&127,7)*n;rt2=(w>>10)&31
    base=self.sp if rn==31 else self.get(rn);addr=base if mode==1 else (base+off)&MASK
    if w&(1<<22):self.put(rd,self.m.get(addr,n));self.put(rt2,self.m.get(addr+n,n))
    else:self.m.put(addr,self.get(rd),n);self.m.put(addr+n,self.get(rt2),n)
    if mode in (1,3):
     if rn==31:self.sp=(base+off)&MASK
     else:self.put(rn,base+off)
   elif (w&0x1f000000)==0x11000000: # ADD/SUB immediate
    imm=((w>>10)&4095)<<(12 if w&(1<<22) else 0);sub=bool(w&(1<<30));a=(self.sp if rn==31 else self.get(rn))&m
    result=(a-imm if sub else a+imm)&m
    if w&(1<<29):self.flags(a,imm,result,size,sub)
    if rd==31 and not(w&(1<<29)):self.sp=result
    else:self.put(rd,result,size)
   elif (w&0x1f200000)==0x0b000000: # ADD/SUB shifted register
    sh=(w>>22)&3;amt=(w>>10)&63
    b=(b<<amt)&m if sh==0 else b>>amt if sh==1 else sx(b,size)>>amt if sh==2 else None
    if b is None:raise Unsupported('add shift type')
    sub=bool(w&(1<<30));result=(a-b if sub else a+b)&m
    if w&(1<<29):self.flags(a,b,result,size,sub)
    self.put(rd,result,size)
   elif (w&0x1fe00000)==0x0b200000: # ADD extended (UXTW)
    opt=(w>>13)&7;amt=(w>>10)&7
    if opt in (0,1,2):b&=(1<<(8<<opt))-1
    elif opt in (4,5,6):b=sx(b&((1<<(8<<(opt-4)))-1),8<<(opt-4))
    elif opt not in (3,7):raise Unsupported('add extend')
    b<<=amt;sub=bool(w&(1<<30));v=a-b if sub else a+b
    if w&(1<<29):self.flags(a,b,v,size,sub)
    self.put(rd,v,size)
   elif (w&0x1fe0f000)==0x1ac02000: # variable LSL/LSR/ASR/ROR
    op=(w>>10)&3;amount=b&(size-1);v=(a<<amount)&m if op==0 else a>>amount if op==1 else sx(a,size)>>amount if op==2 else ror(a,amount,size)
    self.put(rd,v,size)
   elif (w&0x1f800000)==0x12800000: # move wide
    opc=(w>>29)&3;sh=((w>>21)&3)*16;v=((w>>5)&65535)<<sh
    if opc==0:v=~v
    elif opc==3:v=(self.get(rd)&~(65535<<sh))|v
    elif opc!=2:raise Unsupported('wide move opc')
    self.put(rd,v,size)
   elif (w&0x1f800000)==0x12000000: # logical immediate
    n=(w>>22)&1;ss=(w>>10)&63;rr=(w>>16)&63;length=((n<<6)|((~ss)&63)).bit_length()-1
    if length<1:raise Unsupported('invalid logical mask')
    es=1<<length;levels=es-1;ss&=levels;rr&=levels
    if ss==levels or es>size:raise Unsupported('invalid logical mask')
    e=ror((1<<(ss+1))-1,rr,es);v=sum(e<<p for p in range(0,size,es));op=(w>>29)&3
    result=a&v if op in (0,3) else a|v if op==1 else a^v
    if op==3:self.logicalflags(result,size)
    self.put(rd,result,size)
   elif (w&0x1f800000)==0x13000000: # unsigned/signed bitfield, shifts
    immr=(w>>16)&63;imms=(w>>10)&63;opc=(w>>29)&3
    if opc==1:raise Unsupported('BFM not implemented')
    if imms>=immr:
     n=imms-immr+1;v=(a>>immr)&((1<<n)-1)
     if opc==0:v=sx(v,n)
    else:
     v=(a&((1<<(imms+1))-1))<<(size-immr)
     if opc==0:v=sx(v& m,size)
    self.put(rd,v,size)
   elif (w&0x1f000000)==0x0a000000: # logical shifted register
    sh=(w>>22)&3;amt=(w>>10)&63
    b=(b<<amt)&m if sh==0 else b>>amt if sh==1 else (sx(b,size)>>amt)&m if sh==2 else ror(b,amt,size)
    if w&(1<<21):b=(~b)&m
    op=(w>>29)&3;v=a&b if op in (0,3) else a|b if op==1 else a^b
    if op==3:self.logicalflags(v,size)
    self.put(rd,v,size)
   elif (w&0xff20fc00) in (0x4e201c00,0x4e601c00,0x4ea01c00,0x6e201c00):
    key=w&0xffe0fc00;av=self.v[rn];bv=self.v[rm]
    if key==0x4e201c00:v=av&bv
    elif key==0x4e601c00:v=av&~bv
    elif key==0x4ea01c00:v=av|bv
    elif key==0x6e201c00:v=av^bv
    else:raise Unsupported(f'vector logic {w:08x}')
    self.v[rd]=v&((1<<128)-1)
   elif (w&0xff20bc00)==0x4e003800: # ZIP1/ZIP2
    n=1<<((w>>22)&3);hi=bool(w&(1<<14));av=self.v[rn].to_bytes(16,'little');bv=self.v[rm].to_bytes(16,'little');start=8 if hi else 0
    v=b''.join(av[k:k+n]+bv[k:k+n] for k in range(start,start+8,n));self.v[rd]=int.from_bytes(v,'little')
   elif (w&0xff000010)==0x54000000:
    if self.cond(w&15):nextpc=pc+sx((w>>5)&0x7ffff,19)*4
   elif (w&0x7e000000)==0x34000000:
    v=self.get(rd)&m;take=bool(v) if w&(1<<24) else not v
    if take:nextpc=pc+sx((w>>5)&0x7ffff,19)*4
   elif (w&0x7e000000)==0x36000000:
    bit=((w>>31)<<5)|((w>>19)&31);v=(self.get(rd)>>bit)&1
    if bool(v)==bool(w&(1<<24)):nextpc=pc+sx((w>>5)&0x3fff,14)*4
   elif (w&0xfc000000)==0x14000000:nextpc=pc+sx(w&0x3ffffff,26)*4
   elif (w&0xfffffc1f)==0xd63f0000:
    if self.helper is None:raise Unsupported('helper call with no contract handler')
    self.helper(self,self.get(rn))
   elif (w&~(31<<5)) in (0x3a00080d,0x3a00480d):
    n=16 if w&(1<<14) else 8;v=self.get(rn);self.nzcv=((v>>(n-1))&1,int((v&((1<<n)-1))==0),self.nzcv[2],((v>>n)^(v>>(n-1)))&1)
   elif (w&0x1fe00000)==0x1a800000: # conditional select family
    cond=(w>>12)&15
    if self.cond(cond):v=a
    else:
     v=b
     if w&(1<<30):v=~v
     if w&(1<<10):v+=1
    self.put(rd,v,size)
   else:raise Unsupported(f'unsupported A64 word {w:08x} at +{pc:#x}')
   pc=nextpc
  return self
