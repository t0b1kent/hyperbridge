"""Deterministic raw-bit inputs. No NaNs are round-tripped through Python floats."""
import struct
SEED=0x8a1020c5eed5e2
MASK=(1<<64)-1
class SplitMix64:
 def __init__(self,seed):self.s=seed&MASK
 def next(self):
  self.s=(self.s+0x9e3779b97f4a7c15)&MASK;z=self.s
  z=((z^(z>>30))*0xbf58476d1ce4e5b9)&MASK;z=((z^(z>>27))*0x94d049bb133111eb)&MASK
  return z^(z>>31)
def fp_values(bits,conversions=False):
 mant=23 if bits==32 else 52;bias=127 if bits==32 else 1023;exp=255 if bits==32 else 2047
 inf=exp<<mant;q=1<<(mant-1);one=bias<<mant
 pos=[0,1,(1<<mant)-1,1<<mant,(1<<mant)+1,one,one-1,one+1,(bias-1)<<mant,(bias+1)<<mant,((bias+1)<<mant)+(1<<(mant-1)),inf-1,inf,inf|q|1,inf|q|0x12345,inf|q|(q-1),inf|1,inf|0x12345,inf|(q-1)]
 if conversions:
  for e in [23,24,31,32,52,53,63,64]:
   b=(bias+e)<<mant;pos.extend([b-2,b-1,b,b+1,b+2])
  for f in [0.49999999999999994,0.5,1.5,2.5,2147483647.5,2147483647.,2147483649.,2147483648.5,9223372036854774784.,9223372036854775808.]:
   b=int.from_bytes(struct.pack('<f' if bits==32 else '<d',f),'little');pos.append(b)
 return list(dict.fromkeys(pos+[x|(1<<(bits-1)) for x in pos]))
def int_values(bits):
 mask=(1<<bits)-1;signed=[0,1,-1,2,-2,3,-3,(1<<(bits-1))-1,-(1<<(bits-1))]
 for e in [23,24,31,32,52,53,62]:
  if e<bits:
   for d in [-2,-1,0,1,2]:signed.extend([(1<<e)+d,-((1<<e)+d)])
 return list(dict.fromkeys(x&mask for x in signed))
def inputs(op,random_count=256):
 bits=op['bits'];size=bits//8;packed=op['kind'] in ['packed','packconvert','intpack'];integer=op['kind']=='intpack' or op['family']=='cvtdq2ps'
 vals=int_values(bits) if integer else fp_values(bits,op['kind'] in ['convert','ftoi','packconvert'])
 rng=SplitMix64(SEED ^ sum((i+1)*ord(c) for i,c in enumerate(op['name'])))
 def lanes(v,j,side):
  b=v.to_bytes(size,'little')
  if packed:
   for k in range(1,16//size):b+=vals[(j+7*k+side*3)%len(vals)].to_bytes(size,'little')
   return b
  return b+bytes(((37*i+51+side*67)&255) for i in range(16-size))
 if op['kind']=='itof':
  iv=int_values(op['intbits'])+[rng.next()&((1<<op['intbits'])-1) for _ in range(random_count)]
  for j,v in enumerate(iv):yield f'i{j}',lanes(vals[j%len(vals)],j,0),bytes(16),v
 elif op['family'] in ['sqrt','cvtss2sd','cvtsd2ss','ftoi','ftoi_t','cvtdq2ps','cvttps2dq']:
  for j,v in enumerate(vals):yield f'u{j}',lanes(vals[(j+3)%len(vals)],j,0),lanes(v,j,1),0xdefaced5badbeef0
  for j in range(random_count):yield f'r{j}',rng.next().to_bytes(8,'little')+rng.next().to_bytes(8,'little'),rng.next().to_bytes(8,'little')+rng.next().to_bytes(8,'little'),0xdefaced5badbeef0
 else:
  for i,a in enumerate(vals):
   for j,b in enumerate(vals):yield f'p{i}.{j}',lanes(a,i,0),lanes(b,j,1),0xdefaced5badbeef0
  for j in range(random_count):yield f'r{j}',rng.next().to_bytes(8,'little')+rng.next().to_bytes(8,'little'),rng.next().to_bytes(8,'little')+rng.next().to_bytes(8,'little'),0xdefaced5badbeef0
MXCSRS=[0x1f80|(rc<<13)|(daz<<6)|(ftz<<15) for daz,ftz in [(0,0),(1,1),(1,0),(0,1)] for rc in range(4)]
