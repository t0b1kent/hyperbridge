#!/usr/bin/env python3
"""Original MIT independent ordinary C + correctly rounded mpmath crosschecks."""
import pathlib,gzip,ctypes,subprocess,collections,json,math,argparse
P=pathlib.Path(__file__).resolve().parent
subprocess.run(['gcc','-shared','-fPIC','-O0','-frounding-math','-fexcess-precision=standard','-fno-builtin','numeric_crosscheck.c','-lm','-o','build/numeric.so'],cwd=P,check=True)
lib=ctypes.CDLL(str(P/'build/numeric.so'))
lib.arithmetic.argtypes=[ctypes.c_char_p,ctypes.c_int]+[ctypes.c_char_p]*4
lib.conversion.argtypes=[ctypes.c_char_p,ctypes.c_int]+[ctypes.c_char_p]*3

def rows(cls):
 with gzip.open(P/f'out-{cls}.txt.gz','rt') as f:
  for line in f:
   if not line.startswith('#'):
    t=line.split();yield t,line.rstrip()
def bits(s):return bytes.fromhex(s)[::-1] if s not in ('empty','-') else bytes(10)
counts=collections.Counter();mismatches=[]
for cls in ('arithmetic','load-store'):
 for t,line in rows(cls):
  name,cw=t[0],int(t[1],16);expected=ctypes.create_string_buffer(16)
  if cls=='arithmetic':
   r=lib.arithmetic(name.encode(),cw,bits(t[2]),bits(t[3]),bits(t[4]),expected)
   n=10;actual=t[7] if '_ST1_ST0' in name and not name.split('_')[0].endswith('P') else t[6]
  else:r=lib.conversion(name.encode(),cw,bits(t[2]),bits(t[4]),expected);n=r;actual=t[6] if name.startswith(('FLD_','FILD_')) else t[8]
  if r<0:continue
  label=f'{cls}:C-'+('long-double' if cw&0x300==0x300 else ('double-PC53-nearest' if cls=='arithmetic' else 'conversion-PC53-nearest'))
  counts[label]+=1;want=expected.raw[:n][::-1].hex()
  if want!=actual:mismatches.append(dict(check=label,expected=want,actual=actual,row=line))
(P/'numeric-crosscheck.json').write_text(json.dumps(dict(counts=counts,mismatches=mismatches),indent=2)+'\n')
print('C numeric',dict(counts),'mismatches',len(mismatches),flush=True)
# High-precision arithmetic model is used only for validation, never native output.
import mpmath as mp
args=argparse.ArgumentParser();args.add_argument('--precision',type=int,default=640);precision=args.parse_args().precision
assert precision>=256
mp.mp.prec=precision

def decode(s):
 if s in ('-','empty'):return None
 z=int(s,16);se=z>>64;m=z&((1<<64)-1);e=se&32767
 if e==32767 or (e and not m>>63):return None
 return (-1 if se>>15 else 1)*mp.mpf(m)*mp.power(2,(e if e else 1)-16383-63)
def round80(x):
 if not mp.isfinite(x):return None
 sign=0x8000 if x<0 else 0;x=abs(x)
 if not x:return f'{sign:04x}'+16*'0'
 e=int(mp.floor(mp.log(x,2)));k=max(e-63,-16445);q=x/mp.power(2,k);n=int(mp.floor(q));frac=q-n
 if frac>mp.mpf('.5') or (frac==mp.mpf('.5') and n%2):n+=1
 if n>=1<<64:n>>=1;e+=1
 if e>16383:return None
 se=0 if e<-16382 and n<(1<<63) else max(e+16383,1)
 return f'{se|sign:04x}{n:016x}'
def ulp_index(s):
 z=int(s,16);se=z>>64;m=z&((1<<64)-1);e=se&32767
 if e==32767:return None
 # Ordinal distance in representable finite binary80 values, omit explicit integer bit.
 v=((max(1,e)-1)<<63)+m
 return -v if se>>15 else v
stats={};samples=[];skips=collections.Counter()
for t,line in rows('transcendental'):
 name=t[0]
 if t[1]!='037f':continue
 x,y=decode(t[2]),decode(t[3]);sw=int(t[9],16)
 if x is None or (name in ('FPATAN','FYL2X','FYL2XP1') and y is None):skips[name+':noncanonical-or-infinite']+=1;continue
 if sw&0x400:skips[name+':C2-range']+=1;continue
 if name=='F2XM1' and abs(x)>1:skips[name+':outside-documented-domain']+=1;continue
 if (name=='FYL2X' and x<=0) or(name=='FYL2XP1' and x<=-1):skips[name+':log-domain']+=1;continue
 # Avoid astronomically large intermediate exponents and include all bounded finite grid rows.
 if abs(x)>mp.power(2,64) or (y is not None and abs(y)>mp.power(2,64)):skips[name+':bounded-highprecision-domain']+=1;continue
 try:
  if name=='FSIN':pairs=[('sin',mp.sin(x),t[6])]
  elif name=='FCOS':pairs=[('cos',mp.cos(x),t[6])]
  elif name=='FSINCOS':pairs=[('cos',mp.cos(x),t[6]),('sin',mp.sin(x),t[7])]
  elif name=='FPTAN':pairs=[('tan',mp.tan(x),t[7])]
  elif name=='FPATAN':
   z=mp.atan2(y,x)
   if y==0 and (x<0 or (x==0 and int(t[2][:4],16)&0x8000)):
    z=-mp.pi if int(t[3][:4],16)&0x8000 else mp.pi
   pairs=[('atan2',z,t[6])]
  elif name=='F2XM1':pairs=[('exp2m1',mp.expm1(x*mp.log(2)),t[6])]
  elif name=='FYL2X':pairs=[('ylog2x',y*mp.log(x,2),t[6])]
  elif name=='FYL2XP1':pairs=[('ylog2p1',y*mp.log1p(x)/mp.log(2),t[6])]
  else:continue
 except (ValueError,OverflowError):skips[name+':mpmath-domain']+=1;continue
 for component,z,actual in pairs:
  expected=round80(z)
  if expected is None or decode(actual) is None:skips[name+':nonfinite-result']+=1;continue
  # Zero sign is unspecified by real-number reference and is compared by numeric index.
  error=abs(ulp_index(actual)-ulp_index(expected));bucket='large' if abs(x)>=mp.power(2,20) else 'ordinary'
  key=f'{name}/{component}/{bucket}'
  st=stats.setdefault(key,dict(count=0,exact=0,within1=0,over1=0,max_ulp=0))
  st['count']+=1;st['exact']+=error==0;st['within1']+=error<=1;st['over1']+=error>1
  if error>st['max_ulp']:st['max_ulp']=error;st['worst']=dict(input=t[2:4],actual=actual,correct=expected)
  samples.append(dict(op=name,component=component,input=t[2:4],actual=actual,correct=expected,ulp_error=error,bucket=bucket))
(P/'transcendental-crosscheck.json').write_text(json.dumps(dict(mpmath_version=mp.__version__,precision_bits=mp.mp.prec,rounding='binary80 nearest-even, 64 significand bits, with subnormals',stats=stats,skips=skips),indent=2)+'\n')
with gzip.GzipFile(filename=str(P/'transcendental-crosscheck-samples.jsonl.gz'),mode='wb',mtime=0) as f:
 for row in samples:f.write((json.dumps(row,sort_keys=True)+'\n').encode())
print('mpmath samples',len(samples),'max ulp',max(s['max_ulp'] for s in stats.values()),flush=True)
if mismatches:raise SystemExit(1)
