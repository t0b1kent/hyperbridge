#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Independent integer/rational validation; never modifies native raw data.
import csv, collections, fractions, json, math, sys
from pathlib import Path
F=fractions.Fraction
root=Path(__file__).resolve().parent
path=Path(sys.argv[1]) if len(sys.argv)>1 else root/'output/raw.csv'
counts=collections.Counter(); mathchecks=0; sqrtchecks=0; storechecks=0; guarded=0; guard_mismatch=0; controls={}; examples={}; bad=[]; mismatch=collections.Counter(); rem={}
def decode(s):
    se=int(s[:4],16); sig=int(s[4:],16); exp=se&0x7fff
    if exp==0x7fff or (exp and not sig>>63):return None
    sign=se>>15; e=(exp or 1)-16383-63
    z=F(sig<<e,1) if e>=0 else F(sig,1<<(-e))
    return -z if sign else z

def floorlog(n,d):
    e=n.bit_length()-d.bit_length()
    if (n < d<<e) if e>=0 else (n<<(-e)<d): e-=1
    return e

def round_real(z,p,rc,negzero=False):
    if not z:return ('8000' if negzero else '0000')+'0000000000000000'
    sign=z<0;z=abs(z);e=floorlog(z.numerator,z.denominator);q=max(e,-16382)-(p-1)
    n,d=z.numerator,z.denominator
    if q>=0:d<<=q
    else:n<<=-q
    k,r=divmod(n,d)
    inc=(2*r>d or (2*r==d and k&1)) if rc==0 else bool(r) and ((rc==1 and sign) or (rc==2 and not sign))
    k+=inc
    if not k:return ('8000' if sign else '0000')+'0000000000000000'
    e=k.bit_length()-1+q
    if e>16383:
        inf=rc==0 or (rc==1 and sign) or (rc==2 and not sign)
        se=0x7fff if inf else 0x7ffe;sig=1<<63 if inf else ((1<<p)-1)<<(64-p)
    elif e>=-16382:se=e+16383;sig=(k<<(64-k.bit_length())) if k.bit_length()<=64 else (k>>(k.bit_length()-64))
    else:se=0;sig=k<<(q+16445)
    return f'{se|(int(sign)<<15):04x}{sig:016x}'

def sqrt_ext(z,p,rc,negzero=False):
    if not z:return ('8000' if negzero else '0000')+'0000000000000000'
    e=floorlog(z.numerator,z.denominator)//2;q=e-(p-1);n,d=z.numerator,z.denominator
    if q>=0:d<<=2*q
    else:n<<=-2*q
    k=math.isqrt(n//d);exact=n==d*k*k;mid=d*(2*k+1)**2
    k+=(4*n>mid or (4*n==mid and k&1)) if rc==0 else (not exact and rc==2)
    e=k.bit_length()-1+q;sig=(k<<(64-k.bit_length())) if k.bit_length()<=64 else (k>>(k.bit_length()-64))
    return f'{e+16383:04x}{sig:016x}'

def store_ieee(z,bits,rc,negzero):
    p,emin,emax,eb=(24,-126,127,8) if bits==32 else (53,-1022,1023,11)
    sign=z<0 or (not z and negzero);z=abs(z)
    if not z:return f'{int(sign)<<(bits-1):0{bits//4}x}'
    e=floorlog(z.numerator,z.denominator);q=max(e,emin)-(p-1);n,d=z.numerator,z.denominator
    if q>=0:d<<=q
    else:n<<=-q
    k,r=divmod(n,d);k+=(2*r>d or(2*r==d and k&1)) if rc==0 else(bool(r)and((rc==1 and sign)or(rc==2 and not sign)))
    if not k:raw=0
    else:
        e=k.bit_length()-1+q
        if e>emax:
            inf=rc==0 or(rc==1 and sign)or(rc==2 and not sign)
            raw=(((1<<eb)-1)<<(p-1)) if inf else ((((1<<eb)-1)<<(p-1))-1)
        elif e>=emin:
            sig=(k<<(p-k.bit_length())) if k.bit_length()<=p else(k>>(k.bit_length()-p))
            raw=((e-emin+1)<<(p-1))|(sig&((1<<(p-1))-1))
        else:raw=k<<(q-emin+p-1)
    raw|=int(sign)<<(bits-1);return f'{raw:0{bits//4}x}'

for r in csv.DictReader(path.open()):
    counts[r['group']]+=1
    cw=int(r['cw'],16);pc=(cw>>8)&3;p=53 if pc==2 else 64;rc=(cw>>10)&3;op=r['op']
    key=(r['group'],op,r['cw'],r['a_name'],r['b_name'],r['case'])
    if r['reg_equal_sse']=='0':mismatch[f'{op}/PC{p}/RC{rc}']+=1
    if r['group']=='remainder-sequence':rem[(op,r['cw'],r['a_name'],r['b_name'])]=int(r['post_sw'],16)&0x400
    if r['group']=='arithmetic' and op in ('fadd','fsub','fmul','fdiv'):
        a,b=decode(r['a_ext80']),decode(r['b_ext80'])
        # Numerical proof check intentionally excludes extreme ext80 exponents and unsupported encodings.
        if a is not None and b is not None and all(not x or -2200 < floorlog(abs(x.numerator),x.denominator)<2200 for x in (a,b)) and not(op=='fdiv' and not b):
            z=a+b if op=='fadd' else a-b if op=='fsub' else a*b if op=='fmul' else a/b
            sa=int(r['a_ext80'][:4],16)>>15;sb=int(r['b_ext80'][:4],16)>>15
            if op in ('fmul','fdiv'):nz=bool(sa^sb)
            else:
                sb^=op=='fsub';nz=(bool(sa) if not a and not b and sa==sb else rc==1)
            expected=round_real(z,p,rc,nz);mathchecks+=1
            if expected!=r['st0']:bad.append({'row':r['row'],'expected':expected,'observed':r['st0']})
            normal=lambda x: not x or F(1,1<<1022)<=abs(x)<=F((1<<53)-1)*F(2)**971
            if pc==2 and r['sse64_bits']!='-' and normal(a) and normal(b) and normal(z):
                guarded+=1;guard_mismatch+=r['reg_equal_sse']!='1'
    if r['group']=='unary' and op=='fsqrt':
        z=decode(r['a_ext80'])
        if z is not None and z>=0:
            expected=sqrt_ext(z,p,rc,int(r['a_ext80'][:4],16)>>15);sqrtchecks+=1
            if expected!=r['st0']:bad.append({'row':r['row'],'expected':expected,'observed':r['st0']})
    if r['group']=='store' and op in ('fst_m32','fstp_m32','fst_m64','fstp_m64'):
        z=decode(r['a_ext80'])
        if z is not None:
            expected=store_ieee(z,int(op[-2:]),rc,int(r['a_ext80'][:4],16)>>15);storechecks+=1
            if expected!=r['memory_bits']:bad.append({'row':r['row'],'expected':expected,'observed':r['memory_bits']})
    if r['group']=='arithmetic' and op=='fmul' and r['a_name']=='double_round_a' and r['b_name']=='double_round_b' and r['cw']=='027f':examples['double_rounding']=r
    if r['group']=='arithmetic' and op=='fmul' and r['a_name']=='dmax' and r['b_name']=='two' and r['cw']=='027f':examples['wide_overflow']=r
    if r['group']=='arithmetic' and op=='fdiv' and r['a_name']=='dminsub' and r['b_name']=='two' and r['cw']=='027f':examples['wide_underflow']=r
    if r['group']=='arithmetic' and op=='fadd' and r['a_name']=='one' and r['b_name']=='eps53' and r['cw']=='037f':examples['pc64_extra_bit']=r
    if r['group']=='unary' and op=='fsqrt' and r['a_name']=='two' and r['cw']=='027f':examples['sqrt_C1']=r
    if r['group']=='arithmetic' and op=='fadd' and r['a_name']=='none' and r['b_name']=='neps53' and r['cw'] in ('067f','0a7f'):examples['negative_C1_'+r['cw']]=r
    if r['group']=='seeded-status':
        pre=int(r['pre_sw'],16);post=int(r['post_sw'],16)
        assert post&0x3f==pre&0x3f and not post&0x200,(r['row'],'sticky/C1')
    if r['group']=='arithmetic' and op=='fsub' and r['a_name']=='three' and r['b_name']=='two':assert r['st0']=='3fff8000000000000000'
    if r['group']=='arithmetic' and op=='fdiv' and r['a_name']=='three' and r['b_name']=='two':assert r['st0']=='3fffc000000000000000'
assert not bad,bad[:20]
assert not guard_mismatch
assert rem and not any(rem.values()),'incomplete remainder sequence'
x=examples['double_rounding'];assert x['memory_bits']=='0008000000000002' and x['sse64_bits']=='0008000000000001'
result={'rows':sum(counts.values()),'groups':dict(counts),'rational_numerical_checks':mathchecks,'rational_failures':len(bad),'integer_sqrt_checks':sqrtchecks,'rational_store32_64_checks':storechecks,'sampled_conservative_PC53_value_guard_rows':guarded,'sampled_guard_mismatches':guard_mismatch,'remainder_sequences_completed':len(rem),'sse_register_mismatches':dict(sorted(mismatch.items())),'examples':examples,'status':'PASS','limit':'Finite grid validates samples, not an exhaustive guard proof. Rational checks cover FADD/FSUB/FMUL/FDIV in the stated exponent subset, plus nonnegative FSQRT and finite FST/FSTP m32/m64, not transcendental accuracy.'}
print(json.dumps(result,indent=2))
