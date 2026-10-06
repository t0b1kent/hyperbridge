#!/usr/bin/env python3
"""Independent integer reference and exact dataset validator. MIT; see LICENSE."""
import collections
import csv
import hashlib
import itertools
import json
import re
import sys
from pathlib import Path

MASK64=(1<<64)-1
FLAGS=0x8d5
SEED=0x0031c0ffee123456
EDGES=[0,1,2,0xf,0x10,0x7f,0x80,0xff,0x100,0x7fff,0x8000,0xffff,
       0x10000,0x7fffffff,0x80000000,0xffffffff,0x100000000,
       0x7fffffffffffffff,0x8000000000000000,0xffffffffffffffff]
STATES=[0,FLAGS,1,FLAGS^1]
FILES=['A-inc-dec.csv','B-add1-sub1.csv','C-memory-cmp-test.csv','D-high-byte.csv']
COUNTS=[100832,100832,289120,2048]

def randoms(seed):
    while True:
        seed=(seed+0x9e3779b97f4a7c15)&MASK64
        z=((seed^(seed>>30))*0xbf58476d1ce4e5b9)&MASK64
        z=((z^(z>>27))*0x94d049bb133111eb)&MASK64
        yield z^(z>>31)

def values(w):
    if w==8:
        return list(range(256))
    return [x&((1<<w)-1) for x in EDGES]+[x&((1<<w)-1) for x in itertools.islice(randoms(SEED^w),4096)]

def expected_inputs(section):
    if section in (0,1):
        for op in (('INC','DEC') if section==0 else ('ADD1','SUB1')):
            for w in (8,16,32,64):
                for a in values(w):
                    for fi in STATES:
                        yield op,w,fi,a,(0 if section==0 else 1)
    elif section==2:
        for op in ('CMP_M8_IMM8','TEST_M8_IMM8'):
            for a in range(256):
                for b in range(256):
                    for fi in (0,FLAGS):
                        yield op,8,fi,a,b
        for op,w,iw in [('CMP_M16_IMM8',16,8),('CMP_M16_IMM16',16,16),('CMP_M32_IMM8',32,8)]:
            for a in EDGES:
                for b in EDGES:
                    for fi in (0,FLAGS):
                        yield op,w,fi,a&((1<<w)-1),b&((1<<iw)-1)
            r=randoms(SEED^(w<<8)^iw)
            for _ in range(4096):
                a,b=next(r)&((1<<w)-1),next(r)&((1<<iw)-1)
                for fi in (0,FLAGS):
                    yield op,w,fi,a,b
    else:
        for op in ('INC_AH','DEC_CH'):
            for a in range(256):
                for fi in STATES:
                    yield op,8,fi,a,0

def reference(op,w,fi,a,b):
    modulus=1<<w
    mask=modulus-1
    sign=modulus>>1
    def signed(x):
        return x if x<sign else x-modulus
    test=op.startswith('TEST')
    add=op in ('INC','INC_AH','ADD1')
    incdec=op in ('INC','INC_AH','DEC','DEC_CH')
    if op in ('INC','INC_AH','DEC','DEC_CH','ADD1','SUB1'):
        b=1
    elif 'IMM8' in op and w>8 and b>=128:
        b=(b-256)&mask
    if test:
        r=a&b
        cf=of=af=0
    else:
        exact=a+b if add else a-b
        r=exact&mask
        cf=(exact>=modulus) if add else (a<b)
        signed_result=signed(a)+signed(b) if add else signed(a)-signed(b)
        of=not(-sign<=signed_result<sign)
        af=((a&15)+(b&15)>15) if add else ((a&15)<(b&15))
    if incdec:
        cf=bool(fi&1)
    pf=(r&255).bit_count()%2==0
    flags=int(cf)|(int(pf)<<2)|(int(af)<<4)|(int(r==0)<<6)|(int(bool(r&sign))<<7)|(int(of)<<11)
    return r,flags,(FLAGS^0x10 if test else FLAGS)

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):
            h.update(block)
    return h.hexdigest()

def main():
    first=Path(sys.argv[1]) if len(sys.argv)>1 else Path('.')
    second=Path(sys.argv[2]) if len(sys.argv)>2 else Path('repeat')
    report={'status':'PASS','defined_flag_mismatches':0,'result_mismatches':0,
            'coverage_and_order':'exact match','seed':f'0x{SEED:016x}',
            'duplicate_policy':'preserve all truncated edge entries and random draws',
            'files':{},'operations':{},'undefined_flags':{}}
    highref={}
    afhist=collections.Counter()
    for section,name in enumerate(FILES):
        path=first/name
        h1,h2=digest(path),digest(second/name)
        if h1!=h2 or path.read_bytes()!=(second/name).read_bytes():
            raise AssertionError(f'{name}: repeated runs differ')
        n=0
        with path.open(newline='') as f:
            reader=csv.reader(f)
            assert next(reader)==['op','width','flags_in','a','b','result','flags_out']
            for n,pair in enumerate(itertools.zip_longest(reader,expected_inputs(section)),1):
                fields,expected=pair
                assert fields is not None and expected is not None,(name,n,'row count')
                assert len(fields)==7,(name,n,'column count')
                assert all(re.fullmatch('0x[0-9a-f]+',s) for s in fields[1:]),(name,n,'hex formatting')
                op=fields[0]
                w,fi,a,b,result,fo=map(lambda s:int(s,16),fields[1:])
                assert (op,w,fi,a,b)==expected,(name,n,'coverage/order',expected,fields)
                assert fi&~FLAGS==0 and fo&~FLAGS==0
                r,flags,defined=reference(op,w,fi,a,b)
                assert r==result,(name,n,'result',r,result)
                assert (fo^flags)&defined==0,(name,n,'flags',flags,fo,defined)
                report['operations'][op]=report['operations'].get(op,0)+1
                if op.startswith('TEST'):
                    afhist[f'flags_in=0x{fi:03x},observed_AF={(fo>>4)&1}']+=1
                if section==0 and w==8:
                    highref[(op,a,fi)]=(result,fo)
                if section==3:
                    lowop='INC' if op=='INC_AH' else 'DEC'
                    assert highref[(lowop,a,fi)]==(result,fo),(name,n,'high/low byte disagreement')
        assert n==COUNTS[section],(name,n)
        report['files'][name]={'data_rows':n,'sha256_first_run':h1,'sha256_second_run':h2,'byte_identical':True}
    report['total_data_rows']=sum(COUNTS)
    report['high_byte_vs_low_byte']='all 2048 result/flags pairs equal'
    report['undefined_flags']={'TEST_M8_IMM8':{'flag':'AF','bit':'0x010','excluded_from_mismatch_check':True,'hardware_observations':dict(sorted(afhist.items()))}}
    print(json.dumps(report,indent=2,sort_keys=True))

if __name__=='__main__':
    main()
