#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent 0031 checker. Uses signed range/nibble borrow semantics, not captured flags."""
import argparse, collections, csv, hashlib, json, pathlib, re, sys
FLAGS=0x8d5
BOUNDARIES=[0,1,2,0xf,0x10,0x7f,0x80,0xff,0x100,0x7fff,0x8000,0xffff,0x10000,0x7fffffff,0x80000000,0xffffffff,0x100000000,0x7fffffffffffffff,0x8000000000000000,0xffffffffffffffff]

def expected(op,w,a,b,fi):
    m=(1<<w)-1; sign=1<<(w-1)
    assert a==a&m
    def signed(x): return x-(1<<w) if x&sign else x
    if op.startswith('test'):
        r=a&b; f=0; defined=FLAGS&~0x10
    else:
        inc=op.startswith('inc'); dec=op.startswith('dec')
        add=inc or op.startswith('add')
        sub=dec or op.startswith('sub') or op.startswith('cmp')
        assert add or sub,op
        if inc or dec: b=1
        assert b==b&m
        raw=a+b if add else a-b; r=raw&m
        cf=raw>m if add else a<b
        af=(a%16+b%16)>15 if add else a%16<b%16
        sr=signed(a)+signed(b) if add else signed(a)-signed(b)
        of=not (-sign<=sr<sign)
        f=int(cf)|(int(af)<<4)|(int(of)<<11)
        if inc or dec:f=(f&~1)|(fi&1)
        defined=FLAGS
    f|=(int((r&255).bit_count()%2==0)<<2)|(int(r==0)<<6)|(int(r>=sign)<<7)
    return r,f,defined

SEED=0x0031c0ffee123456
MASK64=(1<<64)-1
STATES4=(0,FLAGS,1,FLAGS^1)
def randoms(seed,count):
    s=seed
    for _ in range(count):
        s=(s+0x9e3779b97f4a7c15)&MASK64
        z=((s^(s>>30))*0xbf58476d1ce4e5b9)&MASK64
        z=((z^(z>>27))*0x94d049bb133111eb)&MASK64
        yield z^(z>>31)
def expected_inputs(section):
    if section in 'AB':
        for op in (('inc','dec') if section=='A' else ('add1','sub1')):
            for w in (8,16,32,64):
                vals=list(range(256)) if w==8 else [x&((1<<w)-1) for x in BOUNDARIES]+[x&((1<<w)-1) for x in randoms(SEED^w,4096)]
                for a in vals:
                    for fi in STATES4:yield (op,w,fi,a,0 if section=='A' else 1)
    elif section=='C':
        for op in ('cmp_m8_imm8','test_m8_imm8'):
            for a in range(256):
                for b in range(256):
                    for fi in (0,FLAGS):yield (op,8,fi,a,b)
        for op,w,iw in [('cmp_m16_imm8',16,8),('cmp_m16_imm16',16,16),('cmp_m32_imm8',32,8)]:
            for a in BOUNDARIES:
                for b in BOUNDARIES:
                    for fi in (0,FLAGS):yield(op,w,fi,a&((1<<w)-1),b&((1<<iw)-1))
            stream=iter(randoms(SEED^(w<<8)^iw,8192))
            for _ in range(4096):
                a=next(stream)&((1<<w)-1);b=next(stream)&((1<<iw)-1)
                for fi in (0,FLAGS):yield(op,w,fi,a,b)
    elif section=='D':
        for op in ('inc_ah','dec_ch'):
            for a in range(256):
                for fi in STATES4:yield(op,8,fi,a,0)
    else:raise ValueError(section)

def run(folder,repeat=None):
    allcounts={}; errors=[]; testaf=collections.Counter(); signatures={}; lowbytes={}; checked=0; repeats={}; coverage_errors=0
    for p in sorted(folder.glob('*.csv')):
        expected_rows=iter(expected_inputs(p.name[0])); expected_count={'A':100832,'B':100832,'C':289120,'D':2048}[p.name[0]]
        with p.open(newline='') as f:
            reader=csv.DictReader(f); assert reader.fieldnames==['op','width','flags_in','a','b','result','flags_out'],(p,reader.fieldnames)
            counts=collections.Counter(); values=collections.defaultdict(list)
            for n,row in enumerate(reader,2):
                assert all(re.fullmatch(r'0x[0-9a-f]+',row[k]) for k in reader.fieldnames[1:]),(p,n,row)
                op=row['op'].lower(); w=int(row['width'],16); fi=int(row['flags_in'],16); a=int(row['a'],16); b=int(row['b'],16); out=int(row['result'],16); fo=int(row['flags_out'],16)
                expect_input=next(expected_rows,None)
                if expect_input!=(op,w,fi,a,b):
                    coverage_errors+=1
                    if len(errors)<20:errors.append({'file':p.name,'line':n,'input_actual':(op,w,fi,a,b),'input_expected':expect_input})
                # b is the encoded immediate in CSV; 83 /7 forms sign-extend imm8.
                effective_b=b
                if op.startswith('cmp') and 'imm8' in op and w>8:
                    assert b<=255
                    effective_b=b-(256 if b>=128 else 0)
                    effective_b&=(1<<w)-1
                r,ef,defined=expected(op,w,a,effective_b,fi)
                expected_result=r # C explicitly records a derived temporary; no architectural destination write
                if fo&~FLAGS or fi&~FLAGS or ((fo^ef)&defined) or out!=expected_result:
                    if len(errors)<20:errors.append({'file':p.name,'line':n,'row':row,'expected_result':hex(expected_result),'expected_defined_flags':hex(ef&defined),'defined_mask':hex(defined)})
                if p.name[0]=='A' and w==8:lowbytes[(op,fi,a)]=(out,fo)
                if p.name[0]=='D':
                    assert (out,fo)==lowbytes[(op.split('_')[0],fi,a)],(p,n,'high/low mismatch')
                    checked+=1
                if op.startswith('test'):testaf[f'{fi:#x}:{(fo>>4)&1}']+=1
                counts[(op,w,fi)]+=1
                values[(op,w,fi)].append((a,b,out,fo))
            assert sum(counts.values())==expected_count,(p,sum(counts.values()),expected_count)
            assert next(expected_rows,None) is None,(p,'missing expected rows')
            allcounts[p.name]={'rows':sum(counts.values()),'groups':[{'op':o,'width':w,'flags_in':hex(fi),'rows':c} for (o,w,fi),c in sorted(counts.items())]}
            signatures[p.name]=hashlib.sha256(p.read_bytes()).hexdigest()
            if repeat is not None:
                repeats[p.name]=p.read_bytes()==(repeat/p.name).read_bytes()
                assert repeats[p.name],(p,'repeat differs')
    assert allcounts,'No CSVs found'
    return {'status':'PASS' if not errors else 'FAIL','files':allcounts,'test_af_observed':dict(testaf),'sha256':signatures,'errors':errors,'coverage_errors':coverage_errors,'high_low_byte_rows_matched':checked,'repeat_byte_identity':repeats,'total_rows':sum(f['rows'] for f in allcounts.values())}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('folder',type=pathlib.Path);p.add_argument('--repeat',type=pathlib.Path);args=p.parse_args()
    r=run(args.folder,args.repeat);print(json.dumps(r,indent=2));sys.exit(bool(r['errors']))
