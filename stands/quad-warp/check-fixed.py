#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate fixed vertices/observer bytes; report permutation differences exactly."""
import argparse
import collections
import csv
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import struct

spec = importlib.util.spec_from_file_location('legacy_checker', Path(__file__).with_name('check-output.py'))
legacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legacy)
FIXTURE=json.loads(Path(__file__).with_name('geometry.json').read_text())
P=[g['positions'] for g in FIXTURE['groups']]
C=[g['colors'] for g in FIXTURE['groups']]
IDS=FIXTURE['indices']

def index(vid, shift, cfg):
    local = (vid % 3 + cfg[0] + shift) % 3
    if cfg[1] and local: local = 3-local
    return IDS[vid//3*3+local]

def expected(vid, cfg):
    pi,ci = index(vid,0,cfg), index(vid,cfg[2],cfg)
    return (vid,pi,ci,cfg[6],*P[cfg[3]][pi],*C[cfg[3]][ci])

def vertex(data, cfg, last=0):
    assert len(data)==16+64*48+256, 'vertex size'
    count,overflow,z0,z1=struct.unpack_from('<4I',data)
    assert last <= count <= 64 and count > 0 and (overflow,z0,z1)==(0,0,0), 'vertex header'
    seen=collections.Counter()
    for i in range(count):
        record=struct.unpack_from('<12I',data,16+48*i)
        assert record[0]<6 and record==expected(record[0],cfg), 'vertex values'
        seen[record[0]]+=1
    assert set(seen)==set(range(6)), 'vertex missing'
    assert data[16+48*count:]==b'\xa5'*(len(data)-16-48*count), 'vertex guard'
    return count

def tests():
    cfg=(0,0,0,0,0,0,1,64)
    good=struct.pack('<4I',6,0,0,0)+b''.join(struct.pack('<12I',*expected(i,cfg)) for i in range(6))+b'\xa5'*(58*48+256)
    assert vertex(good,cfg)==6
    bad=[]
    for offset,value in [(0,65),(4,1),(16,6),(20,3),(28,99),(32,0),(48,0x3f800000),(16+6*48,0)]:
        changed=bytearray(good);struct.pack_into('<I',changed,offset,value);bad.append(bytes(changed))
    changed=bytearray(good);changed[16+5*48:16+6*48]=changed[16:16+48];bad.append(bytes(changed))
    for data in bad:
        try:vertex(data,cfg)
        except AssertionError:continue
        raise AssertionError('negative not detected')
    # All six orderings are distinct, retaining identical paired vertices in the identity arm.
    sequences={tuple(index(i,0,(r,v,0)) for i in range(6)) for r in range(3) for v in range(2)}
    assert len(sequences)==6
    # A finite float excursion must remain exact, not be clamped or hidden by
    # tolerance. Exercise both range signs, non-finite words and a one-bit target
    # corruption with the unchanged recorder-layout checks.
    positives=0; negatives=0
    for word in (0x3f800001,0xb4000000):
        image=bytearray(16384*16)
        payload=struct.pack('<4I',word,0,0x3e800000,0x3f800000)
        image[:16]=payload
        data=bytearray(bytes(16)+(struct.pack('<I',0)+b'\xa5'*60)*16384+b'\xa5'*256)
        data[16:80]=struct.pack('<I',1)+b'\xa5'*12+payload+payload+struct.pack('<4f',.5,.5,0.,1.)
        assert legacy.qualify_fragment(bytes(image),bytes(data),True)==1;positives+=1
        for kind in ('target','input','nonfinite','guard'):
            im=bytearray(image);rec=bytearray(data)
            if kind=='target':im[0]^=1
            elif kind=='input':rec[32]^=1
            elif kind=='guard':rec[-1]^=1
            else:
                for off in (0,):struct.pack_into('<I',im,off,0x7f800000)
                for off in (32,48):struct.pack_into('<I',rec,off,0x7f800000)
            try:legacy.qualify_fragment(bytes(im),bytes(rec),True)
            except AssertionError:negatives+=1;continue
            raise AssertionError('fragment negative not detected: '+kind)
    return dict(vertex_positive=1,vertex_negative=len(bad),permutations=6,
                finite_excursion_positive=positives,fragment_negative=negatives)

def float_excursions(image):
    values=struct.unpack('<65536f',image)
    assert all(math.isfinite(v) for v in values), 'float finite'
    counts=collections.Counter();bits=collections.Counter();examples=[];stream=hashlib.sha256()
    for i,v in enumerate(values):
        if 0<=v<=1:continue
        word=struct.unpack_from('<I',image,4*i)[0]
        counts[str(i%4)]+=1;bits[f'{word:08x}']+=1;stream.update(struct.pack('<2I',i,word))
        if len(examples)<8:examples.append(dict(x=i//4%128,y=i//4//128,channel=i%4,word=f'{word:08x}'))
    return values,dict(words=sum(counts.values()),channels=dict(counts),bits=dict(bits),
                       examples_first_8=examples,exact_offset_word_stream_sha256=stream.hexdigest())

def qualify(run):
    cases=list(csv.DictReader((run/'cases.csv').open(encoding='utf-8-sig')))
    normalized=[{k:(v if k=='name' else int(v)) for k,v in c.items()} for c in cases]
    assert normalized==FIXTURE['cases'], 'exact declared matrix'
    rows=[];images={};arms={};raw=[];excursions=[]
    for observed in [False,True]:
        for floating in [False,True]:
            arm=('raw-float' if floating else 'raw')+('-observed' if observed else '')
            root=run/arm;device=json.loads((root/'device.json').read_text());arms[arm]=device
            assert (device['backend'],device['software']) in [('WARP, not hardware',True),('Metal',False)]
            assert device['observer']==observed
            assert device['format']==('RGBA32_FLOAT' if floating else 'RGBA8_UNORM')
            results=[json.loads(l) for l in (root/'results.jsonl').read_text().splitlines()]
            assert len(results)==32;results={(r['name'],r['pass']):r for r in results};assert len(results)==32
            for c in normalized:
                cfg=(c['rotation'],c['reverse'],c['color_shift'],c['geometry'],0,0,c['tag'],64)
                cd=root/c['name'];assert (cd/'params.bin').read_bytes()==struct.pack('<8I',*cfg)
                last=0
                for p in [0,1]:
                    image=(cd/('front.pixels.bin' if p else 'own.pixels.bin')).read_bytes()
                    assert len(image)==16384*(16 if floating else 4)
                    if floating:
                        values,excursion=float_excursions(image)
                        if excursion['words']:excursions.append(dict(arm=arm,name=c['name'],pass_index=p,**excursion))
                        alpha=values[3::4];assert set(alpha)<={0.,1.}
                    else:alpha=image[3::4];assert set(alpha)<={0,255}
                    covered=sum(a!=0 for a in alpha)
                    assert 0<=covered<=16384
                    if not p:assert covered>0, 'uncull empty'
                    elif cfg[1]:assert image==images[arm,c['name'],0], 'front target drift'
                    else:assert image==bytes(len(image)), 'back target nonempty'
                    if cfg[3]==6:
                        expected_pixel=struct.pack('<4I',*C[6][0]) if floating else bytes((32,128,64,255))
                        stride=len(expected_pixel)
                        for pixel in range(16384):
                            actual=image[stride*pixel:stride*(pixel+1)]
                            assert actual==(expected_pixel if alpha[pixel] else bytes(stride)), 'constant color'
                    last=vertex((cd/('recorder.bin' if p else 'recorder-uncull.bin')).read_bytes(),cfg,last)
                    r=results[c['name'],p];assert r['covered']==covered and r['invocations_cumulative']==last and r['guards_tags'] is True and r['overflow']==0
                    active=legacy.qualify_fragment(image,(cd/('fragment.bin' if p else 'fragment-uncull.bin')).read_bytes(),floating,observed)
                    images[arm,c['name'],p]=image
                    rows.append(dict(arm=arm,name=c['name'],geometry=cfg[3],pass_index=p,covered=covered,fragment_records=active,vertex_invocations=last,sha256=hashlib.sha256(image).hexdigest()))
            for path in sorted(root.rglob('*')):
                if path.is_file():raw.append(dict(path=str(path.relative_to(run)),bytes=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    assert len({x['backend'] for x in arms.values()})==1
    observer_equal=0;negative=0;matrix=[]
    for floating in [False,True]:
        arm='raw-float' if floating else 'raw'
        for c in normalized:
            for p in [0,1]:
                assert images[arm,c['name'],p]==images[arm+'-observed',c['name'],p], 'observer target drift';observer_equal+=1
        for g in range(8):
            base=images[arm,f'c{2*g:04}',0];actual=images[arm,f'c{2*g+1:04}',0]
            matrix.append(dict(format=arm,geometry=g,different_bytes_reversed=sum(x!=y for x,y in zip(base,actual))))
            # Report exact ordering differences; do not assume the arithmetic is order invariant.
        for reverse in range(2):
            assert images[arm,f'c{reverse:04}',0]!=images[arm,f'c{14+reverse:04}',0], 'color negative';negative+=1
    return dict(status='PRESENT',backend=next(iter(arms.values()))['backend'],cases=16,draws=128,
                observer_targets_equal=observer_equal,color_negatives_detected=negative,permutation_matrix=matrix,
                rows=rows,raw=raw,float_range_excursions=excursions)

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--run',type=Path);ap.add_argument('--test',action='store_true');a=ap.parse_args()
    if a.test:print(json.dumps(tests()))
    else:
        result=qualify(a.run)
        (a.run/'QUALIFICATION.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps({k:v for k,v in result.items() if k not in ['raw','rows']}))
