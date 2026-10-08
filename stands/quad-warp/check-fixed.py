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
P = [(0xbf600000,0x3f600000,0,0x3f800000),(0xbf600000,0xbf600000,0,0x3f800000),
     (0x3f600000,0xbf600000,0,0x3f800000),(0x3f600000,0x3f600000,0,0x3f800000)]
C = [(0,0,0x3e800000,0x3f800000),(0,0,0x3e800000,0x3f800000),
     (0,0x3f800000,0x3e800000,0x3f800000),(0x3f800000,0x3f800000,0x3e800000,0x3f800000)]
IDS = [1,2,0,0,2,3]

def index(vid, shift, cfg):
    local = (vid % 3 + cfg[0] + shift) % 3
    if cfg[1] and local: local = 3-local
    return IDS[vid//3*3+local]

def expected(vid, cfg):
    pi,ci = index(vid,0,cfg), index(vid,cfg[2],cfg)
    return (vid,pi,ci,cfg[6],*P[pi],*C[ci])

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
    return dict(vertex_positive=1,vertex_negative=len(bad),permutations=6)

def qualify(run):
    cases=list(csv.DictReader((run/'cases.csv').open(encoding='utf-8-sig')))
    assert len(cases)==12 and len({c['name'] for c in cases})==12
    assert {(int(c['rotation']),int(c['reverse']),int(c['color_shift'])) for c in cases}=={
        (r,v,s) for r in range(3) for v in range(2) for s in range(2)}
    rows=[];images={};arms={};raw=[]
    for observed in [False,True]:
        for floating in [False,True]:
            arm=('raw-float' if floating else 'raw')+('-observed' if observed else '')
            root=run/arm;device=json.loads((root/'device.json').read_text());arms[arm]=device
            assert (device['backend'],device['software']) in [('WARP, not hardware',True),('Metal',False)]
            assert device['observer']==observed
            assert device['format']==('RGBA32_FLOAT' if floating else 'RGBA8_UNORM')
            results=[json.loads(l) for l in (root/'results.jsonl').read_text().splitlines()]
            assert len(results)==24;results={(r['name'],r['pass']):r for r in results};assert len(results)==24
            for c in cases:
                cfg=(int(c['rotation']),int(c['reverse']),int(c['color_shift']),0,0,0,int(c['tag']),64)
                cd=root/c['name'];assert (cd/'params.bin').read_bytes()==struct.pack('<8I',*cfg)
                last=0
                for p in [0,1]:
                    image=(cd/('front.pixels.bin' if p else 'own.pixels.bin')).read_bytes()
                    assert len(image)==16384*(16 if floating else 4)
                    if floating:
                        values=struct.unpack('<65536f',image)
                        assert all(math.isfinite(v) and 0<=v<=1 for v in values), 'float range'
                        alpha=values[3::4];assert set(alpha)<={0.,1.}
                    else:alpha=image[3::4];assert set(alpha)<={0,255}
                    covered=sum(a!=0 for a in alpha);assert covered==(12544 if not p else (12544 if cfg[1] else 0)), 'coverage winding'
                    last=vertex((cd/('recorder.bin' if p else 'recorder-uncull.bin')).read_bytes(),cfg,last)
                    r=results[c['name'],p];assert r['covered']==covered and r['invocations_cumulative']==last and r['guards_tags'] is True and r['overflow']==0
                    active=legacy.qualify_fragment(image,(cd/('fragment.bin' if p else 'fragment-uncull.bin')).read_bytes(),floating,observed)
                    images[arm,c['name'],p]=image
                    rows.append(dict(arm=arm,name=c['name'],pass_index=p,covered=covered,fragment_records=active,vertex_invocations=last,sha256=hashlib.sha256(image).hexdigest()))
            for path in sorted(root.rglob('*')):
                if path.is_file():raw.append(dict(path=str(path.relative_to(run)),bytes=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    assert len({x['backend'] for x in arms.values()})==1
    observer_equal=0;negative=0;matrix=[]
    for floating in [False,True]:
        arm='raw-float' if floating else 'raw'
        for c in cases:
            for p in [0,1]:
                assert images[arm,c['name'],p]==images[arm+'-observed',c['name'],p], 'observer target drift';observer_equal+=1
        for n in range(6):
            base=images[arm,'c0000',0];actual=images[arm,f'c{n:04}',0]
            diff=sum(x!=y for x,y in zip(base,actual))
            matrix.append(dict(format=arm,rotation=n%3,reverse=n//3,different_bytes_from_order0=diff,sha256=hashlib.sha256(actual).hexdigest()))
            assert images[arm,f'c{n:04}',0]!=images[arm,f'c{n+6:04}',0], 'color negative';negative+=1
    return dict(status='PRESENT',backend=next(iter(arms.values()))['backend'],cases=12,draws=96,observer_targets_equal=observer_equal,
                color_negatives_detected=negative,permutation_matrix=matrix,rows=rows,raw=raw)

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--run',type=Path);ap.add_argument('--test',action='store_true');a=ap.parse_args()
    if a.test:print(json.dumps(tests()))
    else:
        result=qualify(a.run)
        (a.run/'QUALIFICATION.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps({k:v for k,v in result.items() if k not in ['raw','rows']}))
