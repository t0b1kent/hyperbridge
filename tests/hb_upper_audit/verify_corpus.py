#!/usr/bin/env python3
"""Strict framing/integrity check for the Mac binary corpus (no CPU execution)."""
import argparse,hashlib,json,struct
from pathlib import Path

def main():
    ap=argparse.ArgumentParser();ap.add_argument('corpus',type=Path);a=ap.parse_args();b=a.corpus.read_bytes()
    if b[:8]!=b'HBUP0001':raise SystemExit('bad magic')
    n=struct.unpack_from('<I',b,8)[0];off=12;seen=set();h=hashlib.sha256();groups={}
    if n==0:raise SystemExit('empty corpus')
    for _ in range(n):
        if off+24>len(b):raise SystemExit('truncated header')
        nl,cl,kind,seed,mask=struct.unpack_from('<HHIQQ',b,off);off+=24
        if not(0<nl<=255 and 0<cl<=64) or off+nl+cl+4608>len(b):raise SystemExit('invalid record')
        name=b[off:off+nl].decode();off+=nl;code=b[off:off+cl];off+=cl
        key=(name,seed)
        if key in seen:raise SystemExit('duplicate name/seed')
        seen.add(key);groups[kind]=groups.get(kind,0)+1
        inp=b[off:off+2048];im=b[off+2048:off+2304];expected=b[off+2304:off+4352];em=b[off+4352:off+4608];off+=4608
        h.update(expected+em)
        # Distinct nonzero upper-bank markers are required for useful controls.
        if any(inp[r*64+q*8:r*64+q*8+8]==bytes(8) for r in range(32) for q in range(2,8)):
            raise SystemExit('zero upper sentinel')
    if off!=len(b):raise SystemExit('trailing bytes')
    print(json.dumps(dict(records=n,unique_ids=len(seen),groups=groups,bytes=len(b),corpus_sha256=hashlib.sha256(b).hexdigest(),hardware_sha256=h.hexdigest(),framing='pass'),indent=2))
if __name__=='__main__':main()
