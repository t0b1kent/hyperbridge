"""Selective byte-exact HBCAP index, avoiding copying unrequested code spans."""
import bisect
import mmap
import struct
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]/'stand-diff-20260930'))
from evidence_io import open_binary, mapped

EVENT_TAGS={0x4b,0x49,0x51,0x52,0x47,0x58,0x42,0x46,0x4d,0x56,0x54,0x4a}


def entry_rips(path, sequences=None, sequence=None):
    with open_binary(path) as stream:
        if stream.read(8)!=b'HBSTATE1':raise ValueError('state magic')
        version,size,length,_=struct.unpack('<4I',stream.read(16))
        if version!=1 or not 16<=size<=4096 or length>8192:raise ValueError('state header')
        if len(stream.read(length))!=length:raise ValueError('state metadata')
        while True:
            raw=stream.read(size)
            if not raw:break
            if len(raw)!=size:raise ValueError('truncated state')
            rip,seq=struct.unpack_from('<2Q',raw)
            if sequence is not None and seq!=sequence:continue
            if sequences is not None and seq not in sequences:continue
            yield rip


def code_index(path, entry_rips):
    entries=sorted(set(entry_rips)); codes={}; starts=set(); pages={}; index=0
    with mapped(path) as data:
        magic=data[:8]
        if magic not in [b'HBCAP001',b'HBCAP002']:raise ValueError('capture magic')
        offset=12+struct.unpack_from('<I',data,8)[0]
        if offset>len(data):raise ValueError('capture header')
        while offset<len(data):
            if offset+4>len(data):raise ValueError('truncated capture tag')
            tag=struct.unpack_from('<I',data,offset)[0]
            if tag==0x50:
                if offset+4108>len(data):raise ValueError('truncated capture page')
                pages[struct.unpack_from('<Q',data,offset+4)[0]]=offset+12
                offset+=4108;continue
            if tag==0x43:
                if offset+132>len(data):raise ValueError('truncated capture record')
                fields=struct.unpack_from('<16Q',data,offset+4);np,nq=fields[14:16]
                end=offset+132+np*16+nq*32
                if end>len(data):raise ValueError('truncated capture pairs')
                rip,start,length=fields[1],fields[5],fields[6]
                if not fields[3]&24 and start==rip and 0<length<=65536:
                    pairs=dict(struct.unpack_from('<QQ',data,offset+132+i*16) for i in range(np))
                    spans=[];address=rip
                    while address<rip+length:
                        page=address&~4095;h=pairs.get(page,0)
                        if not h or h not in pages:break
                        n=min(4096-(address-page),rip+length-address)
                        spans.append((pages[h]+address-page,n));address+=n
                    if address==rip+length:
                        starts.add(rip)
                        a=bisect.bisect_left(entries,rip);b=bisect.bisect_left(entries,rip+length)
                        if a<b:
                            code=b''.join(data[p:p+n] for p,n in spans)
                            for entry in entries[a:b]:
                                suffix=code[entry-rip:]
                                if entry not in codes or len(suffix)<len(codes[entry][1]):codes[entry]=(index,suffix)
                index+=1;offset=end;continue
            if magic==b'HBCAP002' and tag in EVENT_TAGS:
                if offset+8>len(data):raise ValueError('truncated event header')
                words=struct.unpack_from('<I',data,offset+4)[0];end=offset+8+words*8
                if words>1000000 or end>len(data):raise ValueError('truncated event')
                offset=end;continue
            raise ValueError(f'bad capture tag {tag:#x}')
    return codes,starts
