"""Strict streaming reader for HBUP0002 and HBFL0001. No runtime dependencies."""
import gzip, struct
from pathlib import Path

def records(path):
    path=Path(path);opener=gzip.open if path.suffix=='.gz' else open
    with opener(path,'rb') as f:
        magic=f.read(8);h=f.read(4)
        if len(h)!=4:raise ValueError('truncated count')
        count=struct.unpack('<I',h)[0]
        if magic not in (b'HBUP0002',b'HBFL0001') or not count:raise ValueError('magic/count')
        fmt='<HHIQ8QiiI' if magic==b'HBUP0002' else '<HHQ7Q7Q7Q';size=struct.calcsize(fmt)
        for i in range(count):
            head=f.read(size)
            if len(head)!=size:raise ValueError('truncated header')
            vals=struct.unpack(fmt,head);nl,cl=vals[:2]
            if not 0<nl<=511 or not 0<cl<=256:raise ValueError('invalid lengths')
            n=nl+cl+(2048+256+2048+256 if magic==b'HBUP0002' else 64);body=f.read(n)
            if len(body)!=n:raise ValueError('truncated body')
            d=dict(magic=magic,name=body[:nl].decode(),code=body[nl:nl+cl],raw=head+body,seed=vals[3] if magic==b'HBUP0002' else vals[2])
            tail=body[nl+cl:]
            if magic==b'HBUP0002':d.update(k=vals[4:12],mode=vals[12],valid=vals[13],fault=vals[14],input_vec=tail[:2048],input_mem=tail[2048:2304],output_vec=tail[2304:4352],output_mem=tail[4352:4608])
            else:d.update(inputs=vals[3:10],outputs=vals[10:17],masks=vals[17:24],memory=tail)
            yield d
        if f.read(1):raise ValueError('trailing bytes')

def write(path,rows,magic):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    data=magic+struct.pack('<I',len(rows))+b''.join(x['raw'] for x in rows)
    if path.suffix=='.gz':
        with gzip.GzipFile(filename=str(path),mode='wb',mtime=0) as f:f.write(data)
    else:path.write_bytes(data)
