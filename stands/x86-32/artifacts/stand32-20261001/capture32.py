#!/usr/bin/env python3
"""Strict offline readers for STAND32 v2 states, weights and memory deltas."""
import argparse,collections,hashlib,json,pathlib,struct,io
import evidence_io
PAGE=struct.Struct('<IIQQIIQII')
HEADER=struct.Struct('<8sIIQQQQQ')

def read_exact(f,n):
    b=f.read(n)
    if len(b)!=n:raise ValueError(f'truncated input: expected {n}, got {len(b)}')
    return b

def zero_decode(raw):
    out=bytearray();pos=0
    while pos<len(raw):
        if pos+2>len(raw):raise ValueError('truncated RLE token')
        token=struct.unpack_from('<H',raw,pos)[0];pos+=2;n=token&0x7fff
        if not n or len(out)+n>4096:raise ValueError('invalid RLE run')
        if token&0x8000:
            if pos+n>len(raw):raise ValueError('truncated RLE literal')
            out.extend(raw[pos:pos+n]);pos+=n
        else:out.extend(bytes(n))
    if len(out)!=4096:raise ValueError('invalid decoded page size')
    return bytes(out)

def memory(path,parent=None):
    parent=parent or {'sequence':0,'pages':{}}
    pages={};page_info={};exclusions=[];counts=collections.Counter();copied=0
    raw_image=evidence_io.read_bytes(path)
    with io.BytesIO(raw_image) as f:
        magic,version,pid,seq,prev,maximum,qpc,frequency=HEADER.unpack(read_exact(f,HEADER.size))
        if magic!=b'HBM32D01' or version!=1 or prev!=parent['sequence'] or seq!=prev+1:
            raise ValueError('memory header/parent mismatch')
        if not frequency or not 1024*1024<=maximum<=1024**3:raise ValueError('memory bounds')
        while True:
            tag,status,address,size,protect,kind,n,error,encoding=PAGE.unpack(read_exact(f,PAGE.size))
            if tag==0x45:
                if status or address!=seq or size!=prev or n!=copied or f.read(1):raise ValueError('memory footer FAILED/incomplete')
                break
            if address<0x10000 or address+size>2**32 or not size or address&4095 or size&4095:
                raise ValueError('invalid guest memory range')
            counts[str(status)]+=1
            if tag==0x52 and status in (2,5):
                if n:raise ValueError('excluded region carries bytes')
                exclusions.append([address,size,protect,kind,status]);continue
            if tag!=0x50 or size!=4096 or address in pages:raise ValueError('invalid page record')
            if status==4:
                if n or address not in parent['pages']:raise ValueError('unchanged page missing from parent')
                raw=parent['pages'][address]
            elif status==1:
                if encoding==0 and n==4096:raw=read_exact(f,n)
                elif encoding==1 and 0<n<4096:raw=zero_decode(read_exact(f,n))
                else:raise ValueError('invalid page encoding')
            else:raise ValueError(f'memory page failed: status={status} error={error}')
            pages[address]=raw;page_info[address]={'protect':protect,'type':kind};copied+=4096
            if copied>maximum:raise ValueError('snapshot exceeds byte cap')
    return dict(path=str(path),pid=pid,sequence=seq,parent=prev,pages=pages,page_info=page_info,counts=dict(counts),
                exclusions=exclusions,bytes=copied,qpc=qpc,frequency=frequency,
                sha256=hashlib.sha256(raw_image).hexdigest())

def states(path):
    result=[]
    with pathlib.Path(path).open('rb') as f:
        magic,version,size,n,reserved=struct.unpack('<8s4I',read_exact(f,24))
        if magic!=b'HBSTATE1' or version!=2 or not 128<=size<=4096 or n>65536 or reserved:
            raise ValueError('state header unsupported')
        meta=json.loads(read_exact(f,n))
        if meta['record_size']!=size or meta['cap_per_block']!=2:raise ValueError('state metadata mismatch')
        required={'gpr_offset':128,'xmm_offset':256,'ymm_offset':256,'fsw_offset':8,
                  'mm_offset':128,'fs_base_offset':8,'gs_base_offset':8,'selectors_offset':16,
                  'bases_offset':48,'descriptors_offset':48,'guest_bits_offset':8,'monotonic_offset':16}
        for k,length in required.items():
            if k not in meta or not isinstance(meta[k],int) or meta[k]<0 or meta[k]+length>size:raise ValueError('invalid '+k)
        counts=collections.Counter()
        while True:
            raw=f.read(size)
            if not raw:break
            if len(raw)!=size:raise ValueError('truncated state record')
            rip,seq,tid,fpcr,fpsr=struct.unpack_from('<5Q',raw)
            width,sync=struct.unpack_from('<II',raw,meta['guest_bits_offset'])
            if seq!=len(result)+1 or width!=32 or sync not in (0,1):raise ValueError('state sequence/mode mismatch')
            counts[rip]+=1
            if counts[rip]>2 or seq>meta['cap_total']:raise ValueError('first-K/total cap violated')
            gpr=struct.unpack_from('<16Q',raw,meta['gpr_offset'])
            selectors=struct.unpack_from('<6H',raw,meta['selectors_offset'])
            valid=struct.unpack_from('<I',raw,meta['selectors_offset']+12)[0]
            fsw,fcw,ftw,reduced=struct.unpack_from('<IHBB',raw,meta['fsw_offset'])
            mm=raw[meta['mm_offset']:meta['mm_offset']+128]
            record=dict(rip=rip,sequence=seq,thread=tid,fpcr=fpcr,fpsr=fpsr,
                rflags=struct.unpack_from('<I',raw,40)[0],mxcsr=struct.unpack_from('<I',raw,44)[0],gpr=list(gpr),
                xmm=[raw[meta['xmm_offset']+i*16:meta['xmm_offset']+(i+1)*16].hex() for i in range(8)],
                fsw=fsw,fcw=fcw,abridged_ftw=ftw,reduced=reduced,mm=mm.hex(),
                selectors=list(selectors),segment_valid=valid,
                bases=list(struct.unpack_from('<6Q',raw,meta['bases_offset'])),
                descriptors=raw[meta['descriptors_offset']:meta['descriptors_offset']+48].hex(),
                sync_memory=sync,monotonic_ns=struct.unpack_from('<Q',raw,meta['monotonic_offset'])[0],
                execution=struct.unpack_from('<Q',raw,meta['monotonic_offset']+8)[0])
            result.append(record)
    return meta,result

def weights(path):
    raw=pathlib.Path(path).read_bytes()
    if len(raw)<128:raise ValueError('short weights')
    magic,version,slot_size,count,capacity,total,k,records,dropped,failed,timeouts=struct.unpack_from('<8s6I4Q',raw)
    if magic!=b'HBWGHT32' or version!=1 or slot_size!=64 or not count<=capacity<=262144 or k!=2:
        raise ValueError('invalid weights metadata')
    if len(raw)!=128+capacity*64:raise ValueError('truncated weights mapping')
    rows=[]
    for i in range(count):
        executed,rip,captured=struct.unpack_from('<QQI',raw,128+i*64)
        if captured>k or captured>executed:raise ValueError('invalid per-block weights')
        rows.append({'rip':rip,'executions':executed,'states':captured})
    return dict(records=records,dropped_slots=dropped,failed=failed,memory_timeouts=timeouts,cap_total=total,
                acknowledged_sequence=struct.unpack_from('<Q',raw,64)[0],blocks=rows)

def hbcaps(path):
    pages={};blocks=[]
    with pathlib.Path(path).open('rb') as f:
        if read_exact(f,8)!=b'HBCAP001':raise ValueError('HBCAP magic')
        n=struct.unpack('<I',read_exact(f,4))[0]
        if n>65536:raise ValueError('HBCAP metadata cap')
        metadata=read_exact(f,n).decode()
        if 'FEX_IS64BIT_MODE=0\n' not in metadata:raise ValueError('HBCAP is not proven 32-bit')
        while True:
            tag=f.read(4)
            if not tag:break
            if len(tag)!=4:raise ValueError('HBCAP truncated tag')
            tag=struct.unpack('<I',tag)[0]
            if tag==0x50:
                digest=struct.unpack('<Q',read_exact(f,8))[0];data=read_exact(f,4096)
                if digest in pages and pages[digest]!=data:raise ValueError('HBCAP page hash collision')
                pages[digest]=data
            elif tag==0x43:
                fields=struct.unpack('<16Q',read_exact(f,128));pairs=[]
                if fields[14]>1048576 or fields[15]>1048576:raise ValueError('HBCAP length cap')
                for _ in range(fields[14]):pairs.append(struct.unpack('<QQ',read_exact(f,16)))
                read_exact(f,fields[15]*32)
                blocks.append({'rip':fields[1],'start':fields[5],'length':fields[6],'instructions':fields[4],
                               'flags':fields[3],'pages':dict(pairs),'record':fields[0]})
            else:raise ValueError('HBCAP unknown tag '+str(tag))
    return metadata,pages,blocks

def memory_bytes(pages,address,size):
    out=bytearray()
    while size:
        base=address&~4095;offset=address-base;n=min(size,4096-offset)
        if base not in pages:raise ValueError('code page missing at '+hex(base))
        out.extend(pages[base][offset:offset+n]);address+=n;size-=n
    return bytes(out)

def main():
    p=argparse.ArgumentParser();p.add_argument('run',type=pathlib.Path);a=p.parse_args()
    report={'run':str(a.run.resolve()),'games':'NOT_CLASSIFIED','state_files':[]}
    for state_path in sorted((a.run/'captures').glob('*.hbstates')):
        item={'path':str(state_path)}
        try:
            meta,records=states(state_path);pid=int(state_path.name.split('.')[1]);parent=None;valid=0;errors=[]
            for record in records:
                path=a.run/'captures'/('memory-'+str(pid))/(f'{record["sequence"]:08d}.hbmem')
                if not path.exists():errors.append({'sequence':record['sequence'],'state':'NOT_PRESENT'});continue
                try:parent=memory(path,parent);valid+=1
                except Exception as exc:errors.append({'sequence':record['sequence'],'state':'FAILED','error':str(exc)});break
            w=weights(state_path.with_suffix('.hbweights'))
            item.update(states=len(records),blocks=len({x['rip'] for x in records}),memory_valid=valid,memory_errors=errors,
                segments_valid=sum(x['segment_valid']==63 for x in records),raw80_states=sum(not x['reduced'] for x in records),
                weights={k:v for k,v in w.items() if k!='blocks'},weight_blocks=len(w['blocks']),
                state='PRESENT' if valid==len(records) and records and not errors and not w['failed'] and not w['memory_timeouts'] else 'FAILED')
        except Exception as exc:item.update(state='FAILED',error=str(exc))
        report['state_files'].append(item)
    path=a.run/'CAPTURE-AUDIT.json';path.write_text(json.dumps(report,indent=2)+'\n');print(path)
    return 0 if report['state_files'] and all(x['state']=='PRESENT' for x in report['state_files']) else 1
if __name__=='__main__':raise SystemExit(main())
