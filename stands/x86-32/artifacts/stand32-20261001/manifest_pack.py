"""Solid groups of eight immutable manifests or ACKed memory deltas; exact bytes."""
import argparse,functools,hashlib,json,pathlib,subprocess,time
import memory_store as ms

LIMIT=256*1024*1024
def digest(raw):return hashlib.sha256(raw).hexdigest()
def identity(path):return ms._identity(path.stat())
def checked(path,expected):
    raw=path.read_bytes()
    if identity(path)!=expected:raise ValueError('manifest archive changed while reading')
    return raw

@functools.lru_cache(maxsize=2)
def archive_bytes(path,stamp):
    path=pathlib.Path(path);raw=checked(path,stamp)
    if digest(raw)!=path.stem:raise ValueError('manifest archive hash mismatch')
    return ms.decompress(raw,LIMIT)

def resolve(ref):
    raw=ref.read_bytes()
    if len(raw)>2048:raise ValueError('manifest pointer size')
    info=json.loads(raw);name=info.get('archive_sha256','')
    if info.get('format') not in ('STAND32_MANIFEST_PACK1','STAND32_EVIDENCE_PACK1') or len(name)!=64 or any(c not in '0123456789abcdef' for c in name):
        raise ValueError('invalid manifest pointer')
    if info['format']=='STAND32_EVIDENCE_PACK1' and info.get('payload_kind') not in ('HBMEM32_DELTA','REPLAY_OUTPUT'):
        raise ValueError('invalid evidence payload kind')
    offset,length=info.get('offset'),info.get('length')
    if not isinstance(offset,int) or not isinstance(length,int) or offset<0 or not 0<length<=32*1024*1024 or offset+length>LIMIT:
        raise ValueError('manifest pointer bounds')
    return info,ref.parent/'.manifest-packs'/(name+'.zst')

@functools.lru_cache(maxsize=2)
def member_bytes(ref,ref_stamp,archive_stamp):
    ref=pathlib.Path(ref);info,archive=resolve(ref)
    if identity(ref)!=ref_stamp:raise ValueError('manifest pointer changed')
    raw=archive_bytes(str(archive),archive_stamp)
    part=raw[info['offset']:info['offset']+info['length']]
    if len(part)!=info['length'] or digest(part)!=info.get('content_sha256',info.get('json_sha256')):raise ValueError('manifest member hash mismatch')
    return part

def read_member(ref):
    ref=pathlib.Path(ref);stamp=identity(ref);info,archive=resolve(ref)
    return member_bytes(str(ref),stamp,identity(archive))

@functools.lru_cache(maxsize=2)
def decoded(ref,ref_stamp,archive_stamp):return ms.decode_index(member_bytes(ref,ref_stamp,archive_stamp))
def read_index(ref):
    ref=pathlib.Path(ref);stamp=identity(ref);info,archive=resolve(ref)
    return decoded(str(ref),stamp,identity(archive))

def pack_group(paths,*,memory=False,replay=False):
    if memory and replay:raise ValueError('one payload kind')
    paths=[pathlib.Path(p) for p in paths]
    if not 1<=len(paths)<=8 or len({p.parent for p in paths})!=1:raise ValueError('one directory, groups1..8')
    raw=[];sources=[]
    for path in paths:
        suffix=('.reference.json.zst','.stdout.zst','.case.json.zst','.case-list.json.zst') if replay else '.hbmem.zst' if memory else '.pages.gz.index.json.zst'
        if not path.name.endswith(suffix):raise ValueError('unexpected solid input kind')
        stamp=identity(path);packed=checked(path,stamp);part=ms.decompress(packed,32*1024*1024)
        if memory:
            import capture32 as capture
            if len(part)<capture.HEADER.size+capture.PAGE.size:raise ValueError('short memory delta')
            magic,version,pid,seq,prev,maximum,qpc,frequency=capture.HEADER.unpack_from(part)
            footer=capture.PAGE.unpack_from(part,len(part)-capture.PAGE.size)
            if magic!=b'HBM32D01' or version!=1 or seq!=prev+1 or int(path.name.split('.')[0])!=seq:
                raise ValueError('memory delta identity mismatch')
            if footer[:4]!=(0x45,0,seq,prev):raise ValueError('memory delta footer FAILED/incomplete')
        elif not replay:ms.decode_index(part)
        sources.append((path,stamp,digest(packed),len(packed)));raw.append(part)
    joined=b''.join(raw)
    if len(joined)>LIMIT:raise ValueError('archive limit')
    packed=ms.compress(joined)
    if ms.decompress(packed,LIMIT)!=joined:raise ValueError('archive compression roundtrip')
    store=paths[0].parent/'.manifest-packs';store.mkdir(exist_ok=True)
    archive=store/(digest(packed)+'.zst')
    if archive.exists():
        if archive.read_bytes()!=packed:raise ValueError('existing archive mismatch')
    else:
        with archive.open('xb') as f:f.write(packed)
        archive.chmod(0o444)
    entries=[];offset=0;removed_inodes=set()
    for (path,stamp,old_sha,old_size),part in zip(sources,raw):
        ref=pathlib.Path(str(path)[:-4]+'.packref')
        info=dict(format='STAND32_MANIFEST_PACK1',archive_sha256=archive.stem,offset=offset,length=len(part),json_sha256=digest(part))
        if memory or replay:
            info.update(format='STAND32_EVIDENCE_PACK1',payload_kind='HBMEM32_DELTA' if memory else 'REPLAY_OUTPUT',content_sha256=info.pop('json_sha256'))
        with ref.open('x') as f:json.dump(info,f);f.write('\n')
        if member_bytes(str(ref),identity(ref),identity(archive))!=part:raise ValueError('stored member mismatch')
        current=identity(path)
        same=current==stamp or (current[:4]==stamp[:4] and current[:2] in removed_inodes)
        if not same or digest(path.read_bytes())!=old_sha:raise ValueError('source drift before removal')
        path.unlink()
        removed_inodes.add(stamp[:2])
        entry=dict(path=str(path),packed_sha256=old_sha,packed_bytes=old_size,pointer=str(ref),archive=str(archive),offset=offset)
        if memory or replay:entry.update(content_sha256=info['content_sha256'],content_bytes=len(part),status='BYTE_EXACT_'+('MEMORY' if memory else 'REPLAY')+'_VERIFIED_THEN_REPACKED')
        else:entry.update(json_sha256=info['json_sha256'],json_bytes=len(part),status='BYTE_EXACT_JSON_VERIFIED_THEN_REPACKED')
        entries.append(entry)
        offset+=len(part)
    return dict(entries=entries,archive_bytes=len(packed),old_bytes=sum(x[3] for x in sources))

def main():
    p=argparse.ArgumentParser();p.add_argument('directory',type=pathlib.Path)
    p.add_argument('--replay',action='store_true',help='Closed legacy replay references/stdout, same verified solid format')
    p.add_argument('--inputs',action='store_true',help='Closed replay case inputs, including interrupted historical runs')
    p.add_argument('--stopped',action='store_true',help='Explicitly allow an interrupted replay after lsof proves the directory is closed')
    a=p.parse_args();directory=a.directory.resolve()
    if a.replay and a.inputs:raise ValueError('choose replay outputs or inputs')
    own=pathlib.Path(__file__).resolve().parent
    if own/'out' not in directory.parents:raise ValueError('own derived output only')
    probe=subprocess.run(['perl','-e','alarm 25; exec @ARGV','lsof','-nP','-Fpn','+D',str(directory)],capture_output=True,timeout=28)
    if probe.returncode!=1 or probe.stdout or probe.stderr:raise ValueError('stopped directory not proven by lsof')
    import evidence_io as io
    if a.replay and not a.stopped and not io.stored_path(directory/'RESULT.json').is_file():raise ValueError('completed replay required; interrupted evidence needs --stopped')
    paths=sorted([*directory.rglob('*.case.json.zst'),*directory.rglob('*.case-list.json.zst')]) if a.inputs else sorted([*directory.rglob('*.reference.json.zst'),*directory.rglob('*.stdout.zst')]) if a.replay else sorted(directory.glob('*.pages.gz.index.json.zst'))
    groups=[]
    for path in paths:
        if not groups or len(groups[-1])==8 or groups[-1][-1].parent!=path.parent:groups.append([])
        groups[-1].append(path)
    before=after=count=0;start=time.monotonic();label='REPLAY-INPUT-PACK' if a.inputs else 'REPLAY-OUTPUT-PACK' if a.replay else 'MANIFEST-PACK'
    with (directory/(label+'.jsonl')).open('x') as log:
        for group in groups:
            result=pack_group(group,replay=a.replay or a.inputs);before+=result['old_bytes'];after+=result['archive_bytes'];count+=len(group)
            log.write(json.dumps(result)+'\n');log.flush()
            if count%400<8:print(json.dumps(dict(packed=count,seconds=time.monotonic()-start)),flush=True)
    result=dict(files=len(paths),original_bytes=before,archive_bytes=after,saved_bytes=before-after,seconds=time.monotonic()-start)
    (directory/(label+'-RESULT.json')).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
