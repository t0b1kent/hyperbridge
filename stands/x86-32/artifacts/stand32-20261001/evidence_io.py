"""Transparent, verified zstd storage for immutable STAND32 JSON evidence."""
import fnmatch
import hashlib
import json
import os
import pathlib
import memory_store

def stored_path(path):
    path=pathlib.Path(path)
    if path.exists():return path
    # Historical registries may pin the physical .zst name. Solid packing
    # retains the exact logical bytes at <logical-name>.packref instead.
    if path.suffix=='.zst':
        relocated=path.with_suffix('.packref')
        if relocated.exists():return relocated
    packed=pathlib.Path(str(path)+'.zst')
    if packed.exists():return packed
    solid=pathlib.Path(str(path)+'.packref')
    if solid.exists():return solid
    return path

def read_bytes(path):
    actual=stored_path(path)
    if actual.suffix=='.packref':
        from manifest_pack import read_member
        return read_member(actual)
    try:raw=actual.read_bytes()
    except FileNotFoundError:
        actual=stored_path(path)
        if actual.suffix=='.packref':
            from manifest_pack import read_member
            return read_member(actual)
        raw=actual.read_bytes()
    return memory_store.decompress(raw,512*1024*1024) if actual.suffix=='.zst' else raw

def read_text(path):return read_bytes(path).decode()
def read_json(path):return json.loads(read_bytes(path))
def sha(path):return hashlib.sha256(read_bytes(path)).hexdigest()

def logical_glob(directory,pattern):
    paths=set(pathlib.Path(directory).glob(pattern))
    paths.update(pathlib.Path(str(p)[:-4]) for p in pathlib.Path(directory).glob(pattern+'.zst'))
    paths.update(pathlib.Path(str(p)[:-8]) for p in pathlib.Path(directory).glob(pattern+'.packref'))
    return sorted(paths)

def write_json(path,obj,*,indent=None):
    raw=(json.dumps(obj,indent=indent)+'\n').encode();path=pathlib.Path(path)
    if len(raw)<32768:path.write_bytes(raw);return path
    packed=memory_store.compress(raw)
    if memory_store.decompress(packed,512*1024*1024)!=raw:raise ValueError('evidence compression roundtrip')
    target=pathlib.Path(str(path)+'.zst');target.write_bytes(packed);return target

def pack_existing(path):
    path=pathlib.Path(path);before=path.stat();raw=path.read_bytes();packed=memory_store.compress(raw)
    if memory_store.decompress(packed,512*1024*1024)!=raw:raise ValueError('evidence compression mismatch')
    target=pathlib.Path(str(path)+'.zst');temporary=pathlib.Path(str(target)+'.tmp-'+str(os.getpid()))
    temporary.write_bytes(packed)
    if hashlib.sha256(memory_store.decompress(temporary.read_bytes(),512*1024*1024)).digest()!=hashlib.sha256(raw).digest():raise ValueError('stored evidence hash mismatch')
    current=path.stat()
    if (before.st_size,before.st_mtime_ns,before.st_ino)!=(current.st_size,current.st_mtime_ns,current.st_ino):raise ValueError('evidence source drift')
    if target.exists():raise ValueError('compressed evidence already exists')
    temporary.replace(target);path.unlink()
    return dict(path=str(path),original_bytes=len(raw),original_sha256=hashlib.sha256(raw).hexdigest(),
                packed_path=str(target),packed_bytes=len(packed),packed_sha256=hashlib.sha256(packed).hexdigest(),
                status='VERIFIED_THEN_REMOVED')
