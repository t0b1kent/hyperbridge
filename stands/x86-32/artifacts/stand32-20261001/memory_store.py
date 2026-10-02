"""Byte-exact HBPAGES1 storage with shared SHA256-addressed zstd pages."""
import ctypes
import functools
import gzip
import hashlib
import json
import pathlib
import struct
from types import MappingProxyType

OWN=pathlib.Path(__file__).resolve().parent
STORE=OWN/'page-store'
LIB=ctypes.CDLL('/opt/homebrew/opt/zstd/lib/libzstd.dylib')
for name,restype,args in [
    ('ZSTD_createCCtx',ctypes.c_void_p,[]),
    ('ZSTD_CCtx_setParameter',ctypes.c_size_t,[ctypes.c_void_p,ctypes.c_int,ctypes.c_int]),
    ('ZSTD_compressBound',ctypes.c_size_t,[ctypes.c_size_t]),
    ('ZSTD_compress2',ctypes.c_size_t,[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t]),
    ('ZSTD_getFrameContentSize',ctypes.c_ulonglong,[ctypes.c_void_p,ctypes.c_size_t]),
    ('ZSTD_decompress',ctypes.c_size_t,[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t]),
    ('ZSTD_isError',ctypes.c_uint,[ctypes.c_size_t]),
    ('ZSTD_getErrorName',ctypes.c_char_p,[ctypes.c_size_t])]:
    function=getattr(LIB,name);function.restype=restype;function.argtypes=args
CTX=LIB.ZSTD_createCCtx()
def checked(result):
    if LIB.ZSTD_isError(result):raise ValueError(LIB.ZSTD_getErrorName(result).decode())
    return result
# zstd.h: compressionLevel100, windowLog101, enableLongDistanceMatching160.
for key,value in [(100,3),(101,27),(160,1)]:checked(LIB.ZSTD_CCtx_setParameter(CTX,key,value))

def compress(data):
    target=ctypes.create_string_buffer(LIB.ZSTD_compressBound(len(data)))
    size=checked(LIB.ZSTD_compress2(CTX,target,len(target),data,len(data)))
    return target.raw[:size]

def decompress(data,limit=16384):
    size=LIB.ZSTD_getFrameContentSize(data,len(data))
    if size>limit:raise ValueError('zstd decompressed size exceeds bound')
    target=ctypes.create_string_buffer(size)
    written=checked(LIB.ZSTD_decompress(target,size,data,len(data)))
    if written!=size:raise ValueError('zstd frame size mismatch')
    return target.raw

def page_path(digest):
    if len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):raise ValueError('bad page hash')
    return STORE/digest[:2]/(digest+'.zst')

@functools.lru_cache(maxsize=512)
def read_object(digest):
    raw=decompress(page_path(digest).read_bytes())
    if len(raw)!=16384 or hashlib.sha256(raw).hexdigest()!=digest:raise ValueError('page object integrity failure')
    return raw

def index_path(path):return pathlib.Path(str(path)+'.index.json')

def has_index(path):
    index=index_path(path)
    return any(path.exists() for path in (index,pathlib.Path(str(index)+'.zst'),pathlib.Path(str(index)+'.packref')))

def read_index(path):
    index=index_path(path)
    if not index.exists():
        if pathlib.Path(str(index)+'.zst').exists():index=pathlib.Path(str(index)+'.zst')
        else:
            from manifest_pack import read_index as packed_index
            return packed_index(pathlib.Path(str(index)+'.packref'))
    return _read_index(str(index.resolve()),_identity(index.stat()))

def _identity(stat):
    return (stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns,stat.st_ctime_ns)

@functools.lru_cache(maxsize=2)
def _read_index(path,identity):
    # A case uses one immutable manifest in the oracle and both native replays.
    # Stat identity invalidates the bounded cache on replacement or modification.
    index=pathlib.Path(path);raw=index.read_bytes()
    if _identity(index.stat())!=identity:raise ValueError('page manifest changed while reading')
    if str(index).endswith('.zst'):raw=decompress(raw,32*1024*1024)
    return decode_index(raw)

def decode_index(raw):
    data=json.loads(raw)
    if data.get('format')=='HBPAGES1_SHARED_ZSTD_V2':
        actual=hashlib.sha256(json.dumps(data['pages'],separators=(',',':')).encode()).hexdigest()
        if actual!=data['manifest_sha256']:raise ValueError('page manifest integrity failure')
    data['pages']=tuple(map(tuple,data['pages']))
    return MappingProxyType(data)

def read_pages(path):
    path=pathlib.Path(path)
    if path.exists():
        opener=gzip.open if str(path).endswith('.gz') else open
        with opener(path,'rb') as file:
            if file.read(8)!=b'HBPAGES1':raise ValueError('invalid HBPAGES1')
            count=struct.unpack('<Q',file.read(8))[0]
            if count>16384:raise ValueError('page cap')
            seen=set()
            for _ in range(count):
                address=struct.unpack('<Q',file.read(8))[0];raw=file.read(16384)
                if address&16383 or address+16384>1<<32 or len(raw)!=16384 or address in seen:raise ValueError('bad page')
                seen.add(address);yield address,raw
            if file.read(1):raise ValueError('trailing image bytes')
    else:
        index=read_index(path)
        if index.get('format') not in ['HBPAGES1_SHARED_ZSTD_V1','HBPAGES1_SHARED_ZSTD_V2'] or len(index['pages'])>65536:raise ValueError('invalid shared image')
        seen=set();digest=hashlib.sha256(b'HBPAGES1'+struct.pack('<Q',len(index['pages'])))
        for address,page_hash in index['pages']:
            if address&16383 or address+16384>1<<32 or address in seen:raise ValueError('invalid page address')
            seen.add(address);raw=read_object(page_hash);digest.update(struct.pack('<Q',address));digest.update(raw)
            yield address,raw
        if 'uncompressed_sha256' in index and digest.hexdigest()!=index['uncompressed_sha256']:raise ValueError('reconstructed image hash mismatch')

def expand(path,destination):
    path=pathlib.Path(path)
    if path.exists():
        opener=gzip.open if str(path).endswith('.gz') else open
        with opener(path,'rb') as source:count=struct.unpack('<Q',source.read(16)[8:])[0]
    else:count=len(read_index(path)['pages'])
    with pathlib.Path(destination).open('xb') as target:
        target.write(b'HBPAGES1'+struct.pack('<Q',count))
        for address,raw in read_pages(path):target.write(struct.pack('<Q',address));target.write(raw)
