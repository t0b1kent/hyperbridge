"""Logical byte-exact access to raw, zstd, or deduplicated HBMEM evidence."""
import base64
import bisect
import contextlib
import collections
import ctypes
import ctypes.util
import functools
import hashlib
import io
import json
import mmap
import pathlib
import sqlite3
import struct
import subprocess


class Zstd:
    def __init__(self):
        self.lib = ctypes.CDLL(ctypes.util.find_library('zstd') or '/opt/homebrew/lib/libzstd.dylib')
        for name, result, args in [
            ('ZSTD_createCCtx', ctypes.c_void_p, []),
            ('ZSTD_freeCCtx', ctypes.c_size_t, [ctypes.c_void_p]),
            ('ZSTD_CCtx_setParameter', ctypes.c_size_t, [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]),
            ('ZSTD_compressBound', ctypes.c_size_t, [ctypes.c_size_t]),
            ('ZSTD_compress2', ctypes.c_size_t, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]),
            ('ZSTD_decompress', ctypes.c_size_t, [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]),
            ('ZSTD_isError', ctypes.c_uint, [ctypes.c_size_t]),
            ('ZSTD_getErrorName', ctypes.c_char_p, [ctypes.c_size_t]),
        ]:
            f = getattr(self.lib, name); f.restype = result; f.argtypes = args
        self.ctx = self.lib.ZSTD_createCCtx()
        if not self.ctx: raise MemoryError('ZSTD_createCCtx')
        self.check(self.lib.ZSTD_CCtx_setParameter(self.ctx, 100, 3))
        self.check(self.lib.ZSTD_CCtx_setParameter(self.ctx, 101, 27))

    def check(self, value):
        if self.lib.ZSTD_isError(value):
            raise ValueError(self.lib.ZSTD_getErrorName(value).decode())
        return value

    def compress(self, data):
        target = ctypes.create_string_buffer(self.lib.ZSTD_compressBound(len(data)))
        n = self.check(self.lib.ZSTD_compress2(self.ctx, target, len(target), data, len(data)))
        return target.raw[:n]

    def decompress(self, data, size):
        target = ctypes.create_string_buffer(size)
        n = self.check(self.lib.ZSTD_decompress(target, size, data, len(data)))
        if n != size: raise ValueError('page decoded length')
        return target.raw[:n]

    def close(self):
        if self.ctx:
            self.lib.ZSTD_freeCCtx(self.ctx); self.ctx = None


def exists(path):
    p = pathlib.Path(path)
    return any(q.is_file() for q in [p, pathlib.Path(str(p)+'.zst'), pathlib.Path(str(p)+'.pages.json')])


class SparseBuffer:
    """Read guest pages without materializing an original multi-GB image."""
    def __init__(self, manifest):
        manifest = pathlib.Path(manifest)
        self.meta = json.loads(manifest.read_text())
        if self.meta.get('format') != 'HBMEM001-PAGES-1': raise ValueError('page manifest format')
        store = (manifest.parent/self.meta['store']).resolve()
        self.db = sqlite3.connect(store.as_uri()+'?mode=ro', uri=True)
        self.zstd = Zstd(); self.chunks = []; offset = 0
        for segment in self.meta['segments']:
            if 'inline' in segment:
                data = base64.b64decode(segment['inline'], validate=True)
                self.chunks.append((offset, len(data), 1, data, None)); offset += len(data)
            else:
                for digest, size, count in segment['pages']:
                    if not 0 < size <= 4096 or count < 1 or len(digest) != 64:
                        raise ValueError('invalid page reference')
                    self.chunks.append((offset, size, count, None, digest)); offset += size*count
        self.length = offset; self.starts = [c[0] for c in self.chunks]
        if offset != self.meta['original_bytes']: raise ValueError('manifest byte count')
        self.load_page = functools.lru_cache(maxsize=512)(self._load_page)

    def _load_page(self, digest, size):
        row = self.db.execute('SELECT size,data FROM pages WHERE digest=?', (digest,)).fetchone()
        if row is None or row[0] != size: raise ValueError('missing page: '+digest)
        data = self.zstd.decompress(row[1], size)
        if hashlib.sha256(data).hexdigest() != digest: raise ValueError('page SHA drift: '+digest)
        return data

    def __len__(self): return self.length

    def __getitem__(self, key):
        if isinstance(key, int):
            if key < 0: key += self.length
            if not 0 <= key < self.length: raise IndexError(key)
            return self[key:key+1][0]
        start, end, step = key.indices(self.length)
        if step != 1: raise ValueError('only contiguous evidence slices')
        result = bytearray()
        while start < end:
            i = bisect.bisect_right(self.starts, start)-1
            offset, size, count, inline, digest = self.chunks[i]
            data = inline if digest is None else self.load_page(digest, size)
            within = (start-offset) % size
            n = min(end-start, size-within)
            result += data[within:within+n]; start += n
        return bytes(result)

    def close(self):
        self.load_page.cache_clear(); self.db.close(); self.zstd.close()


class SparseReader(io.RawIOBase):
    def __init__(self, view): self.view = view; self.offset = 0
    def readable(self): return True
    def seekable(self): return True
    def read(self, n=-1):
        if n < 0: n = len(self.view)-self.offset
        data = self.view[self.offset:self.offset+n]; self.offset += len(data); return data
    def readinto(self, target):
        data = self.read(len(target)); target[:len(data)] = data; return len(data)
    def seek(self, offset, whence=0):
        pos = offset+(self.offset if whence == 1 else len(self.view) if whence == 2 else 0)
        if whence not in [0, 1, 2] or pos < 0: raise ValueError('invalid evidence seek')
        self.offset = pos; return pos
    def tell(self): return self.offset
    def close(self):
        if not self.closed: self.view.close()
        super().close()


@contextlib.contextmanager
def open_binary(path):
    p = pathlib.Path(path)
    if p.is_file():
        with p.open('rb') as stream: yield stream
    elif pathlib.Path(str(p)+'.pages.json').is_file():
        with SparseReader(SparseBuffer(str(p)+'.pages.json')) as stream: yield stream
    else:
        packed = pathlib.Path(str(p)+'.zst')
        if not packed.is_file(): raise FileNotFoundError(p)
        child = subprocess.Popen(['zstd', '-q', '-d', '--long=27', '-c', str(packed)],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            yield child.stdout
            # Validate the complete frame even when the caller consumed only a prefix.
            while child.stdout.read(1024*1024): pass
            error = child.stderr.read(4096); rc = child.wait()
            if rc: raise ValueError('zstd decode failed: '+error.decode(errors='replace'))
        finally:
            child.stdout.close(); child.stderr.close()
            if child.poll() is None: child.terminate(); child.wait()


@contextlib.contextmanager
def open_text(path):
    with open_binary(path) as stream:
        wrapper = io.TextIOWrapper(stream, encoding='utf-8')
        try: yield wrapper
        finally: wrapper.detach()


def iter_lines(path):
    with open_text(path) as stream:
        yield from stream


def logical_size(path):
    p = pathlib.Path(path)
    if p.is_file(): return p.stat().st_size
    if pathlib.Path(str(p)+'.pages.json').is_file():
        with mapped(path) as view: return len(view)
    with open_binary(path) as stream:
        return sum(len(block) for block in iter(lambda: stream.read(1024*1024), b''))


def logical_glob(directory, pattern):
    d = pathlib.Path(directory)
    paths = set(d.glob(pattern))
    paths.update(pathlib.Path(str(p)[:-4]) for p in d.glob(pattern+'.zst'))
    paths.update(pathlib.Path(str(p)[:-11]) for p in d.glob(pattern+'.pages.json'))
    return sorted(paths)


@contextlib.contextmanager
def mapped(path):
    p = pathlib.Path(path)
    if p.is_file():
        with p.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            yield data
    elif pathlib.Path(str(p)+'.pages.json').is_file():
        data = SparseBuffer(str(p)+'.pages.json')
        try: yield data
        finally: data.close()
    else:
        with open_binary(path) as stream: yield stream.read()


def sha(path):
    digest = hashlib.sha256()
    with open_binary(path) as stream:
        for block in iter(lambda: stream.read(1024*1024), b''): digest.update(block)
    return digest.hexdigest()


class Image:
    def __init__(self, path):
        self._mapping = mapped(path); self.data = self._mapping.__enter__()
        if self.data[:8] != b'HBMEM001': raise ValueError('image magic')
        self.regions = []; self.statuses = collections.Counter(); off = 40; self.footer = None
        while off < len(self.data):
            if off+48 > len(self.data): raise ValueError('truncated image region')
            tag,status,addr,size,prot,kind,n,err,_ = struct.unpack('<IIQQIIQII', self.data[off:off+48]); off += 48
            if tag == 0x45: self.footer = status; break
            if tag != 0x52 or off+n > len(self.data): raise ValueError('invalid image region')
            self.statuses[status] += 1
            if status == 1 and n == size: self.regions.append((addr,addr+size,off))
            off += n
        self.regions.sort(); self.starts = [r[0] for r in self.regions]
        if self.footer is None: raise ValueError('missing image footer')

    def read(self, addr, size):
        out = bytearray()
        while size:
            i = bisect.bisect_right(self.starts, addr)-1
            if i < 0: return None
            a,b,o = self.regions[i]
            if not a <= addr < b: return None
            n = min(size,b-addr); out += self.data[o+addr-a:o+addr-a+n]; addr += n; size -= n
        return bytes(out)

    def page(self, addr):
        return b''.join(self.read(addr+i,4096) or bytes(4096) for i in range(0,16384,4096))

    def close(self):
        if self._mapping:
            self._mapping.__exit__(None, None, None); self._mapping = None


@contextlib.contextmanager
def write_text(path):
    """New JSONL is compressed from creation; receipts keep its logical path."""
    p = pathlib.Path(path)
    if exists(p): raise FileExistsError('preserve evidence: '+str(p))
    packed = pathlib.Path(str(p)+'.zst')
    with packed.open('xb') as dest:
        child = subprocess.Popen(['zstd', '-q', '--long=27', '-T1', '-3', '-c'],
                                 stdin=subprocess.PIPE, stdout=dest, stderr=subprocess.PIPE)
        wrapper = io.TextIOWrapper(child.stdin, encoding='utf-8')
        try:
            yield wrapper
            wrapper.close()
            error = child.stderr.read(4096); rc = child.wait()
            if rc: raise ValueError('zstd encode failed: '+error.decode(errors='replace'))
        finally:
            if not wrapper.closed: wrapper.close()
            child.stderr.close()
            if child.poll() is None: child.terminate(); child.wait()
