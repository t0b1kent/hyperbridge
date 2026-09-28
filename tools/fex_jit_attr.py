#!/usr/bin/env python3
"""Attribute the unnamed ("???") leaves of a macOS `sample` profile to guest modules.

    jit_attr.py <sample.txt> <jitmap-dir-or-file> [vmmap.txt] [--threads N] [--top N]

Sources, in order:
  1. FEX JIT map (fex-jitmap-<pid>.map, patch 0012): "<host> <size-hex> <module>+0x<off> (<host>)" per block,
     "<host> <size-hex> JIT_0x<guest>_<host>" for blocks outside known images, "<host> <size-hex> FEXJIT" for
     the whole code buffer.
  2. vmmap -wide of the game process: file-backed regions (PE images mapped by Wine: xtajit64.dll, Wine DLLs).
Leaves are counted as self samples (count minus children), as in sample_threads.py.
"""
import bisect, glob, os, re, sys
from collections import Counter, defaultdict

LINE = re.compile(r'^([\s+!:|]*?)(\d+)\s+(.*)$')
ADDR = re.compile(r'\[0x([0-9a-f]+)\]\s*$')


def load_jitmap(path):
    files = sorted(glob.glob(os.path.join(path, '*.map'))) if os.path.isdir(path) else [path]
    blocks, regions = [], []
    for f in files:
        for raw in open(f, errors='replace'):
            parts = raw.rstrip('\n').split(' ', 2)
            if len(parts) < 3:
                continue
            try:
                start = int(parts[0], 16); size = int(parts[1], 16)
            except ValueError:
                continue
            name = parts[2]
            if name == 'FEXJIT':
                regions.append((start, start + size))
            else:
                if name.endswith(')') and ' (' in name:
                    name = name[:name.rindex(' (')]
                blocks.append((start, start + size, name))
    blocks.sort()
    return blocks, regions, files


def pe_size_of_image(path):
    import struct
    try:
        with open(path, 'rb') as f:
            d = f.read(4096)
        off = struct.unpack_from('<I', d, 0x3c)[0]
        magic = struct.unpack_from('<H', d, off + 24)[0]
        return struct.unpack_from('<I', d, off + 24 + 56)[0] if magic in (0x10b, 0x20b) else None
    except Exception:
        return None


def load_loaddll(log, search_dirs):
    """Module bases from Wine '+loaddll' lines; sizes from SizeOfImage of a matching file, else next base."""
    rx = re.compile(r'Loaded L"([^"]+)" at ([0-9A-Fa-f]+): (\w+)')
    mods = {}
    for raw in open(log, errors='replace'):
        if 'loaddll' not in raw:
            continue
        m = rx.search(raw)
        if m:
            name = m.group(1).replace('\\\\', '\\').split('\\')[-1]
            mods[int(m.group(2), 16)] = name
    out = []
    bases = sorted(mods)
    for i, b in enumerate(bases):
        name = mods[b]
        size = None
        for d in search_dirs:
            cand = os.path.join(d, name)
            if os.path.exists(cand):
                size = pe_size_of_image(cand)
                if size:
                    break
        if not size:
            size = min((bases[i + 1] - b) if i + 1 < len(bases) else 1 << 24, 1 << 28)
        out.append((b, b + size, name))
    return out


def load_vmmap(path):
    maps = []
    if not path or not os.path.exists(path):
        return maps
    rx = re.compile(r'\s([0-9a-f]{6,})-([0-9a-f]{6,})\s.*?(/\S.*\.(?:dll|exe|drv|so|dylib|sys))\s*$', re.I)
    for raw in open(path, errors='replace'):
        m = rx.search(raw)
        if m:
            maps.append((int(m.group(1), 16), int(m.group(2), 16), os.path.basename(m.group(3))))
    maps.sort()
    return maps


def module_of_block(name):
    if name.startswith('JIT_0x'):
        return 'JIT: outside known images'
    m = re.match(r'(.+?)\+0x[0-9a-f]+$', name)
    base = m.group(1) if m else name
    return 'JIT: ' + base.replace('\\', '/').split('/')[-1]


def classify(addr, blocks, starts, regions, maps, mstarts):
    i = bisect.bisect_right(starts, addr) - 1
    # upstream sizes subblocks with the whole fragment size, so prefer the closest start that contains addr
    while i >= 0 and i > len(starts) - 1:
        i -= 1
    j = i
    while j >= 0 and starts[j] > addr - (1 << 20):
        s, e, n = blocks[j]
        if s <= addr < e:
            return module_of_block(n), n
        j -= 1
        if i - j > 64:
            break
    for s, e in regions:
        if s <= addr < e:
            return 'JIT: code buffer, unnamed', None
    k = bisect.bisect_right(mstarts, addr) - 1
    if k >= 0:
        s, e, n = maps[k]
        if s <= addr < e:
            return 'native: ' + n, None
    return 'unknown', None


def main():
    raw = sys.argv[1:]
    args = [a for i, a in enumerate(raw) if not a.startswith('--') and not (i and raw[i - 1].startswith('--'))]
    opts = dict(zip(sys.argv[1::1], sys.argv[2::1]))
    nthreads = int(opts.get('--threads', 4)); ntop = int(opts.get('--top', 12))
    sample, jit = args[0], args[1]
    vm = args[2] if len(args) > 2 else None
    blocks, regions, files = load_jitmap(jit)
    starts = [b[0] for b in blocks]
    maps = load_vmmap(vm)
    log = opts.get('--loaddll')
    if log:
        dirs = [d for d in opts.get('--dlldirs', '').split(':') if d]
        maps += load_loaddll(log, dirs)
        maps.sort()
    mstarts = [m[0] for m in maps]
    print(f'jit map: {len(files)} file(s), {len(blocks)} blocks, {len(regions)} code-buffer regions; native images: {len(maps)}')
    threads, cur = [], None
    for l in open(sample, errors='replace'):
        l = l.rstrip('\n')
        m = re.match(r'^\s{4}(\d+)\s+(Thread_\S+.*)$', l)
        if m:
            cur = [m.group(2).strip(), int(m.group(1)), []]; threads.append(cur); continue
        if cur is None:
            continue
        if l.startswith(('Total number', 'Sort by', 'Binary Images')):
            cur = None; continue
        mm = LINE.match(l)
        if mm and l.strip():
            cur[2].append([len(mm.group(1)), int(mm.group(2)), mm.group(3), 0])
    report = []
    for title, total, nodes in threads:
        stack = []
        for idx, node in enumerate(nodes):
            while stack and nodes[stack[-1]][0] >= node[0]:
                stack.pop()
            if stack:
                nodes[stack[-1]][3] += node[1]
            stack.append(idx)
        mods, blks = Counter(), Counter(); unk = 0
        for col, cnt, sym, csum in nodes:
            selfc = cnt - csum
            if selfc <= 0 or not sym.startswith('???'):
                continue
            a = ADDR.search(sym)
            if not a:
                unk += selfc; continue
            mod, blk = classify(int(a.group(1), 16), blocks, starts, regions, maps, mstarts)
            mods[mod] += selfc
            if blk:
                blks[blk] += selfc
        n = sum(mods.values()) + unk
        if n:
            report.append((n, title, total, mods, blks))
    report.sort(key=lambda r: -r[0])
    for n, title, total, mods, blks in report[:nthreads]:
        print(f'\n== {title}: "???" self samples {n} of {total} ({100.0 * n / total:.1f}% of the thread)')
        for k, v in mods.most_common(ntop):
            print(f'   {v:6d} {100.0 * v / n:5.1f}%  {k}')
        if blks:
            print('   top guest blocks:')
            for k, v in blks.most_common(8):
                print(f'      {v:5d}  {k}')


if __name__ == '__main__':
    main()
