#!/usr/bin/env python3
"""HBUP0002 records for the EVEX FP conversions beyond what the hardware corpus encodes.

The hardware mask corpus (generate.py, recorded on x86) runs vcvtdq2ps, vcvtps2dq, vcvttps2dq,
vcvtps2pd, vcvtpd2ps, vcvtdq2pd, vcvtss2sd and vcvtsd2ss with opmasks, but only with
EVEX.b = 0, [rbx] without displacement, zmm0..2, MXCSR = 0x1F80 and no guard page. This
generator covers the rest of the encoding space of those eight instructions:
  - embedded broadcast {1to2..1to16}; disp8*N ([rbx+d8], [rdi-d8], SIB) and disp32;
  - {er} (EVEX.RC in L'L) and {sae} (L'L ignored, VL = 512) on register sources;
  - MXCSR.RC / DAZ / FTZ, loaded by an LDMXCSR in front of the instruction;
  - boundary values: ties, integer indefinite, denormals, NaN payloads, doubles at the
    binary32 overflow and underflow edges; 128 fixed edge records come first (every
    MXCSR.RC with and without DAZ/FTZ, every {er}), then --count random ones;
  - guard-page records (HBUP mode 1): masked-off elements must not fault, an active one must.

The answers come from Bochs (the bochscpu Python package), NOT from hardware. Bochs runs the
same bytes in 32-bit protected mode with paging: only zmm0..7 and [ebx]/[edi]/[ebx+esi] are
used, and the 256-byte window ends at a not-present page exactly as in the Mac runner
(RBX = window, RDI = window + 128, RSI = 0; in guard mode RBX = boundary - valid). Checked
before use: Bochs agrees with the hardware corpus on 6,048 of 6,048 conversion records (all
512 bits of zmm0..7) and with IEEE host conversions under all four rounding modes
(cvtpd2ps, cvtdq2ps, cvtps2dq). Registers 8..31 carry a fixed pattern and must stay intact.

  generate_evex_cvt_bochs.py --out file.hbup.gz [--count N] [--guard-count M] [--seed S]
"""
import argparse, gzip, random, struct, sys

import bochscpu
import bochscpu._bochscpu as _b
import bochscpu.memory as _mem

KOD, STEK, PDIR, PTAB = 0x2000, 0x9000, 0x80000, 0x81000
GUARD = 0x6000                                     # not-present page; the window ends here
WINDOW = GUARD - 256
LDMXCSR = bytes([0x0f, 0xae, 0x57, 0x7c])          # ldmxcsr [edi+0x7c] = window + 252
MXCSR_OFF = 252

# op, pp, W, shape, what EVEX.b means on a register source, source kind, element sizes
FAMILIES = {
    'vcvtdq2ps':  (0x5b, 0, 0, 'same',   'er',  'i32', 4, 4),
    'vcvtps2dq':  (0x5b, 1, 0, 'same',   'er',  'f32', 4, 4),
    'vcvttps2dq': (0x5b, 2, 0, 'same',   'sae', 'f32', 4, 4),
    'vcvtps2pd':  (0x5a, 0, 0, 'widen',  'sae', 'f32', 4, 8),
    'vcvtpd2ps':  (0x5a, 1, 1, 'narrow', 'er',  'f64', 8, 4),
    'vcvtdq2pd':  (0xe6, 2, 0, 'widen',  None,  'i32', 4, 8),
    'vcvtss2sd':  (0x5a, 2, 0, 'scalar', 'sae', 'f32', 4, 8),
    'vcvtsd2ss':  (0x5a, 3, 1, 'scalar', 'er',  'f64', 8, 4),
}

F32 = [0x00000000, 0x80000000, 0x3f800000, 0xbf800000, 0x3f000000, 0xbf000000, 0x3fc00000,
       0x40200000, 0xc0200000, 0x3effffff, 0x3f000001, 0x00000001, 0x007fffff, 0x80000001,
       0x807fffff, 0x00800000, 0x7f7fffff, 0xff7fffff, 0x7f800000, 0xff800000, 0x7fc00000,
       0x7fc12345, 0x7f800001, 0x7fa00000, 0xffc00000, 0xff812345, 0x4f000000, 0xcf000000,
       0x4effffff, 0xcf000001, 0x4b800001, 0xcb7fffff, 0x3fb33333, 0x40490fdb, 0x501502f9,
       0xd01502f9, 0x4640e6b7, 0x3eaaaaab, 0x47000000, 0x4f7fffff]
I32 = [0, 1, -1, -2147483648, 2147483647, 1 << 24, (1 << 24) + 1, (1 << 24) + 2, (1 << 24) + 3,
       (1 << 25) + 1, (1 << 25) + 2, (1 << 25) + 3, (1 << 25) + 6, -(1 << 24) - 1,
       -(1 << 24) - 3, 0x7fffff80, 0x7fffffc0, 0x7fffffbf, 0x7fffffc1, -0x7fffffc0, 123456789,
       -987654321, 0x40000001, 0x40000040, 0x40000041, 0x400000c0, 0x3f800001]
F64 = [0x0000000000000000, 0x8000000000000000, 0x3ff0000000000000, 0xbff0000000000000,
       0x0000000000000001, 0x800fffffffffffff, 0x0010000000000000, 0x47efffffe0000000,
       0x47efffffefffffff, 0x47effffff0000000, 0x47effffff0000001, 0xc7effffff0000000,
       0x47f0000000000000, 0x7fefffffffffffff, 0x36a0000000000000, 0x3690000000000000,
       0x3690000000000001, 0xb690000000000000, 0x36a8000000000000, 0x3698000000000000,
       0x380fffffe0000000, 0x380fffffd0000000, 0x380ffffff0000000, 0xb80fffffe0000000,
       0x3810000000000000, 0x380ffffff8000000, 0x7ff0000000000000, 0xfff0000000000000,
       0x7ff8000000000000, 0x7ff8000012345678, 0x7ff0000000000001, 0x7ff4000000000000,
       0xfff8000000000000, 0xfff00000abcdef01, 0x3fd5555555555555, 0x400921fb54442d18,
       0x3ff0000010000000, 0x3ff0000030000000, 0x3ff0000010000001, 0xbff0000010000000,
       0x4415af1d78b58c40, 0x3e45798ee2308c3a, 0x7e37e43c8800759c]
UPPER = b''.join(struct.pack('<16I', *[0x3f000000 + r * 0x1357 + q * 0x107 for q in range(16)])
                 for r in range(8, 32))       # registers 8..31: fixed, only checked for intact


def f32_value(rng):
    r = rng.random()
    if r < 0.45: return rng.choice(F32)
    if r < 0.75:                                        # |x| near integers: rounding matters
        v = rng.choice([0.5, 1.5, 2.5, 3.5, -0.5, -1.5, -2.5, 1.25, -1.75, 1e6 + 0.5]) + rng.randint(-40, 40)
        return struct.unpack('<I', struct.pack('<f', v))[0]
    return rng.getrandbits(32)


def i32_value(rng):
    return (rng.choice(I32) if rng.random() < 0.6 else rng.getrandbits(32) - (1 << 31)) & 0xffffffff


def f64_value(rng):
    r = rng.random()
    if r < 0.45: return rng.choice(F64)
    if r < 0.8:                                         # inside the binary32 range, low bits set
        e = rng.randint(1023 - 150, 1023 + 128)
        return (rng.getrandbits(1) << 63) | (e << 52) | rng.getrandbits(52)
    return rng.getrandbits(64)


def fill(rng, kind, nbytes):
    out = b''
    while len(out) < nbytes:
        if kind == 'f64': out += struct.pack('<Q', f64_value(rng))
        elif kind == 'f32': out += struct.pack('<I', f32_value(rng))
        else: out += struct.pack('<I', i32_value(rng))
    return out[:nbytes]


_mapped = False


def _seg(sel, attr):
    s = _b.Segment(); s.selector = sel; s.base = 0; s.limit = 0xFFFFFFFF; s.present = True; s.attr = attr
    return s


def _setup():
    global _mapped
    if _mapped: return
    for a in range(0, 0x100000, 0x1000): _mem.page_insert(a, _mem.allocate_host_page())
    pd = [0] * 1024; pd[0] = PTAB | 7
    pt = [((i << 12) | 7) if (i << 12) != GUARD else 0 for i in range(1024)]
    _mem.phy_write(PDIR, list(struct.pack('<1024I', *pd)))
    _mem.phy_write(PTAB, list(struct.pack('<1024I', *pt)))
    _mapped = True


def bochs(code, ninstr, zmm8, kreg, kval, window, ebx=WINDOW):
    """Run code (after a KMOVW preamble) in Bochs. Returns (zmm0..7 bytes, None) on completion,
    (None, 'pf') on a page fault in the guard page, (None, other) on anything else."""
    _setup()
    pre = (b'\xb8' + struct.pack('<I', kval & 0xffff) + bytes([0xc5, 0xf8, 0x92, 0xc0 | (kreg << 3)])) if kreg else b''
    body = pre + code
    _mem.phy_write(KOD, list(body + b'\x90' * 16))
    _mem.phy_write(WINDOW, list(window))
    st = bochscpu.State()
    st.rip = KOD; st.rsp = STEK; st.cr0 = 0x80000033; st.cr3 = PDIR; st.cr4 = 0x00040600
    st.xcr0 = 0xE7; st.efer = 0; st.rflags = 2; st.mxcsr = 0x1F80; st.mxcsr_mask = 0xFFFF; st.fpcw = 0x37f
    st.cs = _seg(8, 0xC09B)
    for nm in ('ds', 'es', 'ss', 'fs', 'gs'): setattr(st, nm, _seg(0x10, 0xC093))
    z = list(st.zmm)
    for i in range(8):
        zz = _b.Zmm(); zz.q = list(struct.unpack('<8Q', zmm8[i * 64:(i + 1) * 64])); z[i] = zz
    st.zmm = z
    st.rbx = ebx; st.rdi = WINDOW + 128; st.rsi = 0
    need = ninstr + (2 if kreg else 0)
    s = bochscpu.Session(); s.cpu.state = st
    res = {'n': 0, 'exc': None}
    h = bochscpu.Hook()

    def after(sess, cpu, addr):
        res['n'] += 1
        if res['n'] >= need: s.stop()

    def exc(sess, cpu, vector, err):
        res['exc'] = (vector, err); s.stop()
    h.after_execution = after; h.exception = exc
    s.run([h])
    it = s.cpu.state
    if res['exc']:
        return None, ('pf' if res['exc'][0] == 14 and GUARD <= it.cr2 < GUARD + 0x1000 else res['exc'])
    if res['n'] != need or it.rip != KOD + len(body):
        return None, ('stopped', res['n'], it.rip - KOD - len(body))
    return b''.join(struct.pack('<8Q', *it.zmm[i].q) for i in range(8)), None


def encode(fam, ll, b, z, aaa, dst, src1, tail):
    op, pp, w = FAMILIES[fam][:3]
    vvvv = 0xf if src1 is None else (~src1) & 0xf
    return bytes([0x62, 0xf1, (w << 7) | (vvvv << 3) | 4 | pp, (z << 7) | (ll << 5) | (b << 4) | 8 | aaa, op]) + tail


def access_size(fam, form, vl):
    shape, se = FAMILIES[fam][3], FAMILIES[fam][6]
    if shape == 'scalar' or form == 'bcst': return se
    return vl // 2 if shape == 'widen' else vl


def registers(rng, kind, used):
    """zmm0..7: the instruction's own registers get test values (a destination sometimes random
    bits, to see merging); the rest a fixed pattern, which keeps the corpus small."""
    out = bytearray()
    for r in range(8):
        if r not in used: out += struct.pack('<16I', *[0x3e800000 + r * 0x2468 + q * 0x3579 for q in range(16)])
        elif rng.random() < 0.7: out += fill(rng, kind, 64)
        else: out += bytes(rng.getrandbits(8) for _ in range(64))
    return bytes(out)


def mask(rng, aaa):
    if not aaa: return 0
    return rng.choice([0, 0xffff, 0x5555, 0xaaaa, 1, 0x8000, rng.getrandbits(16), rng.getrandbits(16)])


def ordinary_case(rng, fam):
    op, pp, w, shape, emb, kind, se, de = FAMILIES[fam]
    scalar = shape == 'scalar'
    form = rng.choice(['reg', 'mem', 'emb'] if scalar else ['reg', 'reg', 'mem', 'bcst', 'emb'])
    if form == 'emb' and emb is None: form = 'reg'
    ll, b, tag = rng.choice([0, 1, 2]), 0, ''
    if form == 'emb':
        b, ll = 1, rng.randrange(4)                    # RC for {er}; ignored for {sae}
        tag = ('-rc%d' % ll) if emb == 'er' else ('-sae-ll%d' % ll)
    elif form == 'bcst':
        b = 1
    vl = 64 if form == 'emb' else 16 << ll
    aaa = rng.choice([0, 0, 1, 2, 3, 4, 5, 6, 7])
    z = rng.choice([0, 1]) if aaa else 0
    dst, src = rng.randrange(8), rng.randrange(8)
    src1 = rng.randrange(8) if scalar else None
    n = access_size(fam, form, vl)
    if form in ('reg', 'emb'):
        tail, where = bytes([0xc0 | (dst << 3) | src]), ''
    else:
        where = rng.choice(['base', 'd8', 'd8', 'rdi', 'sib', 'd32'])
        if where == 'base':
            tail = bytes([(dst << 3) | 3])
        elif where in ('d8', 'sib'):
            m = rng.randint(0, min((256 - n) // n, 127))
            tail = bytes([0x40 | (dst << 3) | 3, m]) if where == 'd8' else bytes([0x44 | (dst << 3), 0x33, m])
        elif where == 'rdi':
            m = rng.randint(max(-(128 // n), -128), min((128 - n) // n, 127))
            tail = bytes([0x40 | (dst << 3) | 7, m & 0xff])
        else:
            tail = bytes([0x80 | (dst << 3) | 3]) + struct.pack('<i', rng.randint(0, 256 - n))
        where = '-' + where
    code = encode(fam, ll, b, z, aaa, dst, src1, tail)
    mx = None
    if rng.random() < 0.5:
        mx = rng.choice([0x1f80, 0x3f80, 0x5f80, 0x7f80]) | rng.choice([0, 0, 0x40, 0x8000, 0x8040])
    window = bytearray(fill(rng, kind, 256))
    if mx is not None: window[MXCSR_OFF:MXCSR_OFF + 4] = struct.pack('<I', mx)
    name = f"BOCHS-{fam}-vl{vl * 8}-{form}{tag}{where}-k{aaa}-z{z}-mx{mx if mx is not None else 0x1f80:04x}"
    used = {dst, src} if form in ('reg', 'emb') else {dst}
    if src1 is not None: used.add(src1)
    return dict(name=name, prog=(LDMXCSR if mx is not None else b'') + code, ninstr=2 if mx is not None else 1,
                zmm8=registers(rng, kind, used), aaa=aaa, kval=mask(rng, aaa), window=bytes(window), mode=0, valid=0)


def guard_case(rng, fam):
    """[rbx] ends `valid` bytes before the not-present page (HBUP mode 1)."""
    op, pp, w, shape, emb, kind, se, de = FAMILIES[fam]
    scalar = shape == 'scalar'
    form = 'mem' if scalar or rng.random() < 0.75 else 'bcst'
    ll = rng.choice([0, 1, 2])
    vl = 16 << ll
    n = access_size(fam, form, vl)
    valid = rng.choice(sorted({0, se, n // 2, n - se, n - 1} & set(range(0, 65))) + [rng.randrange(0, min(n, 64) + 1)])
    aaa = rng.choice([0, 1, 1, 2, 3, 4, 5, 6, 7])
    z = rng.choice([0, 1]) if aaa else 0
    dst = rng.randrange(8)
    src1 = rng.randrange(8) if scalar else None
    code = encode(fam, ll, 1 if form == 'bcst' else 0, z, aaa, dst, src1, bytes([(dst << 3) | 3]))
    lanes = 1 if scalar else vl // max(se, de)
    ok = max(0, valid // se)                           # elements that fit before the boundary
    kval = rng.choice([0, (1 << ok) - 1, ((1 << ok) - 1) | (1 << min(ok, lanes - 1)), 0xffff,
                       rng.getrandbits(lanes)]) if aaa else 0
    window = fill(rng, kind, 256)
    name = f"BOCHS-GUARD-{fam}-vl{vl * 8}-{form}-k{aaa}-z{z}-valid{valid}"
    used = {dst} if src1 is None else {dst, src1}
    return dict(name=name, prog=code, ninstr=1, zmm8=registers(rng, kind, used), aaa=aaa, kval=kval,
                window=window, mode=1, valid=valid)


F64_EDGE = [0x380ffffff0000000, 0xb80ffffff0000000, 0x380fffffe0000000, 0x3690000000000000,
            0x3690000000000001, 0x3698000000000000, 0x47effffff0000000, 0x0000000000000001]
F32_EDGE = [0x3f000000, 0x3fc00000, 0x40200000, 0xbf000000, 0xbfc00000, 0x4effffff, 0x4f000000,
            0xcf000000, 0xcf000001, 0x00000001, 0x80000001, 0x007fffff, 0x3f7fffff, 0xbf7fffff,
            0x7fc00000, 0xff800000]
I32_EDGE = [(1 << 24) + 1, (1 << 24) + 3, -(1 << 24) - 1, -(1 << 24) - 3, (1 << 25) + 2,
            (1 << 25) + 6, 0x7fffffff, -0x80000000, 0x7fffffc0, 0x7fffffbf, 0x40000040,
            0x400000c0, 1, -1, 0, -0x7fffffc0]


def edge_cases():
    """Fixed vectors of rounding ties, binary32 overflow and underflow edges (2^-126 - 2^-151
    is tiny before rounding but not after), denormals and the integer indefinite, under every
    MXCSR.RC with and without DAZ/FTZ and under every {er}: rare in the random part."""
    out = []
    reg = lambda fam, b, ll, tail: encode(fam, ll, b, 0, 0, 0, None, tail)
    vecs = {'f64': struct.pack('<8Q', *F64_EDGE), 'f32': struct.pack('<16I', *F32_EDGE),
            'i32': struct.pack('<16i', *I32_EDGE)}
    for fam, kind in (('vcvtpd2ps', 'f64'), ('vcvtps2dq', 'f32'), ('vcvttps2dq', 'f32'),
                      ('vcvtdq2ps', 'i32'), ('vcvtps2pd', 'f32'), ('vcvtdq2pd', 'i32')):
        emb = FAMILIES[fam][4]
        for rc in range(4):
            for extra in (0, 0x40, 0x8000):
                mx = 0x1f80 | (rc << 13) | extra
                window = bytearray(256); window[MXCSR_OFF:MXCSR_OFF + 4] = struct.pack('<I', mx)
                zmm8 = bytes(64) + vecs[kind] + bytes(6 * 64)
                out.append(dict(name=f'BOCHS-EDGE-{fam}-mx{mx:04x}', prog=LDMXCSR + reg(fam, 0, 2, b'\xc1'),
                                ninstr=2, zmm8=zmm8, aaa=0, kval=0, window=bytes(window), mode=0, valid=0))
            if emb == 'er':
                window = bytearray(256); window[MXCSR_OFF:MXCSR_OFF + 4] = struct.pack('<I', 0x9fc0)
                zmm8 = bytes(64) + vecs[kind] + bytes(6 * 64)
                out.append(dict(name=f'BOCHS-EDGE-{fam}-er{rc}-ftzdaz', prog=LDMXCSR + reg(fam, 1, rc, b'\xc1'),
                                ninstr=2, zmm8=zmm8, aaa=0, kval=0, window=bytes(window), mode=0, valid=0))
    for fam, kind, vals in (('vcvtsd2ss', 'f64', F64_EDGE), ('vcvtss2sd', 'f32', F32_EDGE[9:12])):
        for v in vals:
            for rc in range(4):
                mx = 0x1f80 | (rc << 13) | 0x8000 | (0x40 if fam == 'vcvtss2sd' and rc & 1 else 0)
                window = bytearray(256); window[MXCSR_OFF:MXCSR_OFF + 4] = struct.pack('<I', mx)
                src2 = struct.pack('<Q' if kind == 'f64' else '<I', v).ljust(64, b'\x55')
                zmm8 = bytes(64) + bytes(range(64)) + src2 + bytes(5 * 64)
                out.append(dict(name=f'BOCHS-EDGE-{fam}-{v:x}-mx{mx:04x}',
                                prog=LDMXCSR + encode(fam, 0, 0, 0, 0, 0, 1, b'\xc2'), ninstr=2, zmm8=zmm8,
                                aaa=0, kval=0, window=bytes(window), mode=0, valid=0))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    ap.add_argument('--count', type=int, default=480)
    ap.add_argument('--guard-count', type=int, default=160)
    ap.add_argument('--seed', type=int, default=0x27092026)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    fams = list(FAMILIES)
    rec, faults, skipped = [], 0, 0
    edges = edge_cases()
    todo = [('edge', i) for i in range(len(edges))] + [('ordinary', i) for i in range(a.count)] + \
           [('guard', i) for i in range(a.guard_count)]
    for kind, i in todo:
        fam = fams[i % len(fams)]
        while True:
            c = edges[i] if kind == 'edge' else (ordinary_case if kind == 'ordinary' else guard_case)(rng, fam)
            ebx = WINDOW if c['mode'] == 0 else GUARD - c['valid']
            out8, exc = bochs(c['prog'], c['ninstr'], c['zmm8'], c['aaa'], c['kval'], c['window'], ebx)
            if out8 is not None or (exc == 'pf' and c['mode'] == 1): break
            skipped += 1
            print('SKIP', c['name'], c['prog'].hex(), exc, file=sys.stderr)
        fault = out8 is None
        faults += fault
        ks = [rng.getrandbits(64) for _ in range(8)]
        if c['aaa']: ks[c['aaa']] = c['kval'] | (rng.getrandbits(48) << 16)   # no lane above 15
        vin = c['zmm8'] + UPPER
        vout = (c['zmm8'] if fault else out8) + UPPER    # a faulting record's vectors are not checked
        nb = c['name'].encode()
        rec.append(struct.pack('<HHIQ8QiiI', len(nb), len(c['prog']), 2, len(rec), *ks, c['mode'], c['valid'],
                               int(fault)) + nb + c['prog'] + vin + c['window'] + vout + c['window'])
    with gzip.GzipFile(filename=a.out, mode='wb', mtime=0) as g:
        g.write(b'HBUP0002' + struct.pack('<I', len(rec)) + b''.join(rec))
    print(f'{len(rec)} records ({faults} expected faults), {skipped} skipped', file=sys.stderr)


if __name__ == '__main__':
    main()
