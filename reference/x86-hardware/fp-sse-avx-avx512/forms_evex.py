# SPDX-License-Identifier: MIT
"""Original AVX-512F/VL/DQ register-form inventory for the shared native harness.

Every form explicitly selects EVEX.  The ISA vector length is ``width``; sizes
specify the actually supplied operands, and out_bytes retains visible upper
zeroing. See evex-notes.md for the bounded control cross-product.
"""
from itertools import product

_ROUND = ('rn-sae', 'rd-sae', 'ru-sae', 'rz-sae')
_REG = {128: 'xmm', 256: 'ymm', 512: 'zmm'}

def _reg(width, slot):
    return '%' + _REG[max(128, width)] + str(slot)

def _masks(width, lane, scalar=False, maskout=False):
    n = 1 if scalar else width // (8 * lane)
    full = (1 << n) - 1
    alt = sum(1 << i for i in range(0, n, 2))
    pairs = [(full, False), (0, False), (alt, False)]
    if not maskout:
        pairs += [(full, True), (0, True), (alt, True)]
    return list(dict.fromkeys(pairs))

def _ctrl(ims, width, lane, scalar, er, maskout=False, masked=True):
    masks = _masks(width, lane, scalar, maskout) if masked else [(0, False)]
    # All immediate values receive the all-active non-SAE form. Additional
    # control cross-products use both endpoint immediates (or the sole None).
    refs = {ims[0], ims[-1]}
    for imm in ims:
        combos = product(masks, ('-',) + tuple(er)) if imm in refs else [(masks[0], '-')]
        for (mask, zero), rounding in combos:
            yield imm, mask, zero, rounding

def _form(name, width, lane, scalar, nops, axes, asm, mask, zero, er,
          imm=None, feature='avx512f', **extra):
    r = dict(cls='evex', name=name, enc='EVEX', width=width, lane=lane,
             scalar=scalar, nops=nops, axes=list(axes), asm=asm,
             mask=mask, zero=zero, er=er, feature=feature)
    if imm is not None:
        r['imm'] = imm
    r.update(extra)
    return r

def _vector(name, width, lane, scalar=False, arity=3, immediates=None,
            er=(), feature='avx512f', axes=None, types=None):
    ims = list(immediates) if immediates is not None else [None]
    if axes is None:
        axes = [1] if arity == 2 else [1, 2]
    regs = [_reg(width, i) for i in range(3)]
    for imm, mask, zero, rounding in _ctrl(ims, width, lane, scalar, er):
        parts = []
        if imm is not None:
            parts.append('$' + str(imm))
        if rounding != '-':
            parts.append('{' + rounding + '}')
        parts += [regs[i] for i in reversed(range(1, arity))]
        parts.append(regs[0] + '{%k1}' + ('{z}' if zero else ''))
        extra = {} if types is None else {'types': types}
        yield _form(name, width, lane, scalar, arity, axes,
                    name + ' ' + ', '.join(parts),
                    mask, zero, rounding, imm, feature, **extra)

def _fp_family(stem, arity=3, er=(), immediates=None, feature='avx512f',
               axes=None, fixup=False, scalar=True):
    for suf, lane in [('ps', 4), ('pd', 8), ('ss', 4), ('sd', 8)]:
        isscalar = suf in ('ss', 'sd')
        if isscalar and not scalar:
            continue
        for width in ([128] if isscalar else [128, 256, 512]):
            actualarity = 3 if isscalar else arity
            legal_er = er if isscalar or width == 512 else ()
            typ = 'f32' if lane == 4 else 'f64'
            types = [typ, typ, ('i32' if lane == 4 else 'i64')] if fixup else None
            yield from _vector(stem + suf, width, lane, isscalar, actualarity,
                               immediates, legal_er, feature, axes, types)

def _mask_result(name, width, lane, scalar, immediates, binary, er=(), feature='avx512f'):
    ims = list(immediates)
    for imm, mask, _, rounding in _ctrl(ims, width, lane, scalar, er, maskout=True):
        parts = ['$' + str(imm)]
        if rounding != '-':
            parts.append('{' + rounding + '}')
        if binary:
            parts += [_reg(width, 2), _reg(width, 1)]
        else:
            parts += [_reg(width, 1)]
        parts += ['%k2{%k1}']
        nops = 3 if binary else 2
        typ = 'f32' if lane == 4 else 'f64'
        yield _form(name, width, lane, scalar, nops,
                    [1, 2] if binary else [1],
                    name + ' ' + ', '.join(parts),
                    mask, False, rounding, imm, feature,
                    pre='movq 0(%rdi), %rax\nkmovq %rax, %k2',
                    post='kmovq %k2, %rax\nmovq %rax, 0(%rsi)',
                    sizes=[8] + [width // 8] * (nops - 1),
                    types=['i64'] + [typ] * (nops - 1), out_bytes=8)

def _convert(name, width, src_type, dst_type, src_width, dst_width,
             er=(), immediates=None, feature='avx512f'):
    ims = list(immediates) if immediates is not None else [None]
    src_lane = int(src_type[1:]) // 8
    dst_lane = int(dst_type[1:]) // 8
    nlanes = min(src_width // (8 * src_lane), dst_width // (8 * dst_lane))
    # Number of mask bits tracks conversion element count, not the maximum
    # register width (narrowing conversions need this distinction).
    for imm, mask, zero, rounding in _ctrl(ims, nlanes * dst_lane * 8,
                                         dst_lane, False, er):
        parts = []
        if imm is not None:
            parts += ['$' + str(imm)]
        if rounding != '-':
            parts += ['{' + rounding + '}']
        parts += [_reg(src_width, 1), _reg(dst_width, 0) + '{%k1}' + ('{z}' if zero else '')]
        yield _form(name, width, src_lane, False, 2, [1],
                    name + ' ' + ', '.join(parts), mask, zero,
                    rounding, imm, feature, types=[dst_type, src_type],
                    sizes=[width // 8, max(16, src_width // 8)], out_bytes=width // 8)

def forms():
    out = []
    add = out.extend
    # Classes 1 and 2: all scalar and packed arithmetic and FMA3 encodings.
    for op in ('add', 'sub', 'mul', 'div'):
        add(_fp_family('v' + op, er=_ROUND))
    for op in ('min', 'max'):
        add(_fp_family('v' + op, er=('sae',)))
    add(_fp_family('vsqrt', arity=2, er=_ROUND))
    for op in ('fmadd', 'fmsub', 'fnmadd', 'fnmsub', 'fmaddsub', 'fmsubadd'):
        for order in (132, 213, 231):
            add(_fp_family('v' + op + str(order), er=_ROUND,
                           axes=[0, 1, 2], scalar=op not in ('fmaddsub', 'fmsubadd')))
    # Classes 3 and 6: masks, flags, and AVX-512 approximate reciprocals.
    for suf, lane in [('ps', 4), ('pd', 8), ('ss', 4), ('sd', 8)]:
        scalar = suf in ('ss', 'sd')
        for width in ([128] if scalar else [128, 256, 512]):
            add(_mask_result('vcmp' + suf, width, lane, scalar, range(32), True,
                             er=('sae',) if scalar or width == 512 else ()))
            add(_mask_result('vfpclass' + suf, width, lane, scalar, range(256), False,
                             feature='avx512dq'))
    for stem in ('vcomi', 'vucomi'):
        for suf, lane in [('ss', 4), ('sd', 8)]:
            for er in ('-', 'sae'):
                asm = ('{evex} ' if er == '-' else '') + stem + suf + (' {sae},' if er == 'sae' else '') + ' %xmm1, %xmm0'
                out.append(_form(stem + suf, 128, lane, True, 2, [0, 1], asm,
                                 0, False, er, flags=True, out_bytes=2))
    for stem in ('vrcp14', 'vrsqrt14'):
        add(_fp_family(stem, arity=2))
    # AVX-512-only range reduction, exponent, mantissa and special-value fixup.
    add(_fp_family('vgetexp', arity=2, er=('sae',)))
    add(_fp_family('vgetmant', arity=2, er=('sae',), immediates=range(16)))
    add(_fp_family('vscalef', er=_ROUND))
    add(_fp_family('vrndscale', arity=2, er=('sae',), immediates=range(256)))
    add(_fp_family('vreduce', arity=2, er=('sae',), immediates=range(256), feature='avx512dq'))
    add(_fp_family('vrange', er=('sae',), immediates=range(16), feature='avx512dq'))
    add(_fp_family('vfixupimm', er=('sae',), immediates=range(256), axes=[0, 1, 2], fixup=True))
    # Packed float, double and signed/unsigned 32/64-bit integer conversions.
    # A descriptor names each instruction exactly. VL is the wider operand.
    conversions = [
        ('vcvtps2pd', 'f32', 'f64', 'sae', 'avx512f'),
        ('vcvtpd2ps', 'f64', 'f32', 'er', 'avx512f'),
        ('vcvtdq2ps', 'i32', 'f32', 'er', 'avx512f'),
        ('vcvtudq2ps', 'i32', 'f32', 'er', 'avx512f'),
        ('vcvtdq2pd', 'i32', 'f64', '-', 'avx512f'),
        ('vcvtudq2pd', 'i32', 'f64', '-', 'avx512f'),
        ('vcvtqq2ps', 'i64', 'f32', 'er', 'avx512dq'),
        ('vcvtuqq2ps', 'i64', 'f32', 'er', 'avx512dq'),
        ('vcvtqq2pd', 'i64', 'f64', 'er', 'avx512dq'),
        ('vcvtuqq2pd', 'i64', 'f64', 'er', 'avx512dq'),
    ]
    for ft in ('ps', 'pd'):
        for it in ('dq', 'udq', 'qq', 'uqq'):
            for trunc in (False, True):
                conversions.append(('vcvtt' + ft + '2' + it if trunc else 'vcvt' + ft + '2' + it,
                                    'f32' if ft == 'ps' else 'f64',
                                    'i32' if it in ('dq', 'udq') else 'i64',
                                    'sae' if trunc else 'er',
                                    'avx512f' if it in ('dq', 'udq') else 'avx512dq'))
    for name, src, dst, mode, feature in conversions:
        sl = int(src[1:])
        dl = int(dst[1:])
        for width in (128, 256, 512):
            sw = width if sl >= dl else width // 2
            dw = width if dl >= sl else width // 2
            er = (() if width != 512 or mode == '-' else ('sae',) if mode == 'sae' else _ROUND)
            add(_convert(name, width, src, dst, sw, dw, er, feature=feature))
    for width in (128, 256, 512):
        add(_convert('vcvtph2ps', width, 'f16', 'f32', width // 2, width,
                     ('sae',) if width == 512 else ()))
        add(_convert('vcvtps2ph', width, 'f32', 'f16', width, width // 2,
                     ('sae',) if width == 512 else (), range(8)))
    # Scalar precision changes retain source 1's upper XMM bits.
    for name, st, dt, mode in [('vcvtss2sd', 'f32', 'f64', ('sae',)),
                               ('vcvtsd2ss', 'f64', 'f32', _ROUND)]:
        lane = int(st[1:]) // 8
        add(_vector(name, 128, lane, True, 3, er=mode, types=[dt, dt, st]))
    # Scalar GPR conversions have no opmask. Slot A is the integer destination
    # for float-to-int, or the vector destination for int-to-float.
    for suf, lane, typ in [('ss', 4, 'f32'), ('sd', 8, 'f64')]:
        for bits in (32, 64):
            gpr = '%eax' if bits == 32 else '%rax'
            suffix = 'l' if bits == 32 else 'q'
            mov = 'movl' if bits == 32 else 'movq'
            for unsigned in (False, True):
                for trunc in (False, True):
                    name = ('vcvtt' if trunc else 'vcvt') + suf + ('2usi' if unsigned else '2si')
                    for er in ('-',) + (('sae',) if trunc else _ROUND):
                        asm = ('{evex} ' if er == '-' else '') + name + ' ' + ('{' + er + '}, ' if er != '-' else '') + '%xmm1, ' + gpr
                        out.append(_form(name, 128, lane, True, 2, [1], asm,
                                         0, False, er, types=['i' + str(bits), typ],
                                         sizes=[bits // 8, 16], out_bytes=bits // 8,
                                         pre=mov + ' 0(%rdi), ' + gpr,
                                         post=mov + ' ' + gpr + ', 0(%rsi)', gpr_bits=bits))
                name = ('vcvtusi2' if unsigned else 'vcvtsi2') + suf
                # Integer32 -> double is exact; ignored-ER encoding aliases are omitted.
                ers = ('-',) if bits == 32 and suf == 'sd' else ('-',) + _ROUND
                for er in ers:
                    asm = ('{evex} ' if er == '-' else '') + name + suffix + ' ' + gpr + ', ' + ('{' + er + '}, ' if er != '-' else '') + '%xmm1, %xmm0'
                    out.append(_form(name, 128, lane, True, 3, [1, 2], asm,
                                     0, False, er, types=[typ, typ, 'i' + str(bits)],
                                     sizes=[16, 16, bits // 8], out_bytes=16,
                                     pre=mov + ' 128(%rdi), ' + gpr, gpr_bits=bits))
    for f in out:
        if 'imm' in f:
            f['cases'] = 16
        f['required_features'] = [f['feature']] + (['avx512vl'] if not f['scalar'] and f['width'] < 512 else [])
    return out

if __name__ == '__main__':
    import collections
    fs = forms()
    print('EVEX forms:', len(fs))
    print('Mnemonics:', len({f['name'] for f in fs}))
    for name, count in sorted(collections.Counter(f['name'] for f in fs).items()):
        print(name, count)
