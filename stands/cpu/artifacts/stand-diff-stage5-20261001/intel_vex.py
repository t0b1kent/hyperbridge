"""Independent VEX oracle: exact rational IEEE arithmetic, explicit vector merge.

No FEX/native output or Unicorn FP arithmetic is used to obtain expected bits.
Unsupported instructions fail closed at the instruction that is executed.
Intel SDM Vol.2 VADDSS/VMULSD/VCVTSS2SD and Vol.1 section 4.8 semantics.
"""
from fractions import Fraction
import re


class Unavailable(Exception):
    pass


def fmt(width):
    return (23, 8, 127) if width == 32 else (52, 11, 1023)


def unpack(bits, width, daz=False):
    f, e, bias = fmt(width)
    sign = bits >> (width - 1)
    exponent = (bits >> f) & ((1 << e) - 1)
    mantissa = bits & ((1 << f) - 1)
    if exponent == (1 << e) - 1:
        return ('nan' if mantissa else 'inf', sign, mantissa)
    if not exponent and (not mantissa or daz):
        return ('zero', sign, Fraction(0))
    significand = mantissa + ((1 << f) if exponent else 0)
    power = (exponent - bias if exponent else 1 - bias) - f
    value = Fraction(significand << max(power, 0), 1 << max(-power, 0))
    return ('finite', sign, -value if sign else value)


def round_ratio(numerator, denominator, negative, rc):
    q, r = divmod(numerator, denominator)
    increment = (2 * r > denominator or (2 * r == denominator and q & 1)) if rc == 0 else bool(r) and (
        (rc == 1 and negative) or (rc == 2 and not negative))
    return q + int(increment)


def encode(value, width, rc=0, zero_sign=0, ftz=False):
    f, e, bias = fmt(width)
    negative = value < 0
    sign = int(negative) if value else zero_sign
    sign_bit = sign << (width - 1)
    if not value:
        return sign_bit
    v = abs(value)
    power = v.numerator.bit_length() - v.denominator.bit_length()
    boundary = Fraction(1 << max(power, 0), 1 << max(-power, 0))
    if v < boundary:
        power -= 1
    minimum, maximum = 1 - bias, bias
    quantum = max(power, minimum) - f
    scaled = v * Fraction(1 << max(-quantum, 0), 1 << max(quantum, 0))
    significand = round_ratio(scaled.numerator, scaled.denominator, negative, rc)
    if significand >= (1 << (f + 1)):
        power += 1
        significand >>= 1
    if power > maximum:
        infinity = rc == 0 or (rc == 1 and negative) or (rc == 2 and not negative)
        return sign_bit | ((((1 << e) - 1) << f) if infinity else ((((1 << e) - 2) << f) | ((1 << f) - 1)))
    if significand < (1 << f):
        return sign_bit if ftz else sign_bit | significand
    return sign_bit | ((max(power, minimum) + bias) << f) | (significand - (1 << f))


def convert(bits, source_width, width, mxcsr):
    kind, sign, value = unpack(bits, source_width, bool(mxcsr & 64))
    f, e, _ = fmt(width)
    if kind == 'inf':
        return (sign << (width - 1)) | (((1 << e) - 1) << f)
    if kind == 'nan':
        source_f = fmt(source_width)[0]
        payload = value << max(f - source_f, 0) if f >= source_f else value >> (source_f - f)
        return (sign << (width - 1)) | (((1 << e) - 1) << f) | payload | (1 << (f - 1))
    return encode(value, width, (mxcsr >> 13) & 3, sign, bool(mxcsr & 0x8000))


def arithmetic(operation, a, b, width, mxcsr):
    ka, sa, va = unpack(a, width, bool(mxcsr & 64))
    kb, sb, vb = unpack(b, width, bool(mxcsr & 64))
    f, e, _ = fmt(width)
    infinity = ((1 << e) - 1) << f
    indefinite = (1 << (width - 1)) | infinity | (1 << (f - 1))
    if ka == 'nan' or kb == 'nan':
        # x86 source-order quiet NaN propagation. Sign and payload are retained.
        return (a if ka == 'nan' else b) | (1 << (f - 1))
    if operation in ('add', 'sub'):
        if operation == 'sub':
            sb ^= 1
            if kb in ('finite', 'zero'):
                vb = -vb
        if ka == kb == 'inf' and sa != sb:
            return indefinite
        if ka == 'inf' or kb == 'inf':
            return infinity | ((sa if ka == 'inf' else sb) << (width - 1))
        result = va + vb
        zero_sign = sa if not va and not vb and sa == sb else int(((mxcsr >> 13) & 3) == 1)
    elif operation == 'mul':
        if (ka == 'inf' and kb == 'zero') or (kb == 'inf' and ka == 'zero'):
            return indefinite
        if ka == 'inf' or kb == 'inf':
            return infinity | ((sa ^ sb) << (width - 1))
        result, zero_sign = va * vb, sa ^ sb
    elif operation == 'div':
        if (ka == kb == 'inf') or (ka == kb == 'zero'):
            return indefinite
        if ka == 'inf' or kb == 'zero':
            return infinity | ((sa ^ sb) << (width - 1))
        if kb == 'inf':
            return (sa ^ sb) << (width - 1)
        result, zero_sign = va / vb, sa ^ sb
    else:
        raise Unavailable(operation)
    return encode(result, width, (mxcsr >> 13) & 3, zero_sign, bool(mxcsr & 0x8000))


def is_vex(ins):
    raw = bytes(ins.bytes)
    i = 0
    while i < len(raw) and raw[i] in (0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x67):
        i += 1
    return i < len(raw) and raw[i] in (0xc4, 0xc5)


def source1(ins):
    raw = bytes(ins.bytes)
    i = next(i for i, b in enumerate(raw) if b in (0xc4, 0xc5))
    return (~raw[i + (1 if raw[i] == 0xc5 else 2)] >> 3) & 15


def execute(ins, em, ux, xc, read_memory, write_memory):
    """Execute one supported VEX instruction and advance RIP, skipping TCG."""
    name = ins.mnemonic
    def register(reg):
        return getattr(ux, 'UC_X86_REG_' + ins.reg_name(reg).upper())
    def vector(index):
        return em.reg_read(getattr(ux, f'UC_X86_REG_YMM{index}')).to_bytes(32, 'little')
    def address(op):
        m = op.mem
        base = ins.address + ins.size if m.base == xc.X86_REG_RIP else em.reg_read(register(m.base)) if m.base else 0
        index = em.reg_read(register(m.index)) if m.index else 0
        segment = em.reg_read(getattr(ux, 'UC_X86_REG_' + ins.reg_name(m.segment).upper() + '_BASE')) if m.segment else 0
        return ((base + index * m.scale + m.disp) & ((1 << 64) - 1)) + segment
    def read(op, size=None):
        n = op.size if size is None else size
        if op.type == xc.X86_OP_MEM:
            return read_memory(address(op), n)
        if op.type == xc.X86_OP_REG:
            return (em.reg_read(register(op.reg)) & ((1 << (8 * n)) - 1)).to_bytes(n, 'little')
        raise Unavailable('operand ' + name)
    def write(op, data):
        if op.type == xc.X86_OP_MEM:
            write_memory(address(op), data)
        elif op.type == xc.X86_OP_REG:
            regname = ins.reg_name(op.reg)
            if regname.startswith(('xmm', 'ymm')):
                index = int(regname[3:])
                em.reg_write(getattr(ux, f'UC_X86_REG_YMM{index}'), int.from_bytes(data, 'little'))
            else:
                em.reg_write(register(op.reg), int.from_bytes(data, 'little'))
        else:
            raise Unavailable('destination ' + name)
    ops = ins.operands
    mxcsr = em.reg_read(ux.UC_X86_REG_MXCSR)
    scalar = re.fullmatch(r'v(add|sub|mul|div)(ss|sd)', name)
    conversion = name in ('vcvtss2sd', 'vcvtsd2ss', 'vcvtsi2ss', 'vcvtsi2sd',
                          'vcvtss2si', 'vcvtsd2si', 'vcvttss2si', 'vcvttsd2si')
    if scalar or conversion:
        if scalar:
            operation, suffix = scalar.groups()
            width = 32 if suffix == 'ss' else 64
            merge = vector(source1(ins))
            left = int.from_bytes(merge[:width // 8], 'little')
            right = int.from_bytes(read(ops[-1], width // 8), 'little')
            result = arithmetic(operation, left, right, width, mxcsr)
        elif name in ('vcvtss2sd', 'vcvtsd2ss'):
            source_width, width = (32, 64) if name == 'vcvtss2sd' else (64, 32)
            merge = vector(source1(ins))
            result = convert(int.from_bytes(read(ops[-1], source_width // 8), 'little'), source_width, width, mxcsr)
        elif name in ('vcvtsi2ss', 'vcvtsi2sd'):
            width = 32 if name.endswith('ss') else 64
            merge = vector(source1(ins))
            integer = int.from_bytes(read(ops[-1]), 'little', signed=True)
            result = encode(Fraction(integer), width, (mxcsr >> 13) & 3)
        else:
            width = 32 if 'ss' in name else 64
            bits = int.from_bytes(read(ops[-1], width // 8), 'little')
            kind, sign, value = unpack(bits, width, bool(mxcsr & 64))
            out_width = ops[0].size * 8
            rc = 3 if name.startswith('vcvtt') else (mxcsr >> 13) & 3
            if kind in ('nan', 'inf'):
                integer = -(1 << (out_width - 1))
            else:
                integer = round_ratio(abs(value.numerator), value.denominator, value < 0, rc)
                if value < 0:
                    integer = -integer
                if not -(1 << (out_width - 1)) <= integer < (1 << (out_width - 1)):
                    integer = -(1 << (out_width - 1))
            write(ops[0], (integer & ((1 << out_width) - 1)).to_bytes(out_width // 8, 'little'))
            em.reg_write(ux.UC_X86_REG_RIP, ins.address + ins.size)
            return
        write(ops[0], result.to_bytes(width // 8, 'little') + merge[width // 8:16])
    elif name == 'vzeroupper':
        for i in range(16):
            em.reg_write(getattr(ux, f'UC_X86_REG_YMM{i}'), int.from_bytes(vector(i)[:16], 'little'))
    elif name in ('vmovaps', 'vmovapd', 'vmovups', 'vmovupd', 'vmovdqa', 'vmovdqu', 'vmovntdq', 'vmovd', 'vmovq'):
        write(ops[0], read(ops[1]))
    elif name in ('vmovss', 'vmovsd'):
        n = 4 if name == 'vmovss' else 8
        if len(ops) == 3:
            write(ops[0], read(ops[2], n) + vector(source1(ins))[n:16])
        elif ops[0].type == xc.X86_OP_MEM:
            write(ops[0], read(ops[1], n))
        elif ops[1].type == xc.X86_OP_MEM:
            write(ops[0], read(ops[1], n) + bytes(16 - n))
        else:
            raise Unavailable(name + ' encoding')
    elif name in ('vxorps', 'vxorpd', 'vpxor', 'vandps', 'vandpd', 'vpand', 'vorps', 'vorpd', 'vpor', 'vandnps', 'vandnpd'):
        n = ops[0].size
        a, b = int.from_bytes(read(ops[1], n), 'little'), int.from_bytes(read(ops[2], n), 'little')
        if 'xor' in name:
            value = a ^ b
        elif 'andn' in name:
            value = (~a & b) & ((1 << (8 * n)) - 1)
        elif 'and' in name:
            value = a & b
        else:
            value = a | b
        write(ops[0], value.to_bytes(n, 'little'))
    else:
        raise Unavailable(name)
    em.reg_write(ux.UC_X86_REG_RIP, ins.address + ins.size)
