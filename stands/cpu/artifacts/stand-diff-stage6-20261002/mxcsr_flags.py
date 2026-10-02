"""Independent Intel SSE/AVX exception-status oracle from operand bits.

Exact Fraction arithmetic; integer square-root bounds for SQRT. No FEX output,
host floating-point arithmetic, or Unicorn exception bits define the answer.
Masked exception semantics (Intel SDM Vol.1 10.2/11.5, Vol.2 instruction pages).
Unmasked #XM and unsupported producers fail closed, never compare as EQUAL.
"""
import collections
from fractions import Fraction
from math import isqrt
import re

import intel_vex as ieee
from census import family

IE, DE, ZE, OE, UE, PE = (1 << n for n in range(6))
STATUS_MASK = 0x3f


class Unavailable(Exception):
    pass


def raw_kind(bits, width):
    f, e, _ = ieee.fmt(width)
    exponent = (bits >> f) & ((1 << e)-1)
    mantissa = bits & ((1 << f)-1)
    return dict(denormal=exponent == 0 and mantissa != 0,
                snan=exponent == (1 << e)-1 and bool(mantissa) and not bool(mantissa & (1 << (f-1))))


def operand(bits, width, mxcsr):
    raw = raw_kind(bits, width)
    return (*ieee.unpack(bits, width, bool(mxcsr & 0x40)), raw)


def power2(n):
    return Fraction(1 << max(n, 0), 1 << max(-n, 0))


def floor_log2(value):
    v = abs(value)
    n = v.numerator.bit_length()-v.denominator.bit_length()
    return n-int(v < power2(n))


def rounded_flags(value, width, mxcsr):
    if not value:
        return 0
    f, _, bias = ieee.fmt(width)
    minimum, maximum = 1-bias, bias
    power = floor_log2(value)
    quantum = max(power, minimum)-f
    scaled = abs(value)/power2(quantum)
    q = ieee.round_ratio(scaled.numerator, scaled.denominator, value < 0, (mxcsr >> 13) & 3)
    rounded = q*power2(quantum)
    if rounded >= power2(maximum+1):
        return OE | PE
    tiny = rounded < power2(minimum)
    inexact = rounded != abs(value)
    if tiny and mxcsr & 0x8000:
        return UE | PE  # software flush also affects exact nonzero tiny results
    return (PE if inexact else 0) | (UE if tiny and inexact else 0)


def arithmetic_flags(operation, a, b, width, mxcsr):
    ka, sa, va, ra = operand(a, width, mxcsr)
    kb, sb, vb, rb = operand(b, width, mxcsr)
    if ka == 'nan' or kb == 'nan':
        return IE if ra['snan'] or rb['snan'] else 0
    flags = DE if not mxcsr & 0x40 and (ra['denormal'] or rb['denormal']) else 0
    if operation in ('min', 'max'):
        return flags
    if operation in ('add', 'sub'):
        if operation == 'sub':
            sb ^= 1
            if kb != 'inf': vb = -vb
        if ka == kb == 'inf' and sa != sb: return flags | IE
        if ka == 'inf' or kb == 'inf': return flags
        exact = va+vb
    elif operation == 'mul':
        if (ka == 'inf' and kb == 'zero') or (kb == 'inf' and ka == 'zero'): return flags | IE
        if ka == 'inf' or kb == 'inf': return flags
        exact = va*vb
    elif operation == 'div':
        if ka == kb and ka in ('zero', 'inf'): return flags | IE
        if kb == 'zero': return flags | (ZE if ka != 'inf' else 0)
        if ka == 'inf' or kb == 'inf': return flags
        exact = va/vb
    else:
        raise Unavailable(operation)
    return flags | rounded_flags(exact, width, mxcsr)


def sqrt_flags(bits, width, mxcsr):
    kind, sign, value, raw = operand(bits, width, mxcsr)
    if kind == 'nan': return IE if raw['snan'] else 0
    flags = DE if raw['denormal'] and not mxcsr & 0x40 else 0
    if sign and kind != 'zero': return flags | IE
    if kind in ('zero', 'inf'): return flags
    f, _, _ = ieee.fmt(width)
    quantum = floor_log2(value)//2-f
    scaled = value/power2(2*quantum)
    q = isqrt(scaled.numerator//scaled.denominator)
    # Perfect rational square is exactly representable; otherwise PE.
    return flags | (PE if q*q*scaled.denominator != scaled.numerator else 0)


def float_to_int(bits, width, out_width, mxcsr, truncate=False):
    kind, sign, value, _ = operand(bits, width, mxcsr)
    # CVT(T)SS/SD/PS/PD -> signed integer lists IE and PE, not DE.
    if kind in ('nan', 'inf'): return IE
    rc = 3 if truncate else (mxcsr >> 13) & 3
    integer = ieee.round_ratio(abs(value.numerator), value.denominator, value < 0, rc)
    if value < 0: integer = -integer
    if not -(1 << (out_width-1)) <= integer < (1 << (out_width-1)): return IE
    return PE if integer != value else 0


def float_convert(bits, source_width, out_width, mxcsr):
    kind, sign, value, raw = operand(bits, source_width, mxcsr)
    if kind == 'nan': return IE if raw['snan'] else 0
    flags = DE if raw['denormal'] and not mxcsr & 0x40 else 0
    return flags if kind == 'inf' else flags | rounded_flags(value, out_width, mxcsr)


def compare_flags(a, b, width, mxcsr, signaling):
    ka, _, _, ra = operand(a, width, mxcsr)
    kb, _, _, rb = operand(b, width, mxcsr)
    if ka == 'nan' or kb == 'nan':
        return IE if signaling or ra['snan'] or rb['snan'] else 0
    return DE if not mxcsr & 0x40 and (ra['denormal'] or rb['denormal']) else 0


def round_flags(bits, width, mxcsr, immediate):
    kind, sign, value, raw = operand(bits, width, mxcsr)
    if kind == 'nan': return IE if raw['snan'] else 0
    if kind == 'inf': return 0
    rc = (mxcsr >> 13) & 3 if immediate & 4 else immediate & 3
    integer = ieee.round_ratio(abs(value.numerator), value.denominator, value < 0, rc)
    if value < 0: integer = -integer
    return PE if not immediate & 8 and integer != value else 0


class Tracker:
    def __init__(self, state):
        self.flags = state['mxcsr'] & STATUS_MASK
        self.events = []
        self.families = collections.Counter()
        self.instructions = collections.Counter()
        self.produced = 0
        self.last_reset_event = 0

    def before(self, ins, em, ux, xc, read_memory):
        original = ins.mnemonic
        name = original.removeprefix('v')
        ops = ins.operands
        def reg(register):
            return getattr(ux, 'UC_X86_REG_'+ins.reg_name(register).upper())
        def address(op):
            m = op.mem
            base = ins.address+ins.size if m.base == xc.X86_REG_RIP else em.reg_read(reg(m.base)) if m.base else 0
            index = em.reg_read(reg(m.index)) if m.index else 0
            segment = em.reg_read(getattr(ux, 'UC_X86_REG_'+ins.reg_name(m.segment).upper()+'_BASE')) if m.segment else 0
            return ((base+index*m.scale+m.disp) & ((1 << 64)-1))+segment
        def read(op, n=None):
            n = op.size if n is None else n
            if op.type == xc.X86_OP_MEM:
                return read_memory(address(op), n)
            if op.type == xc.X86_OP_REG:
                return (em.reg_read(reg(op.reg)) & ((1 << (8*n))-1)).to_bytes(n, 'little')
            raise Unavailable('operand '+original)
        if name == 'ldmxcsr':
            self.flags = int.from_bytes(read(ops[0], 4), 'little') & STATUS_MASK
            self.last_reset_event = len(self.events)
            return
        if name in ('fxrstor', 'fxrstor64'):
            self.flags = int.from_bytes(read_memory(address(ops[0])+24, 4), 'little') & STATUS_MASK
            self.last_reset_event = len(self.events)
            return
        if name in ('stmxcsr', 'fxsave', 'fxsave64') and self.flags != em.reg_read(ux.UC_X86_REG_MXCSR) & STATUS_MASK:
            raise Unavailable('independent_status_memory_transport '+original)
        kind = family(original)
        if not kind or kind == 'approximation_no_status': return
        self.families[kind] += 1
        self.instructions[original] += 1
        mxcsr = (em.reg_read(ux.UC_X86_REG_MXCSR) & ~STATUS_MASK) | self.flags
        flags = 0
        scalar = name.endswith(('ss', 'sd')) or name.endswith(('ss2si', 'sd2si', 'si2ss', 'si2sd', 'ss2sd', 'sd2ss'))
        width = 64 if name.endswith(('sd', 'pd')) or 'sd2' in name or 'pd2' in name else 32
        vector_size = ops[0].size if ops and ops[0].type == xc.X86_OP_REG else 16
        n = width//8 if scalar else vector_size
        def lanes(data, bits):
            return [int.from_bytes(data[i:i+bits//8], 'little') for i in range(0, len(data), bits//8)]
        arithmetic = re.fullmatch(r'(add|sub|mul|div|min|max)(ss|sd|ps|pd)', name)
        if arithmetic:
            left = ops[1] if ieee.is_vex(ins) else ops[0]
            a = lanes(read(left, n), width); b = lanes(read(ops[-1], n), width)
            for x, y in zip(a, b): flags |= arithmetic_flags(arithmetic[1], x, y, width, mxcsr)
        elif name.startswith('sqrt'):
            for x in lanes(read(ops[-1], n), width): flags |= sqrt_flags(x, width, mxcsr)
        elif name.startswith(('comi', 'ucomi', 'cmp')):
            left = ops[1] if ieee.is_vex(ins) and name.startswith('cmp') else ops[0]
            right = ops[-2] if ops[-1].type == xc.X86_OP_IMM else ops[-1]
            signaling = name.startswith('comi')
            if name.startswith('cmp'):
                predicate = bytes(ins.bytes)[-1] & (31 if ieee.is_vex(ins) else 7)
                signaling = predicate in (1, 2, 5, 6, 9, 10, 13, 14, 16, 19, 20, 23, 24, 27, 28, 31)
            for a, b in zip(lanes(read(left, n), width), lanes(read(right, n), width)):
                flags |= compare_flags(a, b, width, mxcsr, signaling)
        elif name.startswith('round'):
            for x in lanes(read(ops[-2], n), width): flags |= round_flags(x, width, mxcsr, bytes(ins.bytes)[-1])
        elif name.startswith(('cvt', 'cvtt')):
            conversion = re.fullmatch(r'cvt(t?)(ss|sd|ps|pd|si|dq)2(ss|sd|ps|pd|si|dq)', name)
            if not conversion: raise Unavailable(original)
            truncate, source, target = conversion.groups()
            source_width = 64 if source in ('sd', 'pd') else 32
            target_width = 64 if target in ('sd', 'pd') else 32
            source_n = source_width//8 if source in ('ss', 'sd') else ops[-1].size
            if source == 'si':
                flags = rounded_flags(Fraction(int.from_bytes(read(ops[-1]), 'little', signed=True)), target_width, mxcsr)
            elif source == 'dq':
                source_n = (vector_size//(target_width//8))*4
                for x in range(0, source_n, 4):
                    flags |= rounded_flags(Fraction(int.from_bytes(read(ops[-1], source_n)[x:x+4], 'little', signed=True)), target_width, mxcsr)
            elif target in ('si', 'dq'):
                if target == 'si': target_width = ops[0].size*8
                for x in lanes(read(ops[-1], source_n), source_width):
                    flags |= float_to_int(x, source_width, target_width, mxcsr, bool(truncate))
            else:
                if source == 'ps' and target == 'pd': source_n = vector_size//2
                for x in lanes(read(ops[-1], source_n), source_width):
                    flags |= float_convert(x, source_width, target_width, mxcsr)
        else:
            raise Unavailable(original)
        # Even already-sticky flags can trigger an unmasked exception anew.
        if flags & ~((mxcsr >> 7) & STATUS_MASK):
            raise Unavailable('unmasked_XM '+original)
        self.flags |= flags
        self.produced |= flags
        if flags:
            self.events.append(dict(address=ins.address, instruction=original, raised=flags))

    def result(self):
        return dict(expected=self.flags, produced=self.produced, events=self.events,
                    last_reset_event=self.last_reset_event,
                    families=dict(self.families), instructions=dict(self.instructions))
