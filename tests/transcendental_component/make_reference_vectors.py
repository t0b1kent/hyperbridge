#!/usr/bin/env python3
"""Independent rational-interval reference vectors; no component/donor execution."""
from fractions import Fraction as F
from math import isqrt
from pathlib import Path

LIMIT = F(1, 1 << 280)
J = 1 << 63

def add(a, b): return a[0] + b[0], a[1] + b[1]
def neg(a): return -a[1], -a[0]
def mul_positive(a, b):
    assert a[0] >= 0 and b[0] >= 0
    return a[0] * b[0], a[1] * b[1]
def div_positive(a, b):
    assert a[0] >= 0 and b[0] > 0
    return a[0] / b[1], a[1] / b[0]
def exact(x): return F(x), F(x)

def alternating(x, kind):
    assert 0 < x <= F(1, 2)
    if kind == 'atan':
        total, power, n, sign = F(0), x, 0, 1
        while True:
            total += sign * power / (2 * n + 1)
            n += 1; power *= x * x; sign = -sign
            correction = sign * power / (2 * n + 1)
            if abs(correction) < LIMIT:
                return min(total, total + correction), max(total, total + correction)
    term = x if kind == 'sin' else F(1)
    total, n = term, 0
    while True:
        a = 2 * n + (2 if kind == 'sin' else 1)
        term = -term * x * x / (a * (a + 1))
        n += 1
        if abs(term) < LIMIT:
            return min(total, total + term), max(total, total + term)
        total += term

def ln_interval(x):
    assert 1 < x <= 2
    z = (x - 1) / (x + 1)
    total, power, n = F(0), z, 0
    while True:
        total += 2 * power / (2 * n + 1)
        n += 1; power *= z * z
        remainder = 2 * power / ((2 * n + 1) * (1 - z * z))
        if remainder < LIMIT:
            return total, total + remainder

def sqrt_two():
    bits = 320
    n = isqrt(2 << (2 * bits))
    assert n * n < 2 << (2 * bits) < (n + 1) * (n + 1)
    return F(n, 1 << bits), F(n + 1, 1 << bits)

def round80(value, rc):
    if not value: return (0x8000 if rc == 1 else 0, 0)
    negative = value < 0
    magnitude = abs(value)
    exponent = magnitude.numerator.bit_length() - magnitude.denominator.bit_length()
    if magnitude < F(2) ** exponent: exponent -= 1
    scaled = magnitude * F(2) ** (63 - exponent)
    whole, remainder = divmod(scaled.numerator, scaled.denominator)
    if remainder:
        if rc == 0:
            twice = 2 * remainder
            whole += twice > scaled.denominator or (twice == scaled.denominator and bool(whole & 1))
        elif (rc == 1 and negative) or (rc == 2 and not negative): whole += 1
    if whole == 1 << 64: whole >>= 1; exponent += 1
    assert J <= whole < 1 << 64 and -16382 <= exponent <= 16383
    return (exponent + 16383) | (0x8000 if negative else 0), whole

def rounded(interval):
    rows = []
    for rc in range(4):
        lo, hi = round80(interval[0], rc), round80(interval[1], rc)
        assert lo == hi, ('Reference interval straddles a rounding boundary', rc)
        rows.append(lo)
    return rows

def dyadic(value):
    assert F(value).denominator & (F(value).denominator - 1) == 0
    return round80(F(value), 0)

def w(raw): return '{UINT16_C(0x%04x),UINT64_C(0x%016x)}' % raw

vectors = []
def literal(name, op, a, b, results, flags=0, provenance='source_exact'):
    vectors.append((name, op, a, b, [[r for r in results] for _ in range(4)], 0x1f, flags, provenance))
def mathematical(name, op, a, b, intervals):
    references = [rounded(v) for v in intervals]
    # Require a comfortable margin from every ext80 integer or nearest midpoint.
    for lo, hi in intervals:
        if lo == hi: continue
        middle = abs((lo + hi) / 2)
        e = middle.numerator.bit_length() - middle.denominator.bit_length()
        if middle < F(2) ** e: e -= 1
        scaled = middle * F(2) ** (63 - e)
        fraction = scaled - scaled.numerator // scaled.denominator
        assert min(fraction, 1 - fraction, abs(fraction - F(1, 2))) > F(1, 1 << 20)
    results = [[r[rc] for r in references] for rc in range(4)]
    vectors.append((name, op, a, b, results, 0x10, 0, 'independent_mathematical_interval'))

zero, one, half = (0, 0), dyadic(1), dyadic(F(1, 2))
minus_zero = (0x8000, 0)
positive_inf, negative_inf = (0x7fff, J), (0xffff, J)
qnan = (0x7fff, 0xc000000000000000)
lowbit = (0x3fff, J + 1)
for sign, a, answer in [('positive', one, one), ('negative', dyadic(-1), dyadic(F(-1, 2)))]:
    literal('f2xm1_' + sign + '_one', 'F2XM1', a, zero, [answer])
literal('fyl2x_two_full_significand', 'FYL2X', dyadic(2), lowbit, [lowbit])
literal('fyl2x_half_negative_multiplier', 'FYL2X', half, dyadic(F(-3, 2)), [dyadic(F(3, 2))])
literal('fyl2xp1_one_full_significand', 'FYL2XP1', one, lowbit, [lowbit])
literal('fyl2xp1_negative_half_full_significand', 'FYL2XP1', dyadic(F(-1, 2)), lowbit, [(0xbfff, J + 1)])
literal('fyl2x_equal_two_inputs', 'FYL2X', dyadic(2), dyadic(2), [dyadic(2)])
literal('fyl2xp1_equal_one_inputs', 'FYL2XP1', one, one, [one])
literal('fscale_equal_one_inputs', 'FSCALE', one, one, [dyadic(2)])
literal('fpatan_positive_axis', 'FPATAN', one, zero, [zero])
literal('fpatan_negative_zero_y_selected_positive_zero', 'FPATAN', one, minus_zero, [zero], provenance='selected_source_zero_policy')
literal('fsin_positive_zero', 'FSIN', zero, zero, [zero])
literal('fcos_positive_zero', 'FCOS', zero, zero, [one])
literal('fsincos_positive_zero_order', 'FSINCOS', zero, zero, [zero, one])
literal('fptan_positive_zero_order', 'FPTAN', zero, zero, [zero, one])
literal('fscale_truncate_positive_fraction', 'FSCALE', lowbit, dyadic(F(3, 2)), [(0x4000, J + 1)])
literal('fscale_truncate_negative_fraction', 'FSCALE', dyadic(F(3, 2)), dyadic(F(-3, 2)), [dyadic(F(3, 4))])
for op in ['FSIN', 'FPTAN']:
    for negative in [False, True]:
        raw = (0x3fff - 1200 | (0x8000 if negative else 0), J)
        literal(op.lower() + '_tiny_' + str(int(negative)), op, raw, zero, [raw] + ([one] if op == 'FPTAN' else []), provenance='selected_source_rounded_identity')
literal('fcos_safe_tiny_lower', 'FCOS', (0x2001, J), zero, [one], provenance='selected_source_interval')
literal('fcos_documented_denormal_scaling_defect', 'FCOS', (0x1fff, J), zero, [dyadic(F(3, 2))], provenance='documented_selected_donor_quirk')
literal('fsincos_documented_denormal_scaling_defect_order', 'FSINCOS', (0x1fff, J), zero, [(0x1fff, J), dyadic(F(3, 2))], provenance='documented_selected_donor_quirk')
literal('fscale_minimum_exact_power', 'FSCALE', one, dyadic(-16382), [(1, J)], provenance='selected_source_exp2_boundary')
literal('fscale_maximum_exact_power', 'FSCALE', one, dyadic(16383), [(0x7ffe, J)], provenance='selected_source_exp2_boundary')
literal('fscale_excluded_compensated_power_returns_zero', 'FSCALE', dyadic(2), dyadic(-16383), [zero], provenance='documented_selected_donor_quirk')
literal('fscale_positive_zero_positive_inf_invalid', 'FSCALE', zero, positive_inf, [qnan], 0x10, 'selected_source_special_policy')
literal('fscale_negative_zero_negative_inf_preserved', 'FSCALE', minus_zero, negative_inf, [minus_zero], provenance='selected_source_special_policy')
literal('fscale_zero_noncanonical_positive_inf_invalid', 'FSCALE', zero, (0x7fff, 0), [qnan], 0x10, 'selected_source_special_policy')
for op in ['FSIN', 'FCOS', 'FSINCOS', 'FPTAN']:
    for negative in [False, True]:
        results = [qnan] + ([qnan] if op == 'FSINCOS' else [one] if op == 'FPTAN' else [])
        literal(op.lower() + '_infinity_' + str(int(negative)), op, negative_inf if negative else positive_inf, zero, results, 0x10, 'selected_source_special_policy')

sine_half, cosine_half = alternating(F(1, 2), 'sin'), alternating(F(1, 2), 'cos')
sine_quarter, cosine_quarter = alternating(F(1, 4), 'sin'), alternating(F(1, 4), 'cos')
atan_half = alternating(F(1, 2), 'atan')
atan_fifth = alternating(F(1, 5), 'atan')
atan_239 = alternating(F(1, 239), 'atan')
pi_quarter = add(mul_positive(exact(4), atan_fifth), neg(atan_239))
ln2 = ln_interval(F(2))
mathematical('f2xm1_half_sqrt_two_minus_one', 'F2XM1', half, zero, [add(sqrt_two(), exact(-1))])
mathematical('fyl2x_three_halves_times_three_quarters', 'FYL2X', dyadic(F(3, 2)), dyadic(F(3, 4)), [mul_positive(div_positive(ln_interval(F(3, 2)), ln2), exact(F(3, 4)))])
mathematical('fyl2xp1_quarter_times_three_halves', 'FYL2XP1', dyadic(F(1, 4)), dyadic(F(3, 2)), [mul_positive(div_positive(ln_interval(F(5, 4)), ln2), exact(F(3, 2)))])
mathematical('fpatan_equal_one_inputs_pi_quarter', 'FPATAN', one, one, [pi_quarter])
mathematical('fpatan_half_ratio_operand_order', 'FPATAN', dyadic(2), one, [atan_half])
mathematical('fpatan_negative_half_ratio', 'FPATAN', dyadic(2), dyadic(-1), [neg(atan_half)])
for negative in [False, True]:
    a = dyadic(F(-1, 2) if negative else F(1, 2))
    sin_result = neg(sine_half) if negative else sine_half
    mathematical('fsin_half_' + str(int(negative)), 'FSIN', a, zero, [sin_result])
    mathematical('fcos_half_' + str(int(negative)), 'FCOS', a, zero, [cosine_half])
    mathematical('fsincos_half_' + str(int(negative)), 'FSINCOS', a, zero, [sin_result, cosine_half])
    tangent = div_positive(sine_quarter, cosine_quarter)
    mathematical('fptan_quarter_' + str(int(negative)), 'FPTAN', dyadic(F(-1, 4) if negative else F(1, 4)), zero, [neg(tangent) if negative else tangent, exact(1)])

assert {v[1] for v in vectors} == {'F2XM1','FYL2X','FYL2XP1','FPATAN','FSIN','FCOS','FSINCOS','FPTAN','FSCALE'}
header = '''/* Generated by make_reference_vectors.py using independent integer/Fraction
 * mathematics and explicitly labeled selected-source special/quirk cases.
 * No component, Cephes, SoftFloat or native oracle executes in the generator. */
#ifndef HB_TRANSCENDENTAL_REFERENCE_VECTORS_H
#define HB_TRANSCENDENTAL_REFERENCE_VECTORS_H
typedef struct { uint16_t sign_exp; uint64_t significand; } ct_words;
typedef struct {
    const char *name;
    hb_x87_transcendental_op_t operation;
    ct_words st0, st1;
    unsigned result_count;
    ct_words expected[4][2];
    unsigned flags_mask, flags_value;
    const char *provenance;
} ct_vector;
static const ct_vector ct_vectors[] = {
'''
for name, op, a, b, rows, mask, flags, provenance in vectors:
    expected = ','.join('{' + ','.join(w(x) for x in row + [zero] * (2 - len(row))) + '}' for row in rows)
    header += ' {"%s",HB_X87_TRANS_%s,%s,%s,%du,{%s},0x%xu,0x%xu,"%s"},\n' % (name, op, w(a), w(b), len(rows[0]), expected, mask, flags, provenance)
header += '};\n#endif\n'
Path(__file__).with_name('reference_vectors.h').write_text(header)
print('Prepared %d independent vectors; all nine operations; no native execution.' % len(vectors))
