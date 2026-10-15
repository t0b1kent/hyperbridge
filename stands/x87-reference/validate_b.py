#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Part B validation: the sticky exception flags of the x87 status word survive compares and integer stores.
# Independent of the probe; never modifies the raw table. Architectural facts checked here are the same for every
# x86 vendor (Intel SDM vol. 1 §8.1.3 / §8.5.1.1, AMD APM vol. 1 §6.3): the six exception flags IE DE ZE OE UE PE are
# sticky and are cleared only by FCLEX/FNCLEX, FINIT/FNINIT, FLDENV, FRSTOR (and FXRSTOR/XRSTOR loading a clean image).
import csv, collections, json, sys
from pathlib import Path
root = Path(__file__).resolve().parent
path = Path(sys.argv[1]) if len(sys.argv) > 1 else root / 'output-b/raw.csv'
SEEDS = {'seed_none': 0x0000, 'seed_IE': 0x0001, 'seed_sticky_IE_DE_ZE_OE_UE_PE': 0x003f, 'seed_C1': 0x0200, 'seed_C1_and_sticky': 0x023f}
IE, STICKY, C0, C1, C2, C3 = 0x1, 0x3f, 0x100, 0x200, 0x400, 0x4000
CF, PF, ZF = 0x1, 0x4, 0x40

def kind(ext80):
    """nan / inf / finite from an extended-precision bit pattern (snan vs qnan by the integer-bit/quiet bit)."""
    se = int(ext80[:4], 16); sig = int(ext80[4:], 16); exp = se & 0x7fff
    if exp == 0x7fff:
        if sig == 1 << 63: return 'inf'
        return 'qnan' if sig & (1 << 62) else 'snan'
    return 'finite'

def value(ext80):
    se = int(ext80[:4], 16); sig = int(ext80[4:], 16); exp = se & 0x7fff; sign = -1 if se >> 15 else 1
    if exp == 0x7fff: return sign * float('inf')
    if not exp and not sig: return 0.0
    return sign * sig * 2.0 ** ((exp or 1) - 16383 - 63)

counts = collections.Counter(); violations = []; checks = collections.Counter(); bad = []
for r in csv.DictReader(path.open()):
    counts[(r['group'], r['op'])] += 1
    seed = SEEDS[r['case']]; pre = int(r['pre_sw'], 16); post = int(r['post_sw'], 16)
    if pre & STICKY != seed & STICKY:
        bad.append({'row': r['row'], 'why': 'seed not applied', 'pre_sw': r['pre_sw'], 'seed': '%04x' % seed}); continue
    # 1. Stickiness: every seeded exception flag is still set after the operation.
    checks['sticky'] += 1
    if post & (seed & STICKY) != seed & STICKY:
        violations.append({'row': r['row'], 'group': r['group'], 'op': r['op'], 'case': r['case'], 'pre_sw': r['pre_sw'], 'post_sw': r['post_sw']})
    if r['group'] == 'seeded-compare':
        a = r['a_ext80']; b = r['b_ext80'] if r['b_name'] != '-' else None
        ka = kind(a); kb = kind(b) if b else 'finite'
        unordered = ka != 'finite' and ka != 'inf' or kb != 'finite' and kb != 'inf'
        ordered_ops = r['op'] in ('fcom', 'fcomp', 'fcomi', 'fcomip', 'ftst')
        # 2. Invalid-operation flag: ordered compares raise IE on any NaN, unordered compares only on a signalling NaN.
        new_ie = bool(post & IE) and not (seed & IE)
        expect_ie = (ka in ('qnan', 'snan') or kb in ('qnan', 'snan')) if ordered_ops else (ka == 'snan' or kb == 'snan')
        checks['ie_rule'] += 1
        if new_ie != expect_ie and not (seed & IE):
            bad.append({'row': r['row'], 'why': 'IE rule', 'op': r['op'], 'a': r['a_name'], 'b': r['b_name'], 'post_sw': r['post_sw'], 'expected_ie': expect_ie})
        # 3. Condition codes / EFLAGS: unordered -> C3=C2=C0=1 (ZF=PF=CF=1); otherwise the usual ordering.
        va = value(a); vb = value(b) if b else 0.0
        if r['op'] == 'ftst': vb = 0.0
        if unordered: exp_c3, exp_c2, exp_c0 = 1, 1, 1
        else: exp_c3, exp_c2, exp_c0 = int(va == vb), 0, int(va < vb)
        got = (int(bool(post & C3)), int(bool(post & C2)), int(bool(post & C0)))
        checks['condition_codes'] += 1
        if got != (exp_c3, exp_c2, exp_c0):
            bad.append({'row': r['row'], 'why': 'C3/C2/C0', 'op': r['op'], 'a': r['a_name'], 'b': r['b_name'], 'got': got, 'expected': (exp_c3, exp_c2, exp_c0)})
        if r['op'] in ('fcomi', 'fcomip', 'fucomi', 'fucomip'):
            fl = int(r['memory_bits'], 16)
            gotf = (int(bool(fl & ZF)), int(bool(fl & PF)), int(bool(fl & CF)))
            checks['eflags'] += 1
            if gotf != (exp_c3, exp_c2, exp_c0):
                bad.append({'row': r['row'], 'why': 'ZF/PF/CF', 'op': r['op'], 'a': r['a_name'], 'b': r['b_name'], 'got': gotf, 'expected': (exp_c3, exp_c2, exp_c0)})
        # 4. C1 is not sticky: compares clear it.
        checks['c1_cleared'] += 1
        if post & C1:
            bad.append({'row': r['row'], 'why': 'C1 not cleared by compare', 'op': r['op'], 'post_sw': r['post_sw']})
    if r['group'] == 'seeded-store':
        # Invalid integer stores (NaN, infinity, out of range) must set IE; in-range exact stores must not add IE.
        ka = kind(r['a_ext80']); va = value(r['a_ext80']); bits = int(r['op'].rsplit('_m', 1)[1])
        lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
        new_ie = bool(post & IE) and not (seed & IE)
        if ka != 'finite' or va <= lo - 1 or va >= hi + 1:
            checks['store_invalid'] += 1
            if not new_ie and not (seed & IE):
                bad.append({'row': r['row'], 'why': 'invalid store without IE', 'op': r['op'], 'a': r['a_name'], 'post_sw': r['post_sw']})
        elif va == int(va) and lo <= va <= hi:
            checks['store_exact'] += 1
            if new_ie:
                bad.append({'row': r['row'], 'why': 'exact store raised IE', 'op': r['op'], 'a': r['a_name'], 'post_sw': r['post_sw']})
    if r['group'] == 'seeded-control':
        checks['control'] += 1
        if post & STICKY != pre & STICKY or post & C1:
            bad.append({'row': r['row'], 'why': 'control fadd changed sticky flags or kept C1', 'pre_sw': r['pre_sw'], 'post_sw': r['post_sw']})
result = {'rows': sum(counts.values()), 'by_group_op': {'%s/%s' % k: v for k, v in sorted(counts.items())}, 'checks': dict(checks),
          'sticky_violations': len(violations), 'sticky_violation_rows': violations[:50], 'rule_failures': len(bad), 'rule_failure_rows': bad[:50]}
print(json.dumps(result, indent=2))
assert not violations, 'sticky exception flags were cleared: %r' % violations[:5]
assert not bad, bad[:5]
