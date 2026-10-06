#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact native-row and uncompressed-hash audit, including explicit CPUID skips."""
import collections
import gzip
import hashlib
import json
import pathlib
import re

P = pathlib.Path(__file__).resolve().parent
inv = json.loads((P / 'core-inventory.json').read_text())
classes = list(dict.fromkeys(f['cls'] for f in inv))
summary = {}
allowed_skips = {('TZCNT', 16), ('TZCNT', 32), ('TZCNT', 64),
                 ('LZCNT', 16), ('LZCNT', 32), ('LZCNT', 64),
                 ('POPCNT', 16), ('POPCNT', 32), ('POPCNT', 64), ('CMPXCHG16B', 128)}
for cls in classes:
    z = P / f'out-{cls}.txt.gz'
    raw = gzip.decompress(z.read_bytes())
    counts, before = collections.Counter(), collections.Counter()
    skipped = set()
    n = traps = 0
    for line in raw.decode('ascii').splitlines():
        if line.startswith('# SKIP '):
            match = re.fullmatch(r'# SKIP (\w+) (\d+) missing CPUID feature', line)
            if not match or (match[1], int(match[2])) not in allowed_skips:
                raise ValueError('Unexpected core skip comment')
            key = match[1], int(match[2])
            if key in skipped or not any(f['op'] == key[0] and f['w'] == key[1] and f['cls'] == cls for f in inv):
                raise ValueError('Duplicate or wrong-class skip')
            skipped.add(key)
            continue
        if line.startswith('#'):
            continue
        t = line.split()
        op, mode = t[0].split('.', 1)
        width = int(t[1])
        trap = t[7] == 'TRAP'
        j = 8 if trap else 7
        if len(t) != j + 3 or t[6] != '->' or width not in (8, 16, 32, 64, 128):
            raise ValueError('Malformed native core row')
        if any(not re.fullmatch('[0-9a-f]{4}', t[k]) for k in (2, j + 2)):
            raise ValueError('Malformed flag width')
        if int(t[2], 16) != (0x202 if n % 2 == 0 else 0xad7):
            raise ValueError('Unexpected initial flag order')
        if any(t[k] != '-' and not re.fullmatch('[0-9a-f]{%d}' % (width // 4), t[k]) for k in (3, 4, 5, j, j + 1)):
            raise ValueError('Malformed operand or result width')
        count = int(t[5], 16) if cls in ('shifts', 'rotates', 'double') or op == 'IMUL3' or mode.endswith('imm') else None
        counts[op, width, mode, count] += 1
        before[t[2]] += 1
        n += 1
        traps += trap
    expected = collections.Counter()
    forms = 0
    for f in inv:
        if f['cls'] != cls or (f['op'], f['w']) in skipped:
            continue
        op, width, mode, count = f['op'], f['w'], f['mode'], f['c']
        key = op, width, mode, count & ((1 << width) - 1) if count >= 0 or op == 'IMUL3' else None
        if cls in ('shifts', 'rotates') or op == 'BSWAP16':
            rows = 44
        elif cls == 'bittest':
            rows = 44 if count >= 0 else 660 + (968 if mode == 'reg-reg' else 0)
        elif cls == 'divide':
            rows = 22 ** 3 * 2 + (21 if width == 64 else 20) * 4 * 3 * 2
        elif op in ('CMPXCHG', 'CMPXCHG8B', 'CMPXCHG16B'):
            rows = 22 ** 3 * 2
        else:
            rows = 22 ** 2 * 2
        expected[key] += rows
        forms += 1
    if counts != expected:
        raise ValueError(f'{cls}: exact per-form counts differ: extra={counts - expected}; missing={expected - counts}')
    digest = hashlib.sha256(raw).hexdigest()
    record = (P / f'out-{cls}.sha256').read_text().split()
    if record != [digest, f'out-{cls}.txt']:
        raise ValueError(f'{cls}: uncompressed raw hash/filename mismatch')
    summary[cls] = {'forms': forms, 'rows': n, 'traps': traps, 'before_flags': dict(before),
                    'skipped': [f'{op}/{width}' for op, width in sorted(skipped)],
                    'sha256_raw': digest, 'sha256_gzip': hashlib.sha256(z.read_bytes()).hexdigest(),
                    'gzip_bytes': z.stat().st_size, 'per_form_counts': 'exact for available native forms'}
bmi = P / 'out-09-bmi.txt.gz'
bmi_raw = gzip.decompress(bmi.read_bytes())
digest = hashlib.sha256(bmi_raw).hexdigest()
if (P / 'out-09-bmi.sha256').read_text().split() != [digest, 'out-09-bmi.txt']:
    raise ValueError('BMI uncompressed raw hash/filename mismatch')
bmi_audit = json.loads((P / 'bmi-audit.json').read_text())
summary['09-bmi'] = {'rows': bmi_audit['rows'], 'sha256_raw': digest,
                     'gzip_bytes': bmi.stat().st_size, 'sha256_gzip': hashlib.sha256(bmi.read_bytes()).hexdigest(),
                     'skipped': bmi_audit['skipped_mnemonics'], 'detail': 'bmi_RULE_CHECKS.txt'}
summary['total_rows'] = sum(v['rows'] for v in summary.values() if isinstance(v, dict))
summary['total_result_gzip_bytes'] = sum(v['gzip_bytes'] for v in summary.values() if isinstance(v, dict))
summary['complete_0002_64bit_coverage'] = not any(v['skipped'] for v in summary.values() if isinstance(v, dict))
if summary['complete_0002_64bit_coverage'] and summary['total_rows'] != 1624804:
    raise ValueError('Full-set row count differs from original 0002')
if summary['total_result_gzip_bytes'] > 60000000:
    raise ValueError('Compressed result budget exceeded')
(P / 'validation-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary, indent=2))
