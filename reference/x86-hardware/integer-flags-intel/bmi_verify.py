#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit captured native BMI rows without requiring AMD undefined-flag values."""
import collections
import gzip
import json
import pathlib
import re
import sys

OPS = ['ANDN', 'BEXTR', 'BLSI', 'BLSMSK', 'BLSR', 'BZHI', 'MULX', 'PDEP',
       'PEXT', 'RORX', 'SARX', 'SHLX', 'SHRX', 'ADCX', 'ADOX']
FLAGS = {'CF': 0, 'PF': 2, 'AF': 4, 'ZF': 6, 'SF': 7, 'OF': 11}


def required(op):
    return 'BMI1' if OPS.index(op) <= 4 else 'BMI2' if OPS.index(op) <= 12 else 'ADX'


def expected(op, width):
    n = 44 if op in ('BLSI', 'BLSMSK', 'BLSR') else 22 * 256 * 2 if op == 'RORX' else 22 * 22 * 2
    return n + ((width + 2) ** 2 * 22 * 2 if op == 'BEXTR' else 0)


def main():
    base = pathlib.Path(__file__).resolve().parent
    path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else base / 'out-09-bmi.txt.gz'
    counts = collections.Counter()
    support = collections.Counter()
    observed = collections.defaultdict(collections.Counter)
    skipped = set()
    with gzip.open(path, 'rt', encoding='ascii') as stream:
        header = stream.readline().rstrip('\n')
        match = re.fullmatch(r'# native x86-64 CPUID\.7\.0:EBX=([0-9a-f]{8}) BMI1=([01]) BMI2=([01]) ADX=([01])', header)
        if not match:
            raise ValueError('Missing original BMI CPUID header')
        ebx = int(match[1], 16)
        features = dict(zip(('BMI1', 'BMI2', 'ADX'), map(int, match.groups()[1:])))
        if list(features.values()) != [(ebx >> bit) & 1 for bit in (3, 8, 19)]:
            raise ValueError('CPUID bits disagree with reported features')
        for line in stream:
            if line.startswith('#'):
                skip = re.fullmatch(r'# SKIP (\w+): CPUID feature unavailable\n', line)
                if not skip or skip[1] not in OPS or skip[1] in skipped:
                    raise ValueError('Unexpected or duplicate skip comment')
                skipped.add(skip[1])
                continue
            t = line.split()
            if len(t) != 10 or t[6] != '->' or t[0] not in OPS:
                raise ValueError('Malformed BMI row')
            op, width, pre, post = t[0], int(t[1]), int(t[2], 16), int(t[9], 16)
            if width not in (32, 64) or pre != (0x202 if counts[op, width] % 2 == 0 else 0xad7):
                raise ValueError('Unexpected width or initial-flag order')
            if any(not re.fullmatch('[0-9a-f]{4}', t[k]) for k in (2, 9)):
                raise ValueError('Malformed flags')
            if any(t[k] != '-' and not re.fullmatch('[0-9a-f]{%d}' % (width // 4), t[k]) for k in (3, 4, 5, 7, 8)):
                raise ValueError('Malformed operand or result width')
            a = int(t[3], 16)
            b = 0 if t[4] == '-' else int(t[4], 16)
            c = 0 if t[5] == '-' else int(t[5], 16)
            result = int(t[7], 16)
            mask = (1 << width) - 1
            pf = 4 if (result & 255).bit_count() % 2 == 0 else 0
            sz = (64 if result == 0 else 0) | (128 if result >> (width - 1) else 0)
            prediction = pre
            if op in ('ANDN', 'BLSI', 'BLSMSK', 'BLSR', 'BZHI'):
                cf = int(a != 0) if op == 'BLSI' else int(a == 0) if op in ('BLSMSK', 'BLSR') else int((c & 255) >= width) if op == 'BZHI' else 0
                prediction = 0x202 | sz | pf | cf
            elif op == 'BEXTR':
                prediction = 0x202 | 16 | pf | (64 if result == 0 else 0)
            elif op in ('ADCX', 'ADOX'):
                bit = 1 if op == 'ADCX' else 2048
                carry = a + b + int(bool(pre & bit)) > mask
                prediction = (pre & ~bit) | (bit if carry else 0)
            undefined = (16 | 4 | 128) if op == 'BEXTR' else (16 | 4) if op in ('ANDN', 'BLSI', 'BLSMSK', 'BLSR', 'BZHI') else 0
            if (post ^ prediction) & (0xffff ^ undefined):
                raise ValueError(f'Defined/non-arithmetic flag mismatch: {op}/{width}')
            counts[op, width] += 1
            support[op, width] += post == prediction
            for flag, bit in FLAGS.items():
                observed[op, width][flag + '_set'] += bool(post & (1 << bit))
                observed[op, width][flag + '_preserved'] += not bool((post ^ pre) & (1 << bit))
    expected_skips = {op for op in OPS if not features[required(op)]}
    if skipped != expected_skips:
        raise ValueError('Skip comments do not match native CPUID feature bits')
    records = []
    for op in OPS:
        for width in (32, 64):
            wanted = 0 if op in expected_skips else expected(op, width)
            if counts[op, width] != wanted:
                raise ValueError(f'Wrong count for {op}/{width}: {counts[op, width]} != {wanted}')
            records.append({'op': op, 'width': width, 'rows': wanted, 'feature': required(op),
                            'status': 'SKIPPED_CPUID_UNAVAILABLE' if op in skipped else 'MEASURED',
                            'amd_candidate_supporting': support[op, width],
                            'amd_candidate_contradicting': wanted - support[op, width],
                            'flag_counts': dict(observed[op, width])})
    report = {'features': features, 'cpuid_ebx': f'{ebx:08x}', 'rows': sum(counts.values()),
              'skipped_mnemonics': sorted(skipped), 'records': records,
              'note': 'AMD empirical candidates are descriptive; contradictions are not validation errors.'}
    (base / 'bmi-audit.json').write_text(json.dumps(report, indent=2) + '\n')
    checks = f'BMI structural, CPUID-aware exact counts, widths and initial flags: PASS\nrows={sum(counts.values())}\n'
    checks += f'skipped_mnemonics={",".join(sorted(skipped)) or "none"}\n'
    checks += 'AMD undefined-flag candidates are counted, never required. Native C defined-semantics checks are unchanged.\n'
    (base / 'bmi_RULE_CHECKS.txt').write_text(checks)
    lines = ['# Class 9: observations from this run', '', '## Coverage and C defined-semantics validation', '',
             f'Native CPUID.7.0:EBX={ebx:08x}; {features}. Measured rows: {sum(counts.values())}.',
             'See bmi_CHECKS.txt for unchanged native C defined-semantics checks.',
             'Unavailable features retain the original native SKIP comments and have zero measured rows.', '',
             '## Measured rules, with support and contradiction counts', '',
             'The following counts test the original AMD full-flags candidates against this capture.',
             'A contradiction is an observation, not a failed assertion. No Intel rule is assumed.', '',
             '| Op | Width | Rows | AMD candidate support | Contradictions | Status |',
             '|---|---:|---:|---:|---:|---|']
    lines += [f'| {r["op"]} | {r["width"]} | {r["rows"]} | {r["amd_candidate_supporting"]} | {r["amd_candidate_contradicting"]} | {r["status"]} |' for r in records]
    lines += ['', 'Full per-flag set/preserved counters are in bmi-audit.json.']
    (base / 'bmi_REPORT.md').write_text('\n'.join(lines) + '\n')
    print(checks, end='')


if __name__ == '__main__':
    main()
