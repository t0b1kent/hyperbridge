#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
"""Join identical hardware inputs into Intel | AMD cells, with exact agreement bits."""
import argparse
import collections
import gzip
import hashlib
import itertools
import json
import os
from pathlib import Path

from capture import CLASSES, EXPECTED, sha, save


def candidates(root):
    result = []
    for p in sorted(root.rglob('RESULT.json')):
        record = json.loads(p.read_text())
        if record.get('scope') == 'native x86-64 authored integer/undefined-flags probes':
            result.append((p.parent, record))
    return result


def rows(path, expected_hash):
    h = hashlib.sha256()
    with gzip.open(path, 'rb') as stream:
        for line in stream:
            h.update(line)
            if not line.strip() or line.startswith(b'#'):
                continue
            values = line.decode('ascii').split()
            if len(values) not in (10, 11) or values[6] != '->':
                raise ValueError('malformed hardware cell')
            trap = values[7] == 'TRAP'
            after = values[7 + trap:]
            yield values[:6], {'trap': trap, 'result': after[:2], 'rflags': int(after[2], 16)}
    if h.hexdigest() != expected_hash:
        raise ValueError('decompressed hardware evidence SHA drift')


def compare(intel, amd, out):
    if intel[1]['source_sha256'] != amd[1]['source_sha256']:
        raise ValueError('Intel/AMD probe sources differ')
    groups = collections.defaultdict(collections.Counter)
    counts = collections.Counter()
    hashes = hashlib.sha256()
    with gzip.open(out / 'intel-amd-cells.jsonl.gz', 'wb', compresslevel=1) as stream:
        for cls in sorted(CLASSES):
            readers = []
            for directory, report in [intel, amd]:
                if report['checked'] != EXPECTED or set(report['tables']) != set(CLASSES):
                    raise ValueError('incomplete native hardware reference')
                measurements = report['tables'][cls]
                if len(measurements) != 2 or measurements[0]['raw_sha256'] != measurements[1]['raw_sha256']:
                    raise ValueError('native hardware A/A not equal')
                for record in measurements:
                    if record['rc'] or record['skipped_forms'] or sha(directory / record['file']) != record['gzip_sha256']:
                        raise ValueError('native reference failed or compressed evidence drifted')
                first = measurements[0]
                readers.append(rows(directory / first['file'], first['raw_sha256']))
            for ordinal, pair in enumerate(itertools.zip_longest(*readers), 1):
                x, y = pair
                if x is None or y is None or x[0] != y[0]:
                    raise ValueError(f'Intel/AMD input cells do not align: {cls}:{ordinal}')
                same = x[1] == y[1]
                bits = (x[1]['rflags'] ^ y[1]['rflags']) & 0x8d5
                record = {'key': f'{cls}:{ordinal}', 'input': x[0], 'intel': x[1], 'amd': y[1],
                          'equal': same, 'arithmetic_equal_mask': 0x8d5 & ~bits,
                          'result_equal': x[1]['result'] == y[1]['result'], 'trap_equal': x[1]['trap'] == y[1]['trap']}
                encoded = (json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode()
                hashes.update(encoded)
                stream.write(encoded)
                for counter in [counts, groups[x[0][0]]]:
                    counter['checked'] += 1
                    counter['equal' if same else 'different'] += 1
                    for name, bit in [('CF', 1), ('PF', 4), ('AF', 16), ('ZF', 64), ('SF', 128), ('OF', 2048)]:
                        counter['equal_' + name] += not bool(bits & bit)
    if counts['checked'] != EXPECTED:
        raise ValueError('joined cell coverage mismatch')
    return {'status': 'PASS', 'counts': dict(counts), 'by_form': dict(groups),
            'canonical_sha256': hashes.hexdigest(), 'table_sha256': sha(out / 'intel-amd-cells.jsonl.gz'),
            'intel': intel[1]['machine'], 'amd': amd[1]['machine'],
            'source_sha256': intel[1]['source_sha256'],
            'limits': ['One recorded CPU model per manufacturer; agreement is observed, not a universal ISA rule.',
                       'No game data or product fix is inferred from this hardware agreement table.']}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--coverage-only', action='store_true')
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=False)
    found = candidates(a.input)
    passed = [(d, r) for d, r in found if r['status'] == 'PASS']
    by_vendor = {}
    for item in passed:
        by_vendor.setdefault(item[1]['machine']['vendor'], item)
    covered = all(v in by_vendor for v in ['GenuineIntel', 'AuthenticAMD'])
    retry = len(found) == 2 and len(passed) == 2 and len(by_vendor) == 1
    result = {'status': 'PRESENT' if covered else 'NOT_COVERED', 'retry_same_vendor': retry,
              'machines': [r.get('machine', {}) for _, r in found],
              'captures': len(found), 'valid_captures': len(passed)}
    if a.coverage_only:
        save(a.out / 'COVERAGE.json', result)
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
                stream.write('retry=' + str(retry).lower() + '\n')
        print('HB_VENDOR_COVERAGE ' + result['status'] + ' retry=' + str(retry).lower())
        return 0
    try:
        if not covered:
            raise ValueError('Intel and AMD both required; bounded cloud retry exhausted or capture failed')
        result = compare(by_vendor['GenuineIntel'], by_vendor['AuthenticAMD'], a.out)
    except Exception as error:
        result.update(status='FAIL', error=type(error).__name__ + ': ' + str(error))
    save(a.out / 'RESULT.json', result)
    print('HB_VENDOR_FLAGS ' + result['status'] + ' ' + json.dumps(result.get('counts', {}), sort_keys=True))
    return int(result['status'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())
