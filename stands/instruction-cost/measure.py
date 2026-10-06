#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
"""Static entry-region emission cost, not dynamic instructions or game timing."""
import argparse
from collections import Counter
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'hardware'))
import common
import generate

METRICS = ('guest_instructions', 'arm_instructions', 'host_code_bytes', 'allocation_bytes')


def decode_cost(record):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    if record.get('status') != 'COMPILED' or record.get('execution') != 'NOT_RUN':
        raise ValueError('incomplete translation')
    data = bytes.fromhex(record['host_hex'])
    if not 0 < len(data) <= 262144 or len(data) != record['allocation_bytes']:
        raise ValueError('invalid allocation')
    blocks = sorted(record['subblocks'])
    if not blocks or record['guest_instructions'] <= 0:
        raise ValueError('missing code blocks or guest denominator')
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    mnemonics = Counter()
    end = 0
    for offset, size in blocks:
        if offset < 0 or size < 0 or offset % 4 or size % 4 or offset + size > len(data):
            raise ValueError('overlapping, unaligned or out-of-bounds code block')
        # FEX can retain an empty block after eliminating a jump. It occupies no
        # host bytes; the next nonempty block may have exactly the same offset.
        if size == 0:
            continue
        if offset < end:
            raise ValueError('overlapping, unaligned or out-of-bounds code block')
        instructions = list(decoder.disasm(data[offset:offset+size], offset))
        if sum(i.size for i in instructions) != size:
            raise ValueError('incomplete ARM decoding')
        mnemonics.update(i.mnemonic for i in instructions)
        end = offset + size
    arm = sum(mnemonics.values())
    if arm == 0 or not 0 < record['host_code_bytes'] <= len(data) or arm * 4 > record['host_code_bytes']:
        raise ValueError('debug code size inconsistent with emitted instructions')
    return {k: record[k] for k in ('guest_instructions', 'host_code_bytes', 'allocation_bytes')} | {
        'arm_instructions': arm, 'arm_per_guest': arm / record['guest_instructions'],
        'decoded_code_bytes': arm * 4, 'mnemonics': dict(sorted(mnemonics.items())),
        'compile_ns': record['compile_ns']}


def signature(row):
    return {k: row[k] for k in METRICS}


def compare(current, baseline):
    if baseline is None:
        return {'status': 'BASELINE_REQUIRED', 'growth': [], 'reason': 'first qualification; no no-growth claim'}
    for key in ('schema', 'forms_sha256', 'host_features'):
        if baseline.get(key) != current.get(key):
            return {'status': 'INCOMPARABLE', 'growth': [], 'reason': key + ' differs'}
    if baseline.get('aa') != 'MATCH':
        return {'status': 'INCOMPARABLE', 'growth': [], 'reason': 'baseline A/A is not MATCH'}
    previous = {r['name']: r for r in baseline['rows']}
    if set(previous) != {r['name'] for r in current['rows']}:
        return {'status': 'INCOMPARABLE', 'growth': [], 'reason': 'case set differs'}
    growth, deltas = [], []
    for row in current['rows']:
        old = previous[row['name']]
        for arm in ('off', 'on'):
            new_cost, old_cost = row[arm], old[arm]
            if new_cost['guest_instructions'] != old_cost['guest_instructions']:
                return {'status': 'INCOMPARABLE', 'growth': [], 'reason': row['name'] + ': guest coverage differs'}
            delta = {k: new_cost[k] - old_cost[k] for k in METRICS}
            deltas.append({'name': row['name'], 'arm': arm, **delta})
            if any(delta[k] > 0 for k in ('arm_instructions', 'host_code_bytes')):
                growth.append(deltas[-1])
    return {'status': 'GROWTH' if growth else 'NO_GROWTH', 'growth': growth, 'deltas': deltas,
            'baseline_commit': baseline['published_commit'], 'baseline_candidate_sha256': baseline['candidate_sha256'],
            'baseline_engine_env': baseline['engine_env'], 'current_engine_env': current['engine_env'],
            'meaning': 'composition comparison; environment differences are explicit, not a causal speed claim'}


def measure(args):
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        raise ValueError('requires native macOS ARM64')
    _, arms, identity = common.candidate(args.candidate)
    build = json.loads((args.bundle / 'BUILD.json').read_text())
    if build['candidate_sha256'] != identity or build['flavor'] != 'accepted':
        raise ValueError('wrong runner composition')
    for name, digest in build['products'].items():
        if common.sha(args.bundle / name) != digest:
            raise ValueError('runner bundle drift: ' + name)
    if 'codegen_runner' not in build['products']:
        raise ValueError('codegen frontend missing from build receipt')
    cases = generate.generate(args.out / 'forms')
    forms_hash = common.fingerprint([{'name': c['name'], 'code': c['code']} for c in cases])
    requests = ''.join(generate.request(c) for c in cases)
    (args.out / 'requests.txt').write_text(requests)
    runner = str((args.bundle / 'codegen_runner').resolve())
    repetitions, features = {}, set()
    started = time.monotonic()
    for arm in ('off', 'on'):
        env = common.runner_environment(arms[arm], args.out / ('home-' + arm))
        repetitions[arm] = []
        for repeat in range(2):
            prefix = args.out / f'{arm}-{repeat}'
            with prefix.with_suffix('.jsonl').open('w') as out, prefix.with_suffix('.stderr').open('w') as err:
                subprocess.run([runner], input=requests, text=True, stdout=out, stderr=err,
                               env=env, timeout=60, check=True)
            records = [json.loads(line) for line in prefix.with_suffix('.jsonl').read_text().splitlines()]
            records = [r for r in records if 'id' in r]
            if [r['id'] for r in records] != [c['id'] for c in cases]:
                raise ValueError('missing, duplicate or reordered cases')
            header = [l for l in prefix.with_suffix('.stderr').read_text().splitlines()
                      if l.startswith('fex-oracle: features ')]
            if len(header) != 1:
                raise ValueError('missing host feature receipt')
            features.add(header[0])
            repetitions[arm].append([decode_cost(r) for r in records])
    if len(features) != 1:
        raise ValueError('host features differ between arms/repeats')
    rows, stable = [], True
    for i, case in enumerate(cases):
        row = {k: case[k] for k in ('name', 'group', 'input_instructions', 'code_sha256')}
        for arm in ('off', 'on'):
            values = [r[i] for r in repetitions[arm]]
            equal = signature(values[0]) == signature(values[1])
            stable &= equal
            row[arm] = signature(values[0]) | {'aa': equal, 'arm_per_guest': values[0]['arm_per_guest'],
                'compile_ns_samples': [v['compile_ns'] for v in values],
                'compile_ns_median': statistics.median(v['compile_ns'] for v in values)}
        row['on_minus_off'] = {k: row['on'][k] - row['off'][k] for k in METRICS}
        rows.append(row)
    result = {'schema': 1, 'kind': 'static-entry-region', 'execution': 'NOT_RUN',
              'timing': 'VM compilation reference only, not guest execution or an FPS/speed claim',
              'coverage': 'reachable entry translation only; callees after indirect control flow and shared helpers excluded',
              'forms_sha256': forms_hash, 'host_features': features.pop(),
              'candidate_sha256': identity, 'published_commit': build['published_commit'],
              'build': build, 'engine_env': arms, 'aa': 'MATCH' if stable else 'MISMATCH',
              'rows': rows, 'seconds': time.monotonic() - started}
    baseline = json.loads(args.baseline.read_text()) if args.baseline else None
    result['comparison'] = compare(result, baseline)
    result['status'] = 'FAIL' if not stable or result['comparison']['status'] in ('GROWTH', 'INCOMPARABLE') else result['comparison']['status']
    result['evidence'] = {str(p.relative_to(args.out)): common.sha(p) for p in args.out.rglob('*') if p.is_file()}
    common.write_json(args.out / 'RESULT.json', result)
    table = ['| Form | Guest off/on | ARM off/on | Code bytes off/on | Compile ns off/on (VM reference) |',
             '|---|---:|---:|---:|---:|']
    for row in rows:
        table.append('| ' + row['name'] + ' | ' + ' | '.join(
            str(row['off'][k]) + '/' + str(row['on'][k]) for k in
            ('guest_instructions', 'arm_instructions', 'host_code_bytes', 'compile_ns_median')) + ' |')
    (args.out / 'TABLE.md').write_text('\n'.join(table) + '\n')
    print(f"HB_INSTRUCTION_COST {result['status']} aa={result['aa']} forms={len(rows)} execution=NOT_RUN")
    return 1 if result['status'] == 'FAIL' else 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--baseline', type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    try:
        sys.exit(measure(args))
    except (ValueError, KeyError, subprocess.SubprocessError) as exc:
        common.write_json(args.out / 'ERROR.json', {'status': 'FAILED', 'reason': str(exc)})
        print('HB_INSTRUCTION_COST FAIL: ' + str(exc), file=sys.stderr)
        sys.exit(1)
