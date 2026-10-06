#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
"""Restore serial order and reproduce the fixed two-part local full fingerprint."""
import argparse
import collections
import gzip
import hashlib
import heapq
import json
from pathlib import Path
import sys

import common


def local_full_fingerprint(component, part_hashes):
    if len(part_hashes) != 2:
        raise ValueError('the local full contract has exactly two ordered parts')
    if component == 'hwflags':
        encoded = json.dumps(part_hashes).encode()
    elif component == 'hwsimd':
        encoded = ''.join(part_hashes).encode()
    else:
        raise ValueError('unknown fingerprint component')
    return hashlib.sha256(encoded).hexdigest()


def records(directory, report):
    h = hashlib.sha256()
    count, previous = 0, None
    evidence = report['evidence_sha256']
    for name in ['semantic.jsonl.gz', 'raw.jsonl.gz', 'native.log']:
        if common.sha(directory / name) != evidence[name]:
            raise ValueError('artifact evidence SHA drift: ' + name)
    with gzip.open(directory / 'semantic.jsonl.gz', 'rt') as stream:
        for line in stream:
            record = json.loads(line)
            key = common.semantic_key(record)
            if previous is not None and key <= previous:
                raise ValueError('non-increasing shard key')
            previous = key
            h.update(common.semantic_bytes(report['component'], record))
            count += 1
            yield record
    if count != report['counts']['checked'] or h.hexdigest() != report['canonical_sha256']:
        raise ValueError('shard row count or serial fingerprint drift')


def merge_group(directories, out):
    reports = [json.loads((d / 'RESULT.json').read_text()) for d in directories]
    first = reports[0]
    component, mode = first['component'], first['mode']
    required = ['component', 'mode', 'arm', 'shards', 'candidate_sha256', 'data_sha256', 'runner_sha256', 'engine_env', 'flavor', 'build']
    for report in reports:
        if any(report.get(k) != first.get(k) for k in required):
            raise ValueError('incompatible shard inputs')
        if report.get('error') or not report.get('complete'):
            raise ValueError('incomplete/failed shard collection')
        expected = (common.COUNTS[component][mode] + first['shards'] - 1 - report['index']) // first['shards']
        if report['counts']['checked'] != expected:
            raise ValueError('wrong shard coverage')
    if sorted(r['index'] for r in reports) != list(range(first['shards'])):
        raise ValueError('missing or duplicated shard')
    streams = [records(d, r) for d, r in zip(directories, reports)]
    out.mkdir(parents=True, exist_ok=False)
    count, previous, h = 0, None, hashlib.sha256()
    local_parts = [hashlib.sha256(), hashlib.sha256()]
    with gzip.open(out / 'semantic.jsonl.gz', 'wb', compresslevel=1) as stream:
        for record in heapq.merge(*streams, key=common.semantic_key):
            key = common.semantic_key(record)
            if previous is not None and key <= previous:
                raise ValueError('duplicate or unordered merged row')
            previous = key
            encoded = common.semantic_bytes(component, record)
            stream.write(encoded)
            h.update(encoded)
            # Historical local full uses ordinal % 2, regardless of how many
            # cloud workers produced the records. Reconstruct from row bytes,
            # never from the actual cloud shard digests (currently four).
            local_parts[count % 2].update(encoded)
            count += 1
    if count != common.COUNTS[component][mode]:
        raise ValueError('incomplete merged row coverage')
    counts = collections.Counter()
    groups = collections.defaultdict(collections.Counter)
    for r in reports:
        counts.update(r['counts'])
        for key, value in r['groups'].items():
            groups[key].update(value)
    result = {k: first[k] for k in required}
    serial_hash = h.hexdigest()
    part_hashes = [part.hexdigest() for part in local_parts]
    canonical = local_full_fingerprint(component, part_hashes) if mode == 'full' else serial_hash
    result.update(gate=first['gate'], status='PASS' if all(r['status'] == 'PASS' for r in reports) else 'FAIL',
                  counts=dict(counts), groups=dict(groups), canonical_sha256=canonical,
                  serial_canonical_sha256=serial_hash,
                  fingerprint_contract='local-two-part-v1' if mode == 'full' else 'serial-row-v1',
                  local_part_sha256=part_hashes if mode == 'full' else [],
                  seconds=sum(r['seconds'] for r in reports),
                  seconds_semantics='sum of shard wall seconds; not matrix elapsed time',
                  max_shard_seconds=max(r['seconds'] for r in reports),
                  cpu_seconds={k: sum(r['cpu_seconds'][k] for r in reports) for k in ['user', 'system']},
                  semantic_sha256=common.sha(out / 'semantic.jsonl.gz'))
    common.write_json(out / 'RESULT.json', result)
    return result


def negative_check(report):
    return (report.get('flavor') == 'negative' and report.get('status') == 'FAIL'
            and report.get('complete') and not report.get('error')
            and report.get('counts', {}).get('defined_bad', 0) > 0
            and report.get('counts', {}).get('new', 0) > 0
            and report.get('counts', {}).get('checked') == common.COUNTS['hwflags']['quick'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--candidate', type=Path, required=True)
    p.add_argument('--mode', choices=['quick', 'full'], default='full')
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    final = {'status': 'FAIL', 'gate': 'HB_CLOUD_HARDWARE', 'results': {}, 'negative': 'MISSING'}
    try:
        spec, _, identity = common.candidate(args.candidate)
        groups = collections.defaultdict(list)
        negatives = []
        for path in sorted(args.input.rglob('RESULT.json')):
            report = json.loads(path.read_text())
            if report.get('candidate_sha256') != identity:
                raise ValueError('artifact from a different candidate')
            if report.get('flavor') == 'negative':
                negatives.append((path.parent, report))
            else:
                groups[(report['component'], report['mode'], report['arm'])].append(path.parent)
        modes = ['quick', 'full'] if args.mode == 'full' else ['quick']
        expected = {(c, m, a) for c in common.COUNTS for m in modes for a in ['off', 'on']}
        final['expected_components'] = len(expected)
        if set(groups) != expected:
            raise ValueError('missing or unexpected component/mode/arm')
        for key, directories in sorted(groups.items()):
            name = '-'.join(key)
            final['results'][name] = merge_group(directories, args.out / name)
        if len(negatives) != 1 or not negative_check(negatives[0][1]):
            raise ValueError('broken translator must fail on defined output, not infrastructure')
        list(records(*negatives[0]))
        final['negative'] = 'FAIL_AS_EXPECTED'
        final['negative_result'] = negatives[0][1]
        final['status'] = 'PASS' if all(r['status'] == 'PASS' for r in final['results'].values()) else 'FAIL'
        # Historical hashes are evidence of equality, not a whitelist for candidate behavior.
        reference = json.loads((common.HERE / 'data/local-reference.json').read_text())
        final['local_reference'] = {}
        for name, r in final['results'].items():
            expected_hash = reference[r['component']][r['mode']]['canonical_sha256']
            final['local_reference'][name] = {'equal': r['canonical_sha256'] == expected_hash,
                                            'local': expected_hash, 'cloud': r['canonical_sha256'],
                                            'cause': 'NONE' if r['canonical_sha256'] == expected_hash else 'UNRESOLVED: compare semantic rows; host/build identity differs'}
        if not spec['independent_keys']:
            final['aa'] = {f'{c}-{m}': final['results'][f'{c}-{m}-off']['canonical_sha256'] == final['results'][f'{c}-{m}-on']['canonical_sha256']
                           for c in common.COUNTS for m in modes}
            if not all(final['aa'].values()):
                final['status'] = 'FAIL'
        final['equivalence'] = 'MATCH' if all(r['equal'] for r in final['local_reference'].values()) else 'MISMATCH'
        if spec.get('require_local_equality') and final['equivalence'] != 'MATCH':
            final['status'] = 'FAIL'
        final['qualification'] = 'DIAGNOSTIC_ONLY: hardware correctness; no game or FPS acceptance'
    except Exception as error:
        final.update(status='FAIL', error=type(error).__name__ + ': ' + str(error))
    common.write_json(args.out / 'RESULT.json', final)
    verdict = f"HB_CLOUD_HARDWARE {final['status']} negative={final['negative']} components={len(final['results'])}/{final.get('expected_components', 0)}"
    (args.out / 'VERDICT.txt').write_text(verdict + '\n')
    print(verdict)
    return int(final['status'] != 'PASS')


if __name__ == '__main__':
    sys.exit(main())
