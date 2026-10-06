#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
"""One bounded hardware shard, preserving the local stand's comparisons and hash."""
import argparse
import collections
import gzip
import hashlib
import json
from pathlib import Path
import resource
import sys
import time

import common
import hwflags
import hwsimd


def selected(component, mode, shards, index):
    seen = set()
    if mode == 'quick' and shards != 1:
        raise ValueError('quick selection is serial; shard only full')
    rows = hwflags.rows() if component == 'hwflags' else hwsimd.rows(hwsimd.TABLE, hwsimd.catalog())
    for ordinal, row in enumerate(rows):
        if ordinal % shards != index:
            continue
        if mode == 'quick':
            if component == 'hwflags':
                key = (row.form, row.width, row.trap, hwflags.condition(row), row.before,
                       row.a == 0, bool((row.b or 0) >> (row.width - 1)))
            else:
                imm = row.meta.get('imm', -1)
                edge = ('imm0' if imm == 0 else 'imm1' if imm == 1 else
                        'imm-edge' if imm in (15, 16, 31, 32, 63, 64, 127, 128, 255) else 'imm-mid')
                key = (row.group, edge) if row.family != 'upper' else row.key
            if key in seen:
                continue
            seen.add(key)
        yield row


def usage():
    values = [resource.getrusage(k) for k in (resource.RUSAGE_SELF, resource.RUSAGE_CHILDREN)]
    return {'user': sum(v.ru_utime for v in values), 'system': sum(v.ru_stime for v in values)}


def execute(args):
    started, cpu_before = time.monotonic(), usage()
    if args.shards < 1 or not 0 <= args.index < args.shards:
        raise ValueError('invalid shard')
    args.out.mkdir(parents=True, exist_ok=False)
    result = {'status': 'FAIL', 'gate': 'HB_' + args.component.upper(),
              'component': args.component, 'mode': args.mode, 'arm': args.arm,
              'shards': args.shards, 'index': args.index, 'counts': {},
              'expected_count': (common.COUNTS[args.component][args.mode] + args.shards - 1 - args.index) // args.shards}
    counts = collections.Counter()
    groups = collections.defaultdict(collections.Counter)
    examples = {}
    hasher = hashlib.sha256()
    try:
        _, arms, identity = common.candidate(args.candidate)
        data_id = common.verify_data()
        build = json.loads((args.bundle / 'BUILD.json').read_text())
        runner = (args.bundle / 'stand_runner').resolve()
        if build['candidate_sha256'] != identity or build['data_sha256'] != data_id:
            raise ValueError('build inputs differ from checked-out candidate/data')
        for name, digest in build['products'].items():
            if common.sha(common.relative_file(args.bundle, name)) != digest:
                raise ValueError('runner bundle product drift: ' + name)
        if build['flavor'] != args.flavor:
            raise ValueError('negative/accepted runner substitution')
        result.update(candidate_sha256=identity, data_sha256=data_id, build=build,
                      runner='stand_runner', runner_sha256=common.sha(runner),
                      engine_env=arms[args.arm], flavor=args.flavor)
        env = common.runner_environment(arms[args.arm], args.out / 'home')
        hwsimd.CACHE = args.bundle / 'simd-code.json.gz'
        flags_iter = hwflags.known_cursor(hwflags.HERE / 'known-hwflags.json', hwflags.TABLE) if args.component == 'hwflags' else iter(())
        baseline = next(flags_iter, None)
        simd_baseline = hwsimd.known(hwsimd.HERE / 'known-hwsimd.json', hwsimd.TABLE) if args.component == 'hwsimd' else {}
        curator = hwflags.curator_rules(hwflags.TABLE) if args.component == 'hwflags' else {}
        pending = []
        with gzip.open(args.out / 'raw.jsonl.gz', 'wt', compresslevel=1) as raw, \
             (args.out / 'native.log').open('x') as native, \
             gzip.open(args.out / 'semantic.jsonl.gz', 'wb', compresslevel=1) as semantic:
            def flush():
                nonlocal baseline
                if time.monotonic() - started > 23 * 60:
                    raise TimeoutError('23 minute active shard budget exceeded')
                if args.component == 'hwflags':
                    states = hwflags.run_batch(runner, pending, counts['checked'], env, raw, native)
                    pairs = zip(pending, states)
                else:
                    pairs = hwsimd.batches(runner, pending, env, raw, native)
                for row, state in pairs:
                    counts['checked'] += 1
                    if args.component == 'hwflags':
                        cmp = hwflags.compare(row, state)
                        while baseline and hwflags.key_order(baseline['key']) < hwflags.key_order(row.key):
                            baseline = next(flags_iter, None)
                        previous = baseline if baseline and baseline['key'] == row.key else None
                        new, known, fixed, partial = hwflags.classify(row, cmp, previous)
                        counts['trap' if row.trap else 'success'] += 1
                        counts['defined_checked'] += bool(cmp['defined_mask'] or hwflags.defined(row)[1])
                        counts['defined_bad'] += cmp['defined_bad']
                        mismatch = bool(cmp['undef_delta'] or cmp['undef_result'])
                        counts['undefined_bad'] += mismatch
                        counts['equal'] += not mismatch and not cmp['defined_bad']
                        for key, value in [('new', new), ('known', known), ('fixed', fixed), ('partial_fixed', partial)]:
                            counts[key] += value
                        record = dict(key=row.key, form=row.form, width=row.width, before=row.before,
                                      a=row.a, b=row.b, c=row.c, **cmp)
                        for rule in curator.get(row.op, []):
                            if hwflags.matches_condition(row, rule['condition']):
                                group_key = f"CURATOR|{row.op}|{rule['condition']}|{rule['flag']}"
                                hwflags.accumulate(groups[group_key], row, cmp, rule['flag'])
                        for name, bit in hwflags.FLAGS.items():
                            if cmp['defined_mask'] & bit:
                                continue
                            group_key = f'{row.op}|{hwflags.condition(row)}|{name}'
                            hwflags.accumulate(groups[group_key], row, cmp, name)
                            if cmp['undef_delta'] & bit:
                                examples.setdefault(group_key, record)
                        if not hwflags.defined(row)[1]:
                            group_key = f'{row.op}|{hwflags.condition(row)}|приёмник'
                            hwflags.accumulate(groups[group_key], row, cmp, 'приёмник')
                            if cmp['undef_result']:
                                examples.setdefault(group_key, record)
                        if cmp['defined_bad']:
                            examples.setdefault('DEFINED|' + row.form + '|' + str(row.width), record)
                    else:
                        cmp = hwsimd.compare(row, state)
                        verdict = hwsimd.classify(cmp, simd_baseline.get(row.key))
                        counts.update([verdict, *cmp['classes']])
                        if verdict == 'PARTIAL_FIXED':
                            counts['KNOWN'] += 1
                        counts['traps'] += bool(row.expected_trap)
                        counts['primary_unavailable'] += cmp['primary_unavailable']
                        groups[row.group].update(['checked', verdict, *cmp['classes']])
                        if verdict == 'PARTIAL_FIXED':
                            groups[row.group]['KNOWN'] += 1
                        record = dict(key=row.key, form=row.form, group=row.group, comparison=cmp, classification=verdict)
                        if cmp['classes'] and row.group not in examples:
                            examples[row.group] = dict(record, input=row.raw, code=row.meta['code'],
                                                       expected_result=row.result, observed_status=state['status'])
                    encoded = common.semantic_bytes(args.component, record)
                    hasher.update(encoded)
                    semantic.write(common.canonical(record) + b'\n')
                pending.clear()
            for row in selected(args.component, args.mode, args.shards, args.index):
                pending.append(row)
                if len(pending) == 512:
                    flush()
            if pending:
                flush()
        result['complete'] = counts['checked'] == result['expected_count']
        result['status'] = 'PASS' if result['complete'] and not counts['new'] and not counts['NEW'] else 'FAIL'
        if common.verify_data() != data_id:
            raise ValueError('data changed during shard')
    except Exception as error:
        result.update(status='FAIL', error=type(error).__name__ + ': ' + str(error))
    finally:
        cpu_after = usage()
        result.update(counts=dict(counts), groups=dict(groups), examples=examples, canonical_sha256=hasher.hexdigest(),
                      seconds=round(time.monotonic() - started, 6),
                      cpu_seconds={k: round(cpu_after[k] - cpu_before[k], 6) for k in cpu_before})
        result['evidence_sha256'] = {p.name: common.sha(p) for p in args.out.iterdir() if p.is_file()}
        common.write_json(args.out / 'RESULT.json', result)
        print(f"{result['gate']} {result['status']} arm={args.arm} mode={args.mode} shard={args.index}/{args.shards} checked={counts['checked']} canonical_sha256={hasher.hexdigest()}")
    return int(result['status'] != 'PASS')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--candidate', type=Path, required=True)
    p.add_argument('--bundle', type=Path, required=True)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--hwflags', dest='component', action='store_const', const='hwflags')
    g.add_argument('--hwsimd', dest='component', action='store_const', const='hwsimd')
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--quick', dest='mode', action='store_const', const='quick')
    g.add_argument('--full', dest='mode', action='store_const', const='full')
    p.add_argument('--arm', choices=['off', 'on'], required=True)
    p.add_argument('--flavor', choices=['accepted', 'negative'], default='accepted')
    p.add_argument('--shards', type=int, default=1)
    p.add_argument('--index', type=int, default=0)
    p.add_argument('--out', type=Path, required=True)
    return execute(p.parse_args())


if __name__ == '__main__':
    sys.exit(main())
