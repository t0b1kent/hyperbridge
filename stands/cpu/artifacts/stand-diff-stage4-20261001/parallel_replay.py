#!/usr/bin/env python3
"""Bounded process shards; byte-exact raw evidence plus deterministic state view."""
import argparse
import collections
import concurrent.futures
import datetime
import heapq
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time

OWN = pathlib.Path(__file__).resolve().parent
ROOT = OWN.parents[1]
sys.path.insert(0, str(OWN))
from real_inputs_batch import sha
from evidence_io import open_text, write_text


def policy(workers=None):
    daytime = 700 <= int(datetime.datetime.now().strftime('%H%M')) < 2330
    cap = 4 if daytime else 6
    workers = cap if workers is None else workers
    if not 1 <= workers <= cap:
        raise ValueError(f'workers outside current operator limit 1..{cap}')
    inherited=os.getpriority(os.PRIO_PROCESS,0)
    return workers, ['nice', '-n', str(max(0,5-inherited))] if daytime and inherited<5 else []


def run_task(task):
    if task.get('reuse_prefix'):
        prefix=pathlib.Path(task['reuse_prefix']);saved=prefix.with_suffix('.json')
        if sha(saved)!=task['reuse_summary_sha256']:raise ValueError('Resume receipt drift')
        result=json.loads(saved.read_text())
        return dict(task=task,prefix=str(prefix),rc=int(bool(result['new_classes'])),result=result,
                    argv=['SAVED_COMPLETED_SHARD',str(saved)],reused=True)
    if task.get('deadline',float('inf'))<=time.monotonic():
        raise TimeoutError('global quick deadline before owned replay start')
    prefix = pathlib.Path(task['prefix'])
    prefix.parent.mkdir(parents=True, exist_ok=True)
    argv = [*policy(1)[1], sys.executable, task.get('adapter',str(OWN / 'real_inputs_batch.py')),
            '--runner', task['runner'], '--states', task['states'],
            '--image', task['image'], '--capture', task['capture'],
            '--out-prefix', str(prefix),
            '--limit', str(task.get('limit', 10000000)),
            '--batch-size', str(task.get('batch_size', 256)),
            '--shard-index', str(task.get('shard_index', 0)),
             '--shard-count', str(task.get('shard_count', 1))]
    argv += ['--game', task['game']]
    if task.get('sequences'): argv += ['--sequences', task['sequences']]
    if task.get('scan_all', True): argv += ['--scan-all']
    with prefix.with_suffix('.driver.log').open('x') as stream:
        child = subprocess.Popen(argv, cwd=ROOT, stdin=subprocess.DEVNULL,
                                 stdout=stream, stderr=stream)
        try:
            remaining=task.get('deadline',float('inf'))-time.monotonic()
            rc = child.wait(timeout=max(0.01,min(task.get('timeout',21600),remaining)))
        except subprocess.TimeoutExpired:
            # Popen identifies exactly the child this task created.
            child.terminate()
            try: child.wait(timeout=8)
            except subprocess.TimeoutExpired: child.kill(); child.wait()
            raise TimeoutError('owned replay deadline: ' + str(prefix))
    result = json.loads(prefix.with_suffix('.json').read_text())
    return dict(task=task, prefix=str(prefix), rc=rc, result=result, argv=argv)


NATIVE_STATE = ['id', 'status', 'state_valid', 'sfd', 'rip', 'regs', 'rflags',
                'mxcsr', 'fcw', 'x87_raw', 'x87_fsw', 'x87_abridged_ftw',
                'x87_reduced', 'xmm', 'ymm_hi', 'init_data_hash', 'init_stack_hash',
                'data_hash', 'stack_hash', 'written_memory', 'memory_page_sha256']


def semantic(row):
    """Timing, host PC and cumulative probes stay only in the preserved raw file."""
    result = dict(row)
    if 'native' in result:
        result['native'] = {k: row['native'][k] for k in NATIVE_STATE if k in row['native']}
    result.pop('known_provenance', None)
    result.pop('retry_attempts', None)
    return result


def merge(parts, prefix):
    prefix = pathlib.Path(prefix)
    counts = collections.Counter(); classes = collections.Counter()
    known = collections.Counter(); fresh = collections.Counter()
    fixed = collections.Counter(); retries = collections.Counter(); phase = collections.Counter()
    checked_rips = set(); input_rips = set(); starts = set()
    files = []; streams = []; part_hashes = []
    raw_hash = hashlib.sha256(); semantic_hash = hashlib.sha256()
    def decoded_rows(stream, digest):
        for line in stream:
            digest.update(line.encode('utf-8'))
            yield json.loads(line)
    source_hashes = {}
    for part in parts:
        r = part['result']; counts.update(r['counts']); classes.update(r['classes'])
        known.update(r['known_classes']); fresh.update(r['new_classes'])
        fixed.update(r.get('fixed_classes',{}));retries.update(r.get('retry_counts',{}));phase.update(r.get('phase_seconds',{}))
        # Each shard hashes the same frozen inputs; disagreement is an error.
        for name, digest in r['inputs_sha256'].items():
            if name in source_hashes and source_hashes[name] != digest:
                raise ValueError('input drift between workers: ' + name)
            source_hashes[name] = digest
        manager = open_text(pathlib.Path(part['prefix']).with_suffix('.jsonl'))
        stream = manager.__enter__()
        streams.append(manager)
        part_hashes.append(hashlib.sha256())
        files.append(decoded_rows(stream, part_hashes[-1]))
    try:
        with write_text(prefix.with_suffix('.jsonl')) as raw, write_text(prefix.with_suffix('.semantic.jsonl')) as normalized:
            previous = None
            for row in heapq.merge(*files, key=lambda x: x['state']['sequence']):
                seq = row['state']['sequence']
                if seq == previous: raise ValueError('duplicate shard sequence')
                previous = seq
                rip = row['state']['rip']; input_rips.add(rip)
                if row.get('native', {}).get('state_valid'): checked_rips.add(rip)
                raw_line = json.dumps(row) + '\n'
                semantic_line = json.dumps(semantic(row), sort_keys=True, separators=(',', ':')) + '\n'
                raw.write(raw_line); raw_hash.update(raw_line.encode('utf-8'))
                normalized.write(semantic_line); semantic_hash.update(semantic_line.encode('utf-8'))
    finally:
        for manager in streams: manager.__exit__(None, None, None)
    # Count coverage against this exact capture, including internal entry RIPs.
    from capture_index import code_index, entry_rips
    starts = code_index(parts[0]['task']['capture'], [])[1]
    all_inputs = set(entry_rips(parts[0]['task']['states']))
    result = dict(label='DIAGNOSTIC_ONLY_NOT_GOLDEN',
                  status='CHECKED' if counts['checked'] else 'UNVERIFIED',
                  counts=dict(counts), classes=dict(classes), known_classes=dict(known),
                  new_classes=dict(fresh), inputs_sha256=source_hashes,
                  fixed_classes=dict(fixed),retry_counts=dict(retries),phase_seconds=dict(phase),
                  coverage=dict(input_unique_rips=len(all_inputs), checked_unique_rips=len(checked_rips),
                                capture_unique_rips=len(starts), checked_capture_start_rips=len(checked_rips & starts),
                                percent=100 * len(checked_rips & starts) / len(starts) if starts else None),
                  raw=str(prefix.with_suffix('.jsonl')),
                  raw_sha256=raw_hash.hexdigest(),
                  semantic=str(prefix.with_suffix('.semantic.jsonl')),
                  semantic_sha256=semantic_hash.hexdigest(),
                  parts=[dict(prefix=p['prefix'], rc=p['rc'], seconds=p['result']['elapsed_seconds'],
                               raw_sha256=h.hexdigest()) for p,h in zip(parts,part_hashes)],
                  boundaries=parts[0]['result']['boundaries'])
    prefix.with_suffix('.json').write_text(json.dumps(result, indent=2) + '\n')
    canonical = {k: result[k] for k in ['label', 'status', 'counts', 'classes',
                 'known_classes', 'new_classes', 'inputs_sha256', 'coverage', 'semantic_sha256', 'boundaries']}
    canonical_path = prefix.with_suffix('.canonical.json')
    canonical_path.write_text(json.dumps(canonical, sort_keys=True, separators=(',', ':')) + '\n')
    result['canonical_report_sha256'] = sha(canonical_path)
    return result


def tasks_for(game, runner, prefix, shards=1, quick=False, batch_size=256):
    return [dict(game=game['game'], runner=str(runner), states=game['states'],
                 image=game['image'], capture=game['capture'],
                 sequences=game.get('sequences') if quick else None,
                 limit=game['expected_quick'] if quick else 10000000,
                 prefix=str(prefix) + f'-part{i:02d}', shard_index=i,
                 shard_count=shards, batch_size=batch_size,
                 timeout=165 if quick else 21600) for i in range(shards)]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--runner', required=True, type=pathlib.Path)
    for name in ['states', 'image', 'capture']: ap.add_argument('--' + name, required=True)
    ap.add_argument('--sequences', type=pathlib.Path)
    ap.add_argument('--workers', type=int)
    ap.add_argument('--batch-size', type=int, default=256)
    ap.add_argument('--out-prefix', required=True, type=pathlib.Path)
    ap.add_argument('--detach', action='store_true')
    a = ap.parse_args(); workers, priority = policy(a.workers)
    if a.detach:
        with a.out_prefix.with_suffix('.driver.log').open('x') as stream:
            p = subprocess.Popen([*priority, sys.executable, str(pathlib.Path(__file__)),
                                  *[x for x in sys.argv[1:] if x != '--detach']],
                                 cwd=ROOT, stdin=subprocess.DEVNULL, stdout=stream,
                                 stderr=stream, start_new_session=True)
        print('REPLAY_PID', p.pid, 'workers', workers, 'OUTPUT', a.out_prefix); return 0
    start = time.monotonic()
    game = dict(game='single', states=a.states, image=a.image, capture=a.capture)
    tasks = tasks_for(game, a.runner.resolve(), a.out_prefix, workers, batch_size=a.batch_size)
    if a.sequences:
        for task in tasks: task['sequences'] = str(a.sequences)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        parts = list(pool.map(run_task, tasks))
    result = merge(parts, a.out_prefix)
    timing = dict(workers=workers, batch_size=a.batch_size, seconds=time.monotonic()-start,
                  semantic_sha256=result['semantic_sha256'], counts=result['counts'])
    a.out_prefix.with_suffix('.timing.json').write_text(json.dumps(timing, indent=2) + '\n')
    print(json.dumps(timing, separators=(',', ':')))
    return int(bool(result['new_classes']) or not result['counts'].get('checked'))


if __name__ == '__main__': raise SystemExit(main())
