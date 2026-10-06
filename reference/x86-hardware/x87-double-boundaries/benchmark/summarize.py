#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 OpenAI
# Deterministic aggregation of the unmodified hardware timing records.
import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path

paths = [Path(p) for p in sys.argv[1:]]
if not paths:
    raise SystemExit('Usage: python3 summarize.py run-1.csv run-2.csv')
groups = defaultdict(list)
for path in paths:
    with path.open(newline='') as source:
        records = list(csv.DictReader(source))
    assert len(records) == 243, (path, len(records))
    seen = set()
    for r in records:
        key = (int(r['pc_bits']), r['test'])
        row_key = (key, int(r['round']))
        assert row_key not in seen, (path, row_key)
        seen.add(row_key)
        assert int(r['iterations']) == 5000000
        assert int(r['cpu_before']) == int(r['cpu_after'])
        assert int(r['wall_ns']) > 0 and int(r['tsc_ticks']) > 0
        groups[key].append(r)
with open('summary.csv', 'w', newline='') as target:
    out = csv.writer(target)
    out.writerow(['pc_bits','test','samples','min_ns_per_iteration','median_ns_per_iteration','max_ns_per_iteration','median_tsc_ticks_per_iteration','min_thread_cpu_over_wall','median_thread_cpu_over_wall','max_thread_cpu_over_wall','result80_le'])
    for (bits,name), rows in sorted(groups.items()):
        values = [int(r['wall_ns'])/int(r['iterations']) for r in rows]
        ticks = [int(r['tsc_ticks'])/int(r['iterations']) for r in rows]
        ratios = [int(r['thread_cpu_ns'])/int(r['wall_ns']) for r in rows]
        results = set(r['result80_le'] for r in rows)
        assert len(results) == 1, (bits, name, results)
        out.writerow([bits,name,len(rows),f'{min(values):.9f}',f'{statistics.median(values):.9f}',f'{max(values):.9f}',f'{statistics.median(ticks):.9f}',f'{min(ratios):.9f}',f'{statistics.median(ratios):.9f}',f'{max(ratios):.9f}',next(iter(results))])
with open('functional-fingerprints.csv', 'w', newline='') as target:
    out = csv.writer(target)
    out.writerow(['pc_bits','test','iterations','result80_le'])
    for (bits,name), rows in sorted(groups.items()):
        out.writerow([bits,name,rows[0]['iterations'],rows[0]['result80_le']])
print(f'SUMMARY_OK files={len(paths)} samples={sum(map(len,groups.values()))} groups={len(groups)} stable_results=yes')
