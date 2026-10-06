#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
"""Prepare a source-pinned automatic candidate and a bounded CI matrix."""
import argparse
import json
import os
from pathlib import Path

import common


def prepare(path):
    if path.resolve() == (common.HERE / 'candidates/published-ci').resolve():
        series = {p.name: common.sha(p) for p in sorted((common.ROOT / 'fex/patches').glob('*.patch'))}
        arms = json.loads((common.HERE / 'candidates/release-1.0.8/arms.json').read_text())
        common.write_json(path / 'arms.json', arms)
        common.write_json(path / 'candidate.json', {'schema': 1, 'base_series_sha256': common.fingerprint(series),
                          'patches': [], 'independent_keys': [], 'require_local_equality': False,
                          'purpose': 'Current published series; automatic quick/full A/A snapshot'})
    return common.candidate(path)


def matrix(mode):
    return {'include': [dict(component=c, arm=a, mode=m, index=i, shards=n)
                        for c in ['hwflags', 'hwsimd'] for a in ['off', 'on']
                        for m, n in [('quick', 1), *([('full', 4)] if mode == 'full' else [])]
                        for i in range(n)]}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--candidate', type=Path, required=True)
    p.add_argument('--mode', choices=['quick', 'full'], default='full')
    p.add_argument('--prepare-only', action='store_true')
    a = p.parse_args()
    _, _, identity = prepare(a.candidate)
    if not a.prepare_only:
        result = json.dumps(matrix(a.mode), separators=(',', ':'))
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
                stream.write('matrix=' + result + '\n')
        print(f'HB_HARDWARE_PLAN mode={a.mode} cells={len(matrix(a.mode)["include"])} candidate_sha256={identity}')


if __name__ == '__main__':
    main()
