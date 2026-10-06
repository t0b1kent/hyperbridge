#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
"""Retrieve the last successful main composition's measured cost, read-only."""
import argparse
import json
from pathlib import Path
import subprocess


def gh(*args):
    return json.loads(subprocess.check_output(['gh', *args], text=True))


def select(repository, current_run, out):
    runs = gh('run', 'list', '-R', repository, '--workflow', 'hardware-gates.yml', '--branch', 'main',
              '--status', 'success', '--limit', '20', '--json', 'databaseId,headSha')
    for run in runs:
        if str(run['databaseId']) == current_run:
            continue
        artifacts = gh('api', f"repos/{repository}/actions/runs/{run['databaseId']}/artifacts")['artifacts']
        found = [a for a in artifacts if a['name'] == 'instruction-cost-RESULT' and not a['expired']]
        if not found:
            continue
        subprocess.run(['gh', 'run', 'download', str(run['databaseId']), '-R', repository,
                        '-n', 'instruction-cost-RESULT', '-D', str(out)], check=True)
        result = json.loads((out / 'RESULT.json').read_text())
        if result['published_commit'] != run['headSha'] or result['aa'] != 'MATCH':
            raise ValueError('baseline provenance or repeatability mismatch')
        print(f"BASELINE run={run['databaseId']} commit={run['headSha']}")
        return
    print('BASELINE NOT_ENABLED: no successful main measurement in last 20 successful runs')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repository', required=True)
    p.add_argument('--current-run', required=True)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    select(args.repository, args.current_run, args.out)
