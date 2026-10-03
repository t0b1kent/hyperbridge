#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
"""Two byte-identical quick runs plus a native-runner mutation control."""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--runner', required=True)
    ap.add_argument('--out', default='build/stand-reports')
    args = ap.parse_args()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    driver = pathlib.Path(__file__).with_name('compare.py')
    receipts = []
    for name, mutation in [('quick-a', False), ('quick-b', False), ('negative', True)]:
        report = out / (name + '.json')
        command = [sys.executable, str(driver), '--quick', '--runner', args.runner, '--report', str(report)]
        if mutation:
            command.append('--mutate-runner')
        result = subprocess.run(command)
        digest = hashlib.sha256(report.read_bytes()).hexdigest() if report.exists() else None
        receipts.append(dict(name=name, rc=result.returncode, sha256=digest))
        (out / 'verification.json').write_text(json.dumps(receipts, indent=2) + '\n')
    deterministic = (out / 'quick-a.json').read_bytes() == (out / 'quick-b.json').read_bytes()
    negative = json.loads((out / 'negative.json').read_text())
    caught = receipts[2]['rc'] == 1 and negative['new'] > 0
    success = all(row['rc'] == 0 for row in receipts[:2]) and deterministic and caught
    print(f'VERIFY {"PASS" if success else "FAIL"} deterministic={int(deterministic)} mutation_caught={int(caught)}')
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
