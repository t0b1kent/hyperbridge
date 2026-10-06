#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
"""Check the negative patch against the exact prepared candidate, without a build."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
TARGET = Path('FEXCore/Source/Interface/Core/OpcodeDispatcher.cpp')
BEFORE = b'const char* Value = getenv("MACRUNNER_FEX_DIV_OVERFLOW_DE");'
AFTER = b'const char* Value = nullptr; // Deliberately broken translator: suppress overflow #DE.'


def check(source, patch=HERE / 'controls/div-overflow-disabled.patch'):
    source, patch = Path(source).resolve(), Path(patch).resolve()
    original = (source / TARGET).read_bytes()
    if original.count(BEFORE) != 1:
        raise ValueError('negative control requires exactly one overflow-mode switch')
    subprocess.run(['git', 'apply', '--check', str(patch)], cwd=source, check=True)
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / TARGET
        target.parent.mkdir(parents=True)
        target.write_bytes(original)
        subprocess.run(['git', 'apply', str(patch)], cwd=directory, check=True)
        changed = target.read_bytes()
    if changed != original.replace(BEFORE, AFTER, 1):
        raise ValueError('negative control changes more than the overflow switch')
    if (source / TARGET).read_bytes() != original:
        raise ValueError('source-only check unexpectedly modified the candidate')
    digest = lambda value: hashlib.sha256(value).hexdigest()
    return {'status': 'PASS', 'source_sha256': digest(original),
            'mutated_source_sha256': digest(changed), 'patch_sha256': digest(patch.read_bytes()),
            'changed_switches': 1, 'source_unchanged': True, 'build': 'NOT_RUN'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    result = check(args.source)
    payload = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload)
    print(payload, end='')


if __name__ == '__main__':
    main()
