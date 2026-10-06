#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
"""Reject repository paths that cannot be checked out consistently on Windows."""
import argparse
from pathlib import Path
import re
import subprocess

DEVICE = re.compile(r'^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$', re.IGNORECASE)
FORBIDDEN = set('<>:"|?*\\')


def violations(paths):
    problems, spellings = set(), {}
    for path in sorted(set(paths)):
        if len(path.encode('utf-16-le')) // 2 > 240:
            problems.add((path, 'path exceeds 240 UTF-16 characters'))
        parts = path.split('/')
        if not path or path.startswith('/') or any(p in ('', '.', '..') for p in parts):
            problems.add((path, 'not a normalized relative path'))
        for index, part in enumerate(parts):
            if part.endswith((' ', '.')):
                problems.add((path, 'trailing space or dot'))
            if any(c in FORBIDDEN or ord(c) < 32 for c in part):
                problems.add((path, 'forbidden Windows filename character'))
            if DEVICE.fullmatch(part.split('.', 1)[0].rstrip(' ')):
                problems.add((path, 'reserved Windows device name'))
            prefix = '/'.join(parts[:index+1])
            folded = prefix.casefold()
            if folded in spellings and spellings[folded] != prefix:
                problems.add((path, 'case collision with ' + spellings[folded]))
            else:
                spellings[folded] = prefix
    return sorted(problems)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    # NUL separation preserves spaces and Unicode; git's quoted display format
    # is not a filename and must never be used for this check.
    raw = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=args.root)
    paths = [name.decode('utf-8') for name in raw.split(b'\0') if name]
    errors = violations(paths)
    for path, reason in errors[:50]:
        print(f'{path}: {reason}')
    if len(errors) > 50:
        print(f'{len(errors)-50} further violations omitted')
    print(f"PORTABLE_PATHS {'FAIL' if errors else 'PASS'} paths={len(set(paths))} violations={len(errors)}")
    return int(bool(errors))


if __name__ == '__main__':
    raise SystemExit(main())
