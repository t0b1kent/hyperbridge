# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
"""Shared, source-only hardware stand inputs. Never source a candidate shell file."""
import hashlib
import json
import os
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
COUNTS = {'hwflags': {'quick': 2204, 'full': 1624804},
          'hwsimd': {'quick': 3021, 'full': 919405}}


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def fingerprint(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def relative_file(root, name):
    path = Path(name)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        raise ValueError('relative file required')
    resolved = (root / path).resolve()
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
        raise ValueError('missing or escaping input: ' + name)
    return resolved


def candidate(path):
    path = Path(path).resolve()
    if not path.is_relative_to((HERE / 'candidates').resolve()):
        raise ValueError('candidate must be in stands/hardware/candidates')
    spec = json.loads((path / 'candidate.json').read_text())
    if spec.get('schema') != 1:
        raise ValueError('candidate schema must be 1')
    series = {p.name: sha(p) for p in sorted((ROOT / 'fex/patches').glob('*.patch'))}
    if spec['base_series_sha256'] != fingerprint(series):
        raise ValueError('candidate was prepared for a different published patch series')
    patches = spec['patches']
    if len(patches) != len({p['file'] for p in patches}):
        raise ValueError('duplicate candidate patch')
    for patch in patches:
        source = relative_file(path, patch['file'])
        if sha(source) != patch['sha256']:
            raise ValueError('candidate patch SHA drift')
        validate_patch(source.read_text())
    arms_path = relative_file(path, 'arms.json')
    arms = json.loads(arms_path.read_text())
    if set(arms) != {'off', 'on'}:
        raise ValueError('exactly off and on arms required')
    for arm in arms.values():
        validate_environment(arm)
    changed = sorted(k for k in set(arms['off']) | set(arms['on'])
                     if arms['off'].get(k) != arms['on'].get(k))
    if changed != spec['independent_keys'] or len(changed) > 1:
        raise ValueError('declare zero (A/A) or one independent environment key')
    actual_files = {str(p.relative_to(path)) for p in path.rglob('*') if p.is_file()}
    if actual_files != {'candidate.json', 'arms.json'} | {p['file'] for p in patches}:
        raise ValueError('unexpected file in candidate directory')
    identity = {'candidate': spec, 'arms': arms, 'published_series': series}
    return spec, arms, fingerprint(identity)


def validate_environment(env):
    if not isinstance(env, dict) or not env:
        raise ValueError('nonempty environment object required')
    for key, value in env.items():
        # MACRUNNER_HB_ keys belong to the same product environment; the translator reads some of them (x87 paths,
        # the code buffer guard), the rest are inert in the native runner. An arm is the literal product environment.
        if not re.fullmatch(r'(?:MACRUNNER_FEX_|MACRUNNER_HB_|FEX_)[A-Z0-9_]+', key):
            raise ValueError('only translator environment keys are accepted')
        if re.search(r'(PATH|OVERLAY|TOKEN|SECRET|PASSWORD|CREDENTIAL|KEY)', key):
            raise ValueError('path or credential environment key forbidden')
        if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_,.+-]{1,80}', value):
            raise ValueError('environment values must be short literals, without paths')


def validate_patch(text):
    if any(x in text for x in ('/Users/', '/Volumes/', '/home/', 'GIT binary patch',
                                'PRIVATE KEY', 'ghp_', 'github_pat_', 'AKIA')):
        raise ValueError('private path, credential or binary patch marker')
    if re.search(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', text):
        raise ValueError('submit a plain diff without email metadata')
    paths = []
    for line in text.splitlines():
        if line.startswith(('+++ ', '--- ')):
            value = line[4:]
            if value == '/dev/null':
                continue
            if not re.fullmatch(r'[ab]/(?:FEXCore|FEXHeaderUtils|CodeEmitter|Source)/[A-Za-z0-9_./+-]+', value):
                raise ValueError('patch paths must name translator source only')
            if '..' in Path(value).parts:
                raise ValueError('patch path traversal')
            paths.append(value)
        if line.startswith(('new file mode 120', 'new file mode 160', 'rename ', 'copy ')):
            raise ValueError('candidate must contain ordinary source diffs')
    if not paths or not text.startswith('diff --git '):
        raise ValueError('plain git diff required')


def verify_data():
    spec = json.loads((HERE / 'data/MANIFEST.json').read_text())
    actual = {str(p.relative_to(HERE / 'data')) for p in (HERE / 'data').rglob('*')
              if p.is_file() and p.name != 'MANIFEST.json'}
    if actual != set(spec['files']):
        raise ValueError('hardware data file set drift')
    for name, record in spec['files'].items():
        path = relative_file(HERE / 'data', name)
        if path.stat().st_size != record['bytes'] or sha(path) != record['sha256']:
            raise ValueError('hardware data drift: ' + name)
    return fingerprint(spec)


def runner_environment(arm, home):
    validate_environment(arm)
    home.mkdir(parents=True, exist_ok=True)
    return {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(home.resolve()),
            'LC_ALL': 'C', 'TZ': 'UTC', **arm}


def semantic_key(record):
    name, number = record['key'].rsplit(':', 1)
    return name, int(number)


def semantic_bytes(component, record):
    if component == 'hwsimd':
        record = {'key': record['key'], 'comparison': record['comparison']}
    return canonical(record) + b'\n'
