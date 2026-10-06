#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
"""Native Intel/AMD capture: original instruction probes, two byte-identical runs."""
import argparse
import difflib
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

from windows_adapter import adapt

HERE = Path(__file__).resolve().parent
CLASSES = ['shifts', 'rotates', 'double', 'multiply', 'divide', 'bitscan', 'bittest', 'logic', 'misc', '09-bmi']
EXPECTED = 1624804


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for b in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def save(path, obj):
    path.write_text(json.dumps(obj, sort_keys=True, indent=2) + '\n')


def probe(argv, work, out, cls, repeat, timeout):
    # Keep the live raw file in the uploaded directory. If the job itself is
    # killed, the checkpoint names this unfinished evidence explicitly.
    raw = out / f'partial-{cls}-{repeat}.txt'
    log = out / (cls + '-' + repeat + '.log')
    started = time.monotonic()
    expired, rc = False, None
    with raw.open('wb') as stdout, log.open('wb') as stderr:
        try:
            rc = subprocess.run(argv, cwd=work, stdout=stdout, stderr=stderr, timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            expired = True  # subprocess.run has terminated and waited for this child
    rows, skips = 0, 0
    with raw.open('rb') as stream:
        for line in stream:
            rows += bool(line.strip() and not line.startswith(b'#'))
            skips += line.startswith(b'# SKIP')
    target = out / f'out-{cls}-{repeat}.txt.gz'
    with raw.open('rb') as source, target.open('wb') as dest:
        with gzip.GzipFile(filename='', fileobj=dest, mode='wb', compresslevel=1, mtime=0) as compressed:
            shutil.copyfileobj(source, compressed)
    result = {'repeat': repeat, 'rc': rc, 'rows': rows, 'skipped_forms': skips,
              'raw_sha256': sha(raw), 'gzip_sha256': sha(target), 'file': target.name,
              'capture_state': 'PROCESS_GONE' if expired else ('PRESENT' if rc == 0 else 'FAILED'),
              'timed_out': expired, 'seconds': round(time.monotonic() - started, 6)}
    raw.unlink()  # byte-exact gzip is now preserved, including on a timeout
    return result


def capture(compiler, work, out):
    out.mkdir(parents=True, exist_ok=False)
    result = {'status': 'RUNNING', 'scope': 'native x86-64 authored integer/undefined-flags probes',
              'tables': {}, 'timeline': [], 'budget_seconds': 1440}
    start = time.monotonic()

    def timeout(limit):
        remaining = result['budget_seconds'] - (time.monotonic() - start)
        if remaining <= 0:
            raise TimeoutError('24-minute capture budget exhausted; preserve evidence before job timeout')
        return min(limit, remaining)

    def checkpoint(phase, state='RUNNING'):
        result['phase'] = phase
        result['seconds'] = round(time.monotonic() - start, 6)
        result['timeline'].append({'utc': datetime.now(timezone.utc).isoformat(),
                                   'elapsed_seconds': result['seconds'], 'phase': phase, 'state': state})
        save(out / 'RESULT.json', result)
        print(f"HB_VENDOR_PHASE {phase} {state} seconds={result['seconds']}", flush=True)

    checkpoint('prepare')
    try:
        if platform.machine().lower() not in ('amd64', 'x86_64'):
            raise ValueError('native x86-64 host required')
        work.mkdir(parents=True, exist_ok=False)
        original = {p.name: sha(p) for p in (HERE / 'probes').iterdir() if p.is_file()}
        for path in (HERE / 'probes').iterdir():
            if path.is_file():
                shutil.copy2(path, work / path.name)
        # Match the already exercised Windows exception stand's compiler/link recipe.
        compiler_flags = ['-static', '-fno-stack-protector'] if platform.system() == 'Windows' else []
        result['source_sha256'] = original
        with (out / 'build.log').open('wb') as log:
            def build(argv):
                phase = 'build:' + Path(argv[-1]).name
                checkpoint(phase)
                subprocess.run(argv, cwd=work, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=timeout(300))
                checkpoint(phase, 'PRESENT')
            # Identify the actual CPU before any expensive generated probe build.
            build([compiler, *compiler_flags, '-O2', str(HERE / 'cpuid.c'), '-o', 'cpuid.exe'])
            result['machine'] = json.loads(subprocess.check_output([str(work / 'cpuid.exe')], text=True, timeout=timeout(10)))
            result['machine']['os'] = platform.system() + ' ' + platform.release()
            result['machine']['compiler'] = subprocess.check_output([compiler, '--version'], text=True, timeout=timeout(10)).splitlines()[0]
            result['cpuid_sha256'] = sha(work / 'cpuid.exe')
            checkpoint('cpuid', 'PRESENT')
            if result['machine']['vendor'] not in ('GenuineIntel', 'AuthenticAMD'):
                raise ValueError('Intel/AMD CPUID vendor required')
            build([sys.executable, 'generate_core.py'])
            before = {p: (work / p).read_text() for p in ['core.c', 'build/core.S']}
            if platform.system() == 'Windows':
                result['adapter'] = adapt(work)
                diff = ''.join(line for p, text in before.items() for line in
                               difflib.unified_diff(text.splitlines(True), (work / p).read_text().splitlines(True), fromfile='original/' + p, tofile='windows/' + p))
                (out / 'windows-adapter.patch').write_text(diff)
            build([compiler, *compiler_flags, '-O2', '-std=gnu11', '-fno-strict-aliasing', 'core.c', 'build/core.S', '-o', 'core.exe'])
            build([compiler, *compiler_flags, '-O2', '-mno-red-zone', 'bmi.c', '-o', 'bmi.exe'])
        result['products_sha256'] = {p.name: sha(p) for p in work.glob('*.exe')}
        total = 0
        for cls in CLASSES:
            measurements = []
            result['tables'][cls] = measurements
            for repeat in ['first', 'second']:
                argv = [str(work / ('bmi.exe' if cls == '09-bmi' else 'core.exe'))]
                if cls != '09-bmi':
                    argv.append(cls)
                phase = 'capture:' + cls + ':' + repeat
                checkpoint(phase)
                measured = probe(argv, work, out, cls, repeat, timeout(120))
                measurements.append(measured)
                checkpoint(phase, measured['capture_state'])
                if measured['timed_out']:
                    raise TimeoutError('native probe timed out: ' + phase)
            a, b = measurements
            if a['rc'] or b['rc'] or a['skipped_forms'] or b['skipped_forms'] or not a['rows'] or a['raw_sha256'] != b['raw_sha256']:
                raise ValueError('failed/incomplete/nondeterministic capture: ' + cls)
            total += a['rows']
        result['checked'] = total
        if total != EXPECTED:
            raise ValueError('hardware row coverage mismatch')
        if original != {p.name: sha(p) for p in (HERE / 'probes').iterdir() if p.is_file()}:
            raise ValueError('probe source drift')
        result['status'] = 'PASS'
    except Exception as error:
        result['status'] = 'FAIL'
        result['error'] = type(error).__name__ + ': ' + str(error)
    result['seconds'] = round(time.monotonic() - start, 6)
    save(out / 'RESULT.json', result)
    print('HB_VENDOR_CAPTURE ' + result['status'] + ' ' + json.dumps(result.get('machine', {}), sort_keys=True))
    return int(result['status'] != 'PASS')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--compiler', required=True)
    p.add_argument('--work', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    raise SystemExit(capture(a.compiler, a.work.resolve(), a.out.resolve()))
