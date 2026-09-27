#!/usr/bin/env python3
"""Portable Apple Silicon checks for opt-in scalar FP forwarding."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    base = ROOT / 'build' / 'fp-forwarding-checks'
    base.mkdir(parents=True, exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix='run-', dir=base))
    env = {k: v for k, v in os.environ.items() if not k.startswith('MACRUNNER_HB_')}
    env.update(MACRUNNER_HB_NATIVE_SSE_FP='1', MACRUNNER_HB_STATIC_REGS='0',
               MACRUNNER_HB_DECODED_SOURCE='1', MACRUNNER_HB_CACHE_DIR=str(out / 'cache'))
    receipt = {'sources': {str(p.relative_to(ROOT)): digest(p) for p in
               [ROOT / 'src/hb_arm64_codegen.c', HERE / 'run.py', *sorted(HERE.glob('*.c'))]},
               'commands': []}

    def run(argv, name, timeout=60):
        start = time.monotonic()
        with (out / (name + '.log')).open('wb') as log:
            try:
                rc = subprocess.run(argv, cwd=ROOT, env=env, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=timeout).returncode
            except subprocess.TimeoutExpired:
                rc = 'timeout'
        receipt['commands'].append({'name': name, 'returncode': rc,
                                    'seconds': time.monotonic() - start,
                                    'environment': {k: v for k, v in env.items()
                                                    if k.startswith('MACRUNNER_HB_')}})
        return rc == 0

    ok = run(['make', '-j1', 'libhyperbridge.a'], 'build', 180)
    if ok:
        for name in ['boundary-tests', 'store-tests', 'emission-tests']:
            ok = run(['clang', '-O2', '-Wall', '-Wextra', '-Werror', '-std=c11',
                      '-D_DARWIN_C_SOURCE', '-I' + str(ROOT / 'include'),
                      str(HERE / (name + '.c')), str(ROOT / 'libhyperbridge.a'),
                      '-o', str(out / name)], 'link-' + name)
            if not ok:
                break
    if ok:
        ok = run([str(out / 'boundary-tests')], 'boundary')
        for forced in [0, 1]:
            for fp in [0, 1]:
                for store in [0, 1]:
                    env.update(MACRUNNER_HB_FORCE_LAZY_STORE=str(forced),
                               MACRUNNER_HB_SCALAR_FP_FORWARD=str(fp),
                               MACRUNNER_HB_SCALAR_FP_STORE_FORWARD=str(store))
                    passed = run([str(out / 'store-tests')], f'store-f{forced}-p{fp}-s{store}')
                    ok = ok and passed
        env['MACRUNNER_HB_FORCE_LAZY_STORE'] = '0'
        passed = run([str(out / 'emission-tests')], 'emission')
        ok = ok and passed
    receipt['passed'] = ok and len(receipt['commands']) == 14
    if (ROOT / 'libhyperbridge.a').is_file():
        receipt['archive_sha256'] = digest(ROOT / 'libhyperbridge.a')
    (out / 'RESULT.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'passed': receipt['passed'], 'result': str((out / 'RESULT.json').relative_to(ROOT))}))
    return 0 if receipt['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
