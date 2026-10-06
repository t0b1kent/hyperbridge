#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
"""Native-only runner build using the published preparation and CMake recipes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import subprocess
import sys
import time

import common


def command(argv, **kwargs):
    subprocess.run(argv, cwd=common.ROOT, stdin=subprocess.DEVNULL, check=True, **kwargs)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--candidate', type=Path, required=True)
    p.add_argument('--flavor', choices=['accepted', 'negative'], default='accepted')
    args = p.parse_args()
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        p.error('requires native macOS ARM64')
    spec, _, identity = common.candidate(args.candidate)
    data_id = common.verify_data()
    started = time.monotonic()
    work = common.ROOT / 'build/hardware'
    work.mkdir(parents=True, exist_ok=True)
    if (work / 'fex/src').exists():
        p.error('use a fresh build/hardware/fex source directory')
    env = dict(os.environ, FEX_PREPARE_ONLY='1', CMAKE_BUILD_PARALLEL_LEVEL='2', LC_ALL='C', TZ='UTC')
    command(['bash', 'fex/build.sh', 'build/hardware/fex'], env=env)
    source = work / 'fex/src'
    for patch in spec['patches']:
        command(['git', '-C', str(source), 'apply', '--check', str((args.candidate / patch['file']).resolve())])
        command(['git', '-C', str(source), 'apply', '--index', str((args.candidate / patch['file']).resolve())])
    if args.flavor == 'negative':
        # This is a translator source mutation, not a changed reference or runner output.
        patch = common.HERE / 'controls/div-overflow-disabled.patch'
        command([sys.executable, 'stands/hardware/check_negative.py', '--source', str(source),
                 '--out', 'build/hardware/negative-apply-check.json'])
        command(['git', '-C', str(source), 'apply', '--index', str(patch)])
    native_command = [sys.executable, 'stands/synthetic/build.py', '--fex-source', 'build/hardware/fex/src',
                      '--build-dir', 'build/hardware/native', '--runner-source', 'stands/hardware/runner.cpp', '--hardware-tso']
    if args.flavor == 'accepted':
        native_command.append('--instruction-cost')
    command(native_command, env=env)
    command([sys.executable, 'stands/hardware/assemble.py', '--out', 'build/hardware/cache'], env=env)
    import hwsimd
    hwsimd.CACHE = work / 'cache/simd-code.json.gz'
    hwsimd.known(hwsimd.HERE / 'known-hwsimd.json', hwsimd.TABLE)
    bundle = work / 'bundle'
    bundle.mkdir(exist_ok=False)
    for source_file in [work / 'native/cmake/Bin/stand_runner',
                        work / 'native/cmake/Bin/libmacrunner-hwtso.dylib', hwsimd.CACHE]:
        shutil.copy2(source_file, bundle / source_file.name)
    if args.flavor == 'accepted':
        shutil.copy2(work / 'native/cmake/Bin/codegen_runner', bundle / 'codegen_runner')
    cpu = resource.getrusage(resource.RUSAGE_CHILDREN)
    own_cpu = resource.getrusage(resource.RUSAGE_SELF)
    host = {}
    for key in ['hw.model', 'hw.ncpu', 'hw.physicalcpu', 'hw.memsize', 'machdep.cpu.brand_string']:
        output = subprocess.run(['/usr/sbin/sysctl', '-n', key], capture_output=True, text=True)
        host[key] = output.stdout.strip() if output.returncode == 0 else 'UNAVAILABLE'
    versions = {}
    for name, argv in [('clang', ['/usr/bin/clang', '--version']), ('cmake', ['cmake', '--version']),
                       ('ninja', ['ninja', '--version'])]:
        versions[name] = subprocess.check_output(argv, text=True).splitlines()[0]
    receipt = {'schema': 1, 'candidate_sha256': identity, 'data_sha256': data_id,
               'flavor': args.flavor, 'host': host, 'os': platform.mac_ver()[0],
               'versions': versions, 'seconds': round(time.monotonic() - started, 6),
               'cpu_seconds': {'user': cpu.ru_utime + own_cpu.ru_utime, 'system': cpu.ru_stime + own_cpu.ru_stime},
               'products': {f.name: common.sha(f) for f in bundle.iterdir()},
               'install': 'skipped', 'pe_wow64_build': 'skipped',
               'base_source_commit': subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip(),
               'candidate_source_diff_sha256': hashlib.sha256(subprocess.check_output(['git', '-C', str(source), 'diff', '--cached', '--binary', '--no-ext-diff'])).hexdigest(),
               'frontend_sources': {str(p.relative_to(common.ROOT)): common.sha(p) for p in
                                    [common.HERE / 'runner.cpp', common.HERE / 'OracleRanges.h',
                                     common.ROOT / 'stands/instruction-cost/runner.cpp',
                                     common.ROOT / 'stands/synthetic/build.py', common.ROOT / 'stands/synthetic/CMakeLists.txt',
                                     common.ROOT / 'stands/synthetic/native-portability.patch', common.ROOT / 'fex/build.sh']},
               'published_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=common.ROOT, text=True).strip()}
    if args.flavor == 'negative':
        receipt['negative_patch_sha256'] = common.sha(common.HERE / 'controls/div-overflow-disabled.patch')
    common.write_json(bundle / 'BUILD.json', receipt)
    command(['tar', '-czf', 'build/hardware/runner.tar.gz', '-C', str(bundle), '.'])
    print(f"HB_HARDWARE_BUILD PASS flavor={args.flavor} install=skipped seconds={receipt['seconds']}")


if __name__ == '__main__':
    main()
