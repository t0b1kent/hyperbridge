#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
"""Build the native runner from the source prepared by fex/build.sh."""
import argparse
import pathlib
import shutil
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]


def run(*command):
    subprocess.run(command, cwd=ROOT, check=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--fex-source', default='build/stand-fex/src')
    ap.add_argument('--build-dir', default='build/stand-native')
    args = ap.parse_args()
    source = (ROOT / args.fex_source).resolve()
    build = (ROOT / args.build_dir).resolve()
    if not (source / 'FEXCore').is_dir():
        ap.error('run bash fex/build.sh build/stand-fex first')
    build.mkdir(parents=True, exist_ok=True)
    native = build / 'src'
    if native.exists():
        ap.error('use a fresh build directory; the adapter never changes the input source')
    # Copy only source directories needed by FEXCore, without git metadata or products.
    native.mkdir()
    for name in ['FEXCore', 'FEXHeaderUtils', 'CodeEmitter', 'External', 'Source']:
        shutil.copytree(source / name, native / name,
                        ignore=shutil.ignore_patterns('.git', '__pycache__', '*.pyc'))
    run('git', '-C', str(native), 'init', '-q')
    run('git', '-C', str(native), 'apply', '--check', str(ROOT / 'stands/synthetic/native-portability.patch'))
    run('git', '-C', str(native), 'apply', str(ROOT / 'stands/synthetic/native-portability.patch'))
    # Match the PE decoder boundary rules without defining _WIN32 on Darwin.
    tables = [
        'FEXCore/Source/Interface/Core/X86Tables/X86Tables.h',
        'FEXCore/Source/Interface/Core/X86Tables/SecondaryTables.cpp',
        'FEXCore/Source/Interface/Core/OpcodeDispatcher/SecondaryTables.h',
    ]
    for relative in tables:
        path = native / relative
        text = path.read_text()
        if 'HB_REPLAY_WIN_TABLES' not in text:
            if '#ifndef _WIN32' not in text:
                raise RuntimeError('decoder adapter anchor absent: ' + relative)
            text = text.replace('#ifndef _WIN32',
                                '#if !defined(_WIN32) && !defined(HB_REPLAY_WIN_TABLES)')
            path.write_text(text)
    command = ['cmake', '-S', 'stand', '-B', str(build / 'cmake'), '-G', 'Ninja',
               '-DFEXSRC=' + str(native), '-DCMAKE_BUILD_TYPE=Release',
               '-DCMAKE_OSX_DEPLOYMENT_TARGET=15.0']
    if shutil.which('ccache'):
        command += ['-DCMAKE_C_COMPILER_LAUNCHER=ccache', '-DCMAKE_CXX_COMPILER_LAUNCHER=ccache']
    run(*command)
    run('cmake', '--build', str(build / 'cmake'), '--target', 'stand_runner', '-j2')
    print('RUNNER=' + str((build / 'cmake/Bin/stand_runner').relative_to(ROOT)))


if __name__ == '__main__':
    main()
