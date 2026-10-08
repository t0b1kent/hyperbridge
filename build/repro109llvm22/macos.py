#!/usr/bin/env python3
"""Cloud-only macOS LLVM22 producer. Windows smoke outputs are never executed."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys
import tarfile
import time
import urllib.request

HERE = Path(__file__).resolve().parent
ARCHES = {'aarch64': 0xaa64, 'arm64ec': 0xa641, 'x86_64': 0x8664, 'i686': 0x14c}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cloud_gate(lock):
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and
            os.environ.get('GITHUB_REPOSITORY') == 't0b1kent/hyperbridge',
            'Owned GitHub cloud only; no local downloads or native tool execution')
    require(platform.system() == 'Darwin' and platform.machine() == lock['host']['machine'],
            'macOS ARM64 host required')
    require(platform.python_version() == lock['host']['python'], 'Pinned Python required')


def validate_dependencies(lock):
    for row in lock['local_dependencies']:
        path = HERE / row['path']
        require(path.is_file() and not path.is_symlink() and
                path.stat().st_size == row['bytes'] and sha(path) == row['sha256'],
                'Accepted LLVM recipe dependency differs: ' + row['path'])
    safety = HERE.parent / 'repro109fex/support/archive_safety.py'
    require(sha(safety) == lock['archive_safety_sha256'], 'Accepted archive safety differs')
    return load('macos_archive_safety', safety)


def fetch(row, path, deadline):
    url = row.get('url', row.get('source_url'))
    require(url.startswith('https://github.com/') and any(url.startswith(prefix) for prefix in [
        'https://github.com/llvm/llvm-project/releases/download/llvmorg-22.1.5/',
        'https://github.com/mstorsjo/llvm-mingw/releases/download/20260505/',
        'https://github.com/Kitware/CMake/releases/download/v4.3.2/',
        'https://github.com/ninja-build/ninja/archive/refs/tags/v1.13.2.']),
        'Foreign publisher/version refused')
    expected_size = row.get('bytes', row.get('source_bytes'))
    maximum = expected_size if expected_size is not None else 200 * 1024 * 1024
    request = urllib.request.Request(url, headers={'User-Agent': 'MacRunner-REPRO109'})
    with urllib.request.urlopen(request, timeout=60) as response, path.open('xb') as stream:
        total = 0
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            require(total <= maximum and time.monotonic() < deadline, 'Download cap/deadline exceeded')
            stream.write(block)
    expected_sha = row.get('sha256', row.get('source_sha256'))
    require(sha(path) == expected_sha and (expected_size is None or path.stat().st_size == expected_size),
            'Official archive bytes differ')
    return {'url': url, 'bytes': path.stat().st_size, 'sha256': sha(path)}


def extract(archive, destination, safety, expected_root=None):
    require(not destination.exists() and not destination.is_symlink(), 'Fresh extraction required')
    with tarfile.open(archive) as stream:
        members = stream.getmembers()
        safety.validate_tar(members)
        roots = {Path(member.name).parts[0] for member in members}
        require(len(roots) == 1 and (expected_root is None or roots == {expected_root}),
                'Archive root differs')
        stream.extractall(destination, members=members, filter='data')
    return destination / next(iter(roots))


def compiler_plan(source, build, tools, cc, cxx, sdk, lock):
    return [str(tools / 'cmake'), '-S', str(source / 'llvm'), '-B', str(build), '-G', 'Ninja',
            '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_C_COMPILER=' + str(cc),
            '-DCMAKE_CXX_COMPILER=' + str(cxx), '-DCMAKE_MAKE_PROGRAM=' + str(tools / 'ninja'),
            '-DCMAKE_OSX_ARCHITECTURES=arm64', '-DCMAKE_OSX_SYSROOT=' + str(sdk),
            '-DCMAKE_OSX_DEPLOYMENT_TARGET=' + lock['host']['deployment_target'],
            '-DBUILD_SHARED_LIBS=OFF', '-DLLVM_BUILD_LLVM_DYLIB=OFF', '-DLLVM_LINK_LLVM_DYLIB=OFF',
            '-DLLVM_ENABLE_PROJECTS=clang;lld', '-DLLVM_ENABLE_RUNTIMES=',
            '-DLLVM_TARGETS_TO_BUILD=AArch64;X86', '-DLLVM_ENABLE_EH=ON', '-DLLVM_ENABLE_RTTI=ON',
            '-DLLVM_ENABLE_THREADS=ON', '-DLLVM_ENABLE_FFI=OFF', '-DLLVM_ENABLE_ZLIB=OFF',
            '-DLLVM_ENABLE_ZSTD=OFF', '-DLLVM_ENABLE_LIBXML2=OFF', '-DLLVM_ENABLE_TERMINFO=OFF',
            '-DLLVM_ENABLE_LIBCXX=OFF', '-DLLVM_INCLUDE_TESTS=ON', '-DLLVM_INCLUDE_EXAMPLES=OFF',
            '-DLLVM_INCLUDE_BENCHMARKS=OFF', '-DLLVM_INCLUDE_DOCS=OFF',
            '-DLLVM_ENABLE_ASSERTIONS=ON', '-DLLVM_ENABLE_WERROR=OFF', '-DLLVM_BUILD_TOOLS=ON',
            '-DLLVM_PARALLEL_LINK_JOBS=' + str(lock['parallel_link']),
            '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON']


def macho_arm64(path):
    with path.open('rb') as stream:
        header = stream.read(12)
    require(len(header) == 12 and struct.unpack('<I', header[:4])[0] == 0xfeedfacf and
            struct.unpack('<I', header[4:8])[0] == 0x100000c, 'Source-built tool is not native ARM64 Mach-O')


def machine(path, pe=False):
    with path.open('rb') as stream:
        if pe:
            require(stream.read(2) == b'MZ', 'PE DOS header missing')
            stream.seek(0x3c)
            offset = struct.unpack('<I', stream.read(4))[0]
            require(0x40 <= offset <= path.stat().st_size - 6, 'PE header offset invalid')
            stream.seek(offset)
            require(stream.read(4) == b'PE\0\0', 'PE signature missing')
        else:
            stream.seek(0)
        return struct.unpack('<H', stream.read(2))[0]


def selected_interfaces(bundle):
    names = ['clang', 'ld.lld'] + [f'{arch}-w64-mingw32-{suffix}'
        for arch in ARCHES for suffix in ['gcc', 'g++']]
    selected = []
    for name in names:
        path = bundle / 'bin' / name
        require(path.is_file() and path.resolve().is_relative_to(bundle.resolve()),
                'Compiler command missing/foreign: ' + name)
        selected.append({'name': name, 'resolved': str(path.resolve().relative_to(bundle)),
                         'sha256': sha(path)})
    return selected


def bootstrap_inputs(root, out, lock, safety, deadline, result):
    archive = root / 'llvm-mingw.tar.xz'
    result['bootstrap'] = fetch(lock['bootstrap'], archive, deadline)
    bundle = extract(archive, root / 'bootstrap', safety, lock['bootstrap']['root'])
    wrapper = bundle / 'bin/clang-target-wrapper.sh'
    require(sha(wrapper) == lock['bootstrap']['wrapper_sha256'], 'Pinned shell wrapper differs')
    for arch in ARCHES:
        require((bundle / (arch + '-w64-mingw32')).is_dir(), 'Required target sysroot missing: ' + arch)
        for suffix in ['gcc', 'g++']:
            path = bundle / 'bin' / (arch + '-w64-mingw32-' + suffix)
            require(path.is_symlink() and path.readlink() == Path('clang-target-wrapper.sh'),
                    'Target command must use accepted source shell wrapper')
    result['bootstrap']['selected'] = selected_interfaces(bundle)
    return bundle


def prepare_source(root, out, lock, safety, deadline, result, command, shared, reuse):
    llvm = lock['llvm']
    archive = root / 'llvm-source.tar.xz'
    result['source_archive'] = fetch(llvm, archive, deadline)
    source = extract(archive, root / 'source', safety, llvm['source_root'])
    require(all((source / (name + '/CMakeLists.txt')).is_file() for name in ['llvm', 'clang', 'lld']),
            'LLVM/Clang/LLD source family incomplete')
    require((source / 'LICENSE.TXT').is_file(), 'LLVM source license missing')
    manifest = json.loads((HERE / 'SOURCE-MANIFEST.json').read_text())
    for row in manifest['files']:
        path = source / row['path']
        require((not path.exists()) if row['base_sha256'] is None else
                path.is_file() and sha(path) == row['base_sha256'], 'Source preimage differs: ' + row['path'])
    for action, name in [(['--check'], 'patch-check'), (['--whitespace=nowarn'], 'patch-apply')]:
        command(['git', 'apply'] + action + [str(HERE / 'LLVM22-ARM64EC-Q-RESTORES.patch')], name, cwd=source)
    for row in manifest['files']:
        require(sha(source / row['path']) == row['patched_sha256'], 'Patched source differs: ' + row['path'])
    result['patched_files'] = manifest['files']
    test = source / 'llvm/test/CodeGen/AArch64/arm64ec-split-thunk-q-restores.ll'
    result['primary_test_run_adjustment'] = reuse.fix_primary_test_stdout(test)
    for row in shared.extra_test_rows(llvm):
        path = HERE / row['file']
        require(path.stat().st_size == row['bytes'] and sha(path) == row['sha256'], 'Extra test pin differs')
        target = test.parent / row['file']
        require(not target.exists(), 'Extra test would overwrite upstream')
        shutil.copy2(path, target)
    for row in llvm['support_inputs']:
        path = test.parent / row['file']
        require(path.stat().st_size == row['bytes'] and sha(path) == row['sha256'], 'Support input pin differs')
    return source, test


def build_tools(root, out, lock, safety, deadline, result, command):
    prefix = root / 'tools'
    prefix.mkdir()
    result['build_tools'] = []
    for row in lock['tools']:
        archive = root / (row['name'] + '.archive')
        record = fetch(row, archive, deadline)
        source = extract(archive, root / (row['name'] + '-source'), safety)
        if row['name'] == 'cmake':
            command([str(source / 'bootstrap'), '--prefix=' + str(prefix),
                     '--parallel=' + str(lock['parallel_compile']), '--no-system-libs',
                     '--system-zlib', '--system-bzip2', '--system-curl', '--',
                     '-DCMAKE_IGNORE_PREFIX_PATH=/opt/homebrew;/usr/local'], 'cmake-bootstrap', cwd=source)
            command(['make', '-j' + str(lock['parallel_compile'])], 'cmake-build', cwd=source)
            command(['make', 'install'], 'cmake-install', cwd=source)
        else:
            command([sys.executable, 'configure.py', '--bootstrap', '--verbose',
                     '--with-python=' + sys.executable], 'ninja-bootstrap', cwd=source)
            (prefix / 'bin').mkdir(exist_ok=True)
            shutil.copy2(source / 'ninja', prefix / 'bin/ninja')
        tool = prefix / 'bin' / row['name']
        command([str(tool), '--version'], row['name'] + '-version')
        require(row['version'] in (out / (row['name'] + '-version.log')).read_text(),
                'Source-built build tool version differs')
        result['build_tools'].append(dict(record, name=row['name'], version=row['version'], tool_sha256=sha(tool)))
    return prefix / 'bin'


def assemble(bootstrap, built, root, lock):
    bundle = root / lock['package_root']
    require(not bundle.exists(), 'Fresh package required')
    shutil.copytree(bootstrap, bundle, symlinks=True)
    replaced = []
    for name in lock['build_targets']:
        source = built / name
        require(source.is_file() and source.resolve().is_relative_to(built.resolve()),
                'Source-built tool missing/foreign: ' + name)
        macho_arm64(source)
        destination = bundle / 'bin' / ('clang-22' if name == 'clang' else name)
        if destination.exists() or destination.is_symlink():
            destination.unlink()
        shutil.copy2(source.resolve(), destination)
        replaced.append(str(destination.relative_to(bundle)))
    for alias, target in [('clang', 'clang-22'), ('ld.lld', 'lld')]:
        path = bundle / 'bin' / alias
        if path.exists() or path.is_symlink():
            path.unlink()
        path.symlink_to(target)
    require(sha(bundle / 'bin/clang-target-wrapper.sh') == lock['bootstrap']['wrapper_sha256'],
            'Wrapper drift during composition')
    return bundle, replaced


def smoke(bundle, out, root, command, result):
    result['interfaces'] = selected_interfaces(bundle)
    c = root / 'smoke.c'
    cpp = root / 'smoke.cpp'
    c.write_text('#include <windows.h>\n#include <stdlib.h>\nint main(void) { return GetCurrentProcessId() == 0; }\n')
    cpp.write_text('#include <cstdio>\nint main() { return std::puts("compiler smoke") < 0; }\n')
    result['target_smokes'] = []
    for arch, expected in ARCHES.items():
        for suffix, source in [('gcc', c), ('g++', cpp)]:
            name = arch + '-' + suffix
            compiler = bundle / 'bin' / (arch + '-w64-mingw32-' + suffix)
            obj, exe = out / (name + '.o'), out / (name + '.exe')
            command([str(compiler), '-O2', '-c', str(source), '-o', str(obj)], name + '-compile')
            require(machine(obj) == expected, 'COFF target differs: ' + name)
            command([str(compiler), str(obj), '-o', str(exe)], name + '-link')
            accepted = [0x8664, 0xa641] if arch == 'arm64ec' else [expected]
            require(machine(exe, pe=True) in accepted, 'PE target differs: ' + name)
            command([str(bundle / 'bin/llvm-readobj'), '--file-headers', '--coff-load-config', str(exe)],
                    name + '-readobj')
            result['target_smokes'].append({'arch': arch, 'language': suffix, 'coff_machine': machine(obj),
                'pe_machine': machine(exe, pe=True), 'object_sha256': sha(obj), 'exe_sha256': sha(exe),
                'target_execution': 'NOT_ENABLED'})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--phase', choices=['llvm-source', 'sysroots', 'build-tools', 'full'], required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    lock = json.loads((HERE / 'macos.lock.json').read_text())
    cloud_gate(lock)  # Before writes, subprocesses, third-party downloads or execution.
    safety = validate_dependencies(lock)
    shared = load('macos_shared_llvm', HERE / 'run.py')
    reuse = load('macos_accepted_reuse', HERE / 'reuse.py')
    out = args.out.resolve()
    require(not out.exists() and not out.is_symlink(), 'Fresh output required')
    out.mkdir(parents=True)
    root = Path(os.environ['RUNNER_TEMP']) / ('repro109-llvm22-macos-' + args.phase)
    records = []
    deadline = time.monotonic() + (lock['minutes'] if args.phase == 'full' else lock['preflight_minutes']) * 60
    result = {'schema': 1, 'phase': args.phase, 'status': 'STARTED',
              'classification': 'SOURCE_BUILD_NOT_PRODUCT_ACCEPTANCE',
              'started_utc': datetime.now(timezone.utc).isoformat(), 'first_failure': None,
              'lock_sha256': sha(HERE / 'macos.lock.json'), 'install': 'SKIPPED',
              'games': 'NOT_ENABLED', 'wine': 'NOT_ENABLED', 'stands': 'NOT_ENABLED',
              'signing': 'NOT_ENABLED', 'notarization': 'NOT_ENABLED',
              'producer': {key: os.environ['GITHUB_' + variable] for key, variable in
                           [('repository', 'REPOSITORY'), ('revision', 'SHA'), ('run_id', 'RUN_ID')]}}
    stage = 'HOST_PREFLIGHT'
    host_env = {}
    def command(argv, name, cwd=root, timeout=3600):
        routed = ['/usr/bin/env'] + [key + '=' + value for key, value in host_env.items()] + list(argv)
        shared.command(routed, out / (name + '.log'), cwd, deadline, records,
                       lock['llvm']['command_log_cap_bytes'], timeout_seconds=timeout)
    try:
        require(not root.exists() and not root.is_symlink(), 'Fresh owned work root required')
        root.mkdir()
        require(shutil.disk_usage(root).free >= lock['minimum_free_disk_bytes'], 'Insufficient cloud disk')
        host_env['DEVELOPER_DIR'] = lock['host']['developer_dir']
        command(['xcodebuild', '-version'], 'xcode-version')
        version = (out / 'xcode-version.log').read_text().strip().splitlines()
        require(version == ['Xcode ' + lock['host']['xcode'], 'Build version ' + lock['host']['xcode_build']],
                'Exact Xcode build differs')
        command(['xcrun', '--sdk', 'macosx', '--show-sdk-version'], 'sdk-version')
        require((out / 'sdk-version.log').read_text().strip() == lock['host']['sdk'], 'Exact SDK differs')
        for flag, name in [('--show-sdk-path', 'sdk-path'), ('--find', 'clang-path')]:
            argv = ['xcrun', '--sdk', 'macosx', flag] + (['clang'] if flag == '--find' else [])
            command(argv, name)
        sdk = Path((out / 'sdk-path.log').read_text().strip())
        cc = Path((out / 'clang-path.log').read_text().strip())
        cxx = cc.with_name('clang++')
        require(sdk.is_dir() and cc.is_file() and cxx.is_file(), 'Owned Xcode tools missing')
        host_env.update(SDKROOT=str(sdk), MACOSX_DEPLOYMENT_TARGET=lock['host']['deployment_target'],
                        CC=str(cc), CXX=str(cxx))
        command(['sysctl', '-n', 'hw.memsize'], 'memory')
        memory = int((out / 'memory.log').read_text().strip())
        require(memory >= lock['minimum_memory_bytes'], 'Insufficient physical memory')
        command([str(cc), '--version'], 'apple-clang-version')
        result['host'] = {'machine': platform.machine(), 'physical_memory_bytes': memory,
                          'free_disk_bytes': shutil.disk_usage(root).free, 'xcode': version,
                          'sdk': lock['host']['sdk'], 'deployment_target': lock['host']['deployment_target']}
        if args.phase in ['llvm-source', 'full']:
            stage = 'LLVM_SOURCE_PATCH_FULL_TEST_INPUTS'
            source, test = prepare_source(root, out, lock, safety, deadline, result, command, shared, reuse)
        if args.phase in ['sysroots', 'full']:
            stage = 'PINNED_SYSROOTS_WRAPPERS_RUNTIME'
            bootstrap = bootstrap_inputs(root, out, lock, safety, deadline, result)
            if args.phase == 'sysroots':
                stage = 'BOOTSTRAP_FOUR_TARGET_C_CPP_COMPILE_LINK'
                smoke(bootstrap, out, root, command, result)
        if args.phase in ['build-tools', 'full']:
            stage = 'SOURCE_BUILT_CMAKE_NINJA'
            tools = build_tools(root, out, lock, safety, deadline, result, command)
        if args.phase != 'full':
            result['status'] = 'PASS_PREFLIGHT_NOT_PRODUCT_ACCEPTANCE'
            return
        stage = 'CONFIGURE_NATIVE_AARCH64_X86'
        build = root / 'build'
        command(compiler_plan(source, build, tools, cc, cxx, sdk, lock), 'configure')
        cache = (build / 'CMakeCache.txt').read_text()
        require('CMAKE_HOME_DIRECTORY:INTERNAL=' + str(source / 'llvm') in cache and
                'LLVM_TARGETS_TO_BUILD:STRING=AArch64;X86' in cache and
                'LLVM_ENABLE_PROJECTS:STRING=clang;lld' in cache,
                'Foreign source or backend/project family in CMake cache')
        shutil.copy2(build / 'CMakeCache.txt', out / 'CMakeCache.txt')
        shutil.copy2(build / 'compile_commands.json', out / 'compile_commands.json')
        stage = 'SOURCE_BUILD_NATIVE_COMPILER_TOOL_FAMILY'
        command([str(tools / 'cmake'), '--build', str(build), '--parallel',
                 str(lock['parallel_compile']), '--target'] + lock['build_targets'],
                'build', timeout=lock['build_minutes'] * 60)
        stage = 'COMPOSE_PINNED_SYSROOT_COMPILER_PACKAGE'
        bundle, replaced = assemble(bootstrap, build / 'bin', root, lock)
        shutil.copy2(source / 'LICENSE.TXT', bundle / 'LLVM22-LICENSE.TXT')
        stage = 'REAL_NATIVE_44_RUNS_AND_SYNTHETIC_ASSEMBLY'
        for phase in ['level4-test', 'synthetic-asm']:
            shared.run_checks(phase, bundle / 'bin', test, out, root, deadline, records, lock['llvm'], result)
        stage = 'FOUR_TARGET_C_CPP_COMPILE_LINK'
        smoke(bundle, out, root, command, result)
        result['source_built_tools'] = replaced
        result['bootstrap_retention'] = 'Official pinned sysroots/runtime/headers/wrappers and other auxiliary files'
        inventory = []
        for path in sorted(bundle.rglob('*')):
            relative = str(path.relative_to(bundle))
            if path.is_symlink():
                inventory.append({'path': relative, 'kind': 'symlink', 'target': str(path.readlink())})
            elif path.is_file():
                inventory.append({'path': relative, 'kind': 'file', 'bytes': path.stat().st_size,
                    'sha256': sha(path), 'origin': 'LLVM22_SOURCE_BUILD' if relative in replaced
                    else 'PINNED_OFFICIAL_LLVM_MINGW' if relative != 'LLVM22-LICENSE.TXT' else 'LLVM22_SOURCE_LICENSE'})
        provenance = {'schema': 1, 'producer': result['producer'], 'lock_sha256': result['lock_sha256'],
                      'llvm_source': result['source_archive'], 'bootstrap': result['bootstrap'],
                      'source_built_tools': replaced, 'interfaces': result['interfaces'], 'inventory': inventory,
                      'scope': lock['scope']}
        (bundle / 'COMPILER.json').write_text(json.dumps(provenance, indent=2) + '\n')
        shutil.copy2(bundle / 'COMPILER.json', out / 'COMPILER.json')
        stage = 'EXPORT_NEW_IMMUTABLE_COMPILER'
        archive = out / (lock['package_root'] + '.tar.xz')
        with tarfile.open(archive, 'w:xz', preset=6) as stream:
            stream.add(bundle, arcname=lock['package_root'])
        require(archive.stat().st_size <= lock['archive_max_bytes'], 'Compiler export cap exceeded')
        (out / (archive.name + '.sha256')).write_text(sha(archive) + '  ' + archive.name + '\n')
        result['compiler'] = {'root': lock['package_root'], 'archive': archive.name,
            'bytes': archive.stat().st_size, 'sha256': sha(archive), 'required_interfaces': len(result['interfaces']),
            'source_built_tool_count': len(replaced), 'provenance_sha256': sha(out / 'COMPILER.json'),
            'wine_consumer': 'NEW_PIN_REQUIRED; existing official-compiler SHA/root guard remains unchanged'}
        result['status'] = 'PASS_COMPILER_BOUNDARY_NOT_PRODUCT_ACCEPTANCE'
    except Exception as error:
        result.update(status='FAILED', first_failure={'stage': stage, 'type': type(error).__name__, 'message': str(error)})
        raise
    finally:
        result['commands'] = records
        result['ended_utc'] = datetime.now(timezone.utc).isoformat()
        (out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
