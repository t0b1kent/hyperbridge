"""Four bounded cloud probes of LEVEL4's pinned LLVM22 patch; no Wine runtime."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import urllib.request

HERE = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def cloud_gate():
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and
            os.environ.get('GITHUB_REPOSITORY') == 't0b1kent/hyperbridge', 'Owned GitHub cloud only')
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'Linux x86-64 host required')
    require(sys.version_info[:3] == (3, 13, 7), 'Pinned Python 3.13.7 required')


def cmake_args(source, build, cc, cxx):
    # Static closure and source ownership follow accepted LLVM recipe 37567821557.
    return ['cmake', '-S', str(source / 'llvm'), '-B', str(build), '-G', 'Ninja',
            '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_C_COMPILER=' + cc, '-DCMAKE_CXX_COMPILER=' + cxx,
            '-DBUILD_SHARED_LIBS=OFF', '-DLLVM_BUILD_LLVM_DYLIB=OFF', '-DLLVM_LINK_LLVM_DYLIB=OFF',
            '-DLLVM_ENABLE_PROJECTS=clang', '-DLLVM_ENABLE_RUNTIMES=', '-DLLVM_TARGETS_TO_BUILD=AArch64',
            '-DLLVM_ENABLE_EH=ON', '-DLLVM_ENABLE_RTTI=ON', '-DLLVM_ENABLE_THREADS=ON',
            '-DLLVM_ENABLE_FFI=OFF', '-DLLVM_ENABLE_ZLIB=OFF', '-DLLVM_ENABLE_ZSTD=OFF',
            '-DLLVM_ENABLE_LIBXML2=OFF', '-DLLVM_ENABLE_TERMINFO=OFF', '-DLLVM_ENABLE_LIBCXX=OFF',
            '-DLLVM_INCLUDE_TESTS=ON', '-DLLVM_INCLUDE_EXAMPLES=OFF', '-DLLVM_INCLUDE_BENCHMARKS=OFF',
            '-DLLVM_INCLUDE_DOCS=OFF', '-DLLVM_ENABLE_ASSERTIONS=ON', '-DLLVM_ENABLE_WERROR=OFF',
            '-DLLVM_BUILD_TOOLS=ON', '-DLLVM_PARALLEL_LINK_JOBS=1', '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON']


def asm_counts(text):
    return {'ldp_q': len(re.findall(r'^\s*ldp\s+q\d+\s*,\s*q\d+\b', text, re.M | re.I)),
            'ldr_q': len(re.findall(r'^\s*ldr\s+q\d+\b', text, re.M | re.I)),
            'stp_q': len(re.findall(r'^\s*stp\s+q\d+\s*,\s*q\d+\b', text, re.M | re.I)),
            'scope': 'ENTIRE_PRESERVED_ASSEMBLY_FILE_NOT_RUNTIME_COUNTS'}


def entry_thunk_counts(text):
    rows, active = {}, None
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        start = re.match(r'^\s*\.seh_proc\s+("[^"]+"|[^\s]+)\s*$', line)
        if start:
            require(active is None, 'Nested assembly procedure')
            active = (start.group(1).strip('"'), index)
        elif re.match(r'^\s*\.seh_endproc\s*$', line):
            require(active is not None, 'Unmatched assembly procedure end')
            name, begin = active
            if name.startswith('$ientry_thunk$'):
                require(name not in rows, 'Duplicate ARM64EC entry thunk')
                body = ''.join(lines[begin:index + 1])
                count = asm_counts(body)
                count.update(scope='ARM64EC_ENTRY_SEH_PROC_NOT_RUNTIME_COUNTS',
                             first_line=begin + 1, last_line=index + 1,
                             body_sha256=hashlib.sha256(body.encode()).hexdigest(),
                             instructions=len(re.findall(r'^\s*[a-z][a-z0-9.]*(?:\s+|$)', body, re.M | re.I)))
                rows[name] = count
            active = None
    require(active is None, 'Unterminated assembly procedure')
    require(bool(rows), 'No ARM64EC entry procedures; counts unavailable')
    return rows


def compare_entries(before, after):
    require(set(before) == set(after), 'ARM64EC entry set differs before/after')
    return {name: {'before': [before[name][key] for key in ('ldp_q', 'ldr_q', 'stp_q')],
                   'after': [after[name][key] for key in ('ldp_q', 'ldr_q', 'stp_q')],
                   'level4_q_restore_shape_matches':
                   [before[name][key] for key in ('ldp_q', 'ldr_q', 'stp_q')] == [5, 0, 5] and
                   [after[name][key] for key in ('ldp_q', 'ldr_q', 'stp_q')] == [0, 10, 5]}
            for name in before}


def run_lines(text, source, temporary):
    lines = [line.split('RUN:', 1)[1].strip() for line in text.splitlines() if re.match(r'^;\s*RUN:', line)]
    require(len(lines) == 17 and all(not line.endswith('\\') for line in lines), 'Pinned LEVEL4 RUN list differs')
    result = []
    for line in lines:
        require(not re.search(r'%(?![sSt])', line), 'Unsupported test substitution')
        result.append(line.replace('%S', shlex.quote(str(source.parent)))
                      .replace('%s', shlex.quote(str(source))).replace('%t', shlex.quote(str(temporary))))
    return result


def command(argv, log, cwd, deadline, records, cap, extra_path=None):
    env = {key: os.environ[key] for key in ['PATH', 'LANG', 'LC_ALL', 'TMPDIR'] if key in os.environ}
    env['LC_ALL'] = 'C'
    if extra_path:
        env['PATH'] = str(extra_path) + os.pathsep + env.get('PATH', '/usr/bin:/bin')
    timeout = min(3600, deadline - time.monotonic())
    require(timeout > 0, 'Producer deadline reached')
    start = time.monotonic()
    state = 'PRESENT'
    with log.open('xb') as stream:
        child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                 stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        while child.poll() is None:
            if log.stat().st_size > cap or time.monotonic() - start > timeout:
                state = 'DROPPED' if log.stat().st_size > cap else 'FAILED_TIMEOUT'
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait(timeout=3)
                break
            time.sleep(0.1)
    size = log.stat().st_size
    if size > cap:
        state = 'DROPPED'
    elif size == 0 and state == 'PRESENT':
        state = 'EMPTY'
    records.append({'argv': list(argv), 'cwd': str(cwd), 'rc': child.returncode,
                    'log': log.name, 'bytes': size, 'sha256': sha(log), 'state': state,
                    'elapsed_seconds': round(time.monotonic() - start, 3), 'environment_keys': sorted(env)})
    require(child.returncode == 0 and state in ['PRESENT', 'EMPTY'], 'Command failed; inspect ' + log.name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--phase', required=True, choices=['patch', 'build', 'level4-test', 'synthetic-asm'])
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    cloud_gate()  # Before any worktree, output, network or third-party execution.
    lock = json.loads((HERE / 'llvm22.lock.json').read_text())
    out = args.out.resolve()
    require(not out.exists() and not out.is_symlink(), 'Fresh result directory required')
    out.mkdir(parents=True)
    root = Path(os.environ['RUNNER_TEMP']) / 'repro109-llvm22-work'
    records = []
    result = {'schema': 1, 'classification': 'DIAGNOSTIC_ONLY_NOT_GOLDEN', 'phase': args.phase,
              'started_utc': datetime.now(timezone.utc).isoformat(), 'first_failure': None,
              'status': 'STARTED', 'install': 'SKIPPED', 'games': 'NOT_ENABLED', 'wine': 'NOT_ENABLED'}
    deadline = time.monotonic() + lock['producer_minutes'] * 60
    stage = 'HOST_PREFLIGHT'
    try:
        require(not root.exists() and not root.is_symlink(), 'Fresh owned work root required')
        root.mkdir()
        disk = shutil.disk_usage(root).free
        memory = {line.split(':')[0]: int(line.split()[1]) * 1024 for line in Path('/proc/meminfo').read_text().splitlines()}
        result['host'] = {'machine': platform.machine(), 'free_disk_bytes': disk,
                          'available_memory_bytes': memory['MemAvailable'], 'python': platform.python_version()}
        require(disk >= lock['minimum_free_disk_bytes'] and
                memory['MemAvailable'] >= lock['minimum_available_memory_bytes'], 'Host disk/memory capacity insufficient')
        cc, cxx = shutil.which(lock['cc']), shutil.which(lock['cxx'])
        require(cc and cxx and shutil.which('cmake') and shutil.which('ninja') and shutil.which('git'), 'Host tool missing')
        for name in ['cmake', 'ninja', lock['cc'], lock['cxx']]:
            command([name, '--version'], out / (name + '-version.log'), root, deadline, records, lock['command_log_cap_bytes'])
        for name, expected in [('LLVM22-ARM64EC-Q-RESTORES.patch', lock['patch_sha256']),
                               ('SOURCE-MANIFEST.json', lock['source_manifest_sha256']), ('synthetic.c', lock['synthetic_sha256'])]:
            require(sha(HERE / name) == expected, 'Authored input pin differs: ' + name)
        safety_path = HERE.parent / 'repro109fex/support/archive_safety.py'
        require(sha(safety_path) == lock['archive_safety_sha256'], 'Accepted archive validator differs')
        spec = importlib.util.spec_from_file_location('llvm22_archive', safety_path)
        safety = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(safety)
        stage = 'OFFICIAL_SOURCE_DOWNLOAD'
        archive = root / 'llvm-source.tar.xz'
        request = urllib.request.Request(lock['source_url'], headers={'User-Agent': 'MacRunner-REPRO109'})
        with urllib.request.urlopen(request, timeout=60) as response, archive.open('xb') as stream:
            total = 0
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                require(total <= lock['source_bytes'] and time.monotonic() < deadline, 'Source size/deadline exceeded')
                stream.write(block)
        require(archive.stat().st_size == lock['source_bytes'] and sha(archive) == lock['source_sha256'], 'Official source pin differs')
        result['source_archive'] = {'bytes': archive.stat().st_size, 'sha256': sha(archive), 'tag': lock['tag']}
        stage = 'SOURCE_EXTRACT_PATCH'
        with tarfile.open(archive) as stream:
            members = stream.getmembers()
            safety.validate_tar(members)
            require({Path(member.name).parts[0] for member in members} == {lock['source_root']}, 'Official archive root differs')
            stream.extractall(root / 'source', members=members, filter='data')
        source = root / 'source' / lock['source_root']
        require((source / 'llvm/CMakeLists.txt').is_file() and (source / 'clang/CMakeLists.txt').is_file(), 'LLVM/Clang sources missing')
        manifest = json.loads((HERE / 'SOURCE-MANIFEST.json').read_text())
        require(manifest['default'] is False and manifest['llvm_tag'] == lock['tag'], 'Scope/default differs')
        for row in manifest['files']:
            path = source / row['path']
            require((not path.exists()) if row['base_sha256'] is None else
                    path.is_file() and sha(path) == row['base_sha256'], 'Source preimage differs: ' + row['path'])
        for action in [['--check'], ['--whitespace=nowarn']]:
            command(['git', 'apply'] + action + [str(HERE / 'LLVM22-ARM64EC-Q-RESTORES.patch')],
                    out / ('patch-check.log' if action[0] == '--check' else 'patch-apply.log'), source,
                    deadline, records, lock['command_log_cap_bytes'])
        for row in manifest['files']:
            require(sha(source / row['path']) == row['patched_sha256'], 'Patched source differs: ' + row['path'])
        result['patched_files'] = manifest['files']
        if args.phase != 'patch':
            stage = 'AARCH64_ONLY_CONFIGURE_BUILD'
            build = root / 'build'
            command(cmake_args(source, build, cc, cxx), out / 'configure.log', root, deadline, records, lock['command_log_cap_bytes'])
            cache = (build / 'CMakeCache.txt').read_text()
            require('CMAKE_HOME_DIRECTORY:INTERNAL=' + str(source / 'llvm') in cache and
                    'LLVM_TARGETS_TO_BUILD:STRING=AArch64' in cache, 'Foreign source or target family in CMake cache')
            shutil.copy2(build / 'CMakeCache.txt', out / 'CMakeCache.txt')
            shutil.copy2(build / 'compile_commands.json', out / 'compile_commands.json')
            command(['cmake', '--build', str(build), '--parallel', str(lock['parallel_compile']), '--target'] +
                    lock['build_targets'], out / 'build.log', root, deadline, records, lock['command_log_cap_bytes'])
            tools = build / 'bin'
            result['tools'] = [{'name': name, 'bytes': (tools / name).stat().st_size, 'sha256': sha(tools / name)} for name in lock['build_targets']]
            for name in ['llc', 'clang']:
                command([str(tools / name), '--version'], out / (name + '-version.log'), root, deadline, records, lock['command_log_cap_bytes'])
            if args.phase == 'level4-test':
                stage = 'LEVEL4_FULL_17_RUN_LINES'
                test = source / 'llvm/test/CodeGen/AArch64/arm64ec-split-thunk-q-restores.ll'
                rows = run_lines(test.read_text(), test, out / 'level4')
                for index, line in enumerate(rows):
                    command(['/bin/bash', '-e', '-o', 'pipefail', '-c', line], out / f'test-{index:02d}.log',
                            root, deadline, records, lock['command_log_cap_bytes'], tools)
                result['test_run_lines_passed'] = len(rows)
            elif args.phase == 'synthetic-asm':
                stage = 'REAL_PATCHED_CLANG_DEFAULT_AND_ENABLED_ASSEMBLY'
                counts = {}
                for arm, options in [('before', []), ('explicit-off', ['-mllvm', '-' + lock['option'] + '=false']),
                                     ('after', ['-mllvm', '-' + lock['option'] + '=true'])]:
                    target = out / ('synthetic.' + arm + '.s')
                    command([str(tools / 'clang'), '-target', 'arm64ec-pc-windows-msvc', '-O2', '-g0', '-S',
                             '-mllvm', '-verify-machineinstrs'] + options + [str(HERE / 'synthetic.c'), '-o', str(target)],
                            out / (arm + '-clang.log'), root, deadline, records, lock['command_log_cap_bytes'])
                    text = target.read_text()
                    counts[arm] = dict(asm_counts(text), entries=entry_thunk_counts(text),
                                       bytes=target.stat().st_size, sha256=sha(target))
                counts['entry_comparison'] = compare_entries(counts['before']['entries'], counts['after']['entries'])
                counts['default_equals_explicit_off'] = ((out / 'synthetic.before.s').read_bytes() ==
                                                        (out / 'synthetic.explicit-off.s').read_bytes())
                (out / 'Q-LOAD-COUNTS.json').write_text(json.dumps(counts, indent=2) + '\n')
                result['assembly'] = counts
                require(counts['default_equals_explicit_off'], 'Default assembly differs from explicit false')
                require(all(row['level4_q_restore_shape_matches'] for row in counts['entry_comparison'].values()),
                        'Measured entry Q restores differ from LEVEL4 expectations')
            # Linux tools are evidence, never a replacement of the owner's Wine compiler.
            (out / 'tools').mkdir()
            for name in lock['build_targets']:
                shutil.copy2(tools / name, out / 'tools' / name)
            shutil.copy2(source / 'llvm/LICENSE.TXT', out / 'tools/LICENSE.TXT')
        result['status'] = 'PASS_BOUNDARY_NOT_PRODUCT_ACCEPTANCE'
    except Exception as error:
        result.update(status='FAILED', first_failure={'stage': stage, 'type': type(error).__name__, 'message': str(error)})
        raise
    finally:
        result['commands'] = records
        result['ended_utc'] = datetime.now(timezone.utc).isoformat()
        (out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
