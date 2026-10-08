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


def run_lines(text, source, temporary, expected_count=17):
    lines = [line.split('RUN:', 1)[1].strip() for line in text.splitlines() if re.match(r'^;\s*RUN:', line)]
    require(len(lines) == expected_count and all(not line.endswith('\\') for line in lines), 'Pinned LEVEL4 RUN list differs')
    result = []
    for line in lines:
        require(not re.search(r'%(?![sSt])', line), 'Unsupported test substitution')
        result.append(line.replace('%S', shlex.quote(str(source.parent)))
                      .replace('%s', shlex.quote(str(source))).replace('%t', shlex.quote(str(temporary))))
    return result


def command(argv, log, cwd, deadline, records, cap, extra_path=None, timeout_seconds=3600):
    env = {key: os.environ[key] for key in ['PATH', 'LANG', 'LC_ALL', 'TMPDIR'] if key in os.environ}
    env['LC_ALL'] = 'C'
    if extra_path:
        env['PATH'] = str(extra_path) + os.pathsep + env.get('PATH', '/usr/bin:/bin')
    require(isinstance(timeout_seconds, (int, float)) and 0 < timeout_seconds <= 21600,
            'Command timeout must be explicit and within six hours')
    timeout = min(timeout_seconds, deadline - time.monotonic())
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
                    'elapsed_seconds': round(time.monotonic() - start, 3), 'environment_keys': sorted(env),
                    'timeout_seconds': timeout})
    require(child.returncode == 0 and state in ['PRESENT', 'EMPTY'], 'Command failed; inspect ' + log.name)


def extra_test_rows(lock):
    path = HERE / 'EXTRA-TESTS.json'
    require(sha(path) == lock['extra_tests_manifest_sha256'], 'Extra test manifest pin differs')
    manifest = json.loads(path.read_bytes())
    require(isinstance(manifest, dict) and manifest.get('schema') == 1 and
            manifest.get('source_patch_sha256') == lock['patch_sha256'], 'Extra test scope differs')
    rows = manifest.get('tests')
    expected = {'arm64ec-split-q-restores.ll': 6, 'large-thunk-split-q-restores.ll': 9,
                'windows-split-q-restores.ll': 12}
    require(isinstance(rows, list) and len(rows) == 3 and all(isinstance(row, dict) for row in rows),
            'Extra test rows differ')
    require({row.get('file') for row in rows} == set(expected), 'Extra test set differs')
    for row in rows:
        require(row.get('run_directives') == expected[row['file']] and
                isinstance(row.get('bytes'), int) and row['bytes'] > 0 and
                re.fullmatch(r'[0-9a-f]{64}', row.get('sha256', '')) is not None,
                'Extra test metadata differs')
    return rows


def export_shared_build(out, tools, test, source, lock, result):
    """Publish just this run's native tools and exact patched test input."""
    (out / 'tools').mkdir()
    for name in lock['build_targets']:
        shutil.copy2(tools / name, out / 'tools' / name)
    shutil.copy2(source / 'llvm/LICENSE.TXT', out / 'tools/LICENSE.TXT')
    (out / 'test-inputs').mkdir()
    shutil.copy2(test, out / 'test-inputs' / test.name)
    extras = extra_test_rows(lock)
    for row in extras:
        shutil.copy2(source / 'llvm/test/CodeGen/AArch64' / row['file'], out / 'test-inputs' / row['file'])
    manifest = {
        'schema': 1, 'repository': os.environ['GITHUB_REPOSITORY'],
        'revision': os.environ['GITHUB_SHA'], 'run_id': os.environ['GITHUB_RUN_ID'],
        'lock_sha256': sha(HERE / 'llvm22.lock.json'),
        'source_sha256': lock['source_sha256'], 'patch_sha256': lock['patch_sha256'],
        'source_manifest_sha256': lock['source_manifest_sha256'],
        'extra_tests_manifest_sha256': lock['extra_tests_manifest_sha256'],
        'tools': [dict(row, path='tools/' + row['name']) for row in result['tools']],
        'test': {'path': 'test-inputs/' + test.name, 'bytes': test.stat().st_size, 'sha256': sha(test)},
        'extra_tests': [dict(row, path='test-inputs/' + row['file']) for row in extras],
        'license': {'path': 'tools/LICENSE.TXT', 'sha256': sha(out / 'tools/LICENSE.TXT')},
    }
    (out / 'SHARED-BUILD.json').write_text(json.dumps(manifest, indent=2) + '\n')
    result['shared_build_manifest_sha256'] = sha(out / 'SHARED-BUILD.json')


def prepare_shared_build(archive, checksum, destination, lock, identity):
    require(re.fullmatch(r'[0-9a-f]{64}', checksum or '') is not None,
            'Shared archive requires a complete lowercase SHA256')
    require(archive.is_file() and not archive.is_symlink() and
            archive.stat().st_size <= lock['shared_archive_max_bytes'] and sha(archive) == checksum,
            'Shared build archive pin/size differs')
    require(not destination.exists() and not destination.is_symlink(), 'Fresh shared input directory required')
    with tarfile.open(archive, 'r:gz') as stream:
        members, total, names = [], 0, set()
        for member in stream:
            name = Path(member.name)
            require(not name.is_absolute() and '..' not in name.parts and
                    (member.isfile() or member.isdir()), 'Shared archive contains unsafe member')
            normalized = name.as_posix()
            require(normalized not in names, 'Shared archive contains duplicate member')
            names.add(normalized)
            total += member.size
            members.append(member)
            require(len(members) <= lock['shared_archive_max_members'] and
                    total <= lock['shared_archive_max_bytes'], 'Shared archive exceeds bounds')
        destination.mkdir(parents=True)
        stream.extractall(destination, members=members, filter='data')
    manifest = json.loads((destination / 'SHARED-BUILD.json').read_bytes())
    receipt = json.loads((destination / 'RESULT.json').read_bytes())
    require(isinstance(manifest, dict) and isinstance(receipt, dict), 'Shared receipt types differ')
    require(manifest.get('schema') == 1 and
            all(manifest.get(key) == value for key, value in identity.items()), 'Foreign shared producer identity')
    require(receipt.get('phase') == 'build' and receipt.get('first_failure', 'MISSING') is None and
            receipt.get('status') == 'PASS_BOUNDARY_NOT_PRODUCT_ACCEPTANCE' and
            receipt.get('shared_build_manifest_sha256') == sha(destination / 'SHARED-BUILD.json'),
            'Shared build did not pass its complete boundary')
    require(manifest.get('lock_sha256') == sha(HERE / 'llvm22.lock.json') and
            all(manifest.get(key) == lock[key] for key in
                ('source_sha256', 'patch_sha256', 'source_manifest_sha256',
                 'extra_tests_manifest_sha256')), 'Shared source/recipe pins differ')
    def selected(row):
        require(isinstance(row, dict) and isinstance(row.get('path'), str), 'Shared file row type differs')
        value = Path(row['path'])
        require(not value.is_absolute() and '..' not in value.parts, 'Shared file path escapes inputs')
        path = destination / value
        require(path.is_file() and not path.is_symlink() and
                path.resolve().is_relative_to(destination.resolve()) and
                sha(path) == row.get('sha256') and
                ('bytes' not in row or path.stat().st_size == row['bytes']), 'Shared file bytes differ')
        return path
    rows = manifest.get('tools')
    require(isinstance(rows, list) and all(isinstance(row, dict) for row in rows), 'Shared tool rows differ')
    require(len(rows) == len(lock['build_targets']) and
            {row.get('name') for row in rows} == set(lock['build_targets']), 'Shared tool set differs')
    for row in rows:
        path = selected(row)
        require(row['path'] == 'tools/' + row['name'] and path.stat().st_mode & 0o111,
                'Shared tool path or executable mode differs')
        with path.open('rb') as stream:
            head = stream.read(20)
        require(len(head) == 20 and head[:6] == b'\x7fELF\x02\x01' and head[18:20] == b'\x3e\x00',
                'Shared tool is not Linux ELF64 x86-64')
    test = selected(manifest.get('test'))
    expected_path = 'llvm/test/CodeGen/AArch64/arm64ec-split-thunk-q-restores.ll'
    source_manifest = json.loads((HERE / 'SOURCE-MANIFEST.json').read_bytes())
    expected = [row for row in source_manifest['files'] if row['path'] == expected_path]
    require(len(expected) == 1 and sha(test) == expected[0]['patched_sha256'], 'Shared LEVEL4 test source differs')
    extras = manifest.get('extra_tests')
    pinned = [dict(row, path='test-inputs/' + row['file']) for row in extra_test_rows(lock)]
    require(extras == pinned, 'Shared extra test set/pins differs')
    for row in extras:
        selected(row)
    selected(manifest.get('license'))
    return destination / 'tools', test, manifest


def run_checks(phase, tools, test, out, root, deadline, records, lock, result):
    if phase == 'level4-test':
        inputs = [(test, lock['test_run_count'])] + [
            (test.parent / row['file'], row['run_directives']) for row in extra_test_rows(lock)]
        result['tests'] = []
        result['test_run_lines_passed'] = 0
        for source, count in inputs:
            rows = run_lines(source.read_text(), source, out / source.stem, count)
            measured = {'file': source.name, 'sha256': sha(source), 'run_lines_expected': count,
                        'run_lines_passed': 0, 'status': 'STARTED'}
            result['tests'].append(measured)
            for index, line in enumerate(rows):
                command(['/bin/bash', '-e', '-o', 'pipefail', '-c', line],
                        out / f'{source.stem}-{index:02d}.log', root, deadline, records,
                        lock['command_log_cap_bytes'], tools)
                measured['run_lines_passed'] += 1
                result['test_run_lines_passed'] += 1
            measured['status'] = 'PASS'
        require(result['test_run_lines_passed'] == 44, 'Full LEVEL4 RUN coverage differs')
    elif phase == 'synthetic-asm':
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


def read_archive_checksum(path, archive):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 512,
            'Shared checksum file type/size differs')
    match = re.fullmatch(r'([0-9a-f]{64})[ \t]+\*?([^\r\n]+)\n?', path.read_text())
    require(match is not None and Path(match.group(2)).name == archive.name,
            'Shared checksum must name the selected archive')
    return match.group(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--phase', required=True, choices=['patch', 'build', 'level4-test', 'synthetic-asm'])
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--build-archive', type=Path)
    parser.add_argument('--build-sha256')
    parser.add_argument('--build-sha256-file', type=Path)
    args = parser.parse_args()
    cloud_gate()  # Before any worktree, output, network or third-party execution.
    lock = json.loads((HERE / 'llvm22.lock.json').read_text())
    consuming = args.phase in ('level4-test', 'synthetic-asm')
    require((args.build_archive is not None and ((args.build_sha256 is not None) !=
                                                (args.build_sha256_file is not None))) if consuming else
            (args.build_archive is None and args.build_sha256 is None and args.build_sha256_file is None),
            'Check phases require this run shared archive; source phases must not consume it')
    if args.build_sha256_file is not None:
        args.build_sha256 = read_archive_checksum(args.build_sha256_file, args.build_archive)
    for name, expected in [('LLVM22-ARM64EC-Q-RESTORES.patch', lock['patch_sha256']),
                           ('SOURCE-MANIFEST.json', lock['source_manifest_sha256']),
                           ('synthetic.c', lock['synthetic_sha256'])]:
        require(sha(HERE / name) == expected, 'Authored input pin differs: ' + name)
    extras = extra_test_rows(lock)
    for row in extras:
        path = HERE / row['file']
        require(path.is_file() and path.stat().st_size == row['bytes'] and sha(path) == row['sha256'],
                'Authored extra test bytes differ: ' + row['file'])
        run_lines(path.read_text(), path, Path('unused'), row['run_directives'])
    out = args.out.resolve()
    require(not out.exists() and not out.is_symlink(), 'Fresh result directory required')
    out.mkdir(parents=True)
    root = Path(os.environ['RUNNER_TEMP']) / 'repro109-llvm22-work'
    records = []
    result = {'schema': 1, 'classification': 'DIAGNOSTIC_ONLY_NOT_GOLDEN', 'phase': args.phase,
              'started_utc': datetime.now(timezone.utc).isoformat(), 'first_failure': None,
              'status': 'STARTED', 'install': 'SKIPPED', 'games': 'NOT_ENABLED', 'wine': 'NOT_ENABLED'}
    deadline = time.monotonic() + lock['check_producer_minutes' if consuming else 'producer_minutes'] * 60
    stage = 'HOST_PREFLIGHT'
    try:
        require(not root.exists() and not root.is_symlink(), 'Fresh owned work root required')
        root.mkdir()
        if consuming:
            stage = 'VERIFY_THIS_RUN_SHARED_BUILD'
            tools, test, shared = prepare_shared_build(
                args.build_archive.resolve(), args.build_sha256, root / 'shared', lock,
                {key: os.environ['GITHUB_' + env] for key, env in
                 [('repository', 'REPOSITORY'), ('revision', 'SHA'), ('run_id', 'RUN_ID')]})
            result['shared_build'] = {'archive_sha256': args.build_sha256, 'producer': shared}
            stage = 'LEVEL4_FULL_44_RUN_LINES' if args.phase == 'level4-test' else 'REAL_PATCHED_CLANG_DEFAULT_AND_ENABLED_ASSEMBLY'
            run_checks(args.phase, tools, test, out, root, deadline, records, lock, result)
            result['status'] = 'PASS_BOUNDARY_NOT_PRODUCT_ACCEPTANCE'
            return
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
        for row in extras:
            target = source / 'llvm/test/CodeGen/AArch64' / row['file']
            require(not target.exists(), 'Extra test would overwrite upstream source: ' + row['file'])
            shutil.copy2(HERE / row['file'], target)
            require(target.stat().st_size == row['bytes'] and sha(target) == row['sha256'],
                    'Staged extra test bytes differ: ' + row['file'])
        result['extra_tests'] = extras
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
                    lock['build_targets'], out / 'build.log', root, deadline, records, lock['command_log_cap_bytes'],
                    timeout_seconds=lock['build_command_minutes'] * 60)
            tools = build / 'bin'
            result['tools'] = [{'name': name, 'bytes': (tools / name).stat().st_size, 'sha256': sha(tools / name)} for name in lock['build_targets']]
            for name in ['llc', 'clang']:
                command([str(tools / name), '--version'], out / (name + '-version.log'), root, deadline, records, lock['command_log_cap_bytes'])
            test = source / 'llvm/test/CodeGen/AArch64/arm64ec-split-thunk-q-restores.ll'
            export_shared_build(out, tools, test, source, lock, result)
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
