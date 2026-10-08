"""Check new IR with a frozen older build. No compiler build or fallback path."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import tarfile
import time
import urllib.request

HERE = Path(__file__).resolve().parent
PRODUCER = HERE / 'producer-d3466bf'


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


current = load(HERE / 'run.py', 'llvm22_reuse_current')
require = current.require
sha = current.sha


def load_producer(selection):
    pins = selection['producer_recipe']
    require(isinstance(pins, dict) and set(pins) ==
            {'run.py', 'llvm22.lock.json', 'SOURCE-MANIFEST.json', 'EXTRA-TESTS.json'},
            'Frozen producer recipe set differs')
    for name, expected in pins.items():
        path = PRODUCER / name
        require(path.is_file() and not path.is_symlink() and sha(path) == expected,
                'Frozen producer recipe bytes differ: ' + name)
    return load(PRODUCER / 'run.py', 'llvm22_reuse_original')


def validate_inputs(lock, old_lock):
    # Only test transport/expectations changed; every compiler recipe field stays exact.
    for key, value in old_lock.items():
        if key != 'extra_tests_manifest_sha256':
            require(lock.get(key) == value, 'Compiler recipe differs: ' + key)
    require(set(lock) == set(old_lock) | {'support_inputs'}, 'Consumer recipe scope differs')
    for name, key in [('LLVM22-ARM64EC-Q-RESTORES.patch', 'patch_sha256'),
                      ('SOURCE-MANIFEST.json', 'source_manifest_sha256'),
                      ('synthetic.c', 'synthetic_sha256')]:
        path = HERE / name
        require(path.is_file() and not path.is_symlink() and sha(path) == lock[key],
                'Consumer authored input differs: ' + name)
    for row in current.extra_test_rows(lock):
        path = HERE / row['file']
        require(path.is_file() and not path.is_symlink() and
                path.stat().st_size == row['bytes'] and sha(path) == row['sha256'],
                'Consumer extra test bytes differ: ' + row['file'])
        current.run_lines(path.read_text(), path, Path('unused'), row['run_directives'])
    rows = lock['support_inputs']
    require(isinstance(rows, list) and len(rows) == 2 and all(isinstance(row, dict) for row in rows)
            and {row.get('file') for row in rows} ==
            {'arm64ec-entry-thunks.ll', 'arm64ec-exit-thunks.ll'}, 'Support input set differs')
    for row in rows:
        require(type(row.get('bytes')) is int and 0 < row['bytes'] <= 1024 * 1024 and
                re.fullmatch(r'[0-9a-f]{64}', row.get('sha256', '')) is not None,
                'Support input pin type differs')


def select_old_build(old, archive, checksum, root, old_lock, selection):
    require(selection.get('schema') == 1 and selection.get('status') == 'ACTUAL_EXPORT_VERIFIED' and
            re.fullmatch(r'[0-9a-f]{64}', selection.get('archive_sha256') or '') is not None,
            'Actual producer export must be collected and sealed before reuse')
    require(checksum == selection['archive_sha256'], 'Selected archive differs from actual export seal')
    identity = {key: selection[key] for key in ('repository', 'revision', 'run_id')}
    return old.prepare_shared_build(archive, checksum, root / 'shared', old_lock, identity)


def fetch_support(lock, archive, deadline):
    # Called only after cloud_gate, recipe validation and the exact old build verifier.
    request = urllib.request.Request(lock['source_url'], headers={'User-Agent': 'MacRunner-REPRO109'})
    total = 0
    with urllib.request.urlopen(request, timeout=60) as response, archive.open('xb') as stream:
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            require(total <= lock['source_bytes'] and time.monotonic() < deadline,
                    'Support source download size/deadline exceeded')
            stream.write(block)
    require(total == lock['source_bytes'] and sha(archive) == lock['source_sha256'],
            'Official support source archive pin differs')


def extract_support(lock, archive, inputs):
    # No tree extraction or source execution: copy only two exact, individually pinned members.
    with tarfile.open(archive, 'r:xz') as stream:
        for row in lock['support_inputs']:
            name = lock['source_root'] + '/llvm/test/CodeGen/AArch64/' + row['file']
            matches = [member for member in stream.getmembers() if member.name == name]
            require(len(matches) == 1 and matches[0].isfile() and matches[0].size == row['bytes'],
                    'Official support member type/size differs: ' + row['file'])
            target = inputs / row['file']
            with stream.extractfile(matches[0]) as source, target.open('xb') as output:
                data = source.read(row['bytes'] + 1)
                require(len(data) == row['bytes'], 'Support member bytes differ')
                output.write(data)
            require(sha(target) == row['sha256'], 'Support member SHA differs: ' + row['file'])


def prepare_tests(test, root, lock, support_archive):
    inputs = root / 'current-test-inputs'
    inputs.mkdir()
    shutil.copy2(test, inputs / test.name)
    manifest = json.loads((HERE / 'SOURCE-MANIFEST.json').read_bytes())
    rows = [row for row in manifest['files'] if row['path'] ==
            'llvm/test/CodeGen/AArch64/' + test.name]
    require(len(rows) == 1 and sha(inputs / test.name) == rows[0]['patched_sha256'],
            'Current primary test differs from verified producer test')
    for row in current.extra_test_rows(lock):
        shutil.copy2(HERE / row['file'], inputs / row['file'])
    extract_support(lock, support_archive, inputs)
    return inputs / test.name, [{'file': path.name, 'bytes': path.stat().st_size, 'sha256': sha(path)}
                                for path in sorted(inputs.iterdir())]


def check_tools(tools, manifest):
    for row in manifest['tools']:
        path = tools / row['name']
        require(path.is_file() and not path.is_symlink() and
                path.stat().st_size == row['bytes'] and sha(path) == row['sha256'],
                'Verified compiler output changed: ' + row['name'])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--phase', choices=['level4-test', 'synthetic-asm'], required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--build-archive', type=Path, required=True)
    parser.add_argument('--build-sha256-file', type=Path, required=True)
    args = parser.parse_args()
    current.cloud_gate()  # Before output/network/work roots and any ELF execution.
    selection = json.loads((HERE / 'REUSE-BUILD.json').read_bytes())
    old = load_producer(selection)
    lock = json.loads((HERE / 'llvm22.lock.json').read_bytes())
    old_lock = json.loads((PRODUCER / 'llvm22.lock.json').read_bytes())
    validate_inputs(lock, old_lock)
    out = args.out.resolve()
    require(not out.exists() and not out.is_symlink(), 'Fresh result directory required')
    out.mkdir(parents=True)
    root = Path(os.environ['RUNNER_TEMP']) / 'repro109-llvm22-reuse'
    records = []
    result = {'schema': 1, 'phase': args.phase, 'classification': 'DIAGNOSTIC_ONLY_NOT_GOLDEN',
              'status': 'STARTED', 'first_failure': None, 'install': 'SKIPPED',
              'games': 'NOT_ENABLED', 'wine': 'NOT_ENABLED', 'compiler_build': 'NOT_ENABLED',
              'started_utc': datetime.now(timezone.utc).isoformat(),
              'consumer_revision': os.environ['GITHUB_SHA'],
              'consumer_lock_sha256': sha(HERE / 'llvm22.lock.json'),
              'requested_test_recipe': sha(HERE / 'EXTRA-TESTS.json')}
    deadline = time.monotonic() + lock['check_producer_minutes'] * 60
    stage = 'VERIFY_FROZEN_PRODUCER_EXPORT'
    try:
        require(not root.exists() and not root.is_symlink(), 'Fresh owned reuse work root required')
        root.mkdir()
        checksum = old.read_archive_checksum(args.build_sha256_file, args.build_archive)
        tools, test, shared = select_old_build(old, args.build_archive.resolve(), checksum,
                                               root, old_lock, selection)
        result['shared_build'] = {'archive_sha256': checksum, 'producer': shared,
                                  'producer_recipe': selection['producer_recipe']}
        stage = 'SELECT_CURRENT_TEST_INPUTS'
        if args.phase == 'level4-test':
            archive = root / 'official-support-source.tar.xz'
            fetch_support(lock, archive, deadline)
            result['support_source_archive'] = {'bytes': archive.stat().st_size, 'sha256': sha(archive)}
            test, rows = prepare_tests(test, root, lock, archive)
            result['effective_test_inputs'] = rows
            require(len(rows) == 6, 'Complete current IR input set differs')
        else:
            result['effective_test_inputs'] = [{'file': 'synthetic.c', 'sha256': lock['synthetic_sha256']}]
        stage = 'CHECK_WITH_UNCHANGED_COMPILER_TOOLS'
        check_tools(tools, shared)
        current.run_checks(args.phase, tools, test, out, root, deadline, records, lock, result)
        check_tools(tools, shared)
        result['status'] = 'PASS_BOUNDARY_NOT_PRODUCT_ACCEPTANCE'
    except Exception as error:
        result.update(status='FAILED', first_failure={'stage': stage, 'type': type(error).__name__,
                                                     'message': str(error)})
        raise
    finally:
        result['commands'] = records
        result['ended_utc'] = datetime.now(timezone.utc).isoformat()
        (out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
