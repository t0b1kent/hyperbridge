"""Build the existing public native runner from this task's patched product tree."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import sys

HERE = Path(__file__).resolve().parent
GUARD_PATCH_SHA = '830815241bcf4e07781ab845ffd4b68b0ac93eef7d0749e1cbf51758a8140590'
GUARD_FILES = (
    'FEXCore/Source/Interface/Core/JIT/JIT.cpp',
    'FEXCore/Source/Interface/Core/SharedCodeBufferManager.cpp',
    'FEXCore/Source/Interface/Core/SharedCodeBufferManager.h',
    'FEXCore/include/FEXCore/Utils/ThreadPoolAllocator.h',
    'FEXCore/include/FEXCore/Utils/TypeDefines.h',
    'Source/Windows/Common/JITGuardPage.h',
)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def order_bytes(lock):
    rows = lock.get('patches')
    require(type(rows) is list and bool(rows), 'Native/product patch order missing')
    names = set()
    for row in rows:
        require(type(row) is dict and set(row) == {'path', 'sha256'} and
                type(row['path']) is str and type(row['sha256']) is str and
                not Path(row['path']).is_absolute() and '..' not in Path(row['path']).parts and
                re.fullmatch('[a-f0-9]{64}', row['sha256']) is not None,
                'Native/product patch order row invalid')
        require(row['path'] not in names, 'Native/product patch order duplicate')
        names.add(row['path'])
    guard = [row for row in rows if Path(row['path']).name.startswith('0161-')]
    require(len(guard) == 1 and guard[0]['sha256'] == GUARD_PATCH_SHA,
            'Native/product patch order must contain the accepted 0161')
    return (json.dumps(dict(schema=1, base=lock['base'], patches=rows),
                       sort_keys=True, indent=2) + '\n').encode()


def guard_files(source):
    source = Path(source).resolve()
    rows, marked = [], []
    for name in GUARD_FILES:
        path = source / name
        require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(source),
                '0161 source file missing or foreign')
        raw = path.read_bytes()
        rows.append(dict(path=name, bytes=len(raw), sha256=digest(raw)))
        if b'JITGuardPageSize' in raw:
            marked.append(name)
    require(bool(marked), '0161 JITGuardPageSize marker missing')
    return rows, marked


def write_order(source, lock, out):
    raw = order_bytes(lock)
    rows, marked = guard_files(source)
    path = Path(out) / 'PATCH-ORDER.json'
    with path.open('xb') as stream:
        stream.write(raw)
    return dict(path=path.name, bytes=len(raw), sha256=digest(raw), patches=len(lock['patches']),
                product_guard_files=rows, product_marked_files=marked)


def paired_sources(product, native, lock, order):
    raw = Path(order).read_bytes()
    require(raw == order_bytes(lock), 'Native/product PATCH-ORDER drift')
    product_rows, product_marked = guard_files(product)
    native_rows, native_marked = guard_files(native)
    require(product_rows == native_rows and product_marked == native_marked,
            'Native/product 0161 files differ after the platform adapter')
    return dict(patch_order_sha256=digest(raw), patches=len(lock['patches']),
                product_guard_files=product_rows, native_guard_files=native_rows,
                product_marked_files=product_marked, native_marked_files=native_marked)


def verify_builder(fork, lock):
    selected = json.loads((HERE / 'native-stand.lock.json').read_bytes())
    require(selected['schema'] == 1 and selected['revision'] == lock['repo_source_revision'],
            'Native builder/public product revision differs')
    for row in selected['files']:
        path = Path(fork) / row['path']
        require(path.is_file() and not path.is_symlink() and
                path.stat().st_size == row['bytes'] and digest(path.read_bytes()) == row['sha256'],
                'Pinned public native builder source differs')
    row = selected['producer']
    require(row['source'] == 'native-builder.py', 'Native producer path differs')
    path = HERE / row['source']
    require(path.is_file() and not path.is_symlink() and
            path.stat().st_size == row['bytes'] and digest(path.read_bytes()) == row['sha256'],
            'Pinned corrected native producer differs')
    return selected


def compile_sources(build, native, adapter, out):
    path = Path(build) / 'compile_commands.json'
    require(path.is_file() and path.stat().st_size <= 64 * 1024**2,
            'Native compile database missing or exceeds cap')
    raw = path.read_bytes()
    rows = json.loads(raw)
    require(type(rows) is list and bool(rows), 'Native compile database empty')
    roots = [Path(value).resolve() for value in (native, adapter, build)]
    counts = [0, 0, 0]
    for row in rows:
        require(type(row) is dict and type(row.get('directory')) is str and
                type(row.get('file')) is str, 'Native compile database row invalid')
        source = (Path(row['directory']) / row['file']).resolve()
        matches = [i for i, root in enumerate(roots) if source.is_relative_to(root)]
        require(bool(matches), 'Native compile database contains foreign source')
        counts[matches[0]] += 1
    require(counts[0] > 0 and counts[1] > 0, 'Native FEX/adapter source coverage missing')
    (Path(out) / 'compile_commands.json').write_bytes(raw)
    return dict(compilation_units=len(rows), fex_units=counts[0], adapter_units=counts[1],
                generated_units=counts[2], foreign_units=0, raw_sha256=digest(raw))


def build(fork, source, lock, build_dir, out, env, fex, clang, clangxx):
    fex.cloud_only()  # Before executing even the owned public builder.
    require(lock.get('build_native_stand') is True and lock.get('variant') != 'fex32',
            'Native runner requires the selected 64-bit product series')
    builder_lock = verify_builder(fork, lock)
    report = Path(out) / 'native-stand'
    report.mkdir()
    shutil.copy2(Path(fork) / 'stands/synthetic/LICENSE', report / 'LICENSE')
    result = dict(schema=1, status='STARTED', first_failure=None, source_built=False,
                  stands='NOT_RUN', comparison='NOT_ENABLED', install='skipped',
                  builder_revision=builder_lock['revision'], builder_files=len(builder_lock['files']))
    result['producer'] = builder_lock['producer']
    result['license_sha256'] = digest((report / 'LICENSE').read_bytes())
    native = Path(build_dir) / 'src'
    configured = False
    def command(*argv):
        nonlocal configured
        args = list(argv)
        if args[:2] == ['cmake', '-S']:
            result['paired_sources'] = paired_sources(source, native, lock, Path(out) / 'PATCH-ORDER.json')
            args += ['-DCMAKE_EXPORT_COMPILE_COMMANDS=ON', '-DCMAKE_C_COMPILER=' + clang,
                     '-DCMAKE_CXX_COMPILER=' + clangxx]
        if args[:2] == ['cmake', '--build']:
            require(configured, 'Native build before source ownership verification')
        fex.run(args, fork, report, 'command-' + str(len(result.setdefault('commands', []))), env)
        result['commands'].append(args)
        if args[:2] == ['cmake', '-S']:
            cmake = Path(build_dir) / 'cmake'
            fex.own_cmake_cache(cmake, Path(fork) / 'stands/synthetic')
            result['source_ownership'] = compile_sources(cmake, native, Path(fork) / 'stands/synthetic', report)
            configured = True
    previous_argv = sys.argv[:]
    try:
        spec = importlib.util.spec_from_file_location('repro109_public_native_builder',
                    HERE / builder_lock['producer']['source'])
        producer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(producer)
        # The byte-pinned producer is the public builder with its output-path
        # fix. Its source root is the already verified public fork, even when
        # the producer file itself lives in this immutable recipe snapshot.
        producer.ROOT = Path(fork).resolve()
        producer.run = command  # Real existing producer; commands use the owned bounded runner.
        sys.argv = [str(producer.__file__), '--fex-source', str(source), '--build-dir', str(build_dir)]
        producer.main()
        result['paired_sources'] = paired_sources(source, native, lock, Path(out) / 'PATCH-ORDER.json')
        executable = Path(build_dir) / 'cmake/Bin/stand_runner'
        require(configured and executable.is_file() and not executable.is_symlink() and
                fex.macho_arm64(executable), 'Native runner output is missing or not ARM64')
        shutil.copy2(executable, report / 'stand_runner')
        result.update(status='NATIVE_STAND_SOURCE_BUILT_NOT_RUN', source_built=True,
                      output=dict(path='stand_runner', bytes=executable.stat().st_size,
                                  sha256=digest(executable.read_bytes())), source_execution='CLOUD_BUILD_ONLY')
    except Exception as error:
        result.update(status='FAILED', first_failure=str(error))
        raise
    finally:
        sys.argv = previous_argv
        (report / 'RESULT.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    return result
