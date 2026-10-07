"""Own inert fixtures for output-root handling and independently selected stages."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build as recipe
import native_stand

fex = recipe.fex


def pe_bytes(ec=True):
    raw = bytearray(2048)
    raw[:2] = b'MZ'
    struct.pack_into('<I', raw, 0x3c, 0x80)
    raw[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HH', raw, 0x84, 0x8664, 3)
    struct.pack_into('<H', raw, 0x94, 240)
    opt = 0x98
    struct.pack_into('<I', raw, opt + 108, 16)
    struct.pack_into('<II', raw, opt + 112 + 80, 0x1000, 0xd8)
    for index, name in enumerate([b'.text', b'.hexpthk', b'.a64xrm']):
        table = opt + 240 + index * 40
        raw[table:table + len(name)] = name
        struct.pack_into('<IIII', raw, table + 8, 512, 0x1000 + index * 0x1000, 512, 1024)
    struct.pack_into('<I', raw, 1024, 0xd8)
    struct.pack_into('<Q', raw, 1024 + 0xc8, 1 if ec else 0)
    return bytes(raw)


class StageTests(unittest.TestCase):
    def setUp(self):
        scratch = os.environ.get('REPRO109_TEST_TMP')
        if not scratch or not Path(scratch).is_dir():
            raise RuntimeError('Set REPRO109_TEST_TMP to owned scratch')
        self.root = Path(tempfile.mkdtemp(dir=scratch))
        self.pin, _, _, locks, self.tools = recipe.inputs()
        self.lock = copy.deepcopy(locks['fex64'])
        self.lock.update({k: self.pin['platform'][k] for k in
            ['xcode', 'xcode_build', 'sdk', 'deployment_target', 'apple_clang_build', 'linker_lc']})
        self.lock.update(repo_source_revision=self.pin['base_revision'], build_native_stand=True)

    def source_fixture(self, source):
        for name in ['FEXCore', 'FEXHeaderUtils', 'CodeEmitter', 'External', 'Source']:
            (source / name).mkdir(parents=True, exist_ok=True)
        tables = ['FEXCore/Source/Interface/Core/X86Tables/X86Tables.h',
                  'FEXCore/Source/Interface/Core/X86Tables/SecondaryTables.cpp',
                  'FEXCore/Source/Interface/Core/OpcodeDispatcher/SecondaryTables.h']
        for name in tables:
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('#ifndef _WIN32\n#endif\n')
        for name in native_stand.GUARD_FILES:
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('// own fixture JITGuardPageSize\n')

    def producer(self, source_file=None):
        source_file = source_file or HERE / 'support/native-builder.py'
        spec = importlib.util.spec_from_file_location('owned_fixture_producer', source_file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def producer_main(self, placement):
        fork = self.root / 'fork'
        fork.mkdir()
        source = self.root / 'source'
        self.source_fixture(source)
        build = fork / 'build/native' if placement == 'child' else self.root / 'sibling/native'
        producer = self.producer()
        producer.ROOT = fork
        commands = []
        stream = io.StringIO()
        with patch.object(producer, 'run', side_effect=lambda *argv: commands.append(argv)), \
             patch.object(producer.shutil, 'which', return_value=None), \
             patch.object(sys, 'argv', ['build.py', '--fex-source', str(source), '--build-dir', str(build)]), \
             contextlib.redirect_stdout(stream):
            producer.main()
        self.assertEqual([a[:2] for a in commands[-2:]], [('cmake', '-S'), ('cmake', '--build')])
        expected = str(build / 'cmake/Bin/stand_runner')
        if placement == 'child':
            expected = 'build/native/cmake/Bin/stand_runner'
        self.assertEqual(stream.getvalue(), 'RUNNER=' + expected + '\n')
        self.assertFalse((source / '.git').exists())

    def test_actual_main_sibling_build_root(self):
        self.producer_main('sibling')

    def test_actual_main_child_build_root(self):
        self.producer_main('child')

    def test_selected_producer_is_pinned(self):
        selected = json.loads((HERE / 'support/native-stand.lock.json').read_text())['producer']
        raw = (HERE / 'support' / selected['source']).read_bytes()
        self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (selected['bytes'], selected['sha256']))
        producer = HERE.parents[1] / 'stands/synthetic/build.py'
        if producer.exists():
            self.assertEqual(raw, producer.read_bytes())

    def trace_stage(self, stage, foreign_unix=False, missing_tool=None):
        out = self.root / 'out'
        commands, overlays = [], []
        patch_shas = {Path(self.lock['public_patch_paths'][row['path']]).name: row['sha256']
                      for row in self.lock['patches']}
        actual_sha = fex.sha
        def sha(path):
            return patch_shas[Path(path).name] if Path(path).name in patch_shas else actual_sha(path)
        def command(argv, cwd, output, name, env, timeout=2400):
            commands.append((name, argv))
            if missing_tool and name == 'tool-' + missing_tool + '-version':
                raise FileNotFoundError('Missing owned tool fixture: ' + missing_tool)
            if argv[:3] == ['git', 'init', '-q']:
                Path(argv[3]).mkdir(parents=True, exist_ok=True)
            if name == 'own-repo-checkout':
                for row in self.lock['patches']:
                    path = Path(cwd) / self.lock['public_patch_paths'][row['path']]
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b'own patch fixture')
            if name == 'apple-ld-version':
                (output / (name + '.log')).write_text('PROJECT:ld-1167.5\n')
            if name.startswith('tool-'):
                (output / (name + '.log')).write_text(' '.join(r['version'] for r in self.tools['tools']) + '\n')
            if name in ('pe-configure', 'unix-configure'):
                build = Path(argv[argv.index('-B') + 1]); source = Path(argv[argv.index('-S') + 1])
                build.mkdir()
                (build / 'CMakeCache.txt').write_text('CMAKE_HOME_DIRECTORY:INTERNAL=' + str(source) + '\n')
                file = self.root / 'foreign.cpp' if foreign_unix and name == 'unix-configure' else source / 'owned.cpp'
                (build / 'compile_commands.json').write_text(json.dumps([dict(directory=str(source), file=str(file))]))
            if name == 'pe-build':
                build = Path(argv[2]); (build / 'Bin').mkdir()
                (build / 'Bin/xtajit64.dll').write_bytes(pe_bytes())
            if name == 'unix-build':
                build = Path(argv[2])
                for file in ['xtajit64.so', 'libmacrunner-hwtso.dylib']:
                    (build / file).write_bytes(struct.pack('<II', 0xfeedfacf, 0x0100000c) + bytes(120))
        def output(argv, cwd=None, **kwargs):
            if argv == ['xcodebuild', '-version']: return 'Xcode 16.4\nBuild version 16F6\n'
            if argv == ['clang', '--version']: return 'Apple clang version 17.0.0\n'
            if argv[:2] == ['xcrun', '--find']: return argv[2] + '\n'
            if '--show-sdk-version' in argv: return '15.5\n'
            if '--show-sdk-path' in argv: return '/owned-sdk\n'
            if argv == ['git', 'rev-parse', 'HEAD']:
                if Path(cwd).name == 'macrunner-source': return self.pin['base_revision'] + '\n'
                for row in self.lock['submodules']:
                    if str(cwd).endswith(row['path']): return row['revision'] + '\n'
                return self.lock['base'] + '\n'
            raise AssertionError('Unmocked subprocess: ' + repr(argv))
        def overlay(stage, *args):
            overlays.append(stage)
            return dict(status='OWN_FIXTURE')
        with patch.object(fex, 'cloud_only'), patch.object(fex, 'HERE', HERE / 'base/repro109'), \
             patch.dict(os.environ, {'RUNNER_TEMP': str(self.root)}), \
             patch.object(fex, 'prepare_build_tools', return_value=self.root / 'tools'), \
             patch.object(fex, 'run', side_effect=command), patch.object(fex, 'sha', side_effect=sha), \
             patch.object(fex, 'verify_source', return_value=dict(files=3577)), \
             patch.object(fex.platform, 'platform', return_value='OWN_FIXTURE'), \
             patch.object(fex.subprocess, 'check_output', side_effect=output), \
             patch.object(fex.subprocess, 'run', return_value=subprocess.CompletedProcess([], 2)), \
             patch.object(native_stand, 'verify_builder'), patch.object(native_stand, 'write_order', return_value={}), \
             patch.object(native_stand, 'build') as native, \
             patch.object(fex.fex_notices, 'collect_source_notices'), \
             patch.object(fex, 'admit_outputs', side_effect=AssertionError('admission leaked into a source stage')):
            if missing_tool:
                with self.assertRaisesRegex(FileNotFoundError, 'Missing owned tool fixture'):
                    fex.build(out, self.lock, self.tools, source_overlay=overlay, stage=stage)
            elif foreign_unix:
                with self.assertRaisesRegex(ValueError, 'Foreign compile sources'):
                    fex.build(out, self.lock, self.tools, source_overlay=overlay, stage=stage)
            else:
                result = fex.build(out, self.lock, self.tools, source_overlay=overlay, stage=stage)
                self.assertEqual(result['stage'], stage)
            native_calls = native.call_count
        self.assertEqual(overlays, [] if missing_tool else ['prepared', 'submodules'])
        return commands, native_calls, out

    def test_patches_stops_before_any_cmake(self):
        commands, native, _ = self.trace_stage('patches')
        self.assertFalse(any(argv[0] == 'cmake' and '-S' in argv for _, argv in commands))
        self.assertEqual(native, 0)

    def test_configure_checks_both_trees_without_building(self):
        commands, native, _ = self.trace_stage('configure')
        self.assertEqual([name for name, _ in commands if name.endswith('-configure')], ['pe-configure', 'unix-configure'])
        self.assertFalse(any(argv[:2] == ['cmake', '--build'] for _, argv in commands))
        self.assertEqual(native, 0)

    def test_compile_preserves_bytes_without_native_or_admission(self):
        commands, native, out = self.trace_stage('compile')
        self.assertEqual([name for name, _ in commands if name.endswith('-build')], ['pe-build', 'unix-build'])
        self.assertEqual(native, 0)
        report = json.loads((out / 'outputs.json').read_bytes())
        self.assertEqual(len(report['files']), 5)
        self.assertEqual(report['ec_modules'], 'NOT_ENABLED')

    def test_native_stage_has_no_pe_or_unix_configure(self):
        commands, native, _ = self.trace_stage('native-stand')
        self.assertFalse(any(name in ['pe-configure', 'pe-build', 'unix-configure', 'unix-build'] for name, _ in commands))
        self.assertEqual(native, 1)

    def test_foreign_unix_source_refused_before_either_build(self):
        commands, native, _ = self.trace_stage('configure', foreign_unix=True)
        self.assertFalse(any(argv[:2] == ['cmake', '--build'] for _, argv in commands))
        self.assertEqual(native, 0)

    def test_missing_build_tools_refused_before_source_or_configure(self):
        for tool in ['cmake', 'ninja', 'ccache']:
            with self.subTest(tool=tool):
                commands, native, _ = self.trace_stage('configure', missing_tool=tool)
                self.assertFalse(any(argv[:2] == ['git', 'fetch'] or argv[:2] == ['cmake', '-S'] for _, argv in commands))
                self.assertEqual(native, 0)
                self.root = Path(tempfile.mkdtemp(dir=os.environ['REPRO109_TEST_TMP']))

    def compiled_fixture(self, ec=True):
        component = self.root / 'compiled'
        names = ['fex/aarch64-windows/xtajit64.dll', 'wine/lib/wine/aarch64-windows/libarm64ecfex.dll',
                 'fex/aarch64-unix/libarm64ecfex.so', 'fex/aarch64-unix/xtajit64.so',
                 'fex/aarch64-unix/libmacrunner-hwtso.dylib']
        rows = {}
        for name in names:
            path = component / 'engine' / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(pe_bytes(ec) if name.endswith('.dll') else struct.pack('<II', 0xfeedfacf, 0x0100000c))
            rows[name] = dict(bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        (component / 'outputs.json').write_text(json.dumps(dict(files=rows)))
        return component

    def admit(self, component):
        out = self.root / 'admitted'; out.mkdir()
        with patch.object(fex, 'HERE', HERE / 'base/repro109'), \
             patch.object(fex.subprocess, 'run', side_effect=AssertionError('admission executed a subprocess')), \
             patch.object(fex.subprocess, 'check_output', side_effect=AssertionError('admission executed a subprocess')):
            return fex.admit_outputs(component, out, 'fex64')

    def test_real_byte_and_ec_admission_without_subprocesses(self):
        result = self.admit(self.compiled_fixture())
        self.assertEqual((len(result['files']), result['ec_modules'], result['unique_ec_binaries']), (5, 2, 1))

    def test_real_ec_missing_metadata_refused(self):
        with self.assertRaisesRegex(AssertionError, 'complete EC metadata'):
            self.admit(self.compiled_fixture(ec=False))

    def test_changed_byte_refused(self):
        component = self.compiled_fixture()
        path = component / 'engine/fex/aarch64-unix/xtajit64.so'
        path.write_bytes(path.read_bytes() + b'x')
        with self.assertRaisesRegex(ValueError, 'bytes differ'):
            self.admit(component)

    def test_extra_output_refused(self):
        component = self.compiled_fixture(); (component / 'engine/extra').write_bytes(b'x')
        with self.assertRaisesRegex(ValueError, 'extra files'):
            self.admit(component)

    def test_missing_predecessor_refused_without_building(self):
        with self.assertRaises(FileNotFoundError):
            self.admit(self.root / 'absent')

    def test_inventory_avoids_tool_or_source_build(self):
        with patch.object(fex, 'cloud_only'), patch.object(fex, 'build', side_effect=AssertionError('source build leaked')):
            recipe.build(self.root / 'inventory', ['fex64'], stage='inventory')
        result = json.loads((self.root / 'inventory/RESULT.json').read_text())
        self.assertEqual(result['variants']['fex64']['postimages'], 6928)
        self.assertEqual(result['variants']['fex64']['actual_source'], 'NOT_ENABLED')

    def test_stage_selectors_and_admission_input_contract(self):
        for variants, stage, inputs in [(['fex32'], 'compile', None), (['fex64'], 'admission', None),
                                        (['fex64'], 'compile', self.root), (['fex64'], 'unknown', None)]:
            with self.subTest(variants=variants, stage=stage), self.assertRaises(ValueError):
                recipe.build(self.root / 'invalid', variants, stage=stage, from_outputs=inputs)
        self.assertFalse((self.root / 'invalid').exists())

    def test_admission_driver_never_calls_source_builder(self):
        compiled = self.root / 'predecessor'; compiled.mkdir()
        report = dict(ec_modules=2, unique_ec_binaries=1)
        with patch.object(fex, 'cloud_only'), patch.object(fex, 'build', side_effect=AssertionError('rebuild leaked')), \
             patch.object(fex, 'admit_outputs', return_value=report) as admit:
            recipe.build(self.root / 'admission', ['fex64'], stage='admission', from_outputs=compiled)
        self.assertEqual(admit.call_args.args[0], compiled / 'fex64')

    def test_workflow_has_all_stages_and_preserves_missing_admission(self):
        workflow = HERE.parents[1] / '.github/workflows/repro109-fex-c9-stages-macos15-arm64.yml'
        text = workflow.read_text()
        slots = re.findall(r'slot: ([a-z0-9-]+),', text)
        self.assertEqual(slots, ['fex64-inventory', 'fex64-patches', 'fex64-configure',
                                 'fex64-compile', 'fex64-native-stand', 'fex32-full'])
        self.assertIn('fail-fast: false', text)
        self.assertIn('needs: stage\n    if: always()', text)
        self.assertIn('NOT_ENABLED_PREDECESSOR_COMPILE_MISSING', text)
        self.assertIn('--stage admission --from-outputs', text)

    def shell_block(self, step):
        path = HERE.parents[1] / '.github/workflows/repro109-fex-c9-stages-macos15-arm64.yml'
        rows = path.read_text().splitlines()
        start = next(i for i, line in enumerate(rows) if 'name: ' + step in line)
        start = next(i for i in range(start, len(rows)) if rows[i].strip() == 'run: |') + 1
        end = next((i for i in range(start, len(rows)) if rows[i].strip() and not rows[i].startswith('          ')), len(rows))
        return '\n'.join(line[10:] for line in rows[start:end]) + '\n'

    def wrapper(self, block, **selection):
        slot = self.root / 'repro109-fex-slot'; slot.mkdir(exist_ok=True)
        (self.root / 'repro109-fex-admission').mkdir(exist_ok=True)
        bindir = self.root / 'bin'; bindir.mkdir(exist_ok=True)
        fake = bindir / 'python3'
        fake.write_text('#!/bin/sh\nprintf "ARG=%s\\n" "$@"\nexit "${FIXTURE_RC:-0}"\n')
        fake.chmod(0o755)
        env = dict(PATH=str(bindir), RUNNER_TEMP=str(self.root), **selection)
        result = subprocess.run(['/bin/bash', '-c', block], cwd=HERE.parents[1], env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        return result, slot

    def test_actual_shell_stage_selectors_on_bash32(self):
        block = self.shell_block('Run one source recipe stage')
        for architecture, stage in [('fex64', s) for s in ['inventory', 'patches', 'configure', 'compile', 'native-stand']] + [('fex32', 'full')]:
            with self.subTest(architecture=architecture, stage=stage):
                result, slot = self.wrapper(block, REPRO109_ARCHITECTURE=architecture, REPRO109_STAGE=stage)
                self.assertEqual(result.returncode, 0, result.stderr)
                log = (slot / 'driver.log').read_text().splitlines()
                self.assertEqual(log[-4:], ['ARG=--only', 'ARG=' + architecture, 'ARG=--stage', 'ARG=' + stage])
                self.assertEqual((slot / 'state.txt').read_text(), 'EXECUTED\n')

    def test_shell_failure_retains_rc_and_complete_log(self):
        result, slot = self.wrapper(self.shell_block('Run one source recipe stage'),
            REPRO109_ARCHITECTURE='fex64', REPRO109_STAGE='compile', FIXTURE_RC='42')
        self.assertEqual(result.returncode, 42)
        self.assertEqual((slot / 'rc.txt').read_text(), '42\n')
        self.assertIn('install skipped', result.stdout.decode())
        self.assertIn('ARG=compile', (slot / 'driver.log').read_text())

    def test_shell_invalid_stage_refuses_before_python(self):
        result, slot = self.wrapper(self.shell_block('Run one source recipe stage'),
            REPRO109_ARCHITECTURE='fex32', REPRO109_STAGE='compile')
        self.assertEqual(result.returncode, 2)
        self.assertFalse((slot / 'driver.log').exists())

    def test_shell_missing_python_is_recorded(self):
        block = self.shell_block('Run one source recipe stage')
        slot = self.root / 'repro109-fex-slot'; slot.mkdir()
        result = subprocess.run(['/bin/bash', '-c', block], cwd=HERE.parents[1],
            env=dict(PATH=str(self.root / 'empty'), RUNNER_TEMP=str(self.root),
                REPRO109_ARCHITECTURE='fex64', REPRO109_STAGE='inventory'),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 127)
        self.assertEqual((slot / 'rc.txt').read_text(), '127\n')
        self.assertIn('command not found', (slot / 'driver.log').read_text())

    def test_actual_admission_wrapper_present_and_missing_bytes(self):
        block = self.shell_block('Admit previously compiled bytes without rebuilding')
        result, _ = self.wrapper(block, REPRO109_COMPILE_TRANSFER='failure')
        slot = self.root / 'repro109-fex-admission'
        self.assertEqual(result.returncode, 1)
        self.assertEqual((slot / 'state.txt').read_text(), 'NOT_ENABLED_PREDECESSOR_COMPILE_MISSING\n')
        self.assertFalse((slot / 'driver.log').exists())
        component = self.root / 'repro109-fex-compiled/build/fex64'; component.mkdir(parents=True)
        (component / 'outputs.json').write_text('{}\n')
        result, _ = self.wrapper(block, REPRO109_COMPILE_TRANSFER='success')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('ARG=admission', (slot / 'driver.log').read_text())

    def test_native_wrapper_uses_the_corrected_producer(self):
        fork = self.root / 'public-fork'; (fork / 'stands/synthetic').mkdir(parents=True)
        (fork / 'stands/synthetic/LICENSE').write_text('own license fixture\n')
        adapter = fork / 'stands/synthetic/own-adapter.cpp'; adapter.write_text('// own adapter fixture\n')
        source = self.root / 'source'; self.source_fixture(source)
        out = self.root / 'out'; out.mkdir()
        build = self.root / 'native-stand'
        lock = dict(variant='fex64', build_native_stand=True, base='0' * 40,
                    patches=[dict(path='0161-fixture.patch', sha256=native_stand.GUARD_PATCH_SHA)])
        native_stand.write_order(source, lock, out)
        selected = json.loads((HERE / 'support/native-stand.lock.json').read_text())
        commands = []
        def run(argv, cwd, report, name, env):
            commands.append(argv)
            if argv[:2] == ['cmake', '-S']:
                cmake = build / 'cmake'; cmake.mkdir()
                (cmake / 'CMakeCache.txt').write_text('CMAKE_HOME_DIRECTORY:INTERNAL=' + str(fork / 'stands/synthetic') + '\n')
                (cmake / 'compile_commands.json').write_text(json.dumps([
                    dict(directory=str(build / 'src'), file=str(build / 'src' / native_stand.GUARD_FILES[0])),
                    dict(directory=str(adapter.parent), file=str(adapter))]))
            if argv[:2] == ['cmake', '--build']:
                binary = build / 'cmake/Bin/stand_runner'; binary.parent.mkdir()
                binary.write_bytes(struct.pack('<II', 0xfeedfacf, 0x0100000c) + bytes(120))
        with patch.object(fex, 'cloud_only'), patch.object(fex, 'run', side_effect=run), \
             patch.object(native_stand, 'verify_builder', return_value=selected), \
             patch.object(fex.subprocess, 'run', side_effect=AssertionError('unmocked compiler')), \
             contextlib.redirect_stdout(io.StringIO()) as stream:
            native_stand.build(fork, source, lock, build, out, {}, fex, 'clang', 'clang++')
        self.assertIn('RUNNER=' + str(build / 'cmake/Bin/stand_runner'), stream.getvalue())
        report = json.loads((out / 'native-stand/RESULT.json').read_text())
        self.assertEqual(report['producer'], selected['producer'])
        self.assertEqual(report['source_built'], True)
        self.assertEqual(len([a for a in commands if a[:2] == ['cmake', '--build']]), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
