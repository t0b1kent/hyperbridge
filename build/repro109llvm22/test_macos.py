"""Offline controls: no third-party download, binary execution or Wine."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('macos_compiler', HERE / 'macos.py')
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)


class MacosCompilerTests(unittest.TestCase):
    def setUp(self):
        scratch = os.environ.get('REPRO109_TEST_SCRATCH')
        if not scratch:
            raise RuntimeError('Explicit scratch on the workspace volume required')
        Path(scratch).mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.lock = json.loads((HERE / 'macos.lock.json').read_text())

    def test_local_gate_refuses_before_any_network_or_subprocess(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(producer.urllib.request, 'urlopen') as network, \
             patch.object(producer.subprocess, 'Popen') as child:
            with self.assertRaisesRegex(ValueError, 'Owned GitHub'):
                producer.cloud_gate(self.lock)
            network.assert_not_called()
            child.assert_not_called()

    def test_wrong_os_arch_and_python_are_independent_rejections(self):
        env = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 't0b1kent/hyperbridge'}
        for system, machine, python in [('Linux', 'arm64', '3.13.7'),
                                        ('Darwin', 'x86_64', '3.13.7'),
                                        ('Darwin', 'arm64', '3.13.8')]:
            with self.subTest(system=system, machine=machine, python=python), \
                 patch.dict(os.environ, env, clear=True), patch.object(producer.platform, 'system', return_value=system), \
                 patch.object(producer.platform, 'machine', return_value=machine), \
                 patch.object(producer.platform, 'python_version', return_value=python):
                with self.assertRaises(ValueError):
                    producer.cloud_gate(self.lock)

    def test_complete_backend_and_linker_plan_uses_owned_paths(self):
        source, build, tools = [self.root / name for name in ['source', 'build', 'tools']]
        plan = producer.compiler_plan(source, build, tools, '/cc', '/cxx', '/sdk', self.lock)
        for required in ['-DLLVM_TARGETS_TO_BUILD=AArch64;X86', '-DLLVM_ENABLE_PROJECTS=clang;lld',
                         '-DBUILD_SHARED_LIBS=OFF', '-DLLVM_PARALLEL_LINK_JOBS=1',
                         '-DCMAKE_MAKE_PROGRAM=' + str(tools / 'ninja')]:
            self.assertIn(required, plan)
        self.assertEqual(plan[plan.index('-S') + 1], str(source / 'llvm'))
        self.assertEqual(plan[plan.index('-B') + 1], str(build))
        self.assertIn('lld', self.lock['build_targets'])
        self.assertEqual(set(producer.ARCHES), {'aarch64', 'arm64ec', 'x86_64', 'i686'})

    def test_host_workflow_and_lock_match_measured_official_image_pair(self):
        workflow = HERE.parent.parent / '.github/workflows/repro109-llvm22-wine-macos.yml'
        runners = [line.split('runs-on:', 1)[1].strip() for line in workflow.read_text().splitlines()
                   if 'runs-on:' in line]
        self.assertEqual(runners, ['macos-26', 'macos-26'])
        host = self.lock['host']
        self.assertEqual(host['runner'], runners[0])
        self.assertEqual((host['xcode'], host['xcode_build'], host['sdk']), ('26.6', '17F113', '26.5'))
        self.assertEqual(host['developer_dir'], '/Applications/Xcode_26.6.app/Contents/Developer')
        self.assertEqual(host['image_document_sha256'],
                         '688dc6f11befc470dd78896f4b69f5956dd9cc3986287919a6b912d748b97f21')
        self.assertLessEqual(self.lock['parallel_compile'], 2)

    def test_dependency_pins_are_current_and_tampering_is_rejected(self):
        producer.validate_dependencies(self.lock)
        for field in ['bytes', 'sha256']:
            lock = json.loads(json.dumps(self.lock))
            lock['local_dependencies'][0][field] = 1 if field == 'bytes' else '0' * 64
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'dependency differs'):
                producer.validate_dependencies(lock)

    def test_foreign_publisher_is_rejected_before_network(self):
        with patch.object(producer.urllib.request, 'urlopen') as network:
            with self.assertRaisesRegex(ValueError, 'Foreign publisher'):
                producer.fetch({'url': 'https://example.invalid/compiler.tar'}, self.root / 'archive', 1)
            network.assert_not_called()

    def test_coff_and_pe_machine_family_and_invalid_offsets(self):
        for arch, value in producer.ARCHES.items():
            with self.subTest(arch=arch):
                obj = self.root / (arch + '.o')
                obj.write_bytes(struct.pack('<H', value) + b'object')
                self.assertEqual(producer.machine(obj), value)
                exe = self.root / (arch + '.exe')
                header = bytearray(0x48)
                header[:2] = b'MZ'
                struct.pack_into('<I', header, 0x3c, 0x40)
                header[0x40:0x44] = b'PE\0\0'
                struct.pack_into('<H', header, 0x44, value)
                exe.write_bytes(header)
                self.assertEqual(producer.machine(exe, pe=True), value)
                struct.pack_into('<I', header, 0x3c, 0xfffffff0)
                exe.write_bytes(header)
                with self.assertRaisesRegex(ValueError, 'offset invalid'):
                    producer.machine(exe, pe=True)

    def test_macho_rejects_x86_64_fat_and_short_files(self):
        path = self.root / 'tool'
        for body in [b'short', struct.pack('<III', 0xfeedfacf, 0x1000007, 0),
                     struct.pack('<III', 0xcafebabe, 0x100000c, 0)]:
            path.write_bytes(body)
            with self.assertRaises(ValueError):
                producer.macho_arm64(path)
        path.write_bytes(struct.pack('<III', 0xfeedfacf, 0x100000c, 0))
        producer.macho_arm64(path)

    def fixture_compiler(self):
        bootstrap = self.root / 'bootstrap'
        built = self.root / 'built'
        (bootstrap / 'bin').mkdir(parents=True)
        built.mkdir()
        wrapper = bootstrap / 'bin/clang-target-wrapper.sh'
        wrapper.write_text('fixture shell wrapper')
        self.lock['bootstrap']['wrapper_sha256'] = producer.sha(wrapper)
        for arch in producer.ARCHES:
            for suffix in ['gcc', 'g++']:
                (bootstrap / 'bin' / (arch + '-w64-mingw32-' + suffix)).symlink_to(wrapper.name)
        for name in self.lock['build_targets']:
            (built / name).write_bytes(struct.pack('<III', 0xfeedfacf, 0x100000c, 0) + name.encode())
        return bootstrap, built

    def test_composition_retains_wrapper_and_replaces_all_selected_tools(self):
        bootstrap, built = self.fixture_compiler()
        bundle, replaced = producer.assemble(bootstrap, built, self.root, self.lock)
        self.assertEqual(len(replaced), 9)
        interfaces = producer.selected_interfaces(bundle)
        self.assertEqual(len(interfaces), 10)
        self.assertEqual(producer.sha(bundle / 'bin/clang-22'), producer.sha(built / 'clang'))
        self.assertEqual(producer.sha(bundle / 'bin/lld'), producer.sha(built / 'lld'))
        self.assertEqual(producer.sha(bundle / 'bin/clang-target-wrapper.sh'), self.lock['bootstrap']['wrapper_sha256'])
        self.assertEqual((bundle / 'bin/clang').readlink(), Path('clang-22'))

    def test_source_tool_external_symlink_and_foreign_interface_refused(self):
        bootstrap, built = self.fixture_compiler()
        outside = self.root / 'foreign'
        outside.write_bytes(struct.pack('<III', 0xfeedfacf, 0x100000c, 0))
        (built / 'clang').unlink()
        (built / 'clang').symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'missing/foreign'):
            producer.assemble(bootstrap, built, self.root, self.lock)
        (built / 'clang').unlink()
        (built / 'clang').write_bytes(outside.read_bytes())
        other = self.root / 'second'
        other.mkdir()
        bundle, _ = producer.assemble(bootstrap, built, other, self.lock)
        interface = bundle / 'bin/i686-w64-mingw32-g++'
        interface.unlink()
        interface.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'missing/foreign'):
            producer.selected_interfaces(bundle)

    def test_smoke_checks_all_eight_object_and_exe_pairs_without_target_execution(self):
        bootstrap, built = self.fixture_compiler()
        bundle, _ = producer.assemble(bootstrap, built, self.root, self.lock)
        out = self.root / 'reports'
        out.mkdir()
        calls = []
        types = {'aarch64': 0xaa64, 'arm64ec': 0xa641, 'x86_64': 0x8664, 'i686': 0x14c}
        def command(argv, name):
            calls.append(argv)
            if '-o' not in argv:
                return
            target = Path(argv[argv.index('-o') + 1])
            arch = name.split('-')[0]
            if target.suffix == '.o':
                target.write_bytes(struct.pack('<H', types[arch]) + b'object')
            else:
                header = bytearray(0x48)
                header[:2] = b'MZ'
                struct.pack_into('<I', header, 0x3c, 0x40)
                header[0x40:0x44] = b'PE\0\0'
                struct.pack_into('<H', header, 0x44, 0x8664 if arch == 'arm64ec' else types[arch])
                target.write_bytes(header)
        result = {}
        producer.smoke(bundle, out, self.root, command, result)
        self.assertEqual(len(calls), 24)
        self.assertEqual(len(result['target_smokes']), 8)
        self.assertEqual({(x['arch'], x['language']) for x in result['target_smokes']},
                         {(arch, suffix) for arch in types for suffix in ['gcc', 'g++']})
        self.assertTrue(all(x['target_execution'] == 'NOT_ENABLED' for x in result['target_smokes']))
        self.assertTrue(all(not argv[0].endswith('.exe') for argv in calls))


if __name__ == '__main__':
    unittest.main()
