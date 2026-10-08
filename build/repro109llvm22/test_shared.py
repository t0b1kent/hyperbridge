"""Offline shared-artifact controls; fixture tools are data and never executed."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('llvm22_shared_probe', HERE / 'run.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class SharedBuildTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(os.environ['REPRO109_TEST_SCRATCH']) / self._testMethodName
        self.root.mkdir(parents=True)
        self.fixture = self.root / 'fixture'
        self.metadata = self.root / 'metadata'
        self.metadata.mkdir()
        self.lock = json.loads((HERE / 'llvm22.lock.json').read_bytes())
        self.identity = {'repository': 't0b1kent/hyperbridge', 'revision': '1' * 40, 'run_id': '109'}
        for name in ('LLVM22-ARM64EC-Q-RESTORES.patch', 'synthetic.c', 'EXTRA-TESTS.json',
                     'arm64ec-split-q-restores.ll', 'large-thunk-split-q-restores.ll',
                     'windows-split-q-restores.ll'):
            shutil.copy2(HERE / name, self.metadata / name)
        test = '; RUN: llc %s | FileCheck %s\n' * 17
        source_manifest = {'files': [{'path': 'llvm/test/CodeGen/AArch64/arm64ec-split-thunk-q-restores.ll',
                                     'patched_sha256': hashlib.sha256(test.encode()).hexdigest()}]}
        (self.metadata / 'SOURCE-MANIFEST.json').write_text(json.dumps(source_manifest))
        self.lock['source_manifest_sha256'] = probe.sha(self.metadata / 'SOURCE-MANIFEST.json')
        (self.metadata / 'llvm22.lock.json').write_text(json.dumps(self.lock))
        (self.fixture / 'tools').mkdir(parents=True)
        rows = []
        for name in self.lock['build_targets']:
            path = self.fixture / 'tools' / name
            path.write_bytes(b'\x7fELF\x02\x01' + b'\0' * 12 + b'\x3e\x00' + b'OWNED_FIXTURE_DATA')
            path.chmod(0o755)
            rows.append({'name': name, 'path': 'tools/' + name,
                         'bytes': path.stat().st_size, 'sha256': probe.sha(path)})
        (self.fixture / 'tools/LICENSE.TXT').write_text('Owned fixture license\n')
        (self.fixture / 'test-inputs').mkdir()
        self.test = self.fixture / 'test-inputs/arm64ec-split-thunk-q-restores.ll'
        self.test.write_text(test)
        extras = probe.extra_test_rows(self.lock)
        for row in extras:
            shutil.copy2(HERE / row['file'], self.fixture / 'test-inputs' / row['file'])
        self.manifest = {'schema': 1, **self.identity,
                         'lock_sha256': probe.sha(self.metadata / 'llvm22.lock.json'),
                         **{key: self.lock[key] for key in
                             ('source_sha256', 'patch_sha256', 'source_manifest_sha256',
                              'extra_tests_manifest_sha256')},
                         'tools': rows,
                          'test': {'path': 'test-inputs/' + self.test.name,
                                   'bytes': self.test.stat().st_size, 'sha256': probe.sha(self.test)},
                          'extra_tests': [dict(row, path='test-inputs/' + row['file']) for row in extras],
                         'license': {'path': 'tools/LICENSE.TXT',
                                     'sha256': probe.sha(self.fixture / 'tools/LICENSE.TXT')}}
        self.receipt = {'phase': 'build', 'status': 'PASS_BOUNDARY_NOT_PRODUCT_ACCEPTANCE', 'first_failure': None}

    def pack(self, extra=None):
        (self.fixture / 'SHARED-BUILD.json').write_text(json.dumps(self.manifest))
        self.receipt['shared_build_manifest_sha256'] = probe.sha(self.fixture / 'SHARED-BUILD.json')
        (self.fixture / 'RESULT.json').write_text(json.dumps(self.receipt))
        archive = self.root / 'build.tar.gz'
        with tarfile.open(archive, 'w:gz') as stream:
            for path in sorted(self.fixture.rglob('*')):
                stream.add(path, arcname=path.relative_to(self.fixture).as_posix(), recursive=False)
            if extra is not None:
                member = tarfile.TarInfo(extra)
                member.size = 1
                stream.addfile(member, io.BytesIO(b'x'))
        return archive

    def verify(self, archive=None, checksum=None, destination='selected'):
        archive = archive or self.pack()
        with patch.object(probe, 'HERE', self.metadata):
            return probe.prepare_shared_build(archive, checksum or probe.sha(archive),
                                              self.root / destination, self.lock, self.identity)

    def test_valid_shared_build_preserves_tool_and_test_pins(self):
        tools, test, manifest = self.verify()
        self.assertEqual(tools.name, 'tools')
        self.assertEqual(probe.sha(test), self.manifest['test']['sha256'])
        self.assertEqual(len(manifest['tools']), 4)
        self.assertEqual(len(manifest['extra_tests']), 3)

    def test_archive_sha_mismatch_before_extract(self):
        with self.assertRaisesRegex(ValueError, 'pin/size'):
            self.verify(checksum='0' * 64)
        self.assertFalse((self.root / 'selected').exists())

    def test_foreign_repository_revision_and_run_refused(self):
        for index, key in enumerate(self.identity):
            with self.subTest(key=key):
                old = self.manifest[key]
                self.manifest[key] = 'foreign'
                with self.assertRaisesRegex(ValueError, 'identity'):
                    self.verify(destination='selected-' + str(index))
                self.manifest[key] = old

    def test_failed_or_incomplete_producer_refused(self):
        for index, (key, value) in enumerate([('status', 'FAILED'), ('phase', 'patch'),
                                             ('first_failure', {'stage': 'BUILD'})]):
            old = self.receipt[key]
            self.receipt[key] = value
            with self.assertRaisesRegex(ValueError, 'complete boundary'):
                self.verify(destination='selected-' + str(index))
            self.receipt[key] = old

    def test_source_and_recipe_pins_refused(self):
        for index, key in enumerate(('source_sha256', 'patch_sha256', 'source_manifest_sha256', 'lock_sha256')):
            old = self.manifest[key]
            self.manifest[key] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'pins differ'):
                self.verify(destination='selected-' + str(index))
            self.manifest[key] = old

    def test_changed_tool_bytes_refused(self):
        (self.fixture / 'tools/llc').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'bytes differ'):
            self.verify()

    def test_tool_machine_and_mode_refused(self):
        path = self.fixture / 'tools/llc'
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'executable mode'):
            self.verify(destination='mode')
        path.chmod(0o755)
        data = path.read_bytes()
        path.write_bytes(data[:18] + b'\xb7\x00' + data[20:])
        self.manifest['tools'][0]['sha256'] = probe.sha(path)
        with self.assertRaisesRegex(ValueError, 'ELF64 x86-64'):
            self.verify(destination='machine')

    def test_changed_or_missing_test_and_license_refused(self):
        self.test.write_text('changed\n')
        with self.assertRaisesRegex(ValueError, 'bytes differ'):
            self.verify()

    def test_changed_or_missing_extra_tests_refused(self):
        for index, row in enumerate(self.manifest['extra_tests']):
            path = self.fixture / row['path']
            original = path.read_bytes()
            path.write_bytes(b'changed\n')
            with self.assertRaisesRegex(ValueError, 'bytes differ'):
                self.verify(destination='changed-' + str(index))
            path.unlink()
            with self.assertRaisesRegex(ValueError, 'bytes differ'):
                self.verify(destination='missing-' + str(index))
            path.write_bytes(original)

    def test_extra_test_row_omission_duplication_and_pin_change_refused(self):
        original = list(self.manifest['extra_tests'])
        for index, rows in enumerate([original[:-1], original + original[:1],
                                     [dict(original[0], sha256='0' * 64)] + original[1:]]):
            self.manifest['extra_tests'] = rows
            with self.assertRaisesRegex(ValueError, 'set/pins differs'):
                self.verify(destination='rows-' + str(index))
        self.manifest['extra_tests'] = original

    def test_all_four_pinned_run_lists_use_distinct_outputs(self):
        tools, test, manifest = self.verify()
        result, records, commands = {}, [], []
        with patch.object(probe, 'HERE', self.metadata), \
             patch.object(probe, 'command', side_effect=lambda *args, **kwargs: commands.append(args)):
            probe.run_checks('level4-test', tools, test, self.root / 'out', self.root,
                             time.monotonic() + 1200, records, self.lock, result)
        self.assertEqual(len(commands), 44)
        self.assertEqual(len({str(args[1]) for args in commands}), 44)
        self.assertEqual(result['test_run_lines_passed'], 44)
        self.assertEqual([row['run_lines_passed'] for row in result['tests']], [17, 6, 9, 12])
        self.assertTrue(all(row['status'] == 'PASS' for row in result['tests']))

    def test_first_extra_failure_preserves_partial_counts(self):
        tools, test, manifest = self.verify()
        result, calls = {}, []
        def fail_at_first_extra(*args, **kwargs):
            calls.append(args)
            if len(calls) == 18:
                raise ValueError('fixture first extra failure')
        with patch.object(probe, 'HERE', self.metadata), patch.object(probe, 'command', fail_at_first_extra):
            with self.assertRaisesRegex(ValueError, 'fixture first extra failure'):
                probe.run_checks('level4-test', tools, test, self.root / 'out', self.root,
                                 time.monotonic() + 1200, [], self.lock, result)
        self.assertEqual(len(calls), 18)
        self.assertEqual(result['test_run_lines_passed'], 17)
        self.assertEqual([row['run_lines_passed'] for row in result['tests']], [17, 0])
        self.assertEqual(result['tests'][-1]['status'], 'STARTED')

    def test_missing_or_duplicate_tool_set_refused(self):
        self.manifest['tools'][0] = self.manifest['tools'][1]
        with self.assertRaisesRegex(ValueError, 'tool set'):
            self.verify()

    def test_archive_traversal_and_duplicate_refused(self):
        for index, extra in enumerate(('../outside', 'RESULT.json')):
            with self.assertRaisesRegex(ValueError, 'unsafe member|duplicate member'):
                self.verify(archive=self.pack(extra), destination='selected-' + str(index))

    def test_archive_member_and_byte_caps_refused(self):
        self.lock['shared_archive_max_members'] = 1
        with self.assertRaisesRegex(ValueError, 'exceeds bounds'):
            self.verify()

    def test_shared_file_path_escape_refused(self):
        self.manifest['test']['path'] = '../outside'
        with self.assertRaisesRegex(ValueError, 'escapes inputs'):
            self.verify()

    def test_checksum_file_selects_exact_archive(self):
        archive = self.pack()
        checksum = self.root / 'build.tar.gz.sha256'
        checksum.write_text(probe.sha(archive) + '  /owned/build.tar.gz\n')
        self.assertEqual(probe.read_archive_checksum(checksum, archive), probe.sha(archive))
        checksum.write_text(probe.sha(archive) + '  other.tar.gz\n')
        with self.assertRaisesRegex(ValueError, 'selected archive'):
            probe.read_archive_checksum(checksum, archive)

    def test_consumers_do_not_download_or_recompile(self):
        archive = self.pack()
        for phase in ('level4-test', 'synthetic-asm'):
            temporary = self.root / ('runner-' + phase)
            temporary.mkdir()
            out = self.root / ('out-' + phase)
            env = {'RUNNER_TEMP': str(temporary), 'GITHUB_REPOSITORY': self.identity['repository'],
                   'GITHUB_SHA': self.identity['revision'], 'GITHUB_RUN_ID': self.identity['run_id']}
            argv = ['run.py', '--phase', phase, '--out', str(out), '--build-archive', str(archive),
                    '--build-sha256', probe.sha(archive)]
            with patch.object(probe, 'HERE', self.metadata), patch.object(probe, 'cloud_gate'), \
                 patch.dict(os.environ, env), patch.object(sys, 'argv', argv), \
                 patch.object(probe.urllib.request, 'urlopen') as download, \
                 patch.object(probe, 'cmake_args') as configure, patch.object(probe, 'command') as command, \
                 patch.object(probe, 'run_checks') as run_checks:
                probe.main()
                download.assert_not_called()
                configure.assert_not_called()
                command.assert_not_called()
                self.assertEqual(run_checks.call_args.args[0], phase)
            receipt = json.loads((out / 'RESULT.json').read_bytes())
            self.assertEqual(receipt['status'], 'PASS_BOUNDARY_NOT_PRODUCT_ACCEPTANCE')
            self.assertEqual(receipt['install'], 'SKIPPED')

    def test_missing_shared_input_cannot_fall_back_to_build(self):
        with patch.object(probe, 'cloud_gate'), patch.object(sys, 'argv',
                  ['run.py', '--phase', 'level4-test', '--out', str(self.root / 'out')]):
            with self.assertRaisesRegex(ValueError, 'require this run shared archive'):
                probe.main()
        self.assertFalse((self.root / 'out').exists())

    def test_long_build_budget_is_recorded_without_running_llvm(self):
        rows = []
        probe.command([sys.executable, '-I', '-c', 'pass'], self.root / 'own.log', self.root,
                      time.monotonic() + 10000, rows, 1024, timeout_seconds=9000)
        self.assertEqual(rows[0]['timeout_seconds'], 9000)
        self.assertEqual(rows[0]['state'], 'EMPTY')

    def test_workflow_has_one_build_and_two_dependent_checks(self):
        workflow = (HERE.parents[1] / '.github/workflows/repro109-llvm22-q-matrix.yml').read_text()
        self.assertIn('phase: [patch, build]', workflow)
        self.assertIn('phase: [level4-test, synthetic-asm]', workflow)
        self.assertIn('needs: probe', workflow)
        self.assertEqual(workflow.count('fail-fast: false'), 2)
        self.assertIn('timeout-minutes: 200', workflow)
        self.assertIn('timeout-minutes: 30', workflow)
        self.assertIn('name: repro109-llvm22-build-${{ github.sha }}', workflow)
        self.assertIn('actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093', workflow)
        self.assertEqual(self.lock['parallel_compile'], 4)
        self.assertEqual(self.lock['build_command_minutes'], 150)


if __name__ == '__main__':
    unittest.main()
