"""Offline cross-run controls. Tiny synthetic ELF files are never executed."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('llvm22_reuse_test', HERE / 'reuse.py')
reuse = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reuse)


class ReuseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(os.environ['REPRO109_TEST_SCRATCH'])
        cls.root.mkdir(parents=True, exist_ok=False)
        cls.selection = json.loads((HERE / 'REUSE-BUILD.json').read_bytes())
        cls.old = reuse.load_producer(cls.selection)
        cls.old_lock = json.loads((reuse.PRODUCER / 'llvm22.lock.json').read_bytes())
        cls.lock = json.loads((HERE / 'llvm22.lock.json').read_bytes())
        cls.recipe = cls.root / 'fixture-recipe'
        cls.recipe.mkdir()
        cls.files = {}
        primary = b'; RUN: llc %s | FileCheck %s\n' * 17
        cls.files['test-inputs/arm64ec-split-thunk-q-restores.ll'] = primary
        source = {'files': [{'path': 'llvm/test/CodeGen/AArch64/arm64ec-split-thunk-q-restores.ll',
                             'patched_sha256': hashlib.sha256(primary).hexdigest()}]}
        source_bytes = json.dumps(source).encode()
        (cls.recipe / 'SOURCE-MANIFEST.json').write_bytes(source_bytes)
        extra = {'schema': 1, 'source_patch_sha256': cls.old_lock['patch_sha256'], 'tests': []}
        for name, count in [('arm64ec-split-q-restores.ll', 6),
                            ('large-thunk-split-q-restores.ll', 9), ('windows-split-q-restores.ll', 12)]:
            data = b'; fixture authored IR\n'
            cls.files['test-inputs/' + name] = data
            extra['tests'].append({'file': name, 'bytes': len(data),
                                   'sha256': hashlib.sha256(data).hexdigest(), 'run_directives': count})
        extra_bytes = json.dumps(extra).encode()
        (cls.recipe / 'EXTRA-TESTS.json').write_bytes(extra_bytes)
        cls.fixture_lock = dict(cls.old_lock,
                                source_manifest_sha256=hashlib.sha256(source_bytes).hexdigest(),
                                extra_tests_manifest_sha256=hashlib.sha256(extra_bytes).hexdigest())
        (cls.recipe / 'llvm22.lock.json').write_text(json.dumps(cls.fixture_lock))
        rows = []
        for name in cls.old_lock['build_targets']:
            data = b'\x7fELF\x02\x01' + b'\0' * 12 + b'\x3e\x00' + b'NEVER_EXECUTED_FIXTURE'
            cls.files['tools/' + name] = data
            rows.append({'name': name, 'path': 'tools/' + name, 'bytes': len(data),
                         'sha256': hashlib.sha256(data).hexdigest()})
        cls.files['tools/LICENSE.TXT'] = b'Owned synthetic fixture license\n'
        cls.manifest = {key: cls.selection[key] for key in ('repository', 'revision', 'run_id')}
        cls.manifest.update(schema=1, lock_sha256=reuse.sha(cls.recipe / 'llvm22.lock.json'),
                            **{key: cls.fixture_lock[key] for key in
                               ('source_sha256', 'patch_sha256', 'source_manifest_sha256',
                                'extra_tests_manifest_sha256')}, tools=rows,
                            test={'path': 'test-inputs/arm64ec-split-thunk-q-restores.ll',
                                  'sha256': hashlib.sha256(primary).hexdigest(), 'bytes': len(primary)},
                            extra_tests=[dict(row, path='test-inputs/' + row['file']) for row in extra['tests']],
                            license={'path': 'tools/LICENSE.TXT',
                                     'sha256': hashlib.sha256(cls.files['tools/LICENSE.TXT']).hexdigest()})
        cls.receipt = {'phase': 'build', 'status': 'PASS_BOUNDARY_NOT_PRODUCT_ACCEPTANCE', 'first_failure': None}
        cls.archive = cls.pack('valid')
        cls.sealed = dict(cls.selection, status='ACTUAL_EXPORT_VERIFIED', archive_sha256=reuse.sha(cls.archive))

    @classmethod
    def pack(cls, name, manifest=None, receipt=None, corrupt_tool=False):
        manifest = manifest or cls.manifest
        data = json.dumps(manifest).encode()
        receipt = dict(receipt or cls.receipt, shared_build_manifest_sha256=hashlib.sha256(data).hexdigest())
        files = dict(cls.files, **{'SHARED-BUILD.json': data, 'RESULT.json': json.dumps(receipt).encode()})
        if corrupt_tool:
            files['tools/llc'] += b'corrupt'
        archive = cls.root / (name + '.tar.gz')
        with tarfile.open(archive, 'w:gz') as stream:
            for path, value in files.items():
                member = tarfile.TarInfo(path)
                member.mode = 0o755 if path in ['tools/' + tool for tool in cls.old_lock['build_targets']] else 0o644
                member.size = len(value)
                stream.addfile(member, io.BytesIO(value))
        return archive

    def verify(self, name, archive=None, selection=None):
        archive = archive or self.archive
        selection = selection or dict(self.sealed, archive_sha256=reuse.sha(archive))
        root = self.root / name
        root.mkdir()
        with patch.object(self.old, 'HERE', self.recipe):
            return reuse.select_old_build(self.old, archive, reuse.sha(archive), root,
                                          self.fixture_lock, selection)

    def test_01_current_inputs_and_exact_frozen_recipe(self):
        reuse.validate_inputs(self.lock, self.old_lock)
        self.assertEqual(reuse.sha(reuse.PRODUCER / 'run.py'), self.selection['producer_recipe']['run.py'])

    def test_02_draft_and_different_seal_refused_before_extract(self):
        draft = dict(self.selection, status='DRAFT_WAITING_FOR_ACTUAL_EXPORT', archive_sha256=None)
        with self.assertRaisesRegex(ValueError, 'collected and sealed'):
            reuse.select_old_build(self.old, self.archive, reuse.sha(self.archive),
                                   self.root / 'draft', self.old_lock, draft)
        with self.assertRaisesRegex(ValueError, 'actual export seal'):
            reuse.select_old_build(self.old, self.archive, reuse.sha(self.archive),
                                   self.root / 'bad-seal', self.old_lock,
                                   dict(self.sealed, archive_sha256='0' * 64))
        self.assertFalse((self.root / 'draft/shared').exists())
        self.assertFalse((self.root / 'bad-seal/shared').exists())

    def test_03_real_old_verifier_preserves_tools_and_test(self):
        tools, primary, manifest = self.verify('valid-selection')
        self.assertEqual(manifest['run_id'], '37736522794')
        self.assertEqual(reuse.sha(primary), self.manifest['test']['sha256'])
        reuse.check_tools(tools, manifest)

    def test_04_wrong_producer_run_revision_and_repository_refused(self):
        for key, value in [('repository', 'fixture/foreign'), ('revision', '0' * 40), ('run_id', '0')]:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'Foreign shared producer'):
                self.verify('wrong-' + key, selection=dict(self.sealed, **{key: value}))

    def test_05_failed_export_and_corrupt_tools_refused(self):
        archive = self.pack('failed-export', receipt=dict(self.receipt, first_failure={'fixture': True}))
        with self.assertRaisesRegex(ValueError, 'complete boundary'):
            self.verify('failed-export-selected', archive=archive)
        archive = self.pack('corrupt-tools', corrupt_tool=True)
        with self.assertRaisesRegex(ValueError, 'Shared file bytes differ'):
            self.verify('corrupt-tools-selected', archive=archive)

    def test_06_changed_compiler_recipe_refused(self):
        for key, value in [('source_sha256', '0' * 64), ('patch_sha256', '0' * 64), ('parallel_compile', 2)]:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'Compiler recipe differs'):
                reuse.validate_inputs(dict(self.lock, **{key: value}), self.old_lock)

    def test_07_missing_support_set_refused(self):
        with self.assertRaisesRegex(ValueError, 'Support input set'):
            reuse.validate_inputs(dict(self.lock, support_inputs=self.lock['support_inputs'][:1]), self.old_lock)

    def test_08_support_extraction_copies_only_two_pinned_members(self):
        rows, members = [], {}
        for row in self.lock['support_inputs']:
            data = ('; owned fixture ' + row['file'] + '\n').encode()
            rows.append(dict(row, bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
            members[self.lock['source_root'] + '/llvm/test/CodeGen/AArch64/' + row['file']] = data
        members['ignored/foreign-source.c'] = b'NEVER_EXECUTED'
        archive = self.root / 'support-fixture.tar.xz'
        with tarfile.open(archive, 'w:xz') as stream:
            for path, data in members.items():
                member = tarfile.TarInfo(path)
                member.size = len(data)
                stream.addfile(member, io.BytesIO(data))
        inputs = self.root / 'support-inputs'
        inputs.mkdir()
        reuse.extract_support(dict(self.lock, support_inputs=rows), archive, inputs)
        self.assertEqual({path.name for path in inputs.iterdir()}, {row['file'] for row in rows})
        for row in rows:
            self.assertEqual(reuse.sha(inputs / row['file']), row['sha256'])

    def test_09_mac_cloud_gate_prevents_network_and_elf_execution(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}), \
             patch.object(reuse.urllib.request, 'urlopen') as network, \
             patch.object(reuse.current, 'run_checks') as checks, \
             patch('sys.argv', ['reuse.py', '--phase', 'level4-test', '--out', str(self.root / 'forbidden'),
                                '--build-archive', str(self.archive), '--build-sha256-file', 'unused']):
            with self.assertRaisesRegex(ValueError, 'Owned GitHub cloud'):
                reuse.main()
        network.assert_not_called()
        checks.assert_not_called()
        self.assertFalse((self.root / 'forbidden').exists())

    def test_10_current_six_ir_inputs_feed_all_44_run_lines(self):
        # Reconstruct our newly added primary IR from our pinned patch, not vendor sources.
        patch_text = (HERE / 'LLVM22-ARM64EC-Q-RESTORES.patch').read_text()
        marker = '+++ b/llvm/test/CodeGen/AArch64/arm64ec-split-thunk-q-restores.ll\n'
        section = patch_text.split(marker, 1)[1].split('\ndiff --git ', 1)[0]
        primary = ''.join(line[1:] + '\n' for line in section.splitlines() if line.startswith('+')).encode()
        test = self.root / 'arm64ec-split-thunk-q-restores.ll'
        test.write_bytes(primary)
        rows, data_by_name = [], {}
        for row in self.lock['support_inputs']:
            data = ('; owned support fixture ' + row['file'] + '\n').encode()
            rows.append(dict(row, bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
            data_by_name[row['file']] = data
        archive = self.root / 'current-support-fixture.tar.xz'
        with tarfile.open(archive, 'w:xz') as stream:
            for name, data in data_by_name.items():
                member = tarfile.TarInfo(self.lock['source_root'] + '/llvm/test/CodeGen/AArch64/' + name)
                member.size = len(data)
                stream.addfile(member, io.BytesIO(data))
        lock = dict(self.lock, support_inputs=rows)
        selected, inputs, adjustment = reuse.prepare_tests(test, self.root, lock, archive)
        self.assertEqual(len(inputs), 6)
        self.assertEqual(test.read_bytes(), primary)
        self.assertEqual(adjustment['run_index'], 10)
        self.assertEqual(adjustment['changed_run_count'], 1)
        self.assertEqual(adjustment['original_sha256'], hashlib.sha256(primary).hexdigest())
        self.assertEqual(adjustment['effective_sha256'], reuse.sha(selected))
        self.assertEqual(adjustment['effective_bytes'] - adjustment['original_bytes'], 5)
        old_runs = reuse.current.run_lines(primary.decode(), selected, self.root / 'run-a', 17)
        fixed_runs = reuse.current.run_lines(selected.read_text(), selected, self.root / 'run-a', 17)
        self.assertEqual([i for i, (a, b) in enumerate(zip(old_runs, fixed_runs)) if a != b], [10])
        self.assertIn(' -o - ', fixed_runs[10])
        result = {}
        with patch.object(reuse.current, 'command') as command:
            reuse.current.run_checks('level4-test', Path('never-executed-tools'), selected,
                                      self.root, self.root, 0, [], lock, result)
        self.assertEqual(command.call_count, 44)
        self.assertEqual(result['test_run_lines_passed'], 44)
        self.assertEqual([row['run_lines_passed'] for row in result['tests']], [17, 6, 9, 12])
        self.assertEqual(len({call.args[1] for call in command.call_args_list}), 44)
        pipelines = [call.args[0][-1] for call in command.call_args_list
                     if call.args[0][-1].startswith('llc ') and '| FileCheck ' in call.args[0][-1]]
        self.assertGreater(len(pipelines), 1)
        for line in pipelines:
            with self.subTest(run=line):
                self.assertTrue(' -o - ' in line or ' < ' in line, line)

    def test_12_primary_stdout_fix_refuses_unknown_input_before_write(self):
        test = self.root / 'unknown-primary.ll'
        original = b'; RUN: llc unexpected.ll | FileCheck unexpected.ll\n'
        test.write_bytes(original)
        with self.assertRaisesRegex(ValueError, 'Primary stdout fix preimage differs'):
            reuse.fix_primary_test_stdout(test)
        self.assertEqual(test.read_bytes(), original)

    def test_13_primary_stdout_fix_is_not_silently_applied_twice(self):
        patch_text = (HERE / 'LLVM22-ARM64EC-Q-RESTORES.patch').read_text()
        marker = '+++ b/llvm/test/CodeGen/AArch64/arm64ec-split-thunk-q-restores.ll\n'
        section = patch_text.split(marker, 1)[1].split('\ndiff --git ', 1)[0]
        primary = ''.join(line[1:] + '\n' for line in section.splitlines() if line.startswith('+')).encode()
        test = self.root / 'double-apply-primary.ll'
        test.write_bytes(primary)
        reuse.fix_primary_test_stdout(test)
        original = test.read_bytes()
        with self.assertRaisesRegex(ValueError, 'Primary stdout fix preimage differs'):
            reuse.fix_primary_test_stdout(test)
        self.assertEqual(test.read_bytes(), original)

    def test_11_same_size_support_corruption_refused(self):
        data = b'; owned support fixture\n'
        rows = [dict(row, bytes=len(data), sha256='0' * 64) for row in self.lock['support_inputs']]
        archive = self.root / 'corrupt-support-fixture.tar.xz'
        with tarfile.open(archive, 'w:xz') as stream:
            for row in rows:
                member = tarfile.TarInfo(self.lock['source_root'] + '/llvm/test/CodeGen/AArch64/' + row['file'])
                member.size = len(data)
                stream.addfile(member, io.BytesIO(data))
        inputs = self.root / 'corrupt-support-inputs'
        inputs.mkdir()
        with self.assertRaisesRegex(ValueError, 'Support member SHA differs'):
            reuse.extract_support(dict(self.lock, support_inputs=rows), archive, inputs)


if __name__ == '__main__':
    unittest.main()
