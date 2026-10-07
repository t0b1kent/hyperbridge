"""Own fixtures only. No network, compilers, vendor imports, or game processes."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
import build as recipe
import candidate_source as source


class CandidateTests(unittest.TestCase):
    def setUp(self):
        base = os.environ.get('REPRO109_TEST_TMP')
        if not base or not Path(base).is_dir():
            raise RuntimeError('Set REPRO109_TEST_TMP to an existing owned scratch directory')
        self.temporary = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.tail = self.root / 'tail'
        self.tail.mkdir()
        self.out = self.root / 'out'
        self.out.mkdir()
        rows = []
        for name in ['z.patch', 'a.patch']:
            p = self.tail / name
            p.write_bytes(name.encode())
            rows.append(dict(file=name, sha256=source.sha(p)))
        self.product = dict(public_base_series_sha256='a' * 64)
        self.order = dict(schema=1, base_series_sha256='a' * 64, patches=rows)
        self.pin = dict(candidate_order_file='candidate.json', candidate_patch_count=2,
                        candidate_revision='b' * 40, candidate_directory='tail',
                        supplement_source='original.patch',
                        supplement_files=['unittests/Native/X87Region.cpp', 'unittests/Native/X87Region.md'])
        text = ''.join('diff --git a/' + n + ' b/' + n + '\nnew file mode 100644\n--- /dev/null\n+++ b/' +
                       n + '\n@@ -0,0 +1 @@\n+own fixture\n' for n in
                       ['production.cpp'] + self.pin['supplement_files'])
        (self.root / 'original.patch').write_text(text)
        self.pin['supplement_source_sha256'] = source.sha(self.root / 'original.patch')
        self.seal()

    def seal(self):
        p = self.tail / 'candidate.json'
        p.write_text(json.dumps(self.order))
        self.pin['candidate_manifest_sha256'] = source.sha(p)

    def test_literal_order_is_preserved(self):
        rows = source.candidate(self.tail, self.pin, self.product)
        self.assertEqual([r['file'] for r in rows], ['z.patch', 'a.patch'])

    def test_manifest_drift_refused(self):
        (self.tail / 'candidate.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'pin differs'):
            source.candidate(self.tail, self.pin, self.product)

    def test_patch_drift_refused(self):
        (self.tail / 'z.patch').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'SHA differs'):
            source.candidate(self.tail, self.pin, self.product)

    def test_duplicate_refused(self):
        self.order['patches'][1] = self.order['patches'][0]
        self.seal()
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            source.candidate(self.tail, self.pin, self.product)

    def test_mapping_instead_of_patch_array_refused(self):
        self.order['patches'] = {}
        self.seal()
        with self.assertRaisesRegex(ValueError, 'count differs'):
            source.candidate(self.tail, self.pin, self.product)

    def test_foreign_patch_path_refused(self):
        self.order['patches'][0]['file'] = '../escape.patch'
        self.seal()
        with self.assertRaisesRegex(ValueError, 'Unsafe'):
            source.candidate(self.tail, self.pin, self.product)

    def test_patch_symlink_refused(self):
        (self.tail / 'z.patch').unlink()
        (self.tail / 'z.patch').symlink_to(self.root / 'original.patch')
        with self.assertRaisesRegex(ValueError, 'foreign'):
            source.candidate(self.tail, self.pin, self.product)

    def test_wrong_base_series_refused(self):
        with self.assertRaisesRegex(ValueError, 'base series'):
            source.candidate(self.tail, self.pin, dict(public_base_series_sha256='c' * 64))

    def test_only_the_two_source_tests_are_extracted(self):
        raw = source.supplement(self.root, self.pin)
        self.assertEqual(raw.count(b'diff --git '), 2)
        self.assertNotIn(b'production.cpp', raw)

    def test_existing_file_supplement_refused(self):
        p = self.root / 'original.patch'
        p.write_bytes(p.read_bytes().replace(b'new file mode 100644\n', b''))
        self.pin['supplement_source_sha256'] = source.sha(p)
        with self.assertRaisesRegex(ValueError, 'add each'):
            source.supplement(self.root, self.pin)

    def test_check_failure_stops_before_apply(self):
        seen = []
        def run(argv, name):
            seen.append(name)
            raise ValueError('owned check refusal')
        with self.assertRaisesRegex(ValueError, 'check refusal'):
            source.apply(self.root, self.tail, self.pin, self.product, self.root, self.out, run)
        self.assertEqual(seen, ['c9-check-01'])

    def test_product_missing_extra_and_changed_refused(self):
        expected = {f'own/{i}': 'a' * 64 for i in range(6925)}
        for kind in ['missing', 'extra', 'changed']:
            with self.subTest(kind=kind):
                actual = dict(expected)
                if kind == 'missing':
                    actual.pop('own/0')
                elif kind == 'extra':
                    actual['extra'] = 'b' * 64
                else:
                    actual['own/0'] = 'b' * 64
                with patch.object(source, 'inventory', return_value=actual):
                    with self.assertRaisesRegex(ValueError, 'postimages differ'):
                        source.verify_product(self.root, dict(product_source_postimages=expected))

    def test_source_directory_symlink_refused(self):
        (self.root / 'foreign').symlink_to(self.tail, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'directory symlink'):
            source.inventory(self.root)

    def test_archive_preserves_licenses_and_excludes_compile_logs(self):
        for name in ['fex64/engine/own.dll', 'fex64/licenses/FEX/LICENSE',
                     'fex64/native-stand/stand_runner', 'fex64/native-stand/compile_commands.json',
                     'ENGINE-environment.json']:
            p = self.out / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b'own fixture')
        row = recipe.archive(self.out, ['fex64'])
        import tarfile
        with tarfile.open(self.out / row['path']) as stream:
            names = stream.getnames()
        self.assertIn('fex64/licenses/FEX/LICENSE', names)
        self.assertIn('fex64/native-stand/stand_runner', names)
        self.assertNotIn('fex64/native-stand/compile_commands.json', names)

    def test_recipe_plan_without_network(self):
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('unexpected command')):
            pin, product, engine, locks, tools = recipe.inputs()
        self.assertEqual(len(product['product_source_postimages']), 6925)
        self.assertEqual(len(engine['environment']), 60)
        self.assertEqual(len(locks['fex32']['patches']), 61)

    def test_cold_cli_plan_does_not_dirty_checkout_with_bytecode(self):
        import shutil
        checkout = self.root / 'cold-checkout'
        shutil.copytree(HERE, checkout, ignore=shutil.ignore_patterns('__pycache__'))
        p = subprocess.run([sys.executable, '-I', str(checkout / 'build.py'), '--check-inputs'],
                           capture_output=True, text=True, timeout=15)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)['status'], 'PLAN_ONLY')
        self.assertEqual(list(checkout.rglob('*.pyc')), [])

    def test_real_builder_refuses_candidate_before_compiling(self):
        for refusal_stage in ['prepared', 'submodules']:
            with self.subTest(stage=refusal_stage):
                self.builder_refusal(refusal_stage)

    def test_actual_workflow_empty_and_selected_wrapper(self):
        workflow = HERE.parents[1] / '.github/workflows/repro109-fex-c9-macos15-arm64.yml'
        section = workflow.read_text().split('- name: Build unsigned source components\n', 1)[1]
        section = section.split('- name:', 1)[0].split('run: |\n', 1)[1]
        script = '\n'.join(l[10:] for l in section.splitlines() if l.startswith('          '))
        bindir = self.root / 'bin'
        bindir.mkdir()
        stub = bindir / 'python3'
        stub.write_text('#!/bin/bash\nprintf "%s\\n" "$@"\n')
        stub.chmod(0o700)
        for value in ['', 'fex64', 'fex32', 'invalid;echo surprise']:
            with self.subTest(selector=value):
                temp = self.root / ('wrapper-' + (value if value in ['fex64', 'fex32'] else str(len(value))))
                temp.mkdir()
                env = dict(os.environ, REPRO109_ONLY=value, RUNNER_TEMP=str(temp),
                           PATH=str(bindir) + ':/usr/bin:/bin')
                p = subprocess.run(['/bin/bash', '-u', '-c', script], cwd=self.root, env=env,
                                   capture_output=True, text=True, timeout=10)
                if value.startswith('invalid'):
                    self.assertEqual(p.returncode, 2)
                    self.assertFalse((temp / 'repro109-fex-c9-driver.log').exists())
                    continue
                self.assertEqual(p.returncode, 0, p.stderr)
                args = (temp / 'repro109-fex-c9-driver.log').read_text().splitlines()
                self.assertEqual(args[:4], ['-I', '-B', 'build/repro109fex/build.py', '--out'])
                self.assertEqual(args[5:], ['--only', value] if value else [])

    def builder_refusal(self, refusal_stage):
        fex = recipe.fex
        pin, _, _, locks, tools = recipe.inputs()
        lock = copy.deepcopy(locks['fex64'])
        lock.update({k: pin['platform'][k] for k in
                     ['xcode', 'xcode_build', 'sdk', 'deployment_target', 'apple_clang_build', 'linker_lc']})
        lock['repo_source_revision'] = pin['base_revision']
        out = self.root / ('builder-' + refusal_stage)
        commands, stages = [], []
        patch_shas = {}
        for row in lock['patches']:
            patch_shas[Path(row['path']).name] = row['sha256']
            patch_shas[Path(row['path']).name.split('-', 1)[1]] = row['sha256']
            patch_shas[Path(lock['public_patch_paths'][row['path']]).name] = row['sha256']
        def command(argv, cwd, output, name, env, timeout=2400):
            commands.append(argv)
            if argv[:3] == ['git', 'init', '-q']:
                Path(argv[3]).mkdir(parents=True, exist_ok=True)
            if name == 'own-repo-checkout':
                for row in lock['patches']:
                    p = Path(cwd) / lock['public_patch_paths'][row['path']]
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_bytes(b'own public-source fixture')
            if name == 'apple-ld-version':
                (output / (name + '.log')).write_text('PROJECT:ld-1167.5\n')
            if name.startswith('tool-'):
                (output / (name + '.log')).write_text(' '.join(r['version'] for r in tools['tools']) + '\n')
        def output(argv, cwd=None, **kwargs):
            if argv == ['xcodebuild', '-version']:
                return 'Xcode 16.4\nBuild version 16F6\n'
            if argv == ['clang', '--version']:
                return 'Apple clang version 17.0.0\n'
            if argv[:2] == ['xcrun', '--find']:
                return argv[2] + '\n'
            if '--show-sdk-version' in argv:
                return '15.5\n'
            if '--show-sdk-path' in argv:
                return '/owned-sdk\n'
            if argv == ['git', 'rev-parse', 'HEAD']:
                if Path(cwd).name == 'macrunner-source':
                    return pin['base_revision'] + '\n'
                for row in lock['submodules']:
                    if str(cwd).endswith(row['path']):
                        return row['revision'] + '\n'
                return lock['base'] + '\n'
            raise AssertionError('Unexpected fixture command: ' + repr(argv))
        def overlay(stage, *args):
            stages.append(stage)
            if stage == refusal_stage:
                raise ValueError('owned precompile refusal')
            return dict(status='OWN_FIXTURE')
        with patch.object(fex, 'cloud_only'), patch.object(fex, 'HERE', HERE / 'base/repro109'), \
             patch.object(fex.platform, 'platform', return_value='OWN_FIXTURE_DARWIN_ARM64'), \
             patch.object(fex, 'prepare_build_tools', return_value=self.root), \
             patch.object(fex, 'run', side_effect=command), \
             patch.object(fex, 'verify_source', return_value=dict(files=3577)), \
             patch.object(fex, 'sha', side_effect=lambda p: patch_shas[Path(p).name]), \
             patch.object(fex.subprocess, 'check_output', side_effect=output), \
             patch.object(fex.subprocess, 'run', return_value=subprocess.CompletedProcess([], 2)):
            with self.assertRaisesRegex(ValueError, 'owned precompile refusal'):
                fex.build(out, lock, tools, source_overlay=overlay)
        self.assertEqual(stages, ['prepared'] if refusal_stage == 'prepared' else ['prepared', 'submodules'])
        self.assertFalse(any(a[:2] in (['cmake', '-S'], ['cmake', '--build']) for a in commands))
        fetches = [a for a in commands if a[:2] == ['git', 'fetch']]
        self.assertEqual(len(fetches), 2 if refusal_stage == 'prepared' else 8)


if __name__ == '__main__':
    unittest.main(verbosity=2)
