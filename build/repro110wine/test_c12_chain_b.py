"""Own fixtures only: c12 overlay pins, the disabled optional step and the default-off Q-restore switch."""
import hashlib
import importlib.util
import json
from pathlib import Path
import os
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
import build_wine as wine


def load_full():
    spec = importlib.util.spec_from_file_location('chain_b_full', HERE / 'build_full.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ChainBC12(unittest.TestCase):
    def setUp(self):
        self.lock = wine.inputs()
        self.full = load_full()
        self.addCleanup(setattr, self.full, 'Q_RESTORES_OVERRIDE', False)

    def test_overlay_rows_match_the_stored_files(self):
        self.assertEqual(len(self.lock['overlay']), 36)
        for row in self.lock['overlay']:
            data = (HERE / 'source' / row['path']).read_bytes()
            self.assertEqual((len(data), hashlib.sha256(data).hexdigest()), (row['bytes'], row['sha256']), row['path'])

    def test_optional_step_is_pinned_and_disabled(self):
        steps = wine.optional_steps(self.lock)
        self.assertEqual([(s['name'], s['enabled']) for s in steps], [('smc4k', False)])
        overlay = {r['path']: r['sha256'] for r in self.lock['overlay']}
        for path, pins in steps[0]['files'].items():
            self.assertEqual(overlay[path], pins['base_sha256'], path)

    def test_q_restores_default_off_and_cli_override(self):
        profile = 'github-macos26-arm64'
        self.assertIs(self.lock['toolchain']['arm64ec_split_thunk_q_restores'], False)
        self.assertIs(self.full.apply_profile(self.lock, profile)['toolchain']['arm64ec_split_thunk_q_restores'], False)
        self.full.Q_RESTORES_OVERRIDE = True
        self.assertIs(self.full.apply_profile(self.lock, profile)['toolchain']['arm64ec_split_thunk_q_restores'], True)
        self.assertIs(self.lock['toolchain']['arm64ec_split_thunk_q_restores'], False)   # the pinned lock is never rewritten
        without_key = dict(toolchain=dict(self.lock['toolchain']))
        del without_key['toolchain']['arm64ec_split_thunk_q_restores']
        self.assertNotIn('arm64ec_split_thunk_q_restores', self.full.apply_profile(without_key, profile)['toolchain'])

    def test_option_reaches_only_the_arm64ec_compilers(self):
        for enabled in (False, True):
            tool = dict(self.lock['toolchain'], arm64ec_split_thunk_q_restores=enabled)
            selected = wine.compiler_environment(Path('/llvm'), '/xc/clang', '/xc/clang++', tool)
            flagged = sorted(k for k, v in selected.items() if 'split-thunk-q-restores' in v)
            self.assertEqual(flagged, ['arm64ec_CC', 'arm64ec_CXX'] if enabled else [])


    def test_job_script_survives_an_empty_option_array_on_macos_bash(self):
        # Run 38501119332 (B0) died with "extra[@]: unbound variable": macOS /bin/bash 3.2 under `set -u`.
        script = (HERE.parents[1] / 'jobs/repro110-wine-b-c12.sh').read_text()
        self.assertNotIn('"${extra[@]}"', script.replace('${extra[@]+"${extra[@]}"}', ''))
        self.assertIn('${extra[@]+"${extra[@]}"}', script)
        import subprocess
        probe = 'set -euo pipefail; extra=(); printf "[%s]" ${extra[@]+"${extra[@]}"}; extra=(--arm64ec-q-restores); printf "[%s]" ${extra[@]+"${extra[@]}"}'
        done = subprocess.run(['/bin/bash', '-c', probe], capture_output=True, text=True)
        self.assertEqual((done.returncode, done.stdout), (0, '[][--arm64ec-q-restores]'), done.stderr)


class PreparedSources(unittest.TestCase):
    """The 47 library sources are prepared by a cheap first job and handed to the long build as a verified set."""
    def setUp(self):
        import tempfile
        self.full = load_full()
        self.temp = tempfile.TemporaryDirectory(prefix='chainb-', dir=os.environ['REPRO109_TEST_TMP'])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_build(self, source_inputs):
        order = []
        check = SimpleNamespace(validate=mock.Mock(side_effect=lambda *a: order.append('validate')),
                                dep=SimpleNamespace(read_lock=lambda: dict(raw=True)))
        deps = SimpleNamespace(read_lock=lambda: dict(toolchain={}),
                               build=mock.Mock(side_effect=lambda *a: (order.append('deps'), 1 / 0)))
        wine = SimpleNamespace(inputs=lambda: dict(toolchain={}))
        drivers = {'repro109_full_source_check': check, 'repro109_full_deps': deps, 'repro109_full_wine': wine,
                   'repro109_full_moltenvk': SimpleNamespace()}
        with mock.patch.object(self.full, 'cloud_guard'), \
             mock.patch.object(self.full, 'apply_profile', side_effect=lambda lock, profile: lock), \
             mock.patch.object(self.full, 'load_driver', side_effect=lambda name, path: drivers[name]):
            with self.assertRaises(ZeroDivisionError):
                self.full.build(self.root / 'work', dict(minutes=1), 2, 'github', None, source_inputs)
        return check, deps, order

    def test_the_prepared_set_is_rehashed_before_the_dependency_build_and_handed_to_it(self):
        prepared = self.root / 'prepared'
        prepared.mkdir()
        check, deps, order = self.run_build(prepared)
        self.assertEqual(order, ['validate', 'deps'])
        check.validate.assert_called_once_with(prepared.resolve(), dict(raw=True))
        self.assertEqual(deps.build.call_args.args[0].source_inputs, prepared.resolve())

    def test_without_a_prepared_set_the_build_downloads_as_before(self):
        check, deps, order = self.run_build(None)
        self.assertEqual(order, ['deps'])
        check.validate.assert_not_called()
        self.assertIsNone(deps.build.call_args.args[0].source_inputs)

    def test_cli_option_reaches_build(self):
        argv = ['build_full.py', '--build', '--work', str(self.root / 'w'), '--source-inputs', str(self.root / 'p')]
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(self.full, 'check_inputs', return_value={}), \
             mock.patch.object(self.full, 'build') as build:
            self.full.main()
        self.assertEqual(build.call_args.args[5], self.root / 'p')

    def test_job_script_passes_the_set_and_the_q_option_under_macos_bash_3_2(self):
        import subprocess
        stub = self.root / 'python-stub'
        stub.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$STUB_ARGS"\nexit 0\n')
        stub.chmod(0o755)
        bundle = self.root / 'bundle.tar.gz'; bundle.write_bytes(b'x')
        prepared = self.root / 'prepared'; prepared.mkdir()
        script = HERE.parents[1] / 'jobs/repro110-wine-b-c12.sh'
        for q, third, expected in (('', None, []), ('1', None, ['--arm64ec-q-restores']),
                                   ('', prepared, ['--source-inputs', str(prepared)]),
                                   ('1', prepared, ['--arm64ec-q-restores', '--source-inputs', str(prepared)])):
            with self.subTest(q=q, third=third):
                out, args = self.root / ('out' + q + str(bool(third))), self.root / ('args' + q + str(bool(third)))
                env = dict(os.environ, GITHUB_ACTIONS='true', GITHUB_REPOSITORY='t0b1kent/hyperbridge', GITHUB_RUN_ID='1',
                           RUNNER_TEMP=str(self.root / ('tmp' + q + str(bool(third)))), REPRO109_PYTHON=str(stub),
                           STUB_ARGS=str(args), REPRO110_Q_RESTORES=q)
                Path(env['RUNNER_TEMP']).mkdir()
                done = subprocess.run(['/bin/bash', str(script), str(out), str(bundle)] + ([str(third)] if third else []),
                                      env=env, capture_output=True, text=True)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                given = args.read_text().split()
                self.assertEqual(given[given.index('--build') + 1:given.index('--work')], [])
                self.assertEqual([a for a in given if a in ('--arm64ec-q-restores',)], [a for a in expected if a == '--arm64ec-q-restores'])
                self.assertEqual(('--source-inputs' in given), bool(third))
                if third:
                    self.assertEqual(given[given.index('--source-inputs') + 1], str(third))

    def test_job_script_refuses_a_missing_or_linked_source_directory(self):
        import subprocess
        stub = self.root / 'python-stub'
        stub.write_text('#!/bin/sh\nexit 0\n'); stub.chmod(0o755)
        bundle = self.root / 'bundle.tar.gz'; bundle.write_bytes(b'x')
        real = self.root / 'real'; real.mkdir()
        link = self.root / 'link'; link.symlink_to(real)
        script = HERE.parents[1] / 'jobs/repro110-wine-b-c12.sh'
        for number, bad in enumerate((self.root / 'absent', link)):
            temp = self.root / ('t%d' % number); temp.mkdir()
            env = dict(os.environ, GITHUB_ACTIONS='true', GITHUB_REPOSITORY='t0b1kent/hyperbridge', GITHUB_RUN_ID='1',
                       RUNNER_TEMP=str(temp), REPRO109_PYTHON=str(stub))
            done = subprocess.run(['/bin/bash', str(script), str(self.root / ('o%d' % number)), str(bundle), str(bad)],
                                  env=env, capture_output=True, text=True)
            self.assertNotEqual(done.returncode, 0, str(bad))

    def test_job_script_refuses_a_missing_or_linked_compiler_bundle(self):
        import subprocess
        stub = self.root / 'python-stub'
        stub.write_text('#!/bin/sh\nexit 0\n'); stub.chmod(0o755)
        real = self.root / 'real.tar.gz'; real.write_bytes(b'x')
        link = self.root / 'link.tar.gz'; link.symlink_to(real)
        script = HERE.parents[1] / 'jobs/repro110-wine-b-c12.sh'
        for number, bad in enumerate((self.root / 'absent.tar.gz', link)):
            temp = self.root / ('b%d' % number); temp.mkdir()
            env = dict(os.environ, GITHUB_ACTIONS='true', GITHUB_REPOSITORY='t0b1kent/hyperbridge', GITHUB_RUN_ID='1',
                       RUNNER_TEMP=str(temp), REPRO109_PYTHON=str(stub))
            done = subprocess.run(['/bin/bash', str(script), str(self.root / ('ob%d' % number)), str(bad)],
                                  env=env, capture_output=True, text=True)
            self.assertEqual(done.returncode, 2, str(bad) + done.stderr)
            self.assertIn('compiler bundle must be a regular file', done.stderr)

    def test_workflow_prepares_the_sources_in_the_cheap_job_and_hands_them_to_the_build(self):
        text = (HERE.parents[1] / '.github/workflows/repro110-wine-b-c12.yml').read_text()
        inputs_job, wine_job = text.split('\n  wine:\n')
        self.assertIn('build/repro110wine/prepare_sources.py --profile github-macos26-arm64', inputs_job)
        self.assertIn('name: repro110-wine-b-c12-inputs-${{ github.sha }}', inputs_job)
        self.assertIn('if: always()', inputs_job)
        self.assertIn('needs: inputs', wine_job)
        self.assertIn('actions/download-artifact', wine_job.split('Receive the verified source set')[1].split('- name:')[0])
        self.assertIn('--extract', wine_job)
        self.assertIn('repro110-wine-b-c12-prepared-inputs"', wine_job.split('Run pinned source recipe')[1])
        self.assertLess(wine_job.index('Unpack the source set'), wine_job.index('Run pinned source recipe'))
        self.assertNotIn('preflight_sources.py', text)

if __name__ == '__main__':
    unittest.main(verbosity=2)
