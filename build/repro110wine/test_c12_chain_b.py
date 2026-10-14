"""Own fixtures only: c12 overlay pins, the disabled optional step and the default-off Q-restore switch."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

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


if __name__ == '__main__':
    unittest.main(verbosity=2)
