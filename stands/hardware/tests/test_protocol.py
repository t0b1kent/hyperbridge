# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
"""Small protocol fixtures only: no translator, table sweep, Wine or game runs."""
import gzip
import io
import hashlib
import json
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import common
import hwflags
import merge
import run
import plan


class MergeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.rows = [{'key': key, 'got': [value, None, 0], 'defined_bad': False}
                     for value, key in enumerate(['a.gz:2', 'a.gz:10', 'a.gz:20', 'b.gz:1', 'b.gz:9', 'b.gz:12'])]
        self.serial = b''.join((json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode() for row in self.rows)
        self.override = patch.dict(common.COUNTS, {'hwflags': {'full': len(self.rows), 'quick': 2}})
        self.override.start()
        self.addCleanup(self.override.stop)

    def shard(self, index, shards=3):
        directory = self.root / str(index)
        directory.mkdir()
        rows = self.rows[index::shards]
        payload = b''.join((json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode() for row in rows)
        (directory / 'semantic.jsonl.gz').write_bytes(gzip.compress(payload))
        (directory / 'raw.jsonl.gz').write_bytes(gzip.compress(b''))
        (directory / 'native.log').write_text('fixture\n')
        evidence = {p.name: common.sha(p) for p in directory.iterdir()}
        report = {'gate': 'HB_HWFLAGS', 'component': 'hwflags', 'mode': 'full', 'arm': 'off',
                  'shards': shards, 'index': index, 'candidate_sha256': 'candidate', 'data_sha256': 'data',
                  'runner_sha256': 'runner', 'engine_env': {}, 'flavor': 'accepted', 'build': {},
                  'counts': {'checked': len(rows), 'known': 1}, 'groups': {}, 'complete': True,
                  'status': 'PASS', 'evidence_sha256': evidence, 'canonical_sha256': hashlib.sha256(payload).hexdigest(),
                  'seconds': 1, 'cpu_seconds': {'user': 0.2, 'system': 0.1}}
        common.write_json(directory / 'RESULT.json', report)
        return directory

    def test_interleaved_shards_restore_numeric_serial_order(self):
        dirs = [self.shard(i) for i in (2, 0, 1)]
        result = merge.merge_group(dirs, self.root / 'merged')
        self.assertEqual(result['canonical_sha256'], hashlib.sha256(self.serial).hexdigest())
        self.assertEqual(gzip.decompress((self.root / 'merged/semantic.jsonl.gz').read_bytes()), self.serial)

    def test_missing_or_duplicate_shards_cannot_pass(self):
        dirs = [self.shard(i) for i in range(3)]
        for bad in [dirs[:2], [dirs[0], dirs[0], dirs[2]]]:
            with self.assertRaises(ValueError):
                merge.merge_group(bad, self.root / 'invalid')

    def test_changed_artifact_cannot_pass(self):
        dirs = [self.shard(i) for i in range(3)]
        (dirs[1] / 'semantic.jsonl.gz').write_bytes(gzip.compress(b'{"key":"wrong:1"}\n'))
        with self.assertRaises(ValueError):
            merge.merge_group(dirs, self.root / 'invalid')

    def test_different_runner_cannot_merge(self):
        dirs = [self.shard(i) for i in range(3)]
        path = dirs[1] / 'RESULT.json'
        report = json.loads(path.read_text())
        report['runner_sha256'] = 'other runner'
        common.write_json(path, report)
        with self.assertRaises(ValueError):
            merge.merge_group(dirs, self.root / 'invalid')

    def test_simd_classification_is_not_in_legacy_hash(self):
        record = {'key': 'x:10', 'comparison': {'classes': []}, 'classification': 'KNOWN', 'form': 'arbitrary'}
        expected = b'{"comparison":{"classes":[]},"key":"x:10"}\n'
        self.assertEqual(common.semantic_bytes('hwsimd', record), expected)
        record['classification'] = 'FIXED'
        self.assertEqual(common.semantic_bytes('hwsimd', record), expected)


class ComparisonTests(unittest.TestCase):
    def test_negative_patch_applies_away_from_start_of_file(self):
        # Regression for first hosted failure: a hunk starting at line 1 implies
        # start-of-file context and cannot be relocated to this actual function.
        negative = Path(__file__).resolve().parents[1] / 'controls/div-overflow-disabled.patch'
        body = ('int MacRunnerDivOverflowMode() {\n'
                '  static const int Mode = [] {\n'
                '    const char* Value = getenv("MACRUNNER_FEX_DIV_OVERFLOW_DE");\n'
                "    return (Value && Value[0] == '1' && !Value[1]) ? 1 : 0;\n"
                '  }();\n  return Mode;\n}\n')
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'FEXCore/Source/Interface/Core/OpcodeDispatcher.cpp'
            source.parent.mkdir(parents=True)
            source.write_text('// prefix\n' * 100 + body + '// suffix\n')
            checked = subprocess.run(['git', 'apply', '--check', str(negative)], cwd=directory, capture_output=True)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            applied = subprocess.run(['git', 'apply', str(negative)], cwd=directory, capture_output=True)
            self.assertEqual(applied.returncode, 0, applied.stderr)
            self.assertIn('const char* Value = nullptr;', source.read_text())

    def test_timeout_keeps_captured_stdout_and_stderr(self):
        raw, native = io.StringIO(), io.StringIO()
        error = subprocess.TimeoutExpired('fixture', 55, output=b'{"id":0}\n', stderr=b'fault\n')
        with patch.object(hwflags.active_timeout, 'run', side_effect=error):
            with self.assertRaises(subprocess.TimeoutExpired):
                hwflags.run_batch(Path('unused-runner'), [], 0, {}, raw, native)
        self.assertEqual(raw.getvalue(), '{"id":0}\n')
        self.assertEqual(native.getvalue(), 'fault\n')

    def test_automatic_and_full_matrices_have_exact_coverage(self):
        quick = plan.matrix('quick')['include']
        full = plan.matrix('full')['include']
        self.assertEqual(len(quick), 4)
        self.assertEqual(len(full), 20)
        self.assertTrue(all(x['mode'] == 'quick' and x['shards'] == 1 for x in quick))
        for component in common.COUNTS:
            for arm in ['off', 'on']:
                selected = [x for x in full if x['component'] == component and x['arm'] == arm and x['mode'] == 'full']
                self.assertEqual([x['index'] for x in selected], [0, 1, 2, 3])
                self.assertTrue(all(x['shards'] == 4 for x in selected))

    def test_defined_result_mutation_is_new_not_known(self):
        row = hwflags.Row('out-arithmetic.txt.gz', 1, 'ADD.rr', 64, 0, 1, 1, None, False, 2, None, 0, '')
        state = {'regs': {'rax': '2'}, 'rflags': '0', 'status': 'ok', 'state_valid': True}
        equal = hwflags.compare(row, state)
        self.assertFalse(equal['defined_bad'])
        state['regs']['rax'] = '3'
        broken = hwflags.compare(row, state)
        self.assertTrue(broken['defined_bad'])
        self.assertTrue(hwflags.classify(row, broken, {'got': [3, None, 0]})[0])

    def test_quick_cannot_be_sharded_with_changed_sampling(self):
        with self.assertRaises(ValueError):
            next(run.selected('hwflags', 'quick', 4, 0))

    def test_timeout_is_not_a_successful_negative_control(self):
        report = {'flavor': 'negative', 'status': 'FAIL', 'complete': True,
                  'counts': {'defined_bad': 3, 'new': 3, 'checked': common.COUNTS['hwflags']['quick']}}
        self.assertTrue(merge.negative_check(report))
        report['error'] = 'TimeoutError'
        self.assertFalse(merge.negative_check(report))
        report.pop('error')
        report['complete'] = False
        self.assertFalse(merge.negative_check(report))

    def test_env_is_data_and_has_no_private_paths(self):
        common.validate_environment({'FEX_TSOENABLED': '1', 'MACRUNNER_FEX_DIV_OVERFLOW_DE': '1'})
        for env in [{'DYLD_LIBRARY_PATH': '.'}, {'FEX_SECRET_KEY': '1'}, {'FEX_SMCCHECKS': 'x;echo'},
                    {'MACRUNNER_FEX_OVERLAY': 'path'}, {'FEX_SMCCHECKS': '/private/path'}]:
            with self.assertRaises(ValueError):
                common.validate_environment(env)


if __name__ == '__main__':
    unittest.main()
