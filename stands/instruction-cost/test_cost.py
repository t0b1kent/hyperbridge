# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
import copy
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate
import measure


class CostTests(unittest.TestCase):
    def record(self):
        return {'status': 'COMPILED', 'execution': 'NOT_RUN', 'host_hex': '1f2003d5c0035fd6' + '00000000',
                'allocation_bytes': 12, 'subblocks': [[0, 8]], 'guest_instructions': 1,
                'host_code_bytes': 8, 'compile_ns': 123}

    def test_counts_code_not_trailing_allocation(self):
        result = measure.decode_cost(self.record())
        self.assertEqual(result['arm_instructions'], 2)
        self.assertEqual(result['arm_per_guest'], 2)
        self.assertEqual(result['allocation_bytes'], 12)

    def test_bad_ranges_and_missing_decode_fail(self):
        for blocks in ([], [[0, 8], [4, 4]], [[0, 16]], [[1, 4]], [[0, 3]], [[-4, 4]]):
            record = self.record(); record['subblocks'] = blocks
            with self.assertRaises(ValueError): measure.decode_cost(record)
        record = self.record(); record['host_hex'] = 'ffffffff' * 3
        with self.assertRaises(ValueError): measure.decode_cost(record)

    def result(self):
        cost = measure.decode_cost(self.record())
        return {'schema': 1, 'forms_sha256': 'forms', 'host_features': 'features', 'aa': 'MATCH',
                'published_commit': 'accepted', 'candidate_sha256': 'candidate', 'engine_env': {},
                'rows': [{'name': 'one', 'off': copy.deepcopy(cost), 'on': copy.deepcopy(cost)}]}

    def test_negative_growth_and_guest_denominator(self):
        baseline = self.result(); candidate = copy.deepcopy(baseline)
        self.assertEqual(measure.compare(candidate, baseline)['status'], 'NO_GROWTH')
        candidate['rows'][0]['on']['arm_instructions'] += 1
        self.assertEqual(measure.compare(candidate, baseline)['status'], 'GROWTH')
        candidate['rows'][0]['on']['guest_instructions'] += 1
        self.assertEqual(measure.compare(candidate, baseline)['status'], 'INCOMPARABLE')

    def test_absent_or_different_host_is_not_no_growth(self):
        baseline = self.result(); candidate = copy.deepcopy(baseline)
        self.assertEqual(measure.compare(candidate, None)['status'], 'BASELINE_REQUIRED')
        candidate['host_features'] = 'other'
        self.assertEqual(measure.compare(candidate, baseline)['status'], 'INCOMPARABLE')

    def test_all_authored_forms_assemble_and_decode(self):
        with tempfile.TemporaryDirectory() as directory:
            cases = generate.generate(directory)
        self.assertEqual(len(cases), 26)
        self.assertEqual(sum(c['group'] == 'comparison' for c in cases), 21)
        self.assertTrue(all(c['input_instructions'] > 0 for c in cases))
        self.assertTrue(all('pages=' not in generate.request(c) for c in cases))


if __name__ == '__main__': unittest.main()
