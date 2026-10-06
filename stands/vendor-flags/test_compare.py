# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
import gzip
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import compare


class CellComparisonTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.classes = patch.object(compare, 'CLASSES', ['logic'])
        self.count = patch.object(compare, 'EXPECTED', 2)
        self.classes.start()
        self.count.start()
        self.addCleanup(self.classes.stop)
        self.addCleanup(self.count.stop)

    def sample(self, vendor, second_flags='0202', operand='00000001'):
        path = self.root / vendor
        path.mkdir()
        prefix = f'AND.reg 32 0202 {operand} 00000001 - -> 00000001 - '
        raw = (prefix + '0202\n' + prefix + second_flags + '\n').encode()
        records = []
        for repeat in ['first', 'second']:
            name = repeat + '.txt.gz'
            (path / name).write_bytes(gzip.compress(raw))
            records.append({'rc': 0, 'rows': 2, 'skipped_forms': 0, 'file': name,
                            'raw_sha256': hashlib.sha256(raw).hexdigest(), 'gzip_sha256': compare.sha(path / name)})
        return path, {'status': 'PASS', 'source_sha256': {'source': 'same'}, 'checked': 2,
                      'tables': {'logic': records}, 'machine': {'vendor': vendor}}

    def test_undefined_flag_agreement_is_reported_per_cell(self):
        intel, amd = self.sample('Intel', '0212'), self.sample('AMD')
        out = self.root / 'out'
        out.mkdir()
        result = compare.compare(intel, amd, out)
        self.assertEqual(result['counts']['equal'], 1)
        self.assertEqual(result['counts']['different'], 1)
        self.assertEqual(result['counts']['equal_AF'], 1)
        self.assertEqual(result['counts']['equal_CF'], 2)

    def test_different_inputs_are_not_a_vendor_difference(self):
        intel, amd = self.sample('Intel'), self.sample('AMD', operand='00000002')
        out = self.root / 'out'
        out.mkdir()
        with self.assertRaises(ValueError):
            compare.compare(intel, amd, out)

    def test_missing_vendor_does_not_appear_in_passed_candidates(self):
        self.assertEqual(compare.candidates(self.root), [])


if __name__ == '__main__':
    unittest.main()
