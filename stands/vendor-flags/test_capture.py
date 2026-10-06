# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
import gzip
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from capture import probe


class CaptureEvidenceTests(unittest.TestCase):
    def test_timeout_preserves_partial_bytes_and_is_not_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            result = probe([sys.executable, '-c', 'import time; print("partial-row", flush=True); time.sleep(30)'],
                           out, out, 'timeout', 'first', 1)
            self.assertTrue(result['timed_out'])
            self.assertIsNone(result['rc'])
            self.assertEqual(result['capture_state'], 'PROCESS_GONE')
            self.assertEqual(gzip.decompress((out / result['file']).read_bytes()).strip(), b'partial-row')

    def test_normal_and_nonzero_exit_are_distinct(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            for rc, state in [(0, 'PRESENT'), (3, 'FAILED')]:
                result = probe([sys.executable, '-c', f'print("row"); raise SystemExit({rc})'],
                               out, out, 'exit', str(rc), 5)
                self.assertEqual(result['capture_state'], state)
                self.assertEqual(result['rc'], rc)
                self.assertEqual(result['rows'], 1)
                self.assertFalse(result['timed_out'])


if __name__ == '__main__': unittest.main()
