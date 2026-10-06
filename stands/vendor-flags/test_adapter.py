# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
"""Generate and inspect ABI adapters only; no compiler or hardware probe execution."""
import contextlib
import io
from pathlib import Path
import runpy
import shutil
import tempfile
import unittest

from windows_adapter import adapt


class AdapterTest(unittest.TestCase):
    def test_every_original_instruction_body_survives_windows_adapter(self):
        with tempfile.TemporaryDirectory() as temp:
            stage = Path(temp)
            probes = Path(__file__).resolve().parent / 'probes'
            for name in ['generate_core.py', 'core.c']:
                shutil.copy2(probes / name, stage / name)
            with contextlib.redirect_stdout(io.StringIO()):
                runpy.run_path(str(stage / 'generate_core.py'))
            original = (stage / 'build/core.S').read_text().splitlines()
            report = adapt(stage)
            changed = (stage / 'build/core.S').read_text().splitlines()
            self.assertGreater(report['adapted_wrappers'], 100)
            self.assertEqual(report['tested_instruction_changes'], 0)
            # Remove only the three ABI entry operations and two ABI exit pops.
            restored, index = [], 0
            while index < len(changed):
                line = changed[index]
                if line == '.globl oracle_fault_return':
                    self.assertEqual(changed[index + 1:], ['oracle_fault_return:', 'pop %rbx', 'pop %rsi', 'pop %rdi', 'ret'])
                    break
                restored.append(line)
                if line.startswith('core_') and line.endswith(':'):
                    self.assertEqual(changed[index + 1:index + 4], ['push %rdi', 'push %rsi', 'mov %rcx,%rdi'])
                    index += 3
                elif line == 'pop %rbx':
                    self.assertEqual(changed[index + 1:index + 3], ['pop %rsi', 'pop %rdi'])
                    index += 2
                index += 1
            expected = [v for v in original if not v.startswith(('.type ', '.size ', '.section .note.GNU-stack'))]
            self.assertEqual(restored, expected)
            code = (stage / 'core.c').read_text()
            self.assertNotIn('siglongjmp', code)
            self.assertNotIn('struct sigaction', code)
            self.assertIn('u->EFlags & 65535', code)
            self.assertIn('AddVectoredExceptionHandler', code)


if __name__ == '__main__':
    unittest.main()
