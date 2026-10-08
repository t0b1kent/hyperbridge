"""Offline probes of source selection, full test list and owned bounded commands."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('llvm22_probe', HERE / 'run.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class LLVM22Tests(unittest.TestCase):
    def test_require_active_without_assert(self):
        with self.assertRaisesRegex(ValueError, 'sentinel'):
            probe.require(False, 'sentinel')

    def test_local_cloud_gate_before_source(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, 'Owned GitHub cloud only'):
                probe.cloud_gate()

    def test_foreign_repository_refused(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS':'true', 'GITHUB_REPOSITORY':'foreign/example'}, clear=True):
            with self.assertRaisesRegex(ValueError, 'Owned GitHub cloud only'):
                probe.cloud_gate()

    def test_linux_host_and_python_are_required(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS':'true', 'GITHUB_REPOSITORY':'t0b1kent/hyperbridge'}, clear=True), \
             patch.object(probe.platform, 'system', return_value='Darwin'):
            with self.assertRaisesRegex(ValueError, 'Linux x86-64 host required'):
                probe.cloud_gate()

    def test_owned_linux_cloud_gate(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS':'true', 'GITHUB_REPOSITORY':'t0b1kent/hyperbridge'}, clear=True), \
             patch.object(probe.platform, 'system', return_value='Linux'), \
             patch.object(probe.platform, 'machine', return_value='x86_64'), \
             patch.object(probe.sys, 'version_info', (3,13,7)):
            probe.cloud_gate()

    def test_static_aarch64_source_is_explicit(self):
        args = probe.cmake_args(Path('/owned/source'), Path('/owned/build'), '/usr/bin/gcc-13', '/usr/bin/g++-13')
        self.assertIn('-DLLVM_TARGETS_TO_BUILD=AArch64', args)
        self.assertIn('-DLLVM_ENABLE_PROJECTS=clang', args)
        self.assertIn('-DBUILD_SHARED_LIBS=OFF', args)
        self.assertIn('-DLLVM_LINK_LLVM_DYLIB=OFF', args)
        self.assertIn('-DLLVM_PARALLEL_LINK_JOBS=1', args)
        self.assertIn('-DLLVM_ENABLE_ASSERTIONS=ON', args)
        self.assertEqual(args[args.index('-S')+1], '/owned/source/llvm')

    def test_q_counts_preserve_small_load_counts(self):
        rows = probe.asm_counts('  ldp q0, q1, [sp]\n  LDR Q31, [sp]\n  ldp x0, x1, [sp]\n// ldr q0\n')
        self.assertEqual((rows['ldp_q'], rows['ldr_q']), (1,1))

    def test_entry_scope_excludes_native_exit_and_comments(self):
        text = ('  ldp q30, q31, [sp]\n.seh_proc native\n  ldr q0, [sp]\n.seh_endproc\n'
                '.seh_proc "$ientry_thunk$cdecl$v$v"\n  ldp q0, q1, [sp]\n'
                '  stp q2, q3, [sp]\n// ldr q0, [sp]\n  ret\n.seh_endproc\n'
                '.seh_proc $iexit_thunk$cdecl$v$v\n  ldr q4, [sp]\n.seh_endproc\n')
        rows = probe.entry_thunk_counts(text)
        self.assertEqual(list(rows), ['$ientry_thunk$cdecl$v$v'])
        entry = next(iter(rows.values()))
        self.assertEqual((entry['ldp_q'], entry['ldr_q'], entry['stp_q'], entry['instructions']), (1, 0, 1, 3))
        self.assertEqual((entry['first_line'], entry['last_line']), (5, 10))

    def test_entry_missing_is_unavailable_not_zero(self):
        with self.assertRaisesRegex(ValueError, 'No ARM64EC'):
            probe.entry_thunk_counts('.seh_proc native\n  ret\n.seh_endproc\n')

    def test_entry_bounds_reject_unterminated_nested_duplicate(self):
        entry = '.seh_proc $ientry_thunk$cdecl$v$v\n  ret\n.seh_endproc\n'
        for text in [entry + entry, entry[:-13], '.seh_proc native\n' + entry, '.seh_endproc\n']:
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    probe.entry_thunk_counts(text)

    def test_entry_shape_reports_each_function_and_rejects_set_drift(self):
        before = {'entry': {'ldp_q': 5, 'ldr_q': 0, 'stp_q': 5}}
        after = {'entry': {'ldp_q': 0, 'ldr_q': 10, 'stp_q': 5}}
        self.assertTrue(probe.compare_entries(before, after)['entry']['level4_q_restore_shape_matches'])
        after['entry']['ldr_q'] = 1
        self.assertFalse(probe.compare_entries(before, after)['entry']['level4_q_restore_shape_matches'])
        with self.assertRaisesRegex(ValueError, 'set differs'):
            probe.compare_entries(before, {'other': after['entry']})

    def test_all_pinned_level4_run_lines_are_selected(self):
        text = '\n'.join(row[1:] for row in (HERE/'LLVM22-ARM64EC-Q-RESTORES.patch').read_text().splitlines()
                         if row.startswith('+; RUN:'))
        rows = probe.run_lines(text, Path('/owned source/test.ll'), Path('/owned result/test'))
        self.assertEqual(len(rows), 17)
        self.assertTrue(any('arm64ec-exit-thunks.ll' in row for row in rows))
        self.assertTrue(any('aarch64-pc-windows-msvc' in row for row in rows))
        self.assertTrue(any('diff ' in row for row in rows))
        self.assertNotIn('%', '\n'.join(rows))

    def test_missing_run_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'RUN list differs'):
            probe.run_lines('; RUN: llc %s', Path('/source/test.ll'), Path('/result/test'))

    def test_unknown_substitution_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unsupported test substitution'):
            probe.run_lines('\n'.join(['; RUN: llc %unknown']*17), Path('/source/test.ll'), Path('/result/test'))

    def test_default_and_input_bytes_are_pinned(self):
        lock = json.loads((HERE/'llvm22.lock.json').read_text())
        manifest = json.loads((HERE/'SOURCE-MANIFEST.json').read_text())
        self.assertIs(lock['default'], False)
        self.assertIs(manifest['default'], False)
        self.assertEqual(manifest['patch_sha256'], probe.sha(HERE/'LLVM22-ARM64EC-Q-RESTORES.patch'))
        self.assertEqual(probe.sha(HERE/'SOURCE-MANIFEST.json'), lock['source_manifest_sha256'])
        self.assertEqual(probe.sha(HERE/'synthetic.c'), lock['synthetic_sha256'])

    def test_owned_command_success_retains_complete_raw(self):
        root = Path(os.environ['REPRO109_TEST_SCRATCH'])
        root.mkdir(parents=True, exist_ok=True)
        rows = []
        probe.command([sys.executable, '-I', '-c', 'print("bounded-own-control")'], root/'success.log', root,
                      time.monotonic()+10, rows, 1024)
        self.assertEqual(rows[0]['state'], 'PRESENT')
        self.assertEqual((root/'success.log').read_text(), 'bounded-own-control\n')

    def test_empty_command_raw_marked_empty(self):
        root = Path(os.environ['REPRO109_TEST_SCRATCH'])
        root.mkdir(parents=True, exist_ok=True)
        rows = []
        probe.command([sys.executable, '-I', '-c', 'pass'], root/'empty.log', root,
                      time.monotonic()+10, rows, 1024)
        self.assertEqual(rows[0]['state'], 'EMPTY')

    def test_failed_command_cannot_pass(self):
        root = Path(os.environ['REPRO109_TEST_SCRATCH'])
        root.mkdir(parents=True, exist_ok=True)
        rows = []
        with self.assertRaisesRegex(ValueError, 'Command failed'):
            probe.command([sys.executable, '-I', '-c', 'raise SystemExit(7)'], root/'failed.log', root,
                          time.monotonic()+10, rows, 1024)
        self.assertEqual(rows[0]['rc'], 7)

    def test_oversize_raw_cannot_pass_even_when_child_succeeded(self):
        root = Path(os.environ['REPRO109_TEST_SCRATCH'])
        root.mkdir(parents=True, exist_ok=True)
        rows = []
        with self.assertRaisesRegex(ValueError, 'Command failed'):
            probe.command([sys.executable, '-I', '-c', 'print("x"*4096)'], root/'oversize.log', root,
                          time.monotonic()+10, rows, 1024)
        self.assertEqual(rows[0]['state'], 'DROPPED')
        self.assertEqual(rows[0]['bytes'], (root/'oversize.log').stat().st_size)

    def test_timeout_stops_only_owned_child_and_marks_failure(self):
        root = Path(os.environ['REPRO109_TEST_SCRATCH'])
        root.mkdir(parents=True, exist_ok=True)
        rows = []
        with self.assertRaisesRegex(ValueError, 'Command failed'):
            probe.command([sys.executable, '-I', '-c', 'import time; time.sleep(5)'], root/'timeout.log', root,
                          time.monotonic()+0.1, rows, 1024)
        self.assertEqual(rows[0]['state'], 'FAILED_TIMEOUT')
        self.assertNotEqual(rows[0]['rc'], 0)


if __name__ == '__main__':
    unittest.main()
