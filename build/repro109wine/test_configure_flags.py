"""Test the owned configure comparison without importing build/vendor code."""
import ast
import os
from pathlib import Path
import re
import shlex
import unittest


SOURCE = Path(os.environ.get('REPRO109_FLAGS_SOURCE', str(Path(__file__).with_name('build_wine.py'))))
tree = ast.parse(SOURCE.read_text())
node = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'configured_compilers')
namespace = {'re': re, 'shlex': shlex}
exec(compile(ast.Module(body=[node], type_ignores=[]), str(SOURCE), 'exec'), namespace)
compare = namespace['configured_compilers']


def makefile(selected, changes=None, missing=()):
    changes = changes or {}
    return ''.join(name + ' = ' + changes.get(name, value) + '\n'
                   for name, value in selected.items() if name not in missing)


class ConfigureFlagsTests(unittest.TestCase):
    def setUp(self):
        self.selected = {'CC': '/Xcode/clang', 'CXX': '/Xcode/clang++',
                         'aarch64_CC': '/llvm/aarch64-gcc', 'arm64ec_CC': '/llvm/arm64ec-gcc',
                         'x86_64_CC': '/llvm/x86_64-gcc', 'i386_CC': '/llvm/i686-gcc'}

    def test_exact_six_compilers_preserve_argv(self):
        rows = compare(makefile(self.selected), self.selected)
        self.assertEqual(len(rows), 6)
        self.assertTrue(all(row['requested_argv'] == row['configured_argv'] and
                            row['configure_added_argv'] == [] for row in rows))

    def test_observed_cc_gnu23_is_recorded(self):
        rows = compare(makefile(self.selected, {'CC': '/Xcode/clang -std=gnu23'}), self.selected)
        self.assertEqual(rows[0]['requested_argv'], ['/Xcode/clang'])
        self.assertEqual(rows[0]['configured_argv'], ['/Xcode/clang', '-std=gnu23'])
        self.assertEqual(rows[0]['configure_added_argv'], ['-std=gnu23'])

    def test_gnu23_rejected_for_every_sibling(self):
        for name in ['CXX', 'aarch64_CC', 'arm64ec_CC', 'x86_64_CC', 'i386_CC', 'arm64ec_CXX']:
            with self.subTest(name=name):
                selected = dict(self.selected)
                selected.setdefault(name, '/llvm/arm64ec-g++')
                with self.assertRaises(ValueError):
                    compare(makefile(selected, {name: selected[name] + ' -std=gnu23'}), selected)

    def test_other_standards_extra_tokens_and_duplicates_rejected(self):
        for suffix in [' -std=gnu17', ' -std=gnu11', ' -std=gnu23 -O0',
                       ' -O0 -std=gnu23', ' -std=gnu23 -std=gnu23', ' -DUNPINNED=1']:
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                compare(makefile(self.selected, {'CC': self.selected['CC'] + suffix}), self.selected)

    def test_compiler_replacement_and_requested_flag_removal_rejected(self):
        for replacement in ['/other/clang -std=gnu23', 'ccache /Xcode/clang -std=gnu23']:
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                compare(makefile(self.selected, {'CC': replacement}), self.selected)
        selected = dict(self.selected, CC='/Xcode/clang -O2')
        with self.assertRaises(ValueError):
            compare(makefile(selected, {'CC': '/Xcode/clang -std=gnu23'}), selected)

    def test_already_requested_standard_exact_only(self):
        selected = dict(self.selected, CC='/Xcode/clang -std=gnu23')
        self.assertEqual(compare(makefile(selected), selected)[0]['configure_added_argv'], [])
        with self.assertRaises(ValueError):
            compare(makefile(selected, {'CC': selected['CC'] + ' -std=gnu23'}), selected)

    def test_required_missing_duplicate_and_empty_rejected(self):
        for name in self.selected:
            with self.subTest(name=name), self.assertRaises(ValueError):
                compare(makefile(self.selected, missing=[name]), self.selected)
        with self.assertRaises(ValueError):
            compare(makefile(self.selected) + 'CC = /Xcode/clang\n', self.selected)
        with self.assertRaises(ValueError):
            compare(makefile(self.selected, {'CC': ''}), self.selected)

    def test_optional_cross_cxx_not_emitted_remains_explicit(self):
        selected = dict(self.selected, aarch64_CXX='/llvm/aarch64-g++')
        rows = compare(makefile(selected, missing=['aarch64_CXX']), selected)
        self.assertEqual(rows[-1]['state'], 'NOT_EMITTED')
        self.assertNotIn('configured_argv', rows[-1])

    def test_quoted_path_and_pinned_guest_flags_preserved(self):
        selected = dict(self.selected, CC=shlex.join(['/Xcode space/clang']),
                        arm64ec_CC=shlex.join(['/llvm space/arm64ec-gcc', '-mllvm', '-selected=true']))
        rows = compare(makefile(selected, {'CC': selected['CC'] + ' -std=gnu23'}), selected)
        self.assertEqual(rows[0]['configured_argv'], ['/Xcode space/clang', '-std=gnu23'])
        ec = next(row for row in rows if row['name'] == 'arm64ec_CC')
        self.assertEqual(ec['configured_argv'], ['/llvm space/arm64ec-gcc', '-mllvm', '-selected=true'])


if __name__ == '__main__':
    unittest.main()
