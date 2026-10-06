# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('portable_paths', Path(__file__).resolve().parents[2] / 'check_portable_paths.py')
portable = importlib.util.module_from_spec(spec)
spec.loader.exec_module(portable)


class PortablePathsTests(unittest.TestCase):
    def test_every_device_with_extensions_and_case(self):
        names = ['CON', 'PRN', 'AUX', 'NUL'] + [f'{prefix}{i}' for prefix in ['COM', 'LPT'] for i in range(1, 10)]
        for name in names:
            for spelling in [name, name.lower(), name.title()]:
                for suffix in ['', '.c', '.long.extension']:
                    with self.subTest(name=spelling+suffix):
                        self.assertTrue(portable.violations(['reference/' + spelling + suffix]))
        self.assertTrue(portable.violations(['AUX.c/nested.txt']))

    def test_forbidden_characters_and_suffixes(self):
        for character in '<>:"|?*\\' + '\x01':
            self.assertTrue(portable.violations(['a' + character + 'b']))
        for name in ['file.', 'file ', 'dir./file', 'dir /file']:
            self.assertTrue(portable.violations([name]))

    def test_length_boundary(self):
        self.assertFalse(portable.violations(['a' * 240]))
        self.assertTrue(portable.violations(['a' * 241]))
        self.assertTrue(portable.violations(['a' * 239 + '\U0001f600']))

    def test_case_collisions_include_directory_prefixes(self):
        for paths in [['file.c', 'FILE.c'], ['Dir/a.c', 'dir/b.c'], ['A/B/c', 'a/b/c']]:
            self.assertTrue(portable.violations(paths))
        self.assertFalse(portable.violations(['same/a.c', 'same/b.c', 'same/a.c']))

    def test_valid_unicode_spaces_and_nondevice_stems(self):
        self.assertFalse(portable.violations(['tests/собрать-runner.sh', 'a file.c', 'auxiliary.c',
                                            'x87-aux.c', 'COM10.c', 'CONTEXT.h', 'dir.with.dot/file.c']))


if __name__ == '__main__':
    unittest.main()
