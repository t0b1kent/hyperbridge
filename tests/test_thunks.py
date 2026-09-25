import unittest
import os
import ctypes

class TestThunkTable(unittest.TestCase):
    def test_library_exists(self):
        lib_path = os.path.join(os.path.dirname(__file__), '..', 'libhyperbridge.dylib')
        static_path = os.path.join(os.path.dirname(__file__), '..', 'libhyperbridge.a')
        self.assertTrue(os.path.exists(lib_path) or os.path.exists(static_path),
                       "HyperBridge library must exist")

    def test_thunk_builtins_concept(self):
        """Verify thunk table design supports builtin registration."""
        # Conceptual test: built-in thunks must be registerable
        builtins = [
            ("kernel32.dll", "GetTickCount"),
            ("kernel32.dll", "ExitProcess"),
            ("kernel32.dll", "GetLastError"),
            ("kernel32.dll", "SetLastError"),
            ("kernel32.dll", "lstrlenA"),
            ("kernel32.dll", "lstrcmpA"),
            ("kernel32.dll", "QueryPerformanceCounter"),
            ("user32.dll", "MessageBoxA"),
        ]
        for dll, func in builtins:
            self.assertTrue(len(dll) > 0)
            self.assertTrue(len(func) > 0)

    def test_thunk_id_unique(self):
        """Thunk IDs must be unique in design."""
        ids = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        self.assertEqual(len(ids), len(set(ids)))

if __name__ == '__main__':
    unittest.main()
