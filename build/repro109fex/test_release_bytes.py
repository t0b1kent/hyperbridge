import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_bytes as rb
import build as driver


def fixture(occurrences=6, outside=False, writable=False, signed=False, overlap=False):
    raw = bytearray(1024)
    raw[:2] = b'MZ'
    struct.pack_into('<I', raw, 0x3c, 128)
    raw[128:132] = b'PE\0\0'
    struct.pack_into('<H', raw, 134, 2)
    struct.pack_into('<H', raw, 148, 240)
    struct.pack_into('<H', raw, 152, 0x20b)
    struct.pack_into('<II', raw, 296, 1000 if signed else 0, 24 if signed else 0)
    for at, name, offset, size, flags in (
        (392, b'.rdata', 512, 256, 0xC0000040 if writable else 0x40000040),
        (432, b'.text', 512 if overlap else 768, 128, 0x60000020),
    ):
        raw[at:at + len(name)] = name
        struct.pack_into('<II', raw, at + 16, size, offset)
        struct.pack_into('<I', raw, at + 36, flags)
    for number in range(occurrences):
        start = 512 + number * 13
        raw[start:start + 12] = rb.SOURCE
    if outside:
        raw[800:812] = rb.SOURCE
    return bytes(raw)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class ReleaseBytes(unittest.TestCase):
    def setUp(self):
        self.owned_temp = Path(os.environ.get('REPRO109_TEST_TMP', ''))
        if not os.environ.get('REPRO109_TEST_TMP') or not self.owned_temp.is_dir():
            raise RuntimeError('Set REPRO109_TEST_TMP to an existing owned scratch directory')

    def test_six_paths_preserve_code_headers_and_size(self):
        raw = fixture()
        expected = digest(raw.replace(rb.SOURCE, rb.CANONICAL))
        after, result = rb.normalize(raw, expected)
        self.assertEqual(after[:512], raw[:512])
        self.assertEqual(after[768:], raw[768:])
        self.assertEqual(len(after), len(raw))
        self.assertEqual(result['source_occurrences'], 6)
        self.assertEqual(result['changed_bytes'], 66)
        self.assertEqual(after.count(rb.CANONICAL), 6)
        self.assertEqual(result['output_sha256'], expected)

    def test_already_release_bytes_is_explicit(self):
        raw = fixture().replace(rb.SOURCE, rb.CANONICAL)
        after, result = rb.normalize(raw, digest(raw))
        self.assertEqual(after, raw)
        self.assertEqual(result['status'], 'ALREADY_RELEASE_BYTES')
        self.assertEqual(result['changed_bytes'], 0)

    def test_wrong_count_refuses(self):

        for number in (0, 5, 7):
            raw = fixture(number)
            with self.subTest(number=number), self.assertRaisesRegex(ValueError, 'six pinned'):
                rb.normalize(raw, digest(fixture().replace(rb.SOURCE, rb.CANONICAL)))

    def test_existing_release_hash_preserves_original_path_spelling(self):
        raw = fixture()
        after, result = rb.normalize(raw, digest(raw))
        self.assertEqual(after, raw)
        self.assertEqual(result['source_occurrences'], 6)
        self.assertEqual(result['changed_bytes'], 0)
        self.assertEqual(result['status'], 'ALREADY_RELEASE_BYTES')

    def test_hash_mismatch_refuses(self):
        with self.assertRaisesRegex(ValueError, 'SHA256 differs'):
            rb.normalize(fixture(), '0' * 64)

    def test_executable_path_refuses(self):
        raw = fixture(5, outside=True)
        with self.assertRaisesRegex(ValueError, 'outside .rdata'):
            rb.normalize(raw, digest(raw.replace(rb.SOURCE, rb.CANONICAL)))

    def test_writable_section_refuses(self):
        raw = fixture(writable=True)
        with self.assertRaisesRegex(ValueError, 'read-only'):
            rb.normalize(raw, digest(raw.replace(rb.SOURCE, rb.CANONICAL)))

    def test_overlapping_code_refuses(self):
        raw = fixture(overlap=True)
        with self.assertRaisesRegex(ValueError, 'overlaps'):
            rb.normalize(raw, digest(raw.replace(rb.SOURCE, rb.CANONICAL)))

    def test_signed_PE_refuses(self):
        raw = fixture(signed=True)
        with self.assertRaisesRegex(ValueError, 'signed PE'):
            rb.normalize(raw, digest(raw.replace(rb.SOURCE, rb.CANONICAL)))

    def test_invalid_PE_and_bounds_refuse(self):
        for raw in (b'MZ', b'x' * 1024, fixture()[:600]):
            with self.subTest(bytes=len(raw)), self.assertRaises(ValueError):
                rb.normalize(raw, '0' * 64)

    def output_fixture(self, root):
        raw = fixture()
        names = ['fex/aarch64-windows/xtajit64.dll',
                 'wine/lib/wine/aarch64-windows/libarm64ecfex.dll']
        files = {}
        for name in names:
            path = root / 'engine' / name
            path.parent.mkdir(parents=True)
            path.write_bytes(raw)
            files[name] = dict(bytes=len(raw), sha256=digest(raw))
        manifest = dict(files=files, ec_modules=2, unique_ec_binaries=1)
        (root / 'outputs.json').write_text(json.dumps(manifest) + '\n')
        return raw, names

    def test_output_peers_manifest_and_preimages(self):
        with tempfile.TemporaryDirectory(dir=self.owned_temp) as directory:
            root = Path(directory)
            raw, names = self.output_fixture(root)
            manifest = (root / 'outputs.json').read_bytes()
            expected = digest(raw.replace(rb.SOURCE, rb.CANONICAL))
            with patch.dict(rb.REFERENCE_HASHES, {'fex64': expected}):
                result = rb.canonicalize_outputs(root, 'fex64')
            self.assertEqual(result['status'], 'PASS_RELEASE_DLL_BYTES')
            self.assertEqual((root / 'outputs.before-pe-paths.json').read_bytes(), manifest)
            after = json.loads((root / 'outputs.json').read_text())
            for name in names:
                self.assertEqual(digest((root / 'engine' / name).read_bytes()), expected)
                self.assertEqual(after['files'][name]['sha256'], expected)
                backup = root / 'pe-path-preimages' / (name.replace('/', '__') + '.before')
                self.assertEqual(backup.read_bytes(), raw)
            self.assertEqual(after['ec_modules'], 2)
            self.assertEqual(after['unique_ec_binaries'], 1)

    def test_bad_hash_leaves_outputs_and_manifest_unchanged(self):
        with tempfile.TemporaryDirectory(dir=self.owned_temp) as directory:
            root = Path(directory)
            raw, names = self.output_fixture(root)
            before = (root / 'outputs.json').read_bytes()
            with patch.dict(rb.REFERENCE_HASHES, {'fex64': '0' * 64}):
                with self.assertRaisesRegex(ValueError, 'SHA256 differs'):
                    rb.canonicalize_outputs(root, 'fex64')
            self.assertEqual((root / 'outputs.json').read_bytes(), before)
            self.assertFalse((root / 'pe-path-preimages').exists())
            self.assertTrue(all((root / 'engine' / name).read_bytes() == raw for name in names))

    def test_guard_failure_produces_nonzero_driver_exit(self):
        with patch.object(sys, 'argv', ['build.py', '--out', 'unused']), \
             patch.object(driver, 'build', side_effect=ValueError('Release DLL SHA256 differs')):
            self.assertEqual(driver.main(), 1)

    def test_artifact_boundary_verifies_then_refuses_drift(self):
        with tempfile.TemporaryDirectory(dir=self.owned_temp) as directory:
            out = Path(directory)
            root = out / 'fex64'
            root.mkdir()
            raw, names = self.output_fixture(root)
            expected = digest(raw.replace(rb.SOURCE, rb.CANONICAL))
            with patch.dict(rb.REFERENCE_HASHES, {'fex64': expected}):
                rb.canonicalize_outputs(root, 'fex64')
                self.assertEqual(rb.verify(out, ['fex64']), 0)
                target = root / 'engine' / names[0]
                target.write_bytes(target.read_bytes() + b'drift')
                with self.assertRaisesRegex(ValueError, 'changed after'):
                    rb.verify(out, ['fex64'])

    def test_artifact_boundary_failure_produces_nonzero_exit(self):
        with patch.object(sys, 'argv', ['release_bytes.py', '--verify', 'unused', '--only', 'fex64']), \
             patch.object(rb, 'verify', side_effect=ValueError('Release DLL changed after canonicalization')):
            self.assertEqual(rb.main(), 1)


if __name__ == '__main__':
    unittest.main()
