import unittest
import struct
import tempfile
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tools'))
from hb_pe_run import parse_pe, extract_entry_bytes, run_pe_file


class TestPERun(unittest.TestCase):
    def _build_minimal_pe64(self):
        """Build a minimal x64 PE with entry point code: mov eax, 0x1234; ret."""
        data = bytearray(1024)
        # DOS header
        data[0:2] = b'MZ'
        data[60:64] = struct.pack('<I', 64)
        # NT signature
        data[64:68] = b'PE\x00\x00'
        # COFF header
        data[68:70] = struct.pack('<H', 0x8664)
        data[70:72] = struct.pack('<H', 1)
        data[84:86] = struct.pack('<H', 240)   # size_of_optional_header
        data[86:88] = struct.pack('<H', 0x2022) # characteristics
        # Optional header (PE32+)
        data[88:90] = struct.pack('<H', 0x20b)   # magic
        data[90] = 1; data[91] = 0               # linker version
        data[104:108] = struct.pack('<I', 0x1000)  # entry_point
        data[108:112] = struct.pack('<I', 0x1000)  # base_of_code
        data[112:120] = struct.pack('<Q', 0x140000000)  # image_base
        data[120:124] = struct.pack('<I', 0x1000)  # section_alignment
        data[124:128] = struct.pack('<I', 0x200)   # file_alignment
        data[144:148] = struct.pack('<I', 0x1000)  # size_of_image
        data[148:152] = struct.pack('<I', 0x200)   # size_of_headers
        data[164:168] = struct.pack('<I', 0x200)   # subsystem
        data[176:180] = struct.pack('<I', 16)     # number_of_rva
        # Section header at 328
        s = 328
        data[s:s+8]   = b'.text\x00\x00\x00'
        data[s+8:s+12] = struct.pack('<I', 0x100)
        data[s+12:s+16] = struct.pack('<I', 0x1000)
        data[s+16:s+20] = struct.pack('<I', 0x100)
        data[s+20:s+24] = struct.pack('<I', 0x200)
        data[s+36:s+40] = struct.pack('<I', 0x60000020)
        # Code at raw 0x200: mov eax, 0x1234; ret
        data[0x200] = 0xB8
        data[0x201] = 0x34
        data[0x202] = 0x12
        data[0x203] = 0x00
        data[0x204] = 0x00
        data[0x205] = 0xC3
        return bytes(data)

    def test_parse_pe_entry_point(self):
        data = self._build_minimal_pe64()
        pe = parse_pe(data)
        self.assertEqual(pe["arch"], "x64")
        self.assertEqual(pe["entry_point_rva"], 0x1000)
        self.assertEqual(pe["image_base"], 0x140000000)

    def test_extract_entry_bytes(self):
        data = self._build_minimal_pe64()
        pe = parse_pe(data)
        entry_bytes, err = extract_entry_bytes(data, pe)
        self.assertIsNone(err)
        self.assertIsNotNone(entry_bytes)
        self.assertTrue(len(entry_bytes) >= 6)
        self.assertEqual(entry_bytes[0], 0xB8)
        self.assertEqual(entry_bytes[5], 0xC3)

    def test_run_pe_file(self):
        data = self._build_minimal_pe64()
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(data)
            path = f.name
        try:
            result = run_pe_file(path)
            self.assertEqual(result["status"], "RET")
            self.assertEqual(result["regs"][0], 0x1234)  # eax/rax
        finally:
            os.unlink(path)


if __name__ == '__main__':
    unittest.main()
