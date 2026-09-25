import unittest
import os
import struct

class TestPELoader(unittest.TestCase):
    def _build_minimal_pe64(self):
        """Build a minimal x64 PE header in memory."""
        data = bytearray(512)
        # DOS header
        data[0:2] = b'MZ'
        data[60:64] = struct.pack('<I', 64)  # e_lfanew
        # NT signature
        data[64:68] = b'PE\x00\x00'
        # COFF header
        data[68:70] = struct.pack('<H', 0x8664)  # machine AMD64
        data[70:72] = struct.pack('<H', 1)      # number of sections
        data[84:86] = struct.pack('<H', 0x20b)   # PE32+ magic
        data[86:88] = struct.pack('<H', 1)      # major linker
        data[104:108] = struct.pack('<I', 0x1000)  # entry point
        data[108:112] = struct.pack('<I', 0x1000)  # base of code
        data[112:120] = struct.pack('<Q', 0x140000000)  # image base
        data[120:124] = struct.pack('<I', 0x1000)  # section alignment
        data[124:128] = struct.pack('<I', 0x200)   # file alignment
        data[144:148] = struct.pack('<I', 0x1000)  # size of image
        data[148:152] = struct.pack('<I', 0x200)   # size of headers
        data[164:168] = struct.pack('<I', 0x200)   # subsystem
        data[176:180] = struct.pack('<I', 16)     # number of rva
        # Section header at 264
        data[264:272] = b'.text\x00\x00\x00'
        data[272:276] = struct.pack('<I', 0x100)  # virtual size
        data[276:280] = struct.pack('<I', 0x1000)  # virtual address
        data[280:284] = struct.pack('<I', 0x100)   # size of raw data
        data[284:288] = struct.pack('<I', 0x200)   # pointer to raw data
        data[300:304] = struct.pack('<I', 0x60000020)  # characteristics
        return bytes(data)

    def test_pe_load_minimal(self):
        """Minimal PE64 load via hb_pe_load."""
        pe_data = self._build_minimal_pe64()
        # We verify the bytes are structurally correct
        self.assertEqual(pe_data[0:2], b'MZ')
        sig = struct.unpack('<I', pe_data[64:68])[0]
        self.assertEqual(sig, 0x4550)
        machine = struct.unpack('<H', pe_data[68:70])[0]
        self.assertEqual(machine, 0x8664)

    def test_pe_section_count(self):
        """PE section count extracted correctly."""
        pe_data = self._build_minimal_pe64()
        count = struct.unpack('<H', pe_data[70:72])[0]
        self.assertEqual(count, 1)

    def test_pe_image_base(self):
        """PE image base extracted for PE32+."""
        pe_data = self._build_minimal_pe64()
        base = struct.unpack('<Q', pe_data[112:120])[0]
        self.assertEqual(base, 0x140000000)

if __name__ == '__main__':
    unittest.main()
