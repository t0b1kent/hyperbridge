#!/usr/bin/env python3
"""Own 32-bit encodings and integer x87 rules; no native runner or output files."""
from pathlib import Path
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'artifacts/stand32-20261001'))
import stand32
import independent_x87

cases = json.loads(Path(__file__).with_name('cases.json').read_text())
for case in cases:
    result = stand32.oracle(case)
    assert result['status'] == 'exit', result['status']
    if case['name'] == 'own_mov_eax_7':
        assert result['regs']['rax'] == 7
    elif case['name'] == 'own_fld1':
        assert result['fsw'] >> 11 & 7 == 7
        assert result['ftw'] != 0xffff
one = struct.pack('<QH', 1 << 63, 0x3fff).hex()
zero = bytes(10).hex()
infinity = struct.pack('<QH', 1 << 63, 0x7fff).hex()
assert independent_x87.tag(one) == 0
assert independent_x87.tag(zero) == 1
assert independent_x87.tag(infinity) == 2
assert independent_x87.tag(one, occupied=False) == 3
print('SYNTHETIC_REFERENCE_ONLY PASS: own MOV/FLD1 encodings and four x87 tag classes; native execution NOT_ENABLED')
