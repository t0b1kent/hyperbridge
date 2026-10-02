#!/usr/bin/env python3
"""Offline own-code example. No native runner, Wine, GPU or files written."""
from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
for directory in ['stand-diff-20260930', 'stand-diff-stage4-20261001',
                  'stand-diff-stage5-20261001', 'stand-diff-stage6-20261002']:
    sys.path.insert(0, str(ROOT / 'artifacts' / directory))
import span_diff
import intel_vex
import mxcsr_flags

example = json.loads(Path(__file__).with_name('synthetic.json').read_text())
initial, data, stack = span_diff.initial(0)
result = span_diff.reference(bytes.fromhex(example['code_hex']), example['rip'], initial, data, stack)
assert result['status'] == 'exit' and result['regs']['rax'] == 7
assert result['rip'] == example['rip'] + len(bytes.fromhex(example['code_hex']))
assert intel_vex.arithmetic('sub', 0x7f800000, 0x7f800000, 32, 0x1f80) == 0xffc00000
assert mxcsr_flags.arithmetic_flags('sub', 0x7f800000, 0x7f800000, 32, 0x1f80) == mxcsr_flags.IE
assert mxcsr_flags.arithmetic_flags('div', 0x3f800000, 0, 32, 0x1f80) == mxcsr_flags.ZE
assert mxcsr_flags.float_to_int(0x3fc00000, 32, 32, 0x1f80, truncate=True) == mxcsr_flags.PE
print('SYNTHETIC_REFERENCE_ONLY PASS: own integer encoding, VEX value rules, IE/ZE/PE witnesses; native execution NOT_ENABLED')
