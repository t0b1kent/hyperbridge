# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
"""Synthetic x86-64 fragments and reproducible input states; no captured inputs."""
import struct

MASK64 = (1 << 64) - 1
CODE = 0x7FFC0000000
DATA = 0x80000000000
STACK = DATA + 0x1000000
SIZE = 0x4000
GPRS = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')
SEEDS = (0, 1, 2, 3, 17, 255, 65535, 0x9E3779B97F4A7C15)


class SplitMix64:
    def __init__(self, seed):
        self.state = seed

    def next(self):
        self.state = (self.state + 0x9E3779B97F4A7C15) & MASK64
        value = self.state
        value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
        value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & MASK64
        return (value ^ (value >> 31)) & MASK64

    def bytes(self, length):
        return b''.join(self.next().to_bytes(8, 'little') for _ in range((length + 7) // 8))[:length]


# Each tuple states which architectural flags are defined. AF is undefined for
# logical/shift operations; IMUL/BSF/BSR have further undefined flags. This is
# an explicit limit of the public Unicorn oracle, not a known-defect allowance.
ARITH = 0x8D5
LOGIC = ARITH & ~0x10
FRAGMENTS = (
    ('add64', '4801d8', ARITH), ('sub64', '4829d8', ARITH),
    ('adc64', '4811d8', ARITH), ('sbb64', '4819d8', ARITH),
    ('add32', '01d8', ARITH), ('sub32', '29d8', ARITH),
    ('add16', '6601d8', ARITH), ('sub16', '6629d8', ARITH),
    ('add8', '00d8', ARITH), ('sub8', '28d8', ARITH),
    ('inc64', '48ffc0', ARITH), ('neg64', '48f7d8', ARITH),
    ('and64', '4821d8', LOGIC), ('xor32', '31d8', LOGIC),
    ('test64', '4885d8', LOGIC), ('compare64', '4839d8', ARITH),
    ('shl64-one', '48d1e0', LOGIC), ('sar32-one', 'd1f8', LOGIC),
    ('shr8-one', 'd0e8', LOGIC), ('rotate16-one', '66d1c8', ARITH),
    ('imul64', '480fafc3', 0x801),
    ('movsx8', '480fbec3', ARITH), ('movsx16', '480fbfc3', ARITH),
    ('movsxd32', '4863c3', ARITH), ('movzx8', '0fb6c3', ARITH),
    ('movzx16', '0fb7c3', ARITH), ('bsf64', '480fbcc3', 0x40),
    ('bsr32', '0fbdc3', 0x40),
    ('store64-load32', '4889078b07', ARITH),
    ('overlap-stores', '488907895f048b4702', ARITH),
    ('xchg-memory', '488707', ARITH),
    ('cmpxchg-memory', '480fb11f', ARITH),
    ('xadd-memory', '480fc107', ARITH),
    ('movd-to-xmm', '660f6ec3', ARITH),
    ('movq-from-xmm', '66480f7ec0', ARITH),
    ('movdqu-memory', 'f30f6f07f30f7f4710', ARITH),
    ('paddb', '660ffcc1', ARITH), ('paddw', '660ffdc1', ARITH),
    ('paddd', '660ffec1', ARITH), ('paddq', '660fd4c1', ARITH),
    ('psubd', '660ffac1', ARITH), ('pand', '660fdbc1', ARITH),
    ('pxor', '660fefc1', ARITH), ('pcmpeqd', '660f76c1', ARITH),
    ('psllw', '660f71f001', ARITH), ('psrad', '660f72e004', ARITH),
    ('punpcklbw', '660f60c1', ARITH), ('pshufd', '660f70c11b', ARITH),
    ('addss-exact', 'f30f58c1', ARITH),
    ('mulsd-exact', 'f20f59c1', ARITH),
    ('cvtsi2ss-exact', 'f30f2ac3', ARITH),
)


def cases(full=False):
    seeds = SEEDS if not full else SEEDS + tuple(range(32, 96))
    for index, (name, code, flag_mask) in enumerate(FRAGMENTS):
        for position, seed in enumerate(seeds):
            random = SplitMix64(seed ^ 0xBADC0FFE)
            registers = {name: random.next() for name in GPRS}
            registers.update(rsp=STACK + 0x2000, rbp=STACK + 0x2100,
                             rsi=DATA + 0x80, rdi=DATA + 0x40, rcx=1)
            registers['rbx'] |= 1  # scans avoid the undefined zero result.
            if name == 'cvtsi2ss-exact':
                registers['rbx'] = position * 127 + 1
            xmm = [random.bytes(16) for _ in range(16)]
            upper = [random.bytes(16) for _ in range(16)]
            if name == 'addss-exact':
                xmm[0] = struct.pack('<f', 1.5) + xmm[0][4:]
                xmm[1] = struct.pack('<f', 2.0) + xmm[1][4:]
            if name == 'mulsd-exact':
                xmm[0] = struct.pack('<d', 1.5) + xmm[0][8:]
                xmm[1] = struct.pack('<d', 2.0) + xmm[1][8:]
            yield dict(id=index * len(seeds) + position, name=name, seed=seed,
                       code=code, regs=registers, xmm=xmm, upper=upper,
                       rflags=2 | (random.next() & ARITH), mxcsr=0x1F80,
                       flag_mask=flag_mask)


def line(case):
    fields = [f'id={case["id"]}', f'seed={case["seed"]}', 'code=' + case['code'] + 'f4',
              f'rip={CODE:#x}', f'rflags={case["rflags"]:#x}', f'mxcsr={case["mxcsr"]:#x}']
    fields.extend(f'{name}={value:#x}' for name, value in case['regs'].items())
    fields.extend(f'x{index}={value.hex()}' for index, value in enumerate(case['xmm']))
    fields.extend(f'y{index}={value.hex()}' for index, value in enumerate(case['upper']))
    return ' '.join(fields)
