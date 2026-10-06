# SPDX-License-Identifier: MIT
"""Native x86-64 memory RMW instruction definitions for NEW0035.

No executable harness is supplied here.  Every instruction addresses [rdi].
The ``width`` field is in bytes; the width in each unique name is in bits.
``asm`` is an independently assemblable GNU-as Intel-syntax specification.
"""

_RAX = 0x1122334455667788
_RDX = 0x99AABBCCDDEEFF00
_PTR = {1: 'BYTE', 2: 'WORD', 4: 'DWORD', 8: 'QWORD', 16: 'XMMWORD'}
_REG = {1: 'bl', 2: 'bx', 4: 'ebx', 8: 'rbx'}


def _prefix(width):
    return b'\x66' if width == 2 else b'\x48' if width == 8 else b''


def forms():
    """Return fresh dicts, including intentional illegal LOCK-prefix cases.

    ``initial`` is full-operand hex and defaults to repeated 0x11.
    ``regs`` values and ``flags`` are integer overrides.  Setting flags to
    0x203 requests CF=1 plus the usual architectural fixed/IF bits.
    Feature tags use the Linux /proc/cpuinfo names cx8 and cx16.
    """
    out = []

    def add(name, width, raw, asm, *, lockable=True, **extra):
        for locked in (False, True):
            # GNU as orders the operand-size prefix before LOCK, and REX
            # after all legacy prefixes.  Use those exact canonical bytes.
            encoded = raw
            if locked:
                encoded = (raw[:1] + b'\xf0' + raw[1:]) if raw[:1] == b'\x66' else b'\xf0' + raw
            item = dict(name=f'{name}_{width * 8}_' + ('lock' if locked else 'nolock'),
                        width=width, code=encoded.hex(),
                        legal=not locked or lockable,
                        asm=('lock ' if locked else '') + asm)
            item.update(extra)
            if 'regs' in item:
                item['regs'] = dict(item['regs'])
            out.append(item)

    # Group 1: full immediates use 80 /digit ib or 81 /digit iw/id.
    # In 64-bit operand size, the full immediate is imm32 sign-extended.
    # The 83 /digit ib alternatives are separately represented for 16+ bits.
    for op, opcode, digit in (
        ('add', 0x00, 0), ('or', 0x08, 1), ('adc', 0x10, 2),
        ('sbb', 0x18, 3), ('and', 0x20, 4), ('sub', 0x28, 5),
        ('xor', 0x30, 6),
    ):
        for w in (1, 2, 4, 8):
            mem = f'{_PTR[w]} PTR [rdi]'
            p = _prefix(w)
            extra = dict(flags=0x203) if op in ('adc', 'sbb') else {}
            add(f'{op}_reg', w, p + bytes([opcode + (w != 1), 0x1f]),
                f'{op} {mem}, {_REG[w]}', **extra)
            n = min(w, 4)
            # Distinct negative signed patterns, avoiding the short encoding.
            immediate = {1: 0xa5, 2: 0xa55a, 4: 0xa55a31a5}[n]
            signed = immediate - (1 << (n * 8))
            add(f'{op}_imm' + ('32sx' if w == 8 else f'{n * 8}'), w,
                p + bytes([0x80 if w == 1 else 0x81, digit * 8 + 7])
                + immediate.to_bytes(n, 'little'),
                f'{op} {mem}, {signed}', **extra)
            if w != 1:
                add(f'{op}_imm8sx', w,
                    p + bytes([0x83, digit * 8 + 7, 0xa5]),
                    f'{op} {mem}, -91', **extra)

    for op, digit in (('inc', 0), ('dec', 1), ('not', 2), ('neg', 3)):
        for w in (1, 2, 4, 8):
            base = 0xfe if op in ('inc', 'dec') else 0xf6
            add(op, w, _prefix(w) + bytes([base + (w != 1), digit * 8 + 7]),
                f'{op} {_PTR[w]} PTR [rdi]')

    # D0/D1 has an implicit count of one; C0/C1 carries immediate count 3.
    # D2/D3 uses CL, explicitly overridden to 3.  LOCK is invalid for all.
    for op, digit in (('rol', 0), ('ror', 1), ('rcl', 2), ('rcr', 3),
                      ('shl', 4), ('shr', 5), ('sar', 7)):
        for w in (1, 2, 4, 8):
            for count, opcode, tail, arg in (
                ('one', 0xd0, b'', '1'),
                ('imm3', 0xc0, b'\x03', '3'),
                ('cl', 0xd2, b'', 'cl'),
            ):
                extra = dict(flags=0x203) if op in ('rcl', 'rcr') else {}
                if count == 'cl':
                    extra['regs'] = dict(rcx=3)
                add(f'{op}_{count}', w,
                    _prefix(w) + bytes([opcode + (w != 1), digit * 8 + 7]) + tail,
                    f'{op} {_PTR[w]} PTR [rdi], {arg}', lockable=False, **extra)

    # Double-precision memory-destination shifts have 16/32/64-bit forms.
    for op, opcode in (('shld', 0xa4), ('shrd', 0xac)):
        for w in (2, 4, 8):
            for count, tail, arg in (('imm1', b'\x01', '1'),
                                     ('imm3', b'\x03', '3'), ('cl', b'', 'cl')):
                extra = dict(regs=dict(rcx=3)) if count == 'cl' else {}
                add(f'{op}_{count}', w,
                    _prefix(w) + bytes([0x0f, opcode + (count == 'cl'), 0x1f]) + tail,
                    f'{op} {_PTR[w]} PTR [rdi], {_REG[w]}, {arg}',
                    lockable=False, **extra)

    for op, opcode in (('xchg', b'\x86'), ('xadd', b'\x0f\xc0')):
        for w in (1, 2, 4, 8):
            raw = _prefix(w) + opcode[:-1] + bytes([opcode[-1] + (w != 1), 0x1f])
            add(f'{op}_reg', w, raw, f'{op} {_PTR[w]} PTR [rdi], {_REG[w]}')

    for w in (1, 2, 4, 8):
        for match in (False, True):
            extra = dict(initial='11' * w)
            if match:
                mask = (1 << (w * 8)) - 1
                extra['regs'] = dict(rax=(_RAX & ~mask) | int('11' * w, 16))
            add('cmpxchg_' + ('match' if match else 'mismatch'), w,
                _prefix(w) + bytes([0x0f, 0xb0 + (w != 1), 0x1f]),
                f'cmpxchg {_PTR[w]} PTR [rdi], {_REG[w]}', **extra)

    # Both index choices address bit 3 of this operand, never a neighboring
    # word selected by the signed register-index / bit-string addressing rule.
    for op, opcode, digit in (('bts', 0xab, 5), ('btr', 0xb3, 6), ('btc', 0xbb, 7)):
        for w in (2, 4, 8):
            mem = f'{_PTR[w]} PTR [rdi]'
            # Make BTR clear a set bit; all three operations then visibly
            # change memory on a clean execution from their initial value.
            initial = ('19' if op == 'btr' else '11') * w
            add(f'{op}_reg3', w, _prefix(w) + bytes([0x0f, opcode, 0x1f]),
                f'{op} {mem}, {_REG[w]}', regs=dict(rbx=3), initial=initial)
            add(f'{op}_imm3', w, _prefix(w) + bytes([0x0f, 0xba, digit * 8 + 7, 3]),
                f'{op} {mem}, 3', regs=dict(rbx=3), initial=initial)

    for w, op, raw, feature in ((8, 'cmpxchg8b', b'\x0f\xc7\x0f', 'cx8'),
                                (16, 'cmpxchg16b', b'\x48\x0f\xc7\x0f', 'cx16')):
        for match in (False, True):
            extra = dict(initial='11' * w, feature=feature)
            if w == 16:
                extra['alignment'] = 16
            if match:
                if w == 8:
                    extra['regs'] = dict(rax=(_RAX & 0xffffffff00000000) | 0x11111111,
                                         rdx=(_RDX & 0xffffffff00000000) | 0x11111111)
                else:
                    extra['regs'] = dict(rax=0x1111111111111111, rdx=0x1111111111111111)
            add(op + '_' + ('match' if match else 'mismatch'), w, raw,
                f'{op} {_PTR[w]} PTR [rdi]', **extra)

    assert len(out) == 466
    assert len({item['name'] for item in out}) == len(out)
    return out
