# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
#!/usr/bin/env python3
"""One x86 instruction, measured EPYC inputs, production stand runner.

Hardware streams are read-only. Defined masks follow the delivered core.c and
bmi.c validators; all remaining arithmetic flags are still compared to hardware.
No Unicorn, Wine, game launch or engine modification.
"""
from __future__ import annotations
import argparse
import collections
import dataclasses
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import concurrent.futures
import shutil

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent / 'data'
active_timeout = subprocess
TABLE = HERE / 'amd-flags'
CODE = 0x7ffc0000000
DATA = 0x80000000000
BASE = DATA + 0x100
ARITH = 0x8d5
ARCH_RFLAGS = 0x3f7fd7  # architectural bits through ID, plus fixed reserved bit1
FLAGS = dict(CF=1, PF=4, AF=16, ZF=64, SF=128, OF=2048)

@dataclasses.dataclass(frozen=True)
class Row:
    file: str
    line: int
    form: str
    width: int
    before: int
    a: int
    b: int | None
    c: int | None
    trap: bool
    r1: int
    r2: int | None
    after: int
    raw: str

    @property
    def op(self):
        return self.form.split('.')[0]

    @property
    def mask(self):
        return (1 << self.width) - 1

    @property
    def count(self):
        return (self.c or 0) & (63 if self.width == 64 else 31)

    @property
    def key(self):
        return f'{self.file}:{self.line}'


def parse_row(file, line, text):
    s = text.split()
    if not s or s[0].startswith('#'):
        return None
    if len(s) not in (10, 11) or s[6] != '->':
        raise ValueError(f'{file}:{line}: malformed row')
    trap = s[7] == 'TRAP'
    n = lambda x: None if x == '-' else int(x, 16)
    return Row(file, line, s[0], int(s[1]), int(s[2], 16), n(s[3]),
               n(s[4]), n(s[5]), trap, n(s[7 + trap]), n(s[8 + trap]),
               int(s[9 + trap], 16), text.rstrip('\n'))


def rows(table=TABLE, files=None):
    for p in sorted(table.glob('out-*.txt.gz')):
        if files and not any(x in p.name for x in files):
            continue
        with gzip.open(p, 'rt') as stream:
            for line, text in enumerate(stream, 1):
                row = parse_row(p.name, line, text)
                if row:
                    yield row


def signed(x, width):
    return x - (1 << width) if x >> (width - 1) else x


def prefix(width):
    return b'\x66' if width == 16 else b'\x48' if width == 64 else b''


def vex(width, opcode, reg, rm, vvvv, pp=0, map_=2):
    # All allocations use low registers. VEX.R/X/B = 1 (inverted).
    return bytes([0xc4, 0xe0 | map_, (0x80 if width == 64 else 0) |
                  ((~vvvv & 15) << 3) | pp, opcode, 0xc0 | reg << 3 | rm])


def encode(row):
    """Return exactly one instruction, initial registers, and memory watches."""
    o, w = row.op, row.width
    p = prefix(w)
    regs = dict(rax=row.a, rbx=row.b or 0, rcx=row.c or 0, rdx=0,
                rdi=BASE, rsp=DATA + 0x5000)
    patches, watches = [], []
    if o in ('SHL', 'SAL', 'SHR', 'SAR', 'ROL', 'ROR', 'RCL', 'RCR'):
        sub = dict(ROL=0, ROR=1, RCL=2, RCR=3, SHL=4, SAL=6, SHR=5, SAR=7)[o]
        imm = row.form.endswith('.imm')
        code = p + bytes([(0xc0 if w == 8 else 0xc1) if imm else
                          (0xd2 if w == 8 else 0xd3), 0xc0 | sub << 3])
        if imm:
            code += bytes([(row.c or 0) & 255])
    elif o in ('SHLD', 'SHRD'):
        imm = row.form.endswith('.imm')
        op = (0xa4 if imm else 0xa5) if o == 'SHLD' else (0xac if imm else 0xad)
        code = p + bytes([0x0f, op, 0xd8])  # dst AX, source BX, count CL/imm
        if imm:
            code += bytes([(row.c or 0) & 255])
    elif o in ('MUL', 'IMUL1', 'DIV', 'IDIV'):
        sub = dict(MUL=4, IMUL1=5, DIV=6, IDIV=7)[o]
        if o in ('DIV', 'IDIV'):
            regs['rdx'] = row.c or 0
            if w == 8:
                regs['rax'] = row.a | ((row.c or 0) << 8)
        code = p + bytes([0xf6 if w == 8 else 0xf7, 0xc3 | sub << 3])
    elif o == 'IMUL2':
        code = p + b'\x0f\xaf\xc3'
    elif o == 'IMUL3':
        # Delivered stubs also enumerate large imm16/imm32; use their exact
        # sign-extended value, rather than truncating every immediate to imm8.
        immediate = signed(row.c or 0, w)
        if -128 <= immediate <= 127:
            code = p + bytes([0x6b, 0xc3, immediate & 255])
        else:
            size = 2 if w == 16 else 4
            code = p + b'\x69\xc3' + (immediate & ((1 << (size*8))-1)).to_bytes(size,'little')
    elif o in ('BSF', 'BSR', 'TZCNT', 'LZCNT', 'POPCNT'):
        lead = b'\xf3' if o in ('TZCNT', 'LZCNT', 'POPCNT') else b''
        # Match the assembler's legacy-prefix order used by hardware stubs.
        ordered = b'\x66' + lead if w == 16 else lead + p
        code = ordered + b'\x0f' + bytes([dict(BSF=0xbc, TZCNT=0xbc,
                        BSR=0xbd, LZCNT=0xbd, POPCNT=0xb8)[o], 0xc3])
    elif o in ('BT', 'BTS', 'BTR', 'BTC'):
        imm = row.form.endswith('imm')
        memory = '.mem-' in row.form
        rm = 7 if memory else 0
        if imm:
            sub = dict(BT=4, BTS=5, BTR=6, BTC=7)[o]
            code = p + bytes([0x0f, 0xba, (0 if memory else 0xc0) | sub << 3 | rm,
                              (row.c or 0) & 255])
        else:
            code = p + bytes([0x0f, dict(BT=0xa3, BTS=0xab, BTR=0xb3, BTC=0xbb)[o],
                              (0 if memory else 0xc0) | 3 << 3 | rm])
        if memory:
            buf = row.a.to_bytes(w // 8, 'little') * (256 // (w // 8))
            patches = [(BASE - 128 + i, buf[i:i+64]) for i in range(0, 256, 64)]
            displacement = 0 if imm else (signed(row.b or 0, w) // w) * (w // 8)
            if not -128 <= displacement <= 128 - w // 8:
                raise ValueError(f'{row.key}: bit-string access outside hardware buffer')
            watches = [(BASE + displacement, w // 8), (BASE, w // 8)]
    elif o in ('AND', 'OR', 'XOR', 'TEST'):
        opcode = dict(AND=0x21, OR=0x09, XOR=0x31, TEST=0x85)[o] - (w == 8)
        code = p + bytes([opcode, 0xd8])
    elif o == 'CMPXCHG':
        regs.update(rax=row.c or 0, rsi=row.a)
        code = p + bytes([0x0f, 0xb0 if w == 8 else 0xb1, 0xde])
        if w == 8:
            code = b'\x40' + code  # SIL, not DH
    elif o == 'XADD':
        code = p + bytes([0x0f, 0xc0 if w == 8 else 0xc1, 0xd8])
    elif o == 'BSWAP16':
        code = b'\x66\x0f\xc8'
    elif o in ('CMPXCHG8B', 'CMPXCHG16B'):
        half = w // 2
        mask = (1 << half) - 1
        regs.update(rax=row.a & mask, rdx=row.a >> half,
                    rbx=(row.c or 0) & mask, rcx=(row.c or 0) >> half)
        code = (b'\x48' if w == 128 else b'') + b'\x0f\xc7\x0f'
        patches = [(BASE, (row.b or 0).to_bytes(w // 8, 'little'))]
        watches = [(BASE, w // 8)]
    elif o in ('ADCX', 'ADOX'):
        code = (b'\x66' if o == 'ADCX' else b'\xf3') + p + b'\x0f\x38\xf6\xc3'
    elif o == 'ANDN':
        code = vex(w, 0xf2, 0, 3, 0)
    elif o == 'BEXTR':
        code = vex(w, 0xf7, 0, 0, 1)
    elif o in ('BLSI', 'BLSMSK', 'BLSR'):
        code = vex(w, 0xf3, dict(BLSR=1, BLSMSK=2, BLSI=3)[o], 0, 0)
    elif o == 'BZHI':
        code = vex(w, 0xf5, 0, 0, 1)
    elif o == 'MULX':
        regs['rdx'] = row.a
        code = vex(w, 0xf6, 0, 3, 1, pp=3)  # high AX, low CX
    elif o in ('PDEP', 'PEXT'):
        code = vex(w, 0xf5, 0, 3, 0, pp=3 if o == 'PDEP' else 2)
    elif o == 'RORX':
        code = vex(w, 0xf0, 0, 0, 0, pp=3, map_=3) + bytes([(row.c or 0) & 255])
    elif o in ('SARX', 'SHLX', 'SHRX'):
        code = vex(w, 0xf7, 0, 0, 1, pp=dict(SARX=2, SHLX=1, SHRX=3)[o])
    else:
        raise ValueError(f'{row.key}: unsupported {row.form}/{w}')
    return code, regs, patches, watches


def defined(row):
    """Architecturally specified flags/results; undefined != ignored."""
    o, n, w = row.op, row.count, row.width
    result = True
    if row.trap:
        return ARITH, True
    if o in ('SHL', 'SAL', 'SHR', 'SAR'):
        mask = ARITH if n == 0 else 0xc4 | (1 if n < w or o == 'SAR' else 0) | (0x800 if n == 1 else 0)
    elif o in ('ROL', 'ROR', 'RCL', 'RCR'):
        mask = ARITH if n == 0 else 0xd5 | (0x800 if n == 1 else 0)
    elif o in ('SHLD', 'SHRD'):
        mask = ARITH if n == 0 else 0xc5 | (0x800 if n == 1 else 0) if n <= w else 0
        result = n <= w
    elif o in ('MUL', 'IMUL1', 'IMUL2', 'IMUL3'):
        mask = 0x801
    elif o in ('DIV', 'IDIV'):
        mask = 0
    elif o in ('BSF', 'BSR'):
        mask = 0x40
        result = bool(row.b)
    elif o in ('TZCNT', 'LZCNT'):
        mask = 0x41
    elif o in ('BT', 'BTS', 'BTR', 'BTC'):
        mask = 0x41
    elif o in ('AND', 'OR', 'XOR', 'TEST'):
        mask = 0x8c5
    elif o == 'BSWAP16':
        mask, result = ARITH, False
    elif o in ('ANDN', 'BEXTR', 'BLSI', 'BLSMSK', 'BLSR', 'BZHI'):
        mask = dict(ANDN=0x8c1, BEXTR=0x841, BLSI=0x8c1,
                    BLSMSK=0x8c1, BLSR=0x8c1, BZHI=0x8c1)[o]
    else:
        mask = ARITH
    return mask, result


def condition(row):
    o, n = row.op, row.count
    if o in ('BSF', 'BSR'):
        return 'источник не 0' if row.b else 'источник 0'
    if o in ('DIV', 'IDIV'):
        return 'TRAP' if row.trap else 'после успешного деления'
    if o in ('SHL', 'SAL', 'SHR', 'SAR', 'SHLD', 'SHRD'):
        return ('счётчик 0' if n == 0 else 'счётчик 1' if n == 1 else
                'счётчик 2…ширина' if n <= row.width else 'счётчик больше ширины')
    if o in ('ROL', 'ROR', 'RCL', 'RCR'):
        return 'счётчик 0' if n == 0 else 'счётчик 1' if n == 1 else 'счётчик не 1'
    if o in ('BT', 'BTS', 'BTR', 'BTC'):
        return 'регистровые формы' if '.reg-' in row.form else 'формы памяти'
    return 'всегда'


def curator_rules(table):
    out = collections.defaultdict(list)
    for line in (table / 'CURATOR-RULES.md').read_text().splitlines():
        if not line.startswith('| ') or line.startswith('| Команда'):
            continue
        op, cond, flag, count, rule = [x.strip() for x in line.split('|')[1:-1]]
        out[op].append(dict(condition=cond, flag=flag, expected_rows=int(count), hardware_rule=rule))
    return out


def matches_condition(row, cond):
    if cond == 'всегда':
        return True
    if cond == 'регистровые формы':
        return '.reg-' in row.form
    if cond == 'счётчик не 1':
        return row.count not in (0, 1)
    return condition(row) == cond


def accumulate(g, row, cmp, name):
    """Empirical rules are retained only when every row obeys them."""
    g['rows'] += 1
    is_result = name == 'приёмник'
    bit = FLAGS.get(name, 0)
    actual = cmp['got'][0] if is_result else bool(cmp['got'][2] & bit)
    expected = row.r1 if is_result else bool(row.after & bit)
    before = row.a if is_result else bool(row.before & bit)
    g['matched'] += actual == expected
    g['железо всегда 0'] += expected == 0
    g['железо всегда 1'] += expected == 1
    g['железо не меняется'] += expected == before
    candidates = [('не меняется', before), ('всегда 0', 0), ('всегда 1', 1)]
    if not is_result:
        z = cmp['got'][0]
        sign = z >> (row.width - 1) & 1
        cf = cmp['got'][2] & 1
        formula = (sign ^ cf if row.op in ('SHL', 'SAL', 'ROL', 'RCL') else
                   sign ^ (z >> (row.width - 2) & 1) if row.op in ('ROR', 'RCR') else
                   (row.a >> (row.width - 1) & 1) if row.op == 'SHR' else
                   0 if row.op == 'SAR' else (row.a >> (row.width - 1) & 1) ^ sign)
        candidates += [('чётность младшего байта результата', (z & 255).bit_count() % 2 == 0),
                       ('старший бит результата', sign), ('результат равен 0', z == 0),
                       ('формула OF для счётчика 1', formula)]
    for label, value in candidates:
        g[label] += actual == value


def case(row, ident):
    code, regs, patches, watches = encode(row)
    fields = [f'id={ident}', 'seed=1', f'code={code.hex()}f4', f'rip={CODE:#x}',
              f'xlen={len(code)}', f'rflags={row.before:#x}', 'mxcsr=0x1f80']
    fields += [f'{k}={v:#x}' for k, v in regs.items()]
    fields += [f'mem={a:#x}:{data.hex()}' for a, data in patches]
    fields += [f'watch={a:#x}:{n}' for a, n in watches]
    return ' '.join(fields) + '\n'


def outputs(row, state):
    regs = {k: int(v, 16) for k, v in state['regs'].items()}
    memory = [int.from_bytes(bytes.fromhex(x[1]), 'little') for x in state.get('written_memory', [])]
    o, w, mask = row.op, row.width, row.mask
    if o in ('CMPXCHG8B', 'CMPXCHG16B'):
        half = w // 2
        r1 = (regs['rax'] & ((1 << half) - 1)) | ((regs['rdx'] & ((1 << half) - 1)) << half)
        r2 = memory[0]
    elif o in ('DIV', 'IDIV', 'MUL', 'IMUL1'):
        r1, r2 = regs['rax'] & mask, ((regs['rax'] >> 8) & 255) if w == 8 else regs['rdx'] & mask
    elif o == 'CMPXCHG':
        r1, r2 = regs['rsi'] & mask, regs['rax'] & mask
    elif o == 'XADD':
        r1, r2 = regs['rax'] & mask, regs['rbx'] & mask
    elif o == 'MULX':
        r1, r2 = regs['rcx'] & mask, regs['rax'] & mask
    elif o in ('BT', 'BTS', 'BTR', 'BTC') and '.mem-' in row.form:
        r1, r2 = memory[0], memory[1] if row.r2 is not None else None
    else:
        r1, r2 = regs['rax'] & mask, None
    return r1, r2, int(state['rflags'], 16) & ARITH


def guest_de(state):
    s = state.get('sfd', {})
    return (s.get('gen') == 1 and s.get('trap') == 0 and s.get('sig') == 11
            and s.get('si_code') == 128 and s.get('err') in (0, 1))


def compare(row, state):
    got = outputs(row, state)
    flagmask, result_defined = defined(row)
    expected = (row.r1, row.r2, row.after & ARITH)
    de = guest_de(state)
    fault_ok = de and state.get('state_valid') if row.trap else state.get('status') in ('ok', 'EXIT_SPAN', 'HLT') and state.get('state_valid') and not de
    defined_bad = (not fault_ok or bool((got[2] ^ expected[2]) & flagmask) or
                   (result_defined and got[:2] != expected[:2]))
    if row.trap:
        # DIV must be precise: every input GPR and every arithmetic flag survives.
        _, regs, _, _ = encode(row)
        defined_bad |= any(int(v, 16) != regs.get(k, 0) for k, v in state['regs'].items())
        defined_bad |= state.get('sfd', {}).get('err') != int(bool(row.b))
        defined_bad |= int(state.get('rip', '0'), 16) != CODE
        # The runner's FEX reconstruction can leak packed-NZCV metadata into
        # reserved bit31. Preserve raw evidence; compare architectural flags.
        defined_bad |= (int(state.get('rflags', '0'), 16) ^ row.before) & ARCH_RFLAGS != 0
    undef_delta = (got[2] ^ expected[2]) & (ARITH ^ flagmask)
    undef_result = not result_defined and got[:2] != expected[:2]
    return dict(got=got, expected=expected, defined_mask=flagmask,
                defined_bad=bool(defined_bad), undef_delta=undef_delta,
                undef_result=undef_result, trap=row.trap, guest_de=de)


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def run_batch(runner, selected, start, env, raw_stream=None, native_stream=None):
    payload = ''.join(case(r, start + i) for i, r in enumerate(selected))
    try:
        proc = active_timeout.run(['nice', '-n', '20', str(runner)], input=payload,
                                  text=True, capture_output=True, env=env, timeout=55)
    except subprocess.TimeoutExpired as error:
        if raw_stream: raw_stream.write(error.stdout.decode('utf-8') if isinstance(error.stdout, bytes) else (error.stdout or ''))
        if native_stream: native_stream.write(error.stderr.decode('utf-8') if isinstance(error.stderr, bytes) else (error.stderr or ''))
        raise
    if raw_stream:
        raw_stream.write(proc.stdout)
    if native_stream:
        native_stream.write(proc.stderr)
    states = [json.loads(x) for x in proc.stdout.splitlines() if x.startswith('{')]
    if proc.returncode or len(states) != len(selected):
        raise RuntimeError(f'runner rc={proc.returncode} states={len(states)}/{len(selected)} stderr={proc.stderr[-1200:]}')
    if any(s.get('id') != start + i for i, s in enumerate(states)):
        raise ValueError('runner output identity/order mismatch')
    return states


def known_cursor(registry, table):
    """Explicit, manually registered baseline; never learn candidate differences."""
    if not registry.exists():
        raise ValueError('missing manually accepted registry')
    spec = json.loads(registry.read_text())
    if {p.name:sha(p) for p in table.glob('out-*.txt.gz')} != spec['table_sha256']:
        raise ValueError('hardware table SHA drift against manually registered corpus')
    if sha(HERE / spec['groups_file']) != spec['groups_file_sha256']:
        raise ValueError('manually reviewed hardware group/rule receipt SHA drift')
    p = HERE / spec['baseline']
    if sha(p) != spec['baseline_sha256']:
        raise ValueError('known hardware baseline SHA drift')
    def stream():
        with gzip.open(p, 'rt') as f:
            for line in f:
                yield json.loads(line)
    return stream()


def classify(row, cmp, previous):
    """Known rows permit repair, never an additional undefined or defined delta."""
    mismatch = bool(cmp['undef_delta'] or cmp['undef_result'])
    old_delta = ((previous['got'][2] ^ cmp['expected'][2]) & (ARITH ^ cmp['defined_mask'])) if previous else 0
    old_result = bool(previous and not defined(row)[1] and tuple(previous['got'][:2]) != tuple(cmp['expected'][:2]))
    new = cmp['defined_bad'] or (mismatch and previous is None)
    if previous and mismatch:
        new |= bool(cmp['undef_delta'] & ~old_delta)
        new |= cmp['undef_result'] and tuple(cmp['got'][:2]) != tuple(previous['got'][:2])
    repaired = bool(old_delta & ~cmp['undef_delta']) or (old_result and not cmp['undef_result'])
    return bool(new), mismatch and not new, repaired, repaired and mismatch


def key_order(key):
    f, n = key.rsplit(':', 1)
    return f, int(n)


def summary(result, report):
    c = result['counts']
    print(json.dumps(dict(gate='HB_HWFLAGS', status=result['status'], mode=result['mode'],
                          checked=c.get('checked', 0), defined_bad=c.get('defined_bad', 0),
                          known=c.get('known', 0), fixed=c.get('fixed', 0),
                          new=c.get('new', 0), traps=c.get('trap', 0),
                          seconds=result['seconds'], report=str(report.resolve()),
                          canonical_sha256=result['canonical_sha256']), ensure_ascii=False))
