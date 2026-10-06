#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
"""Authored loop shapes, assembled afresh; no captures, images or saved states."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

CODE = 0x7ffc0000000


def counted(body):
    return '.Lloop:\n' + body + '\ndec r15\njnz .Lloop\n'


def specifications():
    # Register allocation is explicit and stable. These are the 21 instruction
    # idioms in bench/xbench/xbench.c, not its compiler-generated prologues.
    patterns = [
        ('empty', ''), ('add', 'add rax, 3'), ('imul', 'imul rax, rbx'),
        ('cvttss2si', 'cvttss2si eax, xmm0\nadd r10, rax'),
        ('cvtss2si', 'cvtss2si eax, xmm0\nadd r10, rax'),
        ('cvttsd2si64', 'cvttsd2si rax, xmm0\nadd r10, rax'),
        ('cvttps2dq', 'cvttps2dq xmm1, xmm0\npaddd xmm2, xmm1'),
        ('cvtdq2ps', 'cvtdq2ps xmm1, xmm0\naddps xmm2, xmm1'),
        ('addsubps', 'addsubps xmm0, xmm1'), ('addss', 'addss xmm0, xmm1'),
        ('mulps', 'mulps xmm0, xmm1'), ('pshufb', 'pshufb xmm0, xmm1'),
        ('div32', 'xor edx, edx\nmov eax, r15d\ndiv ecx\nadd r10, rax'),
        ('idiv64', 'mov rax, r15\ncqo\nidiv rcx\nadd r10, rax'),
        ('crc32', 'crc32 eax, r15d'), ('popcnt', 'popcnt rax, r15\nadd r10, rax'),
        ('lock_xadd', 'lock xadd dword ptr [r14], eax\nmov eax, 1'),
        ('rep_movsb_4k', 'lea rsi, [r14]\nlea rdi, [r14+4096]\nmov ecx, 4096\nrep movsb'),
        ('x87_fadd', 'fadd st(0), st(1)'),
    ]
    result = [{'name': name, 'group': 'comparison', 'assembly': counted(body)} for name, body in patterns]
    for name, call in [('call_ret', 'call .Lleaf'), ('indirect_call', 'call r11')]:
        result.append({'name': name, 'group': 'comparison',
                       'assembly': '.Lloop:\n' + call + '\ndec r15\njnz .Lloop\njmp .Ldone\n.Lleaf:\nret\n.Ldone:\nnop\n'})
    # Five authored functions from the native/VM comparison package. The names
    # describe their behavior; no game bytes or addresses enter this stand.
    kernels = {
        'linked_find': 'mov rax, rcx\ntest rax, rax\nje .Ldone\n.Lloop:\ncmp dword ptr [rax+24], r8d\nje .Ldone\nmov rax, [rax+16]\ntest rax, rax\njne .Lloop\n.Ldone:\nret\n',
        'array_fill': 'mov rax, rcx\nmov r10, r8\nxor rcx, rcx\ntest rdx, rdx\nje .Ldone\n.Lloop:\nmov [rax], r10\nlea rax, [rax+8]\ninc rcx\ncmp rcx, rdx\njne .Lloop\n.Ldone:\nmov rax, rcx\nret\n',
        'direct_leaf': 'sub rsp, 40\nmov r9, rcx\nxor rax, rax\n.Lloop:\ncall .Lleaf\ndec r9\njne .Lloop\nadd rsp, 40\nret\n.Lleaf:\nlea rax, [rax+1]\nret\n',
        'indirect_leaf': 'sub rsp, 40\nmov r9, rcx\nlea r11, [rip+.Lleaf]\nxor rax, rax\n.Lloop:\ncall r11\ndec r9\njne .Lloop\nadd rsp, 40\nret\n.Lleaf:\nlea rax, [rax+1]\nret\n',
        'div32_accumulator': 'mov r10d, ecx\nmov r9d, 1234567\nmov ecx, 7\n.Lloop:\nxor edx, edx\nmov eax, r9d\ndiv ecx\nadd r9d, eax\ndec r10d\njne .Lloop\nret\n',
    }
    result.extend({'name': name, 'group': 'authored-kernel', 'assembly': body} for name, body in kernels.items())
    assert len(result) == 26 and len({s['name'] for s in result}) == 26
    return result


def elf_text(data):
    if data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 62:
        raise ValueError('assembler must produce little-endian ELF64 x86-64')
    offset = struct.unpack_from('<Q', data, 40)[0]
    size, count, names_index = struct.unpack_from('<HHH', data, 58)
    if size != 64 or count > 256 or offset + size * count > len(data):
        raise ValueError('invalid ELF section table')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, offset + i * size) for i in range(count)]
    strings = sections[names_index]
    names = data[strings[4]:strings[4]+strings[5]]
    selected = None
    for section in sections:
        name = names[section[0]:].split(b'\0', 1)[0]
        if section[1] in (4, 9) and section[5]:
            raise ValueError('unresolved assembler relocations')
        if name == b'.text':
            selected = data[section[4]:section[4]+section[5]]
    if not selected or len(selected) > 4096:
        raise ValueError('missing or oversized .text')
    return selected


def generate(out, compiler='clang'):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    cases = []
    for ident, spec in enumerate(specifications()):
        source = out / (spec['name'] + '.S')
        obj = source.with_suffix('.o')
        source.write_text('.text\n.intel_syntax noprefix\n' + spec['assembly'])
        subprocess.run([compiler, '-target', 'x86_64-unknown-linux-gnu', '-c', '-x', 'assembler',
                        str(source), '-o', str(obj)], check=True, capture_output=True)
        code = elf_text(obj.read_bytes())
        instructions = list(decoder.disasm(code, CODE))
        if sum(i.size for i in instructions) != len(code):
            raise ValueError('incomplete x86 decoding: ' + spec['name'])
        cases.append({**spec, 'id': ident, 'code': code.hex(), 'input_instructions': len(instructions),
                      'code_sha256': hashlib.sha256(code).hexdigest(),
                      'decoded': [{'offset': i.address-CODE, 'mnemonic': i.mnemonic, 'operands': i.op_str} for i in instructions]})
    (out / 'CASES.json').write_text(json.dumps(cases, indent=2) + '\n')
    return cases


def request(case):
    code = case['code']
    return f"id={case['id']} seed=1 code={code}f4 rip={CODE:#x} xlen={len(code)//2} rflags=0x202 mxcsr=0x1f80\n"


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--compiler', default='clang')
    args = parser.parse_args()
    print(json.dumps({'cases': len(generate(args.out, args.compiler)), 'execution': 'NOT_RUN'}))
