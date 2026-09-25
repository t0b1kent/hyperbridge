#!/usr/bin/env python3
"""hb_decode.py — HyperBridge instruction decoder CLI.

Decodes a real x64/x86 MVP subset (mov, add, sub, cmp, jmp, jcc, call, ret,
push, pop, nop, lea, test, and, or, xor, inc, dec) from hex or file input.
"""

import argparse
import sys
import json

# Register names for x64
REG_NAMES = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
]

COND_NAMES = {
    0: "o", 1: "no", 2: "b/c", 3: "ae/nc", 4: "e/z", 5: "ne/nz",
    6: "be", 7: "a", 8: "s", 9: "ns", 10: "p", 11: "np",
    12: "l", 13: "ge", 14: "le", 15: "g"
}


def reg_name(idx, size):
    if idx is None or idx < 0:
        return "?"
    if idx == 16:
        return "rip"
    if idx >= len(REG_NAMES):
        return f"r{idx}"
    r = REG_NAMES[idx]
    if size == 1:
        return r.replace("r", "").replace("e", "") + "l" if idx >= 8 else r.replace("r", "").replace("e", "") + "l"
    if size == 2:
        return r.replace("r", "")
    if size == 4:
        return "e" + r.replace("r", "")
    return r


class DecodeError(Exception):
    pass


def decode_x64_bytes(data, addr=0):
    results = []
    i = 0
    while i < len(data):
        try:
            insn, length = decode_one_x64(data[i:], addr + i)
            results.append(insn)
            i += length
        except DecodeError as e:
            results.append({
                "addr": f"0x{addr+i:08x}",
                "len": 1,
                "bytes": data[i:i+1].hex(),
                "opcode": "UNSUPPORTED",
                "reason": str(e),
                "next": f"0x{addr+i+1:08x}"
            })
            i += 1
    return results


def decode_one_x64(data, addr):
    """Decode a single x64 instruction. Returns (dict, length)."""
    if not data:
        raise DecodeError("empty input")

    pos = 0
    n = len(data)

    def can_read(k):
        return pos + k <= n

    def read_u8():
        nonlocal pos
        b = data[pos]
        pos += 1
        return b

    def read_s8():
        return int.from_bytes(read_u8().to_bytes(1, "little"), "little", signed=True)

    def read_s32():
        nonlocal pos
        v = int.from_bytes(data[pos:pos+4], "little", signed=True)
        pos += 4
        return v

    def read_u64():
        nonlocal pos
        v = int.from_bytes(data[pos:pos+8], "little", signed=False)
        pos += 8
        return v

    rex_w = rex_r = rex_x = rex_b = False
    while can_read(1) and 0x40 <= data[pos] <= 0x4F:
        rex = read_u8()
        rex_w = bool((rex >> 3) & 1)
        rex_r = bool((rex >> 2) & 1)
        rex_x = bool((rex >> 1) & 1)
        rex_b = bool(rex & 1)

    if not can_read(1):
        raise DecodeError("truncated instruction")

    opcode = read_u8()

    def reg_idx(base):
        return base | (8 if rex_b else 0)

    def reg_idx_r(base):
        return base | (8 if rex_r else 0)

    def reg_idx_x(base):
        return base | (8 if rex_x else 0)

    def sz():
        return 8 if rex_w else 4

    def parse_modrm():
        if not can_read(1):
            raise DecodeError("truncated modrm")
        modrm = read_u8()
        mod = (modrm >> 6) & 3
        reg_op = (modrm >> 3) & 7
        rm = modrm & 7
        return mod, reg_op, rm, modrm

    def parse_sib():
        if not can_read(1):
            raise DecodeError("truncated sib")
        sib = read_u8()
        scale = 1 << ((sib >> 6) & 3)
        index = (sib >> 3) & 7
        base = sib & 7
        return scale, index, base

    def mem_operand(mod, rm, size):
        base = index = -1
        scale = 1
        disp = 0
        if rm == 4:
            s_scale, s_index, s_base = parse_sib()
            scale = s_scale
            idx = reg_idx_x(s_index)
            if s_index == 4 and not rex_x:
                index = -1
            else:
                index = idx
            b = reg_idx(s_base)
            if s_base == 5:
                if mod == 0:
                    base = -1
                else:
                    base = b
            else:
                base = b
        elif rm == 5 and mod == 0:
            base = 16  # rip
        else:
            base = reg_idx(rm)

        if mod == 1:
            if not can_read(1):
                raise DecodeError("truncated disp8")
            disp = read_s8()
        elif mod == 2 or (rm == 5 and mod == 0) or (rm == 4 and (mod == 0 or mod == 2)):
            if not can_read(4):
                raise DecodeError("truncated disp32")
            disp = read_s32()

        return {
            "base": base, "index": index, "scale": scale,
            "disp": disp, "size": size,
            "rip_relative": base == 16
        }

    def modrm_operands(mem_is_dst, op_size):
        mod, reg_op, rm, _ = parse_modrm()
        r = reg_idx_r(reg_op)
        if mod == 3:
            rm_reg = reg_idx(rm)
            if mem_is_dst:
                return {"reg": rm_reg, "size": op_size}, {"reg": r, "size": op_size}
            else:
                return {"reg": r, "size": op_size}, {"reg": rm_reg, "size": op_size}
        mem = mem_operand(mod, rm, op_size)
        reg = {"reg": r, "size": op_size}
        if mem_is_dst:
            return mem, reg
        return reg, mem

    def modrm_ext_operand(modrm, op_size):
        mod = (modrm >> 6) & 3
        rm = modrm & 7
        if mod == 3:
            return {"reg": reg_idx(rm), "size": op_size}
        return mem_operand(mod, rm, op_size)

    def make_insn(opcode_name, op1=None, op2=None, flags_write=False, flags_read=False,
                  branch=False, call=False, ret=False, conditional=False,
                  cond=None, target=None, stack_delta=0, ret_imm=0):
        insn = {
            "addr": f"0x{addr:08x}",
            "len": pos,
            "bytes": data[:pos].hex(),
            "opcode": opcode_name,
            "next": f"0x{addr+pos:08x}"
        }
        if op1:
            insn["op1"] = op1
        if op2:
            insn["op2"] = op2
        if flags_write:
            insn["writes_flags"] = True
        if flags_read:
            insn["reads_flags"] = True
        if branch:
            insn["is_branch"] = True
        if call:
            insn["is_call"] = True
        if ret:
            insn["is_ret"] = True
        if conditional:
            insn["is_conditional"] = True
        if cond is not None:
            insn["cond"] = cond
        if target is not None:
            insn["branch_target"] = f"0x{target:08x}"
        if stack_delta:
            insn["stack_delta"] = stack_delta
        if ret_imm:
            insn["ret_imm"] = ret_imm
        return insn

    # MOV
    if opcode == 0x88:
        op1, op2 = modrm_operands(True, 1)
        return make_insn("MOV", op1, op2), pos
    if opcode == 0x89:
        op1, op2 = modrm_operands(True, sz())
        return make_insn("MOV", op1, op2), pos
    if opcode == 0x8A:
        op1, op2 = modrm_operands(False, 1)
        return make_insn("MOV", op1, op2), pos
    if opcode == 0x8B:
        op1, op2 = modrm_operands(False, sz())
        return make_insn("MOV", op1, op2), pos
    if opcode == 0x8D:
        op1, op2 = modrm_operands(False, sz())
        return make_insn("LEA", op1, op2), pos
    if 0xB0 <= opcode <= 0xB7:
        r = reg_idx(opcode & 7)
        if not can_read(1):
            raise DecodeError("truncated imm8")
        imm = read_s8()
        return make_insn("MOV", {"reg": r, "size": 1}, {"imm": imm, "size": 1}), pos
    if 0xB8 <= opcode <= 0xBF:
        r = reg_idx(opcode & 7)
        if rex_w:
            if not can_read(8):
                raise DecodeError("truncated imm64")
            imm = int.from_bytes(read_u64().to_bytes(8, "little"), "little", signed=True)
            return make_insn("MOV", {"reg": r, "size": 8}, {"imm": imm, "size": 8}), pos
        else:
            if not can_read(4):
                raise DecodeError("truncated imm32")
            imm = read_s32()
            return make_insn("MOV", {"reg": r, "size": 4}, {"imm": imm, "size": 4}), pos
    if opcode == 0xC6:
        mod, reg_op, rm, modrm = parse_modrm()
        if reg_op != 0:
            raise DecodeError("unsupported C6 extension")
        op1 = modrm_ext_operand(modrm, 1)
        if not can_read(1):
            raise DecodeError("truncated imm8")
        imm = read_s8()
        return make_insn("MOV", op1, {"imm": imm, "size": 1}), pos
    if opcode == 0xC7:
        mod, reg_op, rm, modrm = parse_modrm()
        if reg_op != 0:
            raise DecodeError("unsupported C7 extension")
        op1 = modrm_ext_operand(modrm, sz())
        if not can_read(4):
            raise DecodeError("truncated imm32")
        imm = read_s32()
        return make_insn("MOV", op1, {"imm": imm, "size": sz()}), pos

    # ADD
    if opcode == 0x00:
        op1, op2 = modrm_operands(True, 1)
        return make_insn("ADD", op1, op2, flags_write=True), pos
    if opcode == 0x01:
        op1, op2 = modrm_operands(True, sz())
        return make_insn("ADD", op1, op2, flags_write=True), pos
    if opcode == 0x02:
        op1, op2 = modrm_operands(False, 1)
        return make_insn("ADD", op1, op2, flags_write=True), pos
    if opcode == 0x03:
        op1, op2 = modrm_operands(False, sz())
        return make_insn("ADD", op1, op2, flags_write=True), pos
    if opcode == 0x04:
        if not can_read(1):
            raise DecodeError("truncated imm8")
        imm = read_s8()
        return make_insn("ADD", {"reg": 0, "size": 1}, {"imm": imm, "size": 1}, flags_write=True), pos
    if opcode == 0x05:
        if not can_read(4):
            raise DecodeError("truncated imm32")
        imm = read_s32()
        return make_insn("ADD", {"reg": 0, "size": sz()}, {"imm": imm, "size": sz()}, flags_write=True), pos

    # SUB
    if opcode == 0x28:
        op1, op2 = modrm_operands(True, 1)
        return make_insn("SUB", op1, op2, flags_write=True), pos
    if opcode == 0x29:
        op1, op2 = modrm_operands(True, sz())
        return make_insn("SUB", op1, op2, flags_write=True), pos
    if opcode == 0x2A:
        op1, op2 = modrm_operands(False, 1)
        return make_insn("SUB", op1, op2, flags_write=True), pos
    if opcode == 0x2B:
        op1, op2 = modrm_operands(False, sz())
        return make_insn("SUB", op1, op2, flags_write=True), pos
    if opcode == 0x2C:
        if not can_read(1):
            raise DecodeError("truncated imm8")
        imm = read_s8()
        return make_insn("SUB", {"reg": 0, "size": 1}, {"imm": imm, "size": 1}, flags_write=True), pos
    if opcode == 0x2D:
        if not can_read(4):
            raise DecodeError("truncated imm32")
        imm = read_s32()
        return make_insn("SUB", {"reg": 0, "size": sz()}, {"imm": imm, "size": sz()}, flags_write=True), pos

    # CMP
    if opcode == 0x38:
        op1, op2 = modrm_operands(True, 1)
        return make_insn("CMP", op1, op2, flags_write=True), pos
    if opcode == 0x39:
        op1, op2 = modrm_operands(True, sz())
        return make_insn("CMP", op1, op2, flags_write=True), pos
    if opcode == 0x3A:
        op1, op2 = modrm_operands(False, 1)
        return make_insn("CMP", op1, op2, flags_write=True), pos
    if opcode == 0x3B:
        op1, op2 = modrm_operands(False, sz())
        return make_insn("CMP", op1, op2, flags_write=True), pos
    if opcode == 0x3C:
        if not can_read(1):
            raise DecodeError("truncated imm8")
        imm = read_s8()
        return make_insn("CMP", {"reg": 0, "size": 1}, {"imm": imm, "size": 1}, flags_write=True), pos
    if opcode == 0x3D:
        if not can_read(4):
            raise DecodeError("truncated imm32")
        imm = read_s32()
        return make_insn("CMP", {"reg": 0, "size": sz()}, {"imm": imm, "size": sz()}, flags_write=True), pos

    # AND
    if opcode == 0x20:
        op1, op2 = modrm_operands(True, 1)
        return make_insn("AND", op1, op2, flags_write=True), pos
    if opcode == 0x21:
        op1, op2 = modrm_operands(True, sz())
        return make_insn("AND", op1, op2, flags_write=True), pos
    if opcode == 0x22:
        op1, op2 = modrm_operands(False, 1)
        return make_insn("AND", op1, op2, flags_write=True), pos
    if opcode == 0x23:
        op1, op2 = modrm_operands(False, sz())
        return make_insn("AND", op1, op2, flags_write=True), pos

    # OR
    if opcode == 0x08:
        op1, op2 = modrm_operands(True, 1)
        return make_insn("OR", op1, op2, flags_write=True), pos
    if opcode == 0x09:
        op1, op2 = modrm_operands(True, sz())
        return make_insn("OR", op1, op2, flags_write=True), pos
    if opcode == 0x0A:
        op1, op2 = modrm_operands(False, 1)
        return make_insn("OR", op1, op2, flags_write=True), pos
    if opcode == 0x0B:
        op1, op2 = modrm_operands(False, sz())
        return make_insn("OR", op1, op2, flags_write=True), pos

    # XOR
    if opcode == 0x30:
        op1, op2 = modrm_operands(True, 1)
        return make_insn("XOR", op1, op2, flags_write=True), pos
    if opcode == 0x31:
        op1, op2 = modrm_operands(True, sz())
        return make_insn("XOR", op1, op2, flags_write=True), pos
    if opcode == 0x32:
        op1, op2 = modrm_operands(False, 1)
        return make_insn("XOR", op1, op2, flags_write=True), pos
    if opcode == 0x33:
        op1, op2 = modrm_operands(False, sz())
        return make_insn("XOR", op1, op2, flags_write=True), pos

    # TEST
    if opcode == 0x84:
        op1, op2 = modrm_operands(True, 1)
        return make_insn("TEST", op1, op2, flags_write=True), pos
    if opcode == 0x85:
        op1, op2 = modrm_operands(True, sz())
        return make_insn("TEST", op1, op2, flags_write=True), pos
    if opcode == 0xA8:
        if not can_read(1):
            raise DecodeError("truncated imm8")
        imm = read_s8()
        return make_insn("TEST", {"reg": 0, "size": 1}, {"imm": imm, "size": 1}, flags_write=True), pos
    if opcode == 0xA9:
        if not can_read(4):
            raise DecodeError("truncated imm32")
        imm = read_s32()
        return make_insn("TEST", {"reg": 0, "size": sz()}, {"imm": imm, "size": sz()}, flags_write=True), pos

    # PUSH / POP
    if 0x50 <= opcode <= 0x57:
        r = reg_idx(opcode & 7)
        return make_insn("PUSH", {"reg": r, "size": 8}, stack_delta=-8), pos
    if 0x58 <= opcode <= 0x5F:
        r = reg_idx(opcode & 7)
        return make_insn("POP", {"reg": r, "size": 8}, stack_delta=8), pos
    if opcode == 0x68:
        if not can_read(4):
            raise DecodeError("truncated imm32")
        imm = read_s32()
        return make_insn("PUSH", {"imm": imm, "size": 4}, stack_delta=-8), pos
    if opcode == 0x6A:
        if not can_read(1):
            raise DecodeError("truncated imm8")
        imm = read_s8()
        return make_insn("PUSH", {"imm": imm, "size": 1}, stack_delta=-8), pos

    # JMP
    if opcode == 0xEB:
        if not can_read(1):
            raise DecodeError("truncated rel8")
        rel = read_s8()
        target = addr + pos + rel
        return make_insn("JMP", branch=True, target=target), pos
    if opcode == 0xE9:
        if not can_read(4):
            raise DecodeError("truncated rel32")
        rel = read_s32()
        target = addr + pos + rel
        return make_insn("JMP", branch=True, target=target), pos

    # CALL
    if opcode == 0xE8:
        if not can_read(4):
            raise DecodeError("truncated rel32")
        rel = read_s32()
        target = addr + pos + rel
        return make_insn("CALL", branch=True, call=True, target=target, stack_delta=-8), pos

    # RET
    if opcode == 0xC3:
        return make_insn("RET", ret=True, stack_delta=8), pos
    if opcode == 0xC2:
        if not can_read(2):
            raise DecodeError("truncated imm16")
        imm = int.from_bytes(data[pos:pos+2], "little")
        pos += 2
        return make_insn("RET", ret=True, stack_delta=8, ret_imm=imm), pos

    # Jcc short
    if 0x70 <= opcode <= 0x7F:
        if not can_read(1):
            raise DecodeError("truncated rel8")
        rel = read_s8()
        target = addr + pos + rel
        cc = opcode & 0x0F
        return make_insn("Jcc", branch=True, conditional=True, cond=COND_NAMES.get(cc, str(cc)), target=target, flags_read=True), pos

    # NOP
    if opcode == 0x90:
        return make_insn("NOP"), pos

    # Two-byte opcodes
    if opcode == 0x0F:
        if not can_read(1):
            raise DecodeError("truncated two-byte opcode")
        op2 = read_u8()
        if 0x80 <= op2 <= 0x8F:
            if not can_read(4):
                raise DecodeError("truncated rel32")
            rel = read_s32()
            target = addr + pos + rel
            cc = op2 & 0x0F
            return make_insn("Jcc", branch=True, conditional=True, cond=COND_NAMES.get(cc, str(cc)), target=target, flags_read=True), pos
        raise DecodeError(f"unsupported two-byte opcode 0F {op2:02X}")

    # Group: 0x80/0x81/0x83
    if opcode in (0x80, 0x81, 0x83):
        if not can_read(1):
            raise DecodeError("truncated modrm")
        modrm = read_u8()
        ext = (modrm >> 3) & 7
        op_size = 1 if opcode == 0x80 else sz()
        name = {0: "ADD", 5: "SUB", 7: "CMP"}.get(ext)
        if name is None:
            raise DecodeError(f"unsupported group extension {ext}")
        op1 = modrm_ext_operand(modrm, op_size)
        if opcode == 0x80:
            if not can_read(1):
                raise DecodeError("truncated imm8")
            imm = read_s8()
            op2 = {"imm": imm, "size": 1}
        elif opcode == 0x81:
            if not can_read(4):
                raise DecodeError("truncated imm32")
            imm = read_s32()
            op2 = {"imm": imm, "size": op_size}
        else:  # 0x83
            if not can_read(1):
                raise DecodeError("truncated imm8")
            imm = read_s8()
            op2 = {"imm": imm, "size": op_size}
        return make_insn(name, op1, op2, flags_write=True), pos

    # Group: 0xFF
    if opcode == 0xFF:
        if not can_read(1):
            raise DecodeError("truncated modrm")
        modrm = read_u8()
        ext = (modrm >> 3) & 7
        op_size = sz()
        if ext == 0:
            op1 = modrm_ext_operand(modrm, op_size)
            return make_insn("INC", op1, flags_write=True), pos
        if ext == 1:
            op1 = modrm_ext_operand(modrm, op_size)
            return make_insn("DEC", op1, flags_write=True), pos
        if ext == 2:
            op1 = modrm_ext_operand(modrm, 8)
            return make_insn("CALL", op1, branch=True, call=True, stack_delta=-8), pos
        if ext == 4:
            op1 = modrm_ext_operand(modrm, 8)
            return make_insn("JMP", op1, branch=True), pos
        if ext == 6:
            op1 = modrm_ext_operand(modrm, 8)
            return make_insn("PUSH", op1, stack_delta=-8), pos
        raise DecodeError(f"unsupported FF extension {ext}")

    raise DecodeError(f"unsupported opcode {opcode:02X}")


def decode_x86_bytes(data, addr=0):
    results = []
    i = 0
    while i < len(data):
        try:
            insn, length = decode_one_x86(data[i:], addr + i)
            results.append(insn)
            i += length
        except DecodeError as e:
            results.append({
                "addr": f"0x{addr+i:08x}",
                "len": 1,
                "bytes": data[i:i+1].hex(),
                "opcode": "UNSUPPORTED",
                "reason": str(e),
                "next": f"0x{addr+i+1:08x}"
            })
            i += 1
    return results


def decode_one_x86(data, addr):
    """Decode a single x86 instruction. Returns (dict, length)."""
    if not data:
        raise DecodeError("empty input")

    pos = 0
    n = len(data)

    def can_read(k):
        return pos + k <= n

    def read_u8():
        nonlocal pos
        b = data[pos]
        pos += 1
        return b

    def read_s8():
        return int.from_bytes(read_u8().to_bytes(1, "little"), "little", signed=True)

    def read_s32():
        nonlocal pos
        v = int.from_bytes(data[pos:pos+4], "little", signed=True)
        pos += 4
        return v

    if not can_read(1):
        raise DecodeError("truncated instruction")
    opcode = read_u8()

    def sz():
        return 4

    def parse_modrm():
        if not can_read(1):
            raise DecodeError("truncated modrm")
        modrm = read_u8()
        mod = (modrm >> 6) & 3
        reg_op = (modrm >> 3) & 7
        rm = modrm & 7
        return mod, reg_op, rm, modrm

    def parse_sib():
        if not can_read(1):
            raise DecodeError("truncated sib")
        sib = read_u8()
        scale = 1 << ((sib >> 6) & 3)
        index = (sib >> 3) & 7
        base = sib & 7
        return scale, index, base

    def mem_operand(mod, rm, size):
        base = index = -1
        scale = 1
        disp = 0
        if rm == 4:
            s_scale, s_index, s_base = parse_sib()
            scale = s_scale
            if s_index == 4:
                index = -1
            else:
                index = s_index
            if s_base == 5:
                if mod == 0:
                    base = -1
                else:
                    base = s_base
            else:
                base = s_base
        elif rm == 5 and mod == 0:
            base = -1  # disp32 only
        else:
            base = rm

        if mod == 1:
            if not can_read(1):
                raise DecodeError("truncated disp8")
            disp = read_s8()
        elif mod == 2 or (rm == 5 and mod == 0) or (rm == 4 and (mod == 0 or mod == 2)):
            if not can_read(4):
                raise DecodeError("truncated disp32")
            disp = read_s32()

        return {"base": base, "index": index, "scale": scale, "disp": disp, "size": size}

    def modrm_operands(mem_is_dst, op_size):
        mod, reg_op, rm, _ = parse_modrm()
        r = reg_op
        if mod == 3:
            rm_reg = rm
            if mem_is_dst:
                return {"reg": rm_reg, "size": op_size}, {"reg": r, "size": op_size}
            else:
                return {"reg": r, "size": op_size}, {"reg": rm_reg, "size": op_size}
        mem = mem_operand(mod, rm, op_size)
        reg = {"reg": r, "size": op_size}
        if mem_is_dst:
            return mem, reg
        return reg, mem

    def modrm_ext_operand(modrm, op_size):
        mod = (modrm >> 6) & 3
        rm = modrm & 7
        if mod == 3:
            return {"reg": rm, "size": op_size}
        return mem_operand(mod, rm, op_size)

    def make_insn(opcode_name, op1=None, op2=None, flags_write=False, flags_read=False,
                  branch=False, call=False, ret=False, conditional=False,
                  cond=None, target=None, stack_delta=0, ret_imm=0):
        insn = {
            "addr": f"0x{addr:08x}",
            "len": pos,
            "bytes": data[:pos].hex(),
            "opcode": opcode_name,
            "next": f"0x{addr+pos:08x}"
        }
        if op1:
            insn["op1"] = op1
        if op2:
            insn["op2"] = op2
        if flags_write:
            insn["writes_flags"] = True
        if flags_read:
            insn["reads_flags"] = True
        if branch:
            insn["is_branch"] = True
        if call:
            insn["is_call"] = True
        if ret:
            insn["is_ret"] = True
        if conditional:
            insn["is_conditional"] = True
        if cond is not None:
            insn["cond"] = cond
        if target is not None:
            insn["branch_target"] = f"0x{target:08x}"
        if stack_delta:
            insn["stack_delta"] = stack_delta
        if ret_imm:
            insn["ret_imm"] = ret_imm
        return insn

    # MOV
    if opcode == 0x88:
        op1, op2 = modrm_operands(True, 1)
        return make_insn("MOV", op1, op2), pos
    if opcode == 0x89:
        op1, op2 = modrm_operands(True, sz())
        return make_insn("MOV", op1, op2), pos
    if opcode == 0x8A:
        op1, op2 = modrm_operands(False, 1)
        return make_insn("MOV", op1, op2), pos
    if opcode == 0x8B:
        op1, op2 = modrm_operands(False, sz())
        return make_insn("MOV", op1, op2), pos
    if opcode == 0x8D:
        op1, op2 = modrm_operands(False, sz())
        return make_insn("LEA", op1, op2), pos
    if 0xB0 <= opcode <= 0xB7:
        r = opcode & 7
        if not can_read(1):
            raise DecodeError("truncated imm8")
        imm = read_s8()
        return make_insn("MOV", {"reg": r, "size": 1}, {"imm": imm, "size": 1}), pos
    if 0xB8 <= opcode <= 0xBF:
        r = opcode & 7
        if not can_read(4):
            raise DecodeError("truncated imm32")
        imm = read_s32()
        return make_insn("MOV", {"reg": r, "size": 4}, {"imm": imm, "size": 4}), pos
    if opcode == 0xC6:
        mod, reg_op, rm, modrm = parse_modrm()
        if reg_op != 0:
            raise DecodeError("unsupported C6 extension")
        op1 = modrm_ext_operand(modrm, 1)
        if not can_read(1):
            raise DecodeError("truncated imm8")
        imm = read_s8()
        return make_insn("MOV", op1, {"imm": imm, "size": 1}), pos
    if opcode == 0xC7:
        mod, reg_op, rm, modrm = parse_modrm()
        if reg_op != 0:
            raise DecodeError("unsupported C7 extension")
        op1 = modrm_ext_operand(modrm, sz())
        if not can_read(4):
            raise DecodeError("truncated imm32")
        imm = read_s32()
        return make_insn("MOV", op1, {"imm": imm, "size": 4}), pos

    # ADD
    if opcode == 0x00:
        op1, op2 = modrm_operands(True, 1)
        return make_insn("ADD", op1, op2, flags_write=True), pos
    if opcode == 0x01:
        op1, op2 = modrm_operands(True, sz())
        return make_insn("ADD", op1, op2, flags_write=True), pos
    if opcode == 0x02:
        op1, op2 = modrm_operands(False, 1)
        return make_insn("ADD", op1, op2, flags_write=True), pos
    if opcode == 0x03:
        op1, op2 = modrm_operands(False, sz())
        return make_insn("ADD", op1, op2, flags_write=True), pos
    if opcode == 0x04:
        if not can_read(1):
            raise DecodeError("truncated imm8")
        imm = read_s8()
        return make_insn("ADD", {"reg": 0, "size": 1}, {"imm": imm, "size": 1}, flags_write=True), pos
    if opcode == 0x05:
        if not can_read(4):
            raise DecodeError("truncated imm32")
        imm = read_s32()
        return make_insn("ADD", {"reg": 0, "size": 4}, {"imm": imm, "size": 4}, flags_write=True), pos

    # SUB
    if opcode == 0x28:
        op1, op2 = modrm_operands(True, 1)
        return make_insn("SUB", op1, op2, flags_write=True), pos
    if opcode == 0x29:
        op1, op2 = modrm_operands(True, sz())
        return make_insn("SUB", op1, op2, flags_write=True), pos
    if opcode == 0x2A:
        op1, op2 = modrm_operands(False, 1)
        return make_insn("SUB", op1, op2, flags_write=True), pos
    if opcode == 0x2B:
        op1, op2 = modrm_operands(False, sz())
        return make_insn("SUB", op1, op2, flags_write=True), pos
    if opcode == 0x2C:
        if not can_read(1):
            raise DecodeError("truncated imm8")
        imm = read_s8()
        return make_insn("SUB", {"reg": 0, "size": 1}, {"imm": imm, "size": 1}, flags_write=True), pos
    if opcode == 0x2D:
        if not can_read(4):
            raise DecodeError("truncated imm32")
        imm = read_s32()
        return make_insn("SUB", {"reg": 0, "size": 4}, {"imm": imm, "size": 4}, flags_write=True), pos

    # CMP
    if opcode == 0x38:
        op1, op2 = modrm_operands(True, 1)
        return make_insn("CMP", op1, op2, flags_write=True), pos
    if opcode == 0x39:
        op1, op2 = modrm_operands(True, sz())
        return make_insn("CMP", op1, op2, flags_write=True), pos
    if opcode == 0x3A:
        op1, op2 = modrm_operands(False, 1)
        return make_insn("CMP", op1, op2, flags_write=True), pos
    if opcode == 0x3B:
        op1, op2 = modrm_operands(False, sz())
        return make_insn("CMP", op1, op2, flags_write=True), pos
    if opcode == 0x3C:
        if not can_read(1):
            raise DecodeError("truncated imm8")
        imm = read_s8()
        return make_insn("CMP", {"reg": 0, "size": 1}, {"imm": imm, "size": 1}, flags_write=True), pos
    if opcode == 0x3D:
        if not can_read(4):
            raise DecodeError("truncated imm32")
        imm = read_s32()
        return make_insn("CMP", {"reg": 0, "size": 4}, {"imm": imm, "size": 4}, flags_write=True), pos

    # AND
    if opcode == 0x20:
        op1, op2 = modrm_operands(True, 1)
        return make_insn("AND", op1, op2, flags_write=True), pos
    if opcode == 0x21:
        op1, op2 = modrm_operands(True, sz())
        return make_insn("AND", op1, op2, flags_write=True), pos
    if opcode == 0x22:
        op1, op2 = modrm_operands(False, 1)
        return make_insn("AND", op1, op2, flags_write=True), pos
    if opcode == 0x23:
        op1, op2 = modrm_operands(False, sz())
        return make_insn("AND", op1, op2, flags_write=True), pos

    # OR
    if opcode == 0x08:
        op1, op2 = modrm_operands(True, 1)
        return make_insn("OR", op1, op2, flags_write=True), pos
    if opcode == 0x09:
        op1, op2 = modrm_operands(True, sz())
        return make_insn("OR", op1, op2, flags_write=True), pos
    if opcode == 0x0A:
        op1, op2 = modrm_operands(False, 1)
        return make_insn("OR", op1, op2, flags_write=True), pos
    if opcode == 0x0B:
        op1, op2 = modrm_operands(False, sz())
        return make_insn("OR", op1, op2, flags_write=True), pos

    # XOR
    if opcode == 0x30:
        op1, op2 = modrm_operands(True, 1)
        return make_insn("XOR", op1, op2, flags_write=True), pos
    if opcode == 0x31:
        op1, op2 = modrm_operands(True, sz())
        return make_insn("XOR", op1, op2, flags_write=True), pos
    if opcode == 0x32:
        op1, op2 = modrm_operands(False, 1)
        return make_insn("XOR", op1, op2, flags_write=True), pos
    if opcode == 0x33:
        op1, op2 = modrm_operands(False, sz())
        return make_insn("XOR", op1, op2, flags_write=True), pos

    # TEST
    if opcode == 0x84:
        op1, op2 = modrm_operands(True, 1)
        return make_insn("TEST", op1, op2, flags_write=True), pos
    if opcode == 0x85:
        op1, op2 = modrm_operands(True, sz())
        return make_insn("TEST", op1, op2, flags_write=True), pos
    if opcode == 0xA8:
        if not can_read(1):
            raise DecodeError("truncated imm8")
        imm = read_s8()
        return make_insn("TEST", {"reg": 0, "size": 1}, {"imm": imm, "size": 1}, flags_write=True), pos
    if opcode == 0xA9:
        if not can_read(4):
            raise DecodeError("truncated imm32")
        imm = read_s32()
        return make_insn("TEST", {"reg": 0, "size": 4}, {"imm": imm, "size": 4}, flags_write=True), pos

    # PUSH / POP
    if 0x50 <= opcode <= 0x57:
        r = opcode & 7
        return make_insn("PUSH", {"reg": r, "size": 4}, stack_delta=-4), pos
    if 0x58 <= opcode <= 0x5F:
        r = opcode & 7
        return make_insn("POP", {"reg": r, "size": 4}, stack_delta=4), pos
    if opcode == 0x68:
        if not can_read(4):
            raise DecodeError("truncated imm32")
        imm = read_s32()
        return make_insn("PUSH", {"imm": imm, "size": 4}, stack_delta=-4), pos
    if opcode == 0x6A:
        if not can_read(1):
            raise DecodeError("truncated imm8")
        imm = read_s8()
        return make_insn("PUSH", {"imm": imm, "size": 1}, stack_delta=-4), pos

    # INC / DEC reg (0x40-0x4F are not REX in x86)
    if 0x40 <= opcode <= 0x47:
        r = opcode & 7
        return make_insn("INC", {"reg": r, "size": 4}, flags_write=True), pos
    if 0x48 <= opcode <= 0x4F:
        r = opcode & 7
        return make_insn("DEC", {"reg": r, "size": 4}, flags_write=True), pos

    # JMP
    if opcode == 0xEB:
        if not can_read(1):
            raise DecodeError("truncated rel8")
        rel = read_s8()
        target = addr + pos + rel
        return make_insn("JMP", branch=True, target=target), pos
    if opcode == 0xE9:
        if not can_read(4):
            raise DecodeError("truncated rel32")
        rel = read_s32()
        target = addr + pos + rel
        return make_insn("JMP", branch=True, target=target), pos

    # CALL
    if opcode == 0xE8:
        if not can_read(4):
            raise DecodeError("truncated rel32")
        rel = read_s32()
        target = addr + pos + rel
        return make_insn("CALL", branch=True, call=True, target=target, stack_delta=-4), pos

    # RET
    if opcode == 0xC3:
        return make_insn("RET", ret=True, stack_delta=4), pos
    if opcode == 0xC2:
        if not can_read(2):
            raise DecodeError("truncated imm16")
        imm = int.from_bytes(data[pos:pos+2], "little")
        pos += 2
        return make_insn("RET", ret=True, stack_delta=4, ret_imm=imm), pos

    # Jcc short
    if 0x70 <= opcode <= 0x7F:
        if not can_read(1):
            raise DecodeError("truncated rel8")
        rel = read_s8()
        target = addr + pos + rel
        cc = opcode & 0x0F
        return make_insn("Jcc", branch=True, conditional=True, cond=COND_NAMES.get(cc, str(cc)), target=target, flags_read=True), pos

    # NOP
    if opcode == 0x90:
        return make_insn("NOP"), pos

    # Two-byte opcodes
    if opcode == 0x0F:
        if not can_read(1):
            raise DecodeError("truncated two-byte opcode")
        op2 = read_u8()
        if 0x80 <= op2 <= 0x8F:
            if not can_read(4):
                raise DecodeError("truncated rel32")
            rel = read_s32()
            target = addr + pos + rel
            cc = op2 & 0x0F
            return make_insn("Jcc", branch=True, conditional=True, cond=COND_NAMES.get(cc, str(cc)), target=target, flags_read=True), pos
        raise DecodeError(f"unsupported two-byte opcode 0F {op2:02X}")

    # Group: 0x80/0x81/0x83
    if opcode in (0x80, 0x81, 0x83):
        if not can_read(1):
            raise DecodeError("truncated modrm")
        modrm = read_u8()
        ext = (modrm >> 3) & 7
        op_size = 1 if opcode == 0x80 else 4
        name = {0: "ADD", 5: "SUB", 7: "CMP"}.get(ext)
        if name is None:
            raise DecodeError(f"unsupported group extension {ext}")
        op1 = modrm_ext_operand(modrm, op_size)
        if opcode == 0x80:
            if not can_read(1):
                raise DecodeError("truncated imm8")
            imm = read_s8()
            op2 = {"imm": imm, "size": 1}
        elif opcode == 0x81:
            if not can_read(4):
                raise DecodeError("truncated imm32")
            imm = read_s32()
            op2 = {"imm": imm, "size": op_size}
        else:  # 0x83
            if not can_read(1):
                raise DecodeError("truncated imm8")
            imm = read_s8()
            op2 = {"imm": imm, "size": op_size}
        return make_insn(name, op1, op2, flags_write=True), pos

    # Group: 0xFF
    if opcode == 0xFF:
        if not can_read(1):
            raise DecodeError("truncated modrm")
        modrm = read_u8()
        ext = (modrm >> 3) & 7
        if ext == 0:
            op1 = modrm_ext_operand(modrm, 4)
            return make_insn("INC", op1, flags_write=True), pos
        if ext == 1:
            op1 = modrm_ext_operand(modrm, 4)
            return make_insn("DEC", op1, flags_write=True), pos
        if ext == 2:
            op1 = modrm_ext_operand(modrm, 4)
            return make_insn("CALL", op1, branch=True, call=True, stack_delta=-4), pos
        if ext == 4:
            op1 = modrm_ext_operand(modrm, 4)
            return make_insn("JMP", op1, branch=True), pos
        if ext == 6:
            op1 = modrm_ext_operand(modrm, 4)
            return make_insn("PUSH", op1, stack_delta=-4), pos
        raise DecodeError(f"unsupported FF extension {ext}")

    raise DecodeError(f"unsupported opcode {opcode:02X}")


def operand_to_str(op):
    if "reg" in op:
        return reg_name(op["reg"], op.get("size", 8))
    if "imm" in op:
        v = op["imm"]
        if v < 0:
            return f"-0x{-v:x}"
        return f"0x{v:x}"
    if op.get("rip_relative"):
        return f"[rip+0x{op.get('disp', 0):x}]"
    parts = []
    if op.get("base", -1) >= 0:
        parts.append(reg_name(op["base"], 8))
    if op.get("index", -1) >= 0:
        idx = reg_name(op["index"], 8)
        scl = op.get("scale", 1)
        if scl == 1:
            parts.append(f"{idx}")
        else:
            parts.append(f"{idx}*{scl}")
    disp = op.get("disp", 0)
    if disp != 0 or not parts:
        if disp < 0:
            parts.append(f"-0x{-disp:x}")
        else:
            parts.append(f"0x{disp:x}")
    if not parts:
        return "[0x0]"
    return "[" + "+".join(parts) + "]"


def insn_to_text(insn):
    op = insn["opcode"]
    extras = []
    if insn.get("is_conditional"):
        extras.append(insn.get("cond", ""))
    if "op1" in insn:
        extras.append(operand_to_str(insn["op1"]))
    if "op2" in insn:
        extras.append(operand_to_str(insn["op2"]))
    if "branch_target" in insn:
        extras.append(f"-> {insn['branch_target']}")
    if "ret_imm" in insn and insn["ret_imm"]:
        extras.append(f"0x{insn['ret_imm']:x}")
    return f"{insn['addr']}  {insn['bytes']:<30}  {op} {', '.join(extras[1:] if insn.get('is_conditional') else extras)}"


def main():
    parser = argparse.ArgumentParser(description="HyperBridge Decoder")
    parser.add_argument("--arch", choices=["x64", "x86"], default="x64")
    parser.add_argument("--hex", help="hex string of bytes")
    parser.add_argument("--file", help="binary file to decode")
    parser.add_argument("--addr", type=lambda x: int(x, 0), default=0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    data = b""
    if args.hex:
        data = bytes.fromhex(args.hex.replace(" ", ""))
    elif args.file:
        with open(args.file, "rb") as f:
            data = f.read()
    else:
        print("error: provide --hex or --file", file=sys.stderr)
        sys.exit(1)

    if args.arch == "x64":
        results = decode_x64_bytes(data, args.addr)
    else:
        results = decode_x86_bytes(data, args.addr)

    if args.json:
        print(json.dumps({"arch": args.arch, "instructions": results}, indent=2))
    else:
        for r in results:
            print(insn_to_text(r))


if __name__ == "__main__":
    main()
