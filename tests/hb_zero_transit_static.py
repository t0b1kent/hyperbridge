#!/usr/bin/env python3
"""Count the executed unconditional edge in benchmark arena dumps (Capstone).

The benchmark has a 4-block loop. Its first block commits an ADD to RAX,
then jumps to the second block. Follow the warmed matching path, including
the trampoline and the target's accounting, stopping at the target ADD body.
Deadline LO branches are taken; the matching trampoline's NE is not taken.
Print every counted instruction so these assumptions remain reviewable.
"""
import argparse
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG


def measure(directory, mode):
    root = Path(directory)
    manifest = json.loads((root / "manifest.json").read_text())
    arena = (root / "arena.bin").read_bytes()
    base = manifest["arena_base"]
    first, second = manifest["blocks"][:2]
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    decoder.detail = True

    def decode(address):
        offset = address - base
        assert 0 <= offset <= len(arena) - 4, hex(address)
        return next(decoder.disasm(arena[offset:offset + 4], address))

    # ADD RAX's architectural commit is the last STR x20,[x19,#0x20].
    # Decode one word at a time because edge metadata is intentionally data.
    commits = []
    for offset in range(0, first["size"], 4):
        try:
            ins = decode(first["native"] + offset)
        except StopIteration:
            continue
        if ins.mnemonic == "str" and ins.op_str == "x20, [x19, #0x20]":
            commits.append(ins.address)
    assert len(commits) == 1, commits
    pc = commits[0] + 4
    # A target's first guest operation loads a GPR at an offset below 0x100.
    target_body = None
    for offset in range(16, second["size"], 4):
        ins = decode(second["native"] + offset)
        if (ins.mnemonic == "ldr" and len(ins.operands) == 2
                and ins.operands[1].type == ARM64_OP_MEM
                and ins.reg_name(ins.operands[1].mem.base) == "x19"
                and 0 <= ins.operands[1].mem.disp < 0x100):
            target_body = ins.address
            break
    assert target_body is not None
    registers, trace = {}, []
    while pc != target_body:
        assert len(trace) < 100, "edge did not reach the successor body"
        ins = decode(pc)
        trace.append({"offset": pc - base, "asm": ins.mnemonic + " " + ins.op_str})
        following = pc + 4
        if ins.mnemonic in ("b", "bl", "b.lo"):
            following = ins.operands[0].imm
        elif ins.mnemonic == "b.ne":
            pass  # warmed trampoline's expected guest PC matches
        elif ins.mnemonic.startswith("b."):
            raise AssertionError("unexpected condition " + ins.mnemonic)
        elif ins.mnemonic == "ldr" and ins.operands[1].type == ARM64_OP_IMM:
            registers[ins.operands[0].reg] = struct.unpack_from(
                "<Q", arena, ins.operands[1].imm - base)[0]
        elif ins.mnemonic == "br":
            assert ins.operands[0].type == ARM64_OP_REG
            following = registers[ins.operands[0].reg]
        elif ins.mnemonic == "ret":
            raise AssertionError("edge returned to C")
        pc = following
    return {"mode": mode, "instructions": len(trace), "trace": trace,
            "target_body_offset": target_body - base}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("off_dump")
    parser.add_argument("on_dump")
    args = parser.parse_args()
    result = [measure(args.off_dump, "off"), measure(args.on_dump, "on")]
    assert result[1]["instructions"] == 1, result[1]
    print(json.dumps(result, indent=2))
