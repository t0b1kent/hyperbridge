#!/usr/bin/env python3
"""hb_run.py — HyperBridge execution runner CLI.

Runs x64/x86 guest code through an in-process interpreter for the MVP subset.
"""

import argparse
import sys
import json
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from hb_decode import decode_x64_bytes, decode_x86_bytes
from hb_lift import lift_x64, lift_x86


def run_x64(data, addr=0):
    ir = lift_x64(data, addr)
    if ir.get("has_unsupported"):
        return {
            "arch": "x64",
            "status": "UNSUPPORTED",
            "reason": "unsupported instructions in guest code",
            "ir": ir,
            "regs": None,
            "steps": 0,
        }

    regs = {i: 0 for i in range(17)}  # 0-15 = rax-r15, 16 = rip
    flags = {"zf": False, "sf": False, "cf": False, "of": False}
    memory = {}
    stack_top = 0x7FFF0000
    regs[4] = stack_top
    regs[5] = stack_top

    def read_reg(idx):
        return regs.get(idx, 0)

    def write_reg(idx, val):
        if idx < 16:
            regs[idx] = val & 0xFFFFFFFFFFFFFFFF

    def read_mem(addr, size):
        val = 0
        for i in range(size):
            val |= memory.get(addr + i, 0) << (8 * i)
        return val

    def write_mem(addr, val, size):
        for i in range(size):
            memory[addr + i] = (val >> (8 * i)) & 0xFF

    def resolve(op):
        if op["type"] == "reg":
            return read_reg(op["reg"])
        if op["type"] == "imm":
            v = op["value"]
            sz = op.get("size", 8)
            if sz == 1 and v < 0:
                v = v & 0xFF
                if v >= 0x80:
                    v |= ~0xFF
            elif sz == 4 and v < 0:
                v = v & 0xFFFFFFFF
                if v >= 0x80000000:
                    v |= ~0xFFFFFFFF
            return v & 0xFFFFFFFFFFFFFFFF
        if op["type"] == "mem":
            base = read_reg(op["base"]) if op.get("base", -1) >= 0 else 0
            index = read_reg(op["index"]) if op.get("index", -1) >= 0 else 0
            disp = op.get("disp", 0)
            scale = op.get("scale", 1)
            return base + index * scale + disp
        return 0

    def set_flags(result, a=0, b=0, op_name="", size=64):
        mask = {8: 0xFF, 16: 0xFFFF, 32: 0xFFFFFFFF, 64: 0xFFFFFFFFFFFFFFFF}.get(size, 0xFFFFFFFFFFFFFFFF)
        t = result & mask
        ta = a & mask
        tb = b & mask
        msb = {8: 7, 16: 15, 32: 31, 64: 63}.get(size, 63)
        flags["zf"] = (t == 0)
        flags["sf"] = bool((t >> msb) & 1)
        if op_name in ("ADD",):
            flags["cf"] = (t < ta)
            flags["of"] = bool(((ta ^ t) & (tb ^ t) & (1 << msb)) != 0)
        elif op_name in ("SUB", "CMP"):
            flags["cf"] = (ta < tb)
            flags["of"] = bool(((ta ^ tb) & (ta ^ t) & (1 << msb)) != 0)
        elif op_name in ("AND", "OR", "XOR", "TEST"):
            flags["cf"] = False
            flags["of"] = False

    def eval_cond(cond):
        mapping = {
            "e/z": flags["zf"], "ne/nz": not flags["zf"],
            "s": flags["sf"], "ns": not flags["sf"],
            "g": not flags["zf"] and (flags["sf"] == flags["of"]),
            "ge": flags["sf"] == flags["of"],
            "l": flags["sf"] != flags["of"],
            "le": flags["zf"] or (flags["sf"] != flags["of"]),
            "a": not flags["cf"] and not flags["zf"],
            "ae": not flags["cf"],
            "b": flags["cf"], "be": flags["cf"] or flags["zf"],
            "o": flags["of"], "no": not flags["of"],
            "p": False, "np": True,
            "b/c": flags["cf"], "ae/nc": not flags["cf"],
        }
        return mapping.get(cond, False)

    steps = 0
    for blk in ir.get("blocks", []):
        for i in blk.get("instrs", []):
            steps += 1
            op = i["op"]
            sz = i.get("dst", {}).get("size", 64)
            if op == "NOP":
                continue
            elif op == "MOV":
                dst = i["dst"]
                src = i["src"]
                if dst["type"] == "reg":
                    if src["type"] == "reg":
                        write_reg(dst["reg"], read_reg(src["reg"]))
                    elif src["type"] == "imm":
                        write_reg(dst["reg"], resolve(src))
            elif op == "LEA":
                dst = i["dst"]
                addr = resolve(i["addr"])
                if dst["type"] == "reg":
                    write_reg(dst["reg"], addr)
            elif op == "ADD":
                dst = i["dst"]
                a = resolve(i["src1"])
                b = resolve(i["src2"])
                result = (a + b) & 0xFFFFFFFFFFFFFFFF
                write_reg(dst["reg"], result)
                set_flags(result, a, b, "ADD", sz)
            elif op == "SUB":
                dst = i["dst"]
                a = resolve(i["src1"])
                b = resolve(i["src2"])
                result = (a - b) & 0xFFFFFFFFFFFFFFFF
                write_reg(dst["reg"], result)
                set_flags(result, a, b, "SUB", sz)
            elif op == "AND":
                dst = i["dst"]
                a = resolve(i["src1"])
                b = resolve(i["src2"])
                result = a & b
                write_reg(dst["reg"], result)
                set_flags(result, op_name="AND", size=sz)
            elif op == "OR":
                dst = i["dst"]
                a = resolve(i["src1"])
                b = resolve(i["src2"])
                result = a | b
                write_reg(dst["reg"], result)
                set_flags(result, op_name="OR", size=sz)
            elif op == "XOR":
                dst = i["dst"]
                a = resolve(i["src1"])
                b = resolve(i["src2"])
                result = a ^ b
                write_reg(dst["reg"], result)
                set_flags(result, op_name="XOR", size=sz)
            elif op == "CMP":
                a = resolve(i["src1"])
                b = resolve(i["src2"])
                result = (a - b) & 0xFFFFFFFFFFFFFFFF
                set_flags(result, a, b, "CMP", i["src1"].get("size", 64))
            elif op == "TEST":
                a = resolve(i["src1"])
                b = resolve(i["src2"])
                result = a & b
                set_flags(result, op_name="TEST", size=i["src1"].get("size", 64))
            elif op == "LOAD":
                dst = i["dst"]
                addr = resolve(i["addr"])
                sz = i["addr"].get("size", 8)
                val = read_mem(addr, sz)
                if dst["type"] == "reg":
                    write_reg(dst["reg"], val)
            elif op == "STORE":
                addr_op = i["addr"]
                addr = resolve(addr_op)
                src = i["src"]
                sz = src.get("size", 8)
                val = resolve(src)
                write_mem(addr, val, sz)
            elif op == "PUSH":
                regs[4] -= 8
                val = resolve(i["src"])
                write_mem(regs[4], val, 8)
            elif op == "POP":
                val = read_mem(regs[4], 8)
                regs[4] += 8
                dst = i["dst"]
                if dst["type"] == "reg":
                    write_reg(dst["reg"], val)
            elif op == "CALL":
                regs[4] -= 8
                ret_addr = int(i["guest_addr"], 16) + i["guest_len"]
                write_mem(regs[4], ret_addr, 8)
                target = int(i["target"], 16) if i.get("target") else ret_addr
                if target != ret_addr:
                    return {
                        "arch": "x64", "status": "CALL",
                        "reason": f"call to 0x{target:x} -- MVP stops at external call",
                        "regs": regs, "flags": flags, "steps": steps,
                    }
            elif op == "RET":
                val = read_mem(regs[4], 8)
                regs[4] += 8
                return {
                    "arch": "x64", "status": "RET",
                    "reason": f"return to 0x{val:x}",
                    "regs": regs, "flags": flags, "steps": steps,
                }
            elif op == "JMP":
                target = int(i["target"], 16) if i.get("target") else addr
                return {
                    "arch": "x64", "status": "JMP",
                    "reason": f"jump to 0x{target:x}",
                    "regs": regs, "flags": flags, "steps": steps,
                }
            elif op == "Jcc":
                cond = i.get("cond", "")
                if eval_cond(cond):
                    target = int(i["target"], 16) if i.get("target") else addr
                    return {
                        "arch": "x64", "status": "JMP",
                        "reason": f"conditional jump taken to 0x{target:x}",
                        "regs": regs, "flags": flags, "steps": steps,
                    }
            elif op == "UNSUPPORTED":
                return {
                    "arch": "x64", "status": "UNSUPPORTED",
                    "reason": i.get("reason", "unknown"),
                    "regs": regs, "flags": flags, "steps": steps,
                }

    return {
        "arch": "x64",
        "status": "OK",
        "reason": "execution completed",
        "regs": regs,
        "flags": flags,
        "steps": steps,
    }


def run_x86(data, addr=0):
    ir = lift_x86(data, addr)
    if ir.get("has_unsupported"):
        return {
            "arch": "x86",
            "status": "UNSUPPORTED",
            "reason": "unsupported instructions in guest code",
            "ir": ir,
            "regs": None,
            "steps": 0,
        }

    regs = {i: 0 for i in range(9)}  # 0-7 = eax-edi, 8 = eip
    flags = {"zf": False, "sf": False, "cf": False, "of": False}
    memory = {}
    stack_top = 0x7FFF0000
    regs[4] = stack_top
    regs[5] = stack_top

    def read_reg(idx):
        return regs.get(idx, 0)

    def write_reg(idx, val):
        if idx < 8:
            regs[idx] = val & 0xFFFFFFFF

    def read_mem(addr, size):
        val = 0
        for i in range(size):
            val |= memory.get(addr + i, 0) << (8 * i)
        return val

    def write_mem(addr, val, size):
        for i in range(size):
            memory[addr + i] = (val >> (8 * i)) & 0xFF

    def resolve(op):
        if op["type"] == "reg":
            return read_reg(op["reg"])
        if op["type"] == "imm":
            v = op["value"]
            sz = op.get("size", 4)
            if sz == 1 and v < 0:
                v = v & 0xFF
                if v >= 0x80:
                    v |= ~0xFF
            elif sz == 4 and v < 0:
                v = v & 0xFFFFFFFF
                if v >= 0x80000000:
                    v |= ~0xFFFFFFFF
            return v & 0xFFFFFFFF
        if op["type"] == "mem":
            base = read_reg(op["base"]) if op.get("base", -1) >= 0 else 0
            index = read_reg(op["index"]) if op.get("index", -1) >= 0 else 0
            disp = op.get("disp", 0)
            scale = op.get("scale", 1)
            return base + index * scale + disp
        return 0

    def set_flags(result, a=0, b=0, op_name="", size=32):
        mask = {8: 0xFF, 16: 0xFFFF, 32: 0xFFFFFFFF, 64: 0xFFFFFFFFFFFFFFFF}.get(size, 0xFFFFFFFF)
        t = result & mask
        ta = a & mask
        tb = b & mask
        msb = {8: 7, 16: 15, 32: 31, 64: 63}.get(size, 31)
        flags["zf"] = (t == 0)
        flags["sf"] = bool((t >> msb) & 1)
        if op_name in ("ADD",):
            flags["cf"] = (t < ta)
            flags["of"] = bool(((ta ^ t) & (tb ^ t) & (1 << msb)) != 0)
        elif op_name in ("SUB", "CMP"):
            flags["cf"] = (ta < tb)
            flags["of"] = bool(((ta ^ tb) & (ta ^ t) & (1 << msb)) != 0)
        elif op_name in ("AND", "OR", "XOR", "TEST"):
            flags["cf"] = False
            flags["of"] = False

    def eval_cond(cond):
        mapping = {
            "e/z": flags["zf"], "ne/nz": not flags["zf"],
            "s": flags["sf"], "ns": not flags["sf"],
            "g": not flags["zf"] and (flags["sf"] == flags["of"]),
            "ge": flags["sf"] == flags["of"],
            "l": flags["sf"] != flags["of"],
            "le": flags["zf"] or (flags["sf"] != flags["of"]),
            "a": not flags["cf"] and not flags["zf"],
            "ae": not flags["cf"],
            "b": flags["cf"], "be": flags["cf"] or flags["zf"],
            "o": flags["of"], "no": not flags["of"],
            "p": False, "np": True,
            "b/c": flags["cf"], "ae/nc": not flags["cf"],
        }
        return mapping.get(cond, False)

    steps = 0
    for blk in ir.get("blocks", []):
        for i in blk.get("instrs", []):
            steps += 1
            op = i["op"]
            sz = i.get("dst", {}).get("size", 32)
            if op == "NOP":
                continue
            elif op == "MOV":
                dst = i["dst"]
                src = i["src"]
                if dst["type"] == "reg":
                    if src["type"] == "reg":
                        write_reg(dst["reg"], read_reg(src["reg"]))
                    elif src["type"] == "imm":
                        write_reg(dst["reg"], resolve(src))
            elif op == "LEA":
                dst = i["dst"]
                addr = resolve(i["addr"])
                if dst["type"] == "reg":
                    write_reg(dst["reg"], addr)
            elif op == "ADD":
                dst = i["dst"]
                a = resolve(i["src1"])
                b = resolve(i["src2"])
                result = (a + b) & 0xFFFFFFFF
                write_reg(dst["reg"], result)
                set_flags(result, a, b, "ADD", sz)
            elif op == "SUB":
                dst = i["dst"]
                a = resolve(i["src1"])
                b = resolve(i["src2"])
                result = (a - b) & 0xFFFFFFFF
                write_reg(dst["reg"], result)
                set_flags(result, a, b, "SUB", sz)
            elif op == "AND":
                dst = i["dst"]
                a = resolve(i["src1"])
                b = resolve(i["src2"])
                result = a & b
                write_reg(dst["reg"], result)
                set_flags(result, op_name="AND", size=sz)
            elif op == "OR":
                dst = i["dst"]
                a = resolve(i["src1"])
                b = resolve(i["src2"])
                result = a | b
                write_reg(dst["reg"], result)
                set_flags(result, op_name="OR", size=sz)
            elif op == "XOR":
                dst = i["dst"]
                a = resolve(i["src1"])
                b = resolve(i["src2"])
                result = a ^ b
                write_reg(dst["reg"], result)
                set_flags(result, op_name="XOR", size=sz)
            elif op == "CMP":
                a = resolve(i["src1"])
                b = resolve(i["src2"])
                result = (a - b) & 0xFFFFFFFF
                set_flags(result, a, b, "CMP", i["src1"].get("size", 32))
            elif op == "TEST":
                a = resolve(i["src1"])
                b = resolve(i["src2"])
                result = a & b
                set_flags(result, op_name="TEST", size=i["src1"].get("size", 32))
            elif op == "LOAD":
                dst = i["dst"]
                addr = resolve(i["addr"])
                sz = i["addr"].get("size", 4)
                val = read_mem(addr, sz)
                if dst["type"] == "reg":
                    write_reg(dst["reg"], val)
            elif op == "STORE":
                addr_op = i["addr"]
                addr = resolve(addr_op)
                src = i["src"]
                sz = src.get("size", 4)
                val = resolve(src)
                write_mem(addr, val, sz)
            elif op == "PUSH":
                regs[4] -= 4
                val = resolve(i["src"])
                write_mem(regs[4], val, 4)
            elif op == "POP":
                val = read_mem(regs[4], 4)
                regs[4] += 4
                dst = i["dst"]
                if dst["type"] == "reg":
                    write_reg(dst["reg"], val)
            elif op == "CALL":
                regs[4] -= 4
                ret_addr = int(i["guest_addr"], 16) + i["guest_len"]
                write_mem(regs[4], ret_addr, 4)
                target = int(i["target"], 16) if i.get("target") else ret_addr
                if target != ret_addr:
                    return {
                        "arch": "x86", "status": "CALL",
                        "reason": f"call to 0x{target:x} -- MVP stops at external call",
                        "regs": regs, "flags": flags, "steps": steps,
                    }
            elif op == "RET":
                val = read_mem(regs[4], 4)
                regs[4] += 4
                return {
                    "arch": "x86", "status": "RET",
                    "reason": f"return to 0x{val:x}",
                    "regs": regs, "flags": flags, "steps": steps,
                }
            elif op == "JMP":
                target = int(i["target"], 16) if i.get("target") else addr
                return {
                    "arch": "x86", "status": "JMP",
                    "reason": f"jump to 0x{target:x}",
                    "regs": regs, "flags": flags, "steps": steps,
                }
            elif op == "Jcc":
                cond = i.get("cond", "")
                if eval_cond(cond):
                    target = int(i["target"], 16) if i.get("target") else addr
                    return {
                        "arch": "x86", "status": "JMP",
                        "reason": f"conditional jump taken to 0x{target:x}",
                        "regs": regs, "flags": flags, "steps": steps,
                    }
            elif op == "UNSUPPORTED":
                return {
                    "arch": "x86", "status": "UNSUPPORTED",
                    "reason": i.get("reason", "unknown"),
                    "regs": regs, "flags": flags, "steps": steps,
                }

    return {
        "arch": "x86",
        "status": "OK",
        "reason": "execution completed",
        "regs": regs,
        "flags": flags,
        "steps": steps,
    }


def main():
    parser = argparse.ArgumentParser(description="HyperBridge Runner")
    parser.add_argument("--arch", choices=["x64", "x86"], default="x64")
    parser.add_argument("--hex", help="hex string of bytes")
    parser.add_argument("--backend", choices=["interp", "jit", "aot"], default="interp")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if not args.hex:
        print("error: provide --hex", file=sys.stderr)
        sys.exit(1)

    data = bytes.fromhex(args.hex.replace(" ", ""))
    if args.arch == "x86":
        result = run_x86(data)
    else:
        result = run_x64(data)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Run: {result['status']} -- {result['reason']} (steps={result['steps']})")
        if result.get("regs"):
            for idx, val in sorted(result["regs"].items()):
                if args.arch == "x86":
                    names = ["eax","ecx","edx","ebx","esp","ebp","esi","edi","eip"]
                else:
                    names = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                             "r8","r9","r10","r11","r12","r13","r14","r15","rip"]
                if idx < len(names):
                    print(f"  {names[idx]} = 0x{val:08x}" if args.arch == "x86" else f"  {names[idx]} = 0x{val:016x}")
        if result.get("flags"):
            f = result["flags"]
            print(f"  flags: ZF={f['zf']} SF={f['sf']} CF={f['cf']} OF={f['of']}")


if __name__ == "__main__":
    main()
