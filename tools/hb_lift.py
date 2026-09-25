#!/usr/bin/env python3
"""hb_lift.py — HyperBridge IR lifter CLI.

Lifts decoded x64 instructions to HyperBridge IR.
"""

import argparse
import sys
import json
import os

# Import decoder
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from hb_decode import decode_x64_bytes, decode_x86_bytes


def lift_x64(data, addr=0):
    decoded = decode_x64_bytes(data, addr)
    blocks = []
    current_block = {"id": 0, "addr": f"0x{addr:08x}", "instrs": []}
    block_id = 1

    for d in decoded:
        if d.get("opcode") == "UNSUPPORTED":
            current_block["instrs"].append({
                "op": "UNSUPPORTED",
                "reason": d.get("reason", "unknown"),
                "guest_addr": d["addr"],
                "guest_len": d["len"]
            })
            continue

        ir = lift_insn(d)
        if ir:
            current_block["instrs"].append(ir)

        if d.get("is_branch") or d.get("is_ret") or d.get("is_call"):
            blocks.append(current_block)
            if d.get("is_branch") and not d.get("is_ret"):
                current_block = {"id": block_id, "addr": d.get("branch_target", d["next"]), "instrs": []}
                block_id += 1
            else:
                current_block = None
            break

    if current_block:
        blocks.append(current_block)

    return {
        "arch": "x64",
        "entry": f"0x{addr:08x}",
        "blocks": blocks,
        "has_unsupported": any(i.get("op") == "UNSUPPORTED" for b in blocks for i in b["instrs"])
    }


def lift_x86(data, addr=0):
    decoded = decode_x86_bytes(data, addr)
    blocks = []
    current_block = {"id": 0, "addr": f"0x{addr:08x}", "instrs": []}
    block_id = 1

    for d in decoded:
        if d.get("opcode") == "UNSUPPORTED":
            current_block["instrs"].append({
                "op": "UNSUPPORTED",
                "reason": d.get("reason", "unknown"),
                "guest_addr": d["addr"],
                "guest_len": d["len"]
            })
            continue

        ir = lift_insn(d)
        if ir:
            current_block["instrs"].append(ir)

        if d.get("is_branch") or d.get("is_ret") or d.get("is_call"):
            blocks.append(current_block)
            if d.get("is_branch") and not d.get("is_ret"):
                current_block = {"id": block_id, "addr": d.get("branch_target", d["next"]), "instrs": []}
                block_id += 1
            else:
                current_block = None
            break

    if current_block:
        blocks.append(current_block)

    return {
        "arch": "x86",
        "entry": f"0x{addr:08x}",
        "blocks": blocks,
        "has_unsupported": any(i.get("op") == "UNSUPPORTED" for b in blocks for i in b["instrs"])
    }


def lift_insn(d):
    """Convert a single decoded instruction to IR."""
    op = d.get("opcode")
    addr = d["addr"]
    ir = {
        "op": op,
        "guest_addr": addr,
        "guest_len": d["len"]
    }

    def opnd(field):
        if field not in d:
            return None
        o = d[field]
        if "reg" in o:
            return {"type": "reg", "reg": o["reg"], "size": o.get("size", 8)}
        if "imm" in o:
            return {"type": "imm", "value": o["imm"], "size": o.get("size", 8)}
        if o.get("rip_relative"):
            return {"type": "mem", "base": 16, "index": -1, "scale": 1,
                    "disp": o.get("disp", 0), "size": o.get("size", 8)}
        if "base" in o:
            return {"type": "mem", "base": o.get("base", -1), "index": o.get("index", -1),
                    "scale": o.get("scale", 1), "disp": o.get("disp", 0), "size": o.get("size", 8)}
        return None

    def set_binop(name):
        ir["op"] = name
        ir["dst"] = opnd("op1")
        ir["src1"] = opnd("op1")
        ir["src2"] = opnd("op2")

    if op == "MOV":
        o1 = opnd("op1")
        o2 = opnd("op2")
        if o1 and o2:
            if o1.get("type") == "mem" and o2.get("type") == "reg":
                ir["op"] = "STORE"
                ir["addr"] = o1
                ir["src"] = o2
            elif o1.get("type") == "reg" and o2.get("type") == "mem":
                ir["op"] = "LOAD"
                ir["dst"] = o1
                ir["addr"] = o2
            else:
                ir["op"] = "MOV"
                ir["dst"] = o1
                ir["src"] = o2
    elif op == "LEA":
        ir["op"] = "LEA"
        ir["dst"] = opnd("op1")
        ir["addr"] = opnd("op2")
    elif op == "ADD":
        set_binop("ADD")
    elif op == "SUB":
        set_binop("SUB")
    elif op == "AND":
        set_binop("AND")
    elif op == "OR":
        set_binop("OR")
    elif op == "XOR":
        set_binop("XOR")
    elif op == "INC":
        ir["op"] = "ADD"
        ir["dst"] = opnd("op1")
        ir["src1"] = opnd("op1")
        ir["src2"] = {"type": "imm", "value": 1, "size": ir["dst"]["size"] if ir["dst"] else 8}
    elif op == "DEC":
        ir["op"] = "SUB"
        ir["dst"] = opnd("op1")
        ir["src1"] = opnd("op1")
        ir["src2"] = {"type": "imm", "value": 1, "size": ir["dst"]["size"] if ir["dst"] else 8}
    elif op == "CMP":
        ir["op"] = "CMP"
        ir["src1"] = opnd("op1")
        ir["src2"] = opnd("op2")
    elif op == "TEST":
        ir["op"] = "TEST"
        ir["src1"] = opnd("op1")
        ir["src2"] = opnd("op2")
    elif op == "PUSH":
        ir["op"] = "PUSH"
        ir["src"] = opnd("op1")
    elif op == "POP":
        ir["op"] = "POP"
        ir["dst"] = opnd("op1")
    elif op == "CALL":
        ir["op"] = "CALL"
        ir["target"] = d.get("branch_target")
    elif op == "RET":
        ir["op"] = "RET"
        if d.get("ret_imm"):
            ir["ret_imm"] = d["ret_imm"]
    elif op == "JMP":
        ir["op"] = "JMP"
        ir["target"] = d.get("branch_target")
    elif op == "Jcc":
        ir["op"] = "Jcc"
        ir["cond"] = d.get("cond")
        ir["target"] = d.get("branch_target")
    elif op == "NOP":
        ir["op"] = "NOP"
    else:
        ir["op"] = "UNSUPPORTED"
        ir["reason"] = f"unlifted opcode {op}"

    return ir


def main():
    parser = argparse.ArgumentParser(description="HyperBridge Lifter")
    parser.add_argument("--arch", choices=["x64", "x86"], default="x64")
    parser.add_argument("--hex", help="hex string of bytes")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if not args.hex:
        print("error: provide --hex", file=sys.stderr)
        sys.exit(1)

    data = bytes.fromhex(args.hex.replace(" ", ""))
    if args.arch == "x86":
        result = lift_x86(data)
    else:
        result = lift_x64(data)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Lifter: arch={result['arch']} blocks={len(result['blocks'])}")
        for blk in result["blocks"]:
            print(f"  Block {blk['id']} @ {blk['addr']}:")
            for i in blk["instrs"]:
                print(f"    {i['op']:10} {i}")


if __name__ == "__main__":
    main()
