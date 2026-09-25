#!/usr/bin/env python3
"""hb_translate.py — HyperBridge translate CLI.

Runs the full decode → lift pipeline and prints the resulting IR.
"""

import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from hb_decode import decode_x64_bytes, decode_x86_bytes
from hb_lift import lift_x64, lift_x86


def main():
    parser = argparse.ArgumentParser(description="HyperBridge Translator")
    parser.add_argument("--arch", choices=["x64", "x86"], default="x64")
    parser.add_argument("--hex", help="hex string of guest code")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--stats", action="store_true", help="show block/instruction counts")
    parser.add_argument("--cache-root", default=None, help="persistent translation cache root")
    parser.add_argument("--clear-cache", action="store_true")
    args = parser.parse_args()

    if not args.hex:
        print("error: provide --hex", file=sys.stderr)
        sys.exit(1)

    data = bytes.fromhex(args.hex.replace(" ", ""))
    cache_status = "disabled"
    cache_key = hashlib.sha256((args.arch + ":" + data.hex()).encode()).hexdigest()
    if args.cache_root:
        from pathlib import Path
        root = Path(args.cache_root)
        root.mkdir(parents=True, exist_ok=True)
        cache_file = root / f"{cache_key}.json"
        if args.clear_cache and cache_file.exists():
            cache_file.unlink()
        if cache_file.exists():
            cached = json.loads(cache_file.read_text())
            cached["cache"] = {"status": "hit", "key": cache_key, "path": str(cache_file)}
            print(json.dumps(cached, indent=2) if args.json else "Translate: OK (cache hit)")
            return
        cache_status = "miss"
    if args.arch == "x86":
        decoded = decode_x86_bytes(data)
        ir = lift_x86(data)
    else:
        decoded = decode_x64_bytes(data)
        ir = lift_x64(data)

    blocks = ir.get("blocks", [])
    instr_count = sum(len(b.get("instrs", [])) for b in blocks)

    decoded_instrs = decoded if isinstance(decoded, list) else decoded.get("instructions", [])
    result = {
        "arch": args.arch,
        "status": "UNSUPPORTED" if ir.get("has_unsupported") else "OK",
        "decoded_instructions": len(decoded_instrs),
        "ir_blocks": len(blocks),
        "ir_instructions": instr_count,
        "decoded": decoded_instrs,
        "ir": ir,
        "cache": {"status": cache_status, "key": cache_key if args.cache_root else None},
    }
    if args.cache_root:
        from pathlib import Path
        cache_file = Path(args.cache_root) / f"{cache_key}.json"
        cache_file.write_text(json.dumps(result, indent=2) + "\n")
        result["cache"]["path"] = str(cache_file)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Translate: {result['status']}")
        print(f"  Decoded: {result['decoded_instructions']} instructions")
        print(f"  IR: {result['ir_blocks']} blocks, {result['ir_instructions']} instructions")
        for blk in blocks:
            addr_str = blk['addr']
            print(f"\n  Block {blk['id']} @ {addr_str}:")
            for i in blk.get("instrs", []):
                print(f"    {i['op']:<12} dst={i.get('dst')} src={i.get('src')} src1={i.get('src1')} src2={i.get('src2')}")


if __name__ == "__main__":
    main()
