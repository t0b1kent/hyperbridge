#!/usr/bin/env python3
"""hb_bench.py — HyperBridge benchmark CLI.

Measures decode, lift, and interpreter execution latency for the MVP subset.
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from hb_decode import decode_x64_bytes, decode_x86_bytes
from hb_lift import lift_x64, lift_x86
from hb_run import run_x64, run_x86


def bench(data, arch="x64", rounds=1000):
    if arch == "x86":
        decode_fn = decode_x86_bytes
        lift_fn = lift_x86
        run_fn = run_x86
    else:
        decode_fn = decode_x64_bytes
        lift_fn = lift_x64
        run_fn = run_x64

    # Warmup
    for _ in range(10):
        decode_fn(data)
        lift_fn(data)
        run_fn(data)

    t0 = time.perf_counter_ns()
    for _ in range(rounds):
        decoded = decode_fn(data)
    t1 = time.perf_counter_ns()
    decode_ns = (t1 - t0) // rounds

    t0 = time.perf_counter_ns()
    for _ in range(rounds):
        ir = lift_fn(data)
    t1 = time.perf_counter_ns()
    lift_ns = (t1 - t0) // rounds

    t0 = time.perf_counter_ns()
    for _ in range(rounds):
        out = run_fn(data)
    t1 = time.perf_counter_ns()
    run_ns = (t1 - t0) // rounds

    return {
        "arch": arch,
        "rounds": rounds,
        "bytes": len(data),
        "decode_ns": decode_ns,
        "lift_ns": lift_ns,
        "run_ns": run_ns,
        "total_ns": decode_ns + lift_ns + run_ns,
    }


def main():
    parser = argparse.ArgumentParser(description="HyperBridge Benchmark")
    parser.add_argument("--arch", choices=["x64", "x86"], default="x64")
    parser.add_argument("--hex", help="hex string of guest code")
    parser.add_argument("--rounds", type=int, default=1000)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if not args.hex:
        # Default benchmark payload: mov rax, 0x1234; add rax, 1; ret
        args.hex = "48c7c034120000004883c001c3"

    data = bytes.fromhex(args.hex.replace(" ", ""))
    result = bench(data, arch=args.arch, rounds=args.rounds)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"HyperBridge Benchmark ({result['arch']}, {result['rounds']} rounds, {result['bytes']} bytes)")
        print(f"  decode : {result['decode_ns']:,} ns/op")
        print(f"  lift   : {result['lift_ns']:,} ns/op")
        print(f"  run    : {result['run_ns']:,} ns/op")
        print(f"  total  : {result['total_ns']:,} ns/op")


if __name__ == "__main__":
    main()
