#!/usr/bin/env python3
"""Fresh-process AB/BA forwarding benchmark and ctx load/store census.

Run the driver under taskpolicy -b nice -n 15 while GAME-RUNNING.lock exists,
otherwise under nice -n 15. --emitdump and --gamegates add a static census of
the same straight-line snippets using the coordinator's tools (bash wrapper).
The ARM64 census counts instructions and transferred bytes, including pairs;
it recognizes unsigned-immediate and pair accesses with ctx base x19 only.
"""
import argparse
import collections
import json
import os
import pathlib
import statistics
import struct
import subprocess
import tempfile


def census(data):
    counts = collections.Counter()
    for (word,) in struct.iter_unpack("<I", data):
        if (word >> 5) & 31 != 19:
            continue
        vector = bool(word & (1 << 26))
        pair = word & 0x3A000000 == 0x28000000
        if word & 0x3B000000 == 0x39000000:
            opcode = (word >> 22) & 3
            # SIMD Q is encoded as size=0, opc=2/3; integer opc=2/3
            # denotes a signed load or prefetch, absent in these snippets.
            if opcode > 1 and not vector:
                continue
            size = 1 << (((word >> 30) & 3) + (4 if vector and opcode > 1 else 0))
            offset = ((word >> 10) & 4095) * size
            load = bool(opcode & 1)
            registers = 1
        elif pair:
            opc = (word >> 30) & 3
            if opc == 3 or (not vector and opc == 1):
                continue
            size = (4 << opc) if vector else (8 if opc == 2 else 4)
            immediate = (word >> 15) & 127
            offset = (immediate if immediate < 64 else immediate - 128) * size
            load = bool(word & (1 << 22))
            registers = 2
        else:
            continue
        group = "gpr" if 0x20 <= offset < 0xA0 else "xmm" if 0xB0 <= offset < 0x1B0 else None
        if group is None:
            continue
        operation = "load" if load else "store"
        counts[f"{group}_{operation}_instructions"] += 1
        counts[f"{group}_{operation}_bytes"] += size * registers
    names = [f"{g}_{op}_{unit}" for g in ("gpr", "xmm")
             for op in ("load", "store") for unit in ("instructions", "bytes")]
    return {"native_bytes": len(data), **{name: counts[name] for name in names}}


def run(command, env=None):
    process = subprocess.run(command, text=True, capture_output=True, env=env, timeout=60)
    if process.returncode:
        raise RuntimeError(f"command failed {command!r}: {process.stderr[-3000:]}")
    return process


def sample(binary, arm, workload, iterations, dump=None):
    command = [binary, arm, workload, str(iterations)]
    if dump is not None:
        command.append(str(dump))
    process = run(command)
    lines = [line for line in process.stdout.splitlines() if line.startswith('{"mode":')]
    if len(lines) != 1:
        raise RuntimeError(f"unexpected benchmark output: {process.stdout[-2000:]}")
    return json.loads(lines[0])


def distribution(values):
    return {"median": statistics.median(values), "min": min(values), "max": max(values),
            "stdev": statistics.stdev(values) if len(values) > 1 else 0.0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="./tests/hb_reg_forward_bench")
    parser.add_argument("--pairs", type=int, default=12)
    parser.add_argument("--iterations", type=int, default=500000)
    parser.add_argument("--treatment", choices=["on", "gpr", "xmm"], default="on")
    parser.add_argument("--workload", choices=["gpr", "sse", "sse_int", "both", "all"], default="all")
    parser.add_argument("--emitdump", help="optional path to coordinator hb_emitdump")
    parser.add_argument("--gamegates", help="optional path to coordinator gamegates.sh")
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    if args.pairs < 2 or args.iterations < 1 or args.iterations > 1000000000:
        parser.error("at least 2 pairs; 1..1000000000 iterations required")
    if bool(args.emitdump) != bool(args.gamegates):
        parser.error("--emitdump and --gamegates must be supplied together")
    workloads = (["gpr", "sse", "sse_int"] if args.workload == "all" else
                 ["gpr", "sse"] if args.workload == "both" else [args.workload])
    result = {"order": "AB/BA alternating, fresh process per sample", "pairs": args.pairs,
              "iterations": args.iterations, "treatment": args.treatment, "workloads": {}}
    with tempfile.TemporaryDirectory(prefix="hb-reg-forward-") as temporary:
        directory = pathlib.Path(temporary)
        for workload in workloads:
            samples, ratios, static = [], [], {}
            for arm in ["off", args.treatment]:
                dump = directory / f"{workload}-{arm}.bin"
                sample(args.binary, arm, workload, 128, dump)
                static[arm] = census(dump.read_bytes())
            for pair in range(args.pairs):
                arms = ["off", args.treatment] if pair % 2 == 0 else [args.treatment, "off"]
                pair_values = {}
                for position, arm in enumerate(arms):
                    row = sample(args.binary, arm, workload, args.iterations)
                    row.update(pair=pair, position=position)
                    samples.append(row)
                    pair_values[arm] = row["ns_per_iteration"]
                ratios.append(pair_values[args.treatment] / pair_values["off"])
                print(f"{workload} pair {pair + 1}/{args.pairs}: off={pair_values['off']:.3f} "
                      f"{args.treatment}={pair_values[args.treatment]:.3f} ns/iteration", flush=True)
            summary = {"ns_per_iteration": {arm: distribution([r["ns_per_iteration"] for r in samples
                                                               if r["mode"] == arm])
                                             for arm in ["off", args.treatment]},
                       "paired_speedup_percent": 100 * (1 - statistics.median(ratios)),
                       "paired_ratio": distribution(ratios),
                       "winning_pairs": sum(r < 1 for r in ratios)}
            result["workloads"][workload] = {"summary": summary, "static": static, "samples": samples}
        if args.emitdump:
            result["emitdump_static"] = {}
            snippets = {"gpr": "4801d0" * 8 + "c3", "sse": "660f58c1" * 8 + "c3",
                        "sse_int": "660fd4c1" * 8 + "c3"}
            for workload in workloads:
                result["emitdump_static"][workload] = {}
                for arm in ["off", args.treatment]:
                    dump = directory / f"emitdump-{workload}-{arm}.bin"
                    env = os.environ.copy()
                    env["MACRUNNER_HB_REG_FORWARD"] = str(int(arm in ("on", "gpr")))
                    env["MACRUNNER_HB_XMM_FORWARD"] = str(int(arm in ("on", "xmm")))
                    env["MACRUNNER_HB_TEST_REG_FORWARD_FLIP"] = "0"
                    env["MACRUNNER_HB_TEST_XMM_FORWARD_FLIP"] = "0"
                    env["MACRUNNER_HB_JCC_FUSE_FULL"] = "2"
                    run(["bash", args.gamegates, args.emitdump, snippets[workload], str(dump)], env)
                    result["emitdump_static"][workload][arm] = census(dump.read_bytes())
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({name: data["summary"] for name, data in result["workloads"].items()}, indent=2))


if __name__ == "__main__":
    main()
