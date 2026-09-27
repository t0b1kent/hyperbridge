#!/usr/bin/env python3
"""Paired fresh-process benchmark; run the driver under taskpolicy/nice."""
import argparse
import json
import pathlib
import statistics
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="./tests/hb_zero_transit_bench")
    parser.add_argument("--pairs", type=int, default=12)
    parser.add_argument("--iterations", type=int, default=500000)
    parser.add_argument("--treatment", choices=["on", "frame", "counters", "pc", "slot"], default="on")
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    if args.pairs < 2 or args.iterations < 1:
        parser.error("at least two pairs and one iteration are required")
    rows = []
    ratios = []
    for pair in range(args.pairs):
        modes = ["off", args.treatment] if pair % 2 == 0 else [args.treatment, "off"]
        sample = {}
        for position, mode in enumerate(modes):
            proc = subprocess.run([args.binary, mode, str(args.iterations)],
                                  text=True, capture_output=True, timeout=60, check=False)
            if proc.returncode:
                raise RuntimeError(f"{mode} failed ({proc.returncode}): {proc.stderr[-6000:]}")
            lines = [line for line in proc.stdout.splitlines() if line.startswith('{"mode":')]
            if len(lines) != 1:
                raise RuntimeError(f"unexpected benchmark output: {proc.stdout[-4000:]}")
            row = json.loads(lines[0])
            row.update(pair=pair, position=position)
            rows.append(row)
            sample[mode] = row["ns_per_iteration"]
        ratios.append(sample[args.treatment] / sample["off"])
        print(f"pair {pair + 1}/{args.pairs}: off={sample['off']:.3f} "
              f"{args.treatment}={sample[args.treatment]:.3f} ns/iteration", flush=True)
    summary = {"pairs": args.pairs, "iterations": args.iterations,
               "blocks_per_iteration": 4, "order": "AB/BA alternating", "arms": {}}
    for mode in ["off", args.treatment]:
        values = [r["ns_per_iteration"] for r in rows if r["mode"] == mode]
        summary["arms"][mode] = {"median_ns": statistics.median(values),
                                 "min_ns": min(values), "max_ns": max(values),
                                 "stdev_ns": statistics.stdev(values)}
    summary["paired_speedup_percent"] = 100 * (1 - statistics.median(ratios))
    summary["pair_ratio_min"] = min(ratios)
    summary["pair_ratio_max"] = max(ratios)
    summary["winning_pairs"] = sum(r < 1 for r in ratios)
    result = {"summary": summary, "samples": rows}
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
