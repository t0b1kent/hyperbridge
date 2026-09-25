#!/usr/bin/env python3
"""LazyFlags microbenchmark for the HyperBridge report pipeline."""

from __future__ import annotations

import json
import time


MASK64 = (1 << 64) - 1
SIGN64 = 1 << 63


def eager_add_flags(a: int, b: int) -> dict[str, bool]:
    r = (a + b) & MASK64
    return {
        "zf": r == 0,
        "sf": bool(r & SIGN64),
        "cf": r < (a & MASK64),
        "of": bool(((a ^ r) & (b ^ r) & SIGN64) != 0),
        "pf": bin(r & 0xFF).count("1") % 2 == 0,
        "af": bool((a ^ b ^ r) & 0x10),
    }


def lazy_add_descriptor(a: int, b: int) -> tuple[int, int, int]:
    return a & MASK64, b & MASK64, (a + b) & MASK64


def lazy_materialize_zf(desc: tuple[int, int, int]) -> bool:
    return desc[2] == 0


def bench(rounds: int = 100_000) -> dict[str, object]:
    data = [(i * 0x100000001B3) & MASK64 for i in range(512)]
    workloads: dict[str, dict[str, int | None]] = {}

    t0 = time.perf_counter_ns()
    sink = 0
    for i in range(rounds):
        f = eager_add_flags(data[i & 511], data[(i + 17) & 511])
        sink ^= int(f["zf"]) ^ int(f["sf"]) ^ int(f["cf"]) ^ int(f["of"])
    eager_ns = (time.perf_counter_ns() - t0) // rounds

    t0 = time.perf_counter_ns()
    for i in range(rounds):
        desc = lazy_add_descriptor(data[i & 511], data[(i + 17) & 511])
        sink ^= int(lazy_materialize_zf(desc))
    branch_lazy_ns = (time.perf_counter_ns() - t0) // rounds

    t0 = time.perf_counter_ns()
    for i in range(rounds):
        desc = lazy_add_descriptor(data[i & 511], data[(i + 17) & 511])
        if (i & 15) == 0:
            sink ^= int(lazy_materialize_zf(desc))
    arithmetic_lazy_ns = (time.perf_counter_ns() - t0) // rounds

    t0 = time.perf_counter_ns()
    for i in range(rounds):
        value = data[i & 511]
        count = data[(i + 1) & 511] & 0x3F
        result = value if count == 0 else (value << count) & MASK64
        if count != 0:
            sink ^= int(result == 0)
    shift_lazy_ns = (time.perf_counter_ns() - t0) // rounds

    workloads["eager_all_flags_add"] = {"ns_per_op": eager_ns}
    workloads["lazy_branch_zf"] = {"ns_per_op": branch_lazy_ns}
    workloads["lazy_arithmetic_sparse_consumers"] = {"ns_per_op": arithmetic_lazy_ns}
    workloads["lazy_shift_zf_cf_model"] = {"ns_per_op": shift_lazy_ns}

    return {
        "benchmark": "HyperBridge LazyFlags host-side microbenchmark",
        "rounds": rounds,
        "scope": "Formula-level model benchmark; full JIT uses helper materialization in C.",
        "eager_flags_available": True,
        "lazy_flags_available": True,
        "sink": sink,
        "workloads": workloads,
    }


def main() -> None:
    print(json.dumps(bench(), indent=2))


if __name__ == "__main__":
    main()
