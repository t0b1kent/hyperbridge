#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
cd "$(dirname "$0")"
out="${1:-../results/0035-write-fault-atomicity-hardware/amd-epyc-9v74-linux}"
mkdir -p "$out"
python3 build.py
./probe35 --metadata > "$out/CPUID-KERNEL.txt"
for run in 1 2; do
 for group in scalar rmw vector; do
  ./probe35 "$group" 2> "$out/$group.run$run.log" | gzip -n -1 > "$out/$group.run$run.jsonl.gz"
  echo 0 > "$out/$group.run$run.exit"
 done
done
python3 check_fault_state.py "$out" > "$out/fault-state-check.log"
python3 analyze.py "$out" > "$out/analysis.log"
