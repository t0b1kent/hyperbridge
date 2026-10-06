#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 OpenAI
set -eu
cd -- "$(dirname -- "$0")"
cc -O2 -Wall -Wextra -Werror -std=c11 -fno-lto -mno-avx \
  x87_benchmark.c x87_loops.S -o x87_benchmark
objdump -d -M intel x87_benchmark > disassembly.txt
{
  printf 'start_utc='; date -u '+%Y-%m-%dT%H:%M:%SZ'
  printf 'kernel='; uname -sr
  printf 'architecture='; uname -m
  printf 'compiler='; cc --version | head -n 1
  ./x87_benchmark 5000000 9 run-1.csv metadata-1.txt
  ./x87_benchmark 5000000 9 run-2.csv metadata-2.txt
  python3 summarize.py run-1.csv run-2.csv
  printf 'end_utc='; date -u '+%Y-%m-%dT%H:%M:%SZ'
} | tee run.log
sha256sum x87_benchmark.c x87_loops.S summarize.py run.sh LICENSE \
  run-1.csv run-2.csv metadata-1.txt metadata-2.txt summary.csv \
  functional-fingerprints.csv disassembly.txt run.log > SHA256SUMS
