#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
cd "$(dirname "$0")"
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo "Native Linux x86-64 required" >&2; exit 2; }
python3 movement/generate.py
cc -O2 -std=c11 -Wall -Wextra -mavx2 -fno-tree-vectorize -fno-tree-slp-vectorize -o movement/movement-runner movement/runner.c movement/movement-generated.S
timeout 900 movement/movement-runner > movement/out-movement.first.txt 2> movement/movement.log
gzip -n -9 -c movement/out-movement.first.txt > out-movement.txt.gz
timeout 900 movement/movement-runner > movement/out-movement.second.txt 2> movement/movement-second.log
gzip -n -9 -c movement/out-movement.second.txt > movement/out-movement.second.txt.gz
cmp out-movement.txt.gz movement/out-movement.second.txt.gz
sha256sum movement/out-movement.first.txt | sed 's@movement/out-movement.first.txt@out-movement.txt@' > out-movement.sha256
python3 movement/audit.py
python3 movement/docs.py
cat movement/movement.log
rm movement/out-movement.first.txt movement/out-movement.second.txt movement/out-movement.second.txt.gz
