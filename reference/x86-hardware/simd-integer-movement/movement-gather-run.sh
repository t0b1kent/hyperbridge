#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
cd "$(dirname "$0")"
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo "Native Linux x86-64 required" >&2; exit 2; }
python3 movement/gather-generate.py
cc -O2 -std=c11 -Wall -Wextra -mavx2 -fno-tree-vectorize -fno-tree-slp-vectorize -o movement/gather-runner movement/gather.c movement/gather-generated.S
timeout 900 movement/gather-runner > movement/out-gather.first.txt 2> movement/gather.log
gzip -n -9 -c movement/out-gather.first.txt > out-gather.txt.gz
timeout 900 movement/gather-runner > movement/out-gather.second.txt 2> movement/gather-second.log
gzip -n -9 -c movement/out-gather.second.txt > movement/out-gather.second.txt.gz
cmp out-gather.txt.gz movement/out-gather.second.txt.gz
sha256sum movement/out-gather.first.txt | sed 's@movement/out-gather.first.txt@out-gather.txt@' > out-gather.sha256
python3 movement/gather-audit.py
python3 movement/gather-docs.py
python3 movement/check-output.py
cat movement/gather.log
rm movement/out-gather.first.txt movement/out-gather.second.txt movement/out-gather.second.txt.gz
