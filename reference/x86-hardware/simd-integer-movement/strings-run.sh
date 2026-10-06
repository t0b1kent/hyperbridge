#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
cd "$(dirname "$0")"
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo "Native Linux x86_64 required" >&2; exit 2; }
mkdir -p strings/build
python3 strings/generate.py
gcc -O2 -std=c11 -Wall -Wextra -fno-tree-vectorize -fno-tree-slp-vectorize -mavx strings/main.c strings/ops.S -o strings/build/oracle
python3 strings/verify.py
for pass in 1 2; do
  timeout 900 strings/build/oracle > strings/build/raw-$pass.txt 2> strings/build/validation-$pass.txt
  gzip -n -9 -c strings/build/raw-$pass.txt > strings/build/out-$pass.txt.gz
done
cmp strings/build/raw-1.txt strings/build/raw-2.txt
cmp strings/build/out-1.txt.gz strings/build/out-2.txt.gz
cmp strings/build/validation-1.txt strings/build/validation-2.txt
cp strings/build/out-1.txt.gz out-strings.txt.gz
sha256sum strings/build/raw-1.txt | awk '{print $1 "  out-strings.txt"}' > out-strings.sha256
cp strings/build/validation-1.txt strings-validation.txt
python3 strings/check-output.py
cat strings-validation.txt
