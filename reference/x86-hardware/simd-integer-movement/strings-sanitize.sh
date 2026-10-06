#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
cd "$(dirname "$0")"
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo "Native Linux x86_64 required" >&2; exit 2; }
[[ -f strings/build/raw-1.txt ]] || bash strings-run.sh
gcc -O2 -std=c11 -Wall -Wextra -fno-tree-vectorize -fno-tree-slp-vectorize -mavx -fsanitize=undefined -fno-sanitize-recover=undefined strings/main.c strings/ops.S -o strings/build/oracle-ubsan
timeout 900 strings/build/oracle-ubsan > strings/build/raw-ubsan.txt 2> strings/build/ubsan-validation.txt
cmp strings/build/raw-1.txt strings/build/raw-ubsan.txt
{ printf '%s\n' 'UBSan: PASS (-fsanitize=undefined -fno-sanitize-recover=undefined)' 'Native sanitized data rows match normal-build output byte-for-byte'; cat strings/build/ubsan-validation.txt; } > strings-SANITIZER.txt
cat strings-SANITIZER.txt
