#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
cd "$(dirname "$0")"
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo "Native Linux x86_64 required" >&2; exit 2; }
[[ -f crypto/build/raw-1.txt ]] || bash crypto-run.sh
gcc -O2 -std=c11 -Wall -Wextra -fno-tree-vectorize -fno-tree-slp-vectorize -mavx -fsanitize=undefined -fno-sanitize-recover=undefined crypto/main.c crypto/ops.S -o crypto/build/oracle-ubsan
timeout 900 crypto/build/oracle-ubsan > crypto/build/raw-ubsan.txt 2> crypto/build/ubsan-validation.txt
cmp crypto/build/raw-1.txt crypto/build/raw-ubsan.txt
{ printf '%s\n' 'UBSan: PASS (-fsanitize=undefined -fno-sanitize-recover=undefined)' 'Native sanitized data rows match normal-build output byte-for-byte'; cat crypto/build/ubsan-validation.txt; } > crypto-SANITIZER.txt
cat crypto-SANITIZER.txt
