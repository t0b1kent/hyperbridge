#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Native Linux x86-64 required' >&2; exit 2; }
python3 core-generate.py
gcc -O2 -std=c11 -Wall -Wextra -fno-tree-vectorize -fno-tree-slp-vectorize core.c core-build/core.S -o core-build/core
classes=(permutation arithmetic logic shifts pack)
if (($#)); then classes=("$@"); fi
for cls in "${classes[@]}"; do
  timeout 900 core-build/core "$cls" > "core-build/$cls.first.txt" 2> "out-$cls.validation.txt"
  timeout 900 core-build/core "$cls" > "core-build/$cls.second.txt" 2> "core-build/$cls.second.log"
  cmp "core-build/$cls.first.txt" "core-build/$cls.second.txt"
  gzip -n -9 -c "core-build/$cls.first.txt" > "out-$cls.txt.gz"
  gzip -n -9 -c "core-build/$cls.second.txt" > "core-build/$cls.second.txt.gz"
  cmp "out-$cls.txt.gz" "core-build/$cls.second.txt.gz"
  sha256sum "core-build/$cls.first.txt" | sed "s@core-build/$cls.first.txt@out-$cls.txt@" > "out-$cls.sha256"
  printf 'repeat_raw_and_gzip_identical=yes\n' >> "out-$cls.validation.txt"
  cat "out-$cls.validation.txt"
done
