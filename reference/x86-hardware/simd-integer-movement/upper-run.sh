#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || exit 2
python3 upper-generate.py
gcc -O2 -std=c11 -Wall -Wextra -fno-tree-vectorize -fno-tree-slp-vectorize upper.c core-build/upper.S -o core-build/upper
for n in first second; do timeout 900 core-build/upper > "core-build/upper.$n.txt" 2>"core-build/upper.$n.log"; done
cmp core-build/upper.first.txt core-build/upper.second.txt
gzip -n -9 -c core-build/upper.first.txt > out-upper.txt.gz
gzip -n -9 -c core-build/upper.second.txt > core-build/upper.second.txt.gz
cmp out-upper.txt.gz core-build/upper.second.txt.gz
sha256sum core-build/upper.first.txt | sed 's@core-build/upper.first.txt@out-upper.txt@' > out-upper.sha256
cp core-build/upper.first.log out-upper.validation.txt
printf 'repeat_raw_and_gzip_identical=yes\n' >> out-upper.validation.txt
cat out-upper.validation.txt
