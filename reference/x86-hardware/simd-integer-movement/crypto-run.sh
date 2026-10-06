#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
cd "$(dirname "$0")"
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo "Native Linux x86_64 required" >&2; exit 2; }
mkdir -p crypto/build
python3 crypto/generate.py
gcc -O2 -std=c11 -Wall -Wextra -fno-tree-vectorize -fno-tree-slp-vectorize -mavx crypto/main.c crypto/ops.S -o crypto/build/oracle
python3 crypto/verify.py
gcc -O2 -std=c11 crypto/machine.c -o crypto/build/machine
crypto/build/machine > crypto-machine.txt
gcc --version | head -n 1 >> crypto-machine.txt
uname -srm >> crypto-machine.txt
for pass in 1 2; do
  timeout 900 crypto/build/oracle > crypto/build/raw-$pass.txt 2> crypto/build/validation-$pass.txt
  gzip -n -9 -c crypto/build/raw-$pass.txt > crypto/build/out-$pass.txt.gz
done
cmp crypto/build/raw-1.txt crypto/build/raw-2.txt
cmp crypto/build/out-1.txt.gz crypto/build/out-2.txt.gz
cmp crypto/build/validation-1.txt crypto/build/validation-2.txt
cp crypto/build/out-1.txt.gz out-crypto.txt.gz
sha256sum crypto/build/raw-1.txt | awk '{print $1 "  out-crypto.txt"}' > out-crypto.sha256
cp crypto/build/validation-1.txt crypto-validation.txt
python3 crypto/check-output.py
cat crypto-validation.txt
