#!/bin/sh
# MIT; see LICENSE. Run from this script's directory.
set -eu
cd "$(dirname "$0")"
export LC_ALL=C
python3 generate_asm.py
gcc -O2 -std=c11 -Wall -Wextra -Werror -fno-pie -no-pie \
  -Wl,--build-id=none -o probe probe.c probes.S
mkdir -p repeat
./probe . > capture-run1.log
./probe repeat > repeat/capture-run2.log
cmp capture-run1.log repeat/capture-run2.log
for f in A-inc-dec.csv B-add1-sub1.csv C-memory-cmp-test.csv D-high-byte.csv; do
  cmp "$f" "repeat/$f"
done
python3 verify.py . repeat > validation.json
python3 independent-audit/audit_elf.py probe > encoding-validation.json
echo 'PASS: two runs byte-identical; dataset/formulas and native instruction encodings validated.'
