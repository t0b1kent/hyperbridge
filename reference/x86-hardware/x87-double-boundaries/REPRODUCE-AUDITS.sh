#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p validation
for p in core-audit-exact extended-audit-exact remainder-audit-exact; do
  gcc -O2 -std=c11 -Wall -Wextra -Werror -fno-strict-aliasing -fno-fast-math -ffp-contract=off "$p.c" -o "/tmp/0024-$p"
  "/tmp/0024-$p" >"validation/$p.log"
done
gcc -O2 -std=c11 -Wall -Wextra -Wno-misleading-indentation -fno-strict-aliasing -fno-fast-math -frounding-math -msse2 -mno-avx aux-audit-edges.c -o /tmp/0024-aux-audit-edges
/tmp/0024-aux-audit-edges >validation/aux-audit-edges.log
python3 scale-audit-edges.py >validation/scale-audit-edges.log
python3 format-audit-specials.py >validation/format-audit-specials.log
printf 'Independent small audits PASS\n'
