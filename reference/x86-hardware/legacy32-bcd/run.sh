#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
cd -- "$(dirname -- "$0")"
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo "Requires native Linux x86-64" >&2; exit 77; }
mkdir -p build
cc -O2 -Wall -Wextra -Werror probe.c -o build/probe
set +e
build/probe > build/probe.first.txt
probe_rc=$?
set -e
cat build/probe.first.txt
printf 'probe_exit=%s\n' "$probe_rc" > build/probe.exit.txt
if [[ $probe_rc != 0 ]]; then exit "$probe_rc"; fi
# LDT capability in a separate probe process is not a bridge configuration.
# This measured implementation uses the existing GDT selector verified here.
if ! grep -q '^READY: existing user 32-bit code selector 0023$' build/probe.first.txt; then
  echo 'The existing measured 0023 bridge is unavailable; LDT capability probe is not instruction coverage.' >&2
  exit 77
fi
build/probe > build/probe.second.txt
cmp build/probe.first.txt build/probe.second.txt
python3 generate.py
cc -O2 -Wall -Wextra -Werror -fno-pie -no-pie -fno-stack-protector roundtrip.c bridge.S bridge_check.S -o build/roundtrip
build/roundtrip > build/roundtrip.first.txt
build/roundtrip > build/roundtrip.second.txt
cmp build/roundtrip.first.txt build/roundtrip.second.txt
cc -O2 -Wall -Wextra -Werror -fno-pie -no-pie -fno-stack-protector oracle.c bridge.S build/ops.S -o build/oracle
for group in bcd extra control; do
  build/oracle "$group" > "build/$group.first.txt" 2> "build/$group.first.checks"
  build/oracle "$group" > "build/$group.second.txt" 2> "build/$group.second.checks"
  cmp "build/$group.first.txt" "build/$group.second.txt"
  cmp "build/$group.first.checks" "build/$group.second.checks"
  gzip -n -9 -c "build/$group.first.txt" > "out-$group.txt.gz"
  gzip -n -9 -c "build/$group.second.txt" > "build/$group.second.txt.gz"
  cmp "out-$group.txt.gz" "build/$group.second.txt.gz"
  sha256sum "build/$group.first.txt" | awk '{print $1 "  decompressed.txt"}' > "out-$group.sha256"
  cp "build/$group.first.checks" "$group-CHECKS.txt"
  head -1 "$group-CHECKS.txt"
done
cp build/probe.first.txt PROBE.txt
cat build/probe.exit.txt >> PROBE.txt
cp build/roundtrip.first.txt ROUNDTRIP.txt
python3 analyze.py
python3 audit.py
bash run-ubsan.sh
if [[ -f FILE-SHA256.txt ]]; then python3 manifest.py; fi
printf 'PASS: native semantics, per-case duplicate, complete-run byte identity, deterministic gzip, rules, raw hashes, counts and cross-mode controls\n'
