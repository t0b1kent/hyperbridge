#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
cd "$(dirname "$0")"
if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then echo 'Native Linux x86-64 required' >&2; exit 2; fi
out=${1:-reproduction}
mkdir -p "$out"
cc -std=c11 -O2 -Wall -Wextra -Wpedantic -fno-strict-aliasing probe.c -o "$out/probe" 2>"$out/build.log"
"$out/probe" --metadata > "$out/cpu-os.txt"
(timeout 900 "$out/probe" "$out/summary.tsv" "$out/layout.tsv" > "$out/observations.tsv") 2>"$out/run.log"
gzip -n -c "$out/observations.tsv" > "$out/observations.tsv.gz"
sha256sum "$out/observations.tsv" "$out/summary.tsv" "$out/layout.tsv" > "$out/result-sha256.txt"
printf '1000 repetitions per executable cell; raw results in %s\n' "$out"
