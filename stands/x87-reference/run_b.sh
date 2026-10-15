#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Part B of the x87 reference stand: sticky status flags across compares and integer stores. Same contract as run.sh.
set -euo pipefail
cd -- "$(dirname -- "$0")"
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Requires native Linux x86_64' >&2; exit 1; }
mkdir -p output-b
cc=${CC:-gcc}
"$cc" -O2 -std=c11 -Wall -Wextra -Werror -fno-fast-math -fno-strict-aliasing -mno-avx -o output-b/probe_b probe_b.c 2> output-b/build.log
./output-b/probe_b --metadata > output-b/hardware.txt
printf 'build_flags=-O2 -std=c11 -Wall -Wextra -Werror -fno-fast-math -fno-strict-aliasing -mno-avx\n' >> output-b/hardware.txt
if [[ -r /proc/cpuinfo ]]; then awk '/^microcode[[:space:]]*:/{print "microcode=" $3; exit}' /proc/cpuinfo >> output-b/hardware.txt; fi
timeout 900 ./output-b/probe_b > output-b/raw.csv 2> output-b/run.log
timeout 900 ./output-b/probe_b > output-b/repeat.csv 2> output-b/repeat.log
cmp output-b/raw.csv output-b/repeat.csv
sha256sum output-b/raw.csv > output-b/raw.sha256
# The validator never discards the data: the table is the deliverable, the verdict is recorded next to it.
validation=skipped
if [[ -f validate_b.py ]] && command -v python3 >/dev/null; then
    if timeout 900 python3 validate_b.py output-b/raw.csv > output-b/validation.json; then validation=PASS; else validation=FAIL; fi
fi
# No timestamps, machine names, environment variables, credentials or addresses.
gzip -n -9 -c output-b/raw.csv > output-b/raw.csv.gz
rm output-b/repeat.csv
printf 'SUMMARY: Part B rows=%s byte-identical-repeat=PASS validation=%s\n' "$(($(wc -l < output-b/raw.csv)-1))" "$validation" | tee output-b/SUMMARY.txt
