#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
cd -- "$(dirname -- "$0")"
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Requires native Linux x86_64' >&2; exit 1; }
mode=${1:-full}; [[ $mode == full || $mode == quick ]] || { echo 'Usage: bash run.sh [full|quick]' >&2; exit 2; }
mkdir -p output
cc=${CC:-gcc}
"$cc" -O2 -std=c11 -Wall -Wextra -Werror -fno-fast-math -fno-strict-aliasing -mno-avx -o output/probe probe.c 2> output/build.log
./output/probe --metadata > output/hardware.txt
printf 'build_flags=-O2 -std=c11 -Wall -Wextra -Werror -fno-fast-math -fno-strict-aliasing -mno-avx\n' >> output/hardware.txt
if [[ -r /proc/cpuinfo ]]; then awk '/^microcode[[:space:]]*:/{print "microcode=" $3; exit}' /proc/cpuinfo >> output/hardware.txt; fi
args=(); [[ $mode == quick ]] && args+=(--quick)
timeout 900 ./output/probe "${args[@]}" > output/raw.csv 2> output/run.log
timeout 900 ./output/probe "${args[@]}" > output/repeat.csv 2> output/repeat.log
cmp output/raw.csv output/repeat.csv
sha256sum output/raw.csv > output/raw.sha256
if [[ $mode == full && -f validate.py ]] && command -v python3 >/dev/null; then
    timeout 900 python3 validate.py output/raw.csv > output/validation.json
fi
# No timestamps, machine names, environment variables, credentials or addresses.
gzip -n -9 -c output/raw.csv > output/raw.csv.gz
rm output/repeat.csv
printf 'SUMMARY: Part A %s rows=%s byte-identical-repeat=PASS Intel=NOT_MEASURED\n' "$mode" "$(($(wc -l < output/raw.csv)-1))" | tee output/SUMMARY.txt
