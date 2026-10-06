#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Re-run deterministic correctness suites twice. --with-benchmark also replaces timing evidence.
set -euo pipefail
cd "$(dirname "$0")"
[[ $(uname -m) == x86_64 && $(uname -s) == Linux ]] || { echo 'native Linux x86-64 required' >&2; exit 2; }
mkdir -p raw validation/{core-repeat,chains-repeat,extended-repeat,aux-repeat}
bash run-core.sh 1000000 7
timeout 900 ./core 1000000 7 validation/core-repeat 2>validation/core-repeat.log
bash run-chains.sh 1000000
timeout 900 ./chains 1000000 validation/chains-repeat 2>validation/chains-repeat.log
bash run-extended.sh 1000000
timeout 900 ./extended 1000000 validation/extended-repeat 2>validation/extended-repeat.log
bash run-aux.sh 1000000 raw 2>raw/aux-run.log
bash run-aux.sh 1000000 validation/aux-repeat 2>validation/aux-repeat.log
for suite in remainder scale format; do
  mkdir -p "validation/$suite-repeat"
  bash "run-$suite.sh" 1000000 raw 2>"raw/$suite-run.log"
  bash "run-$suite.sh" 1000000 "validation/$suite-repeat" 2>"validation/$suite-repeat.log"
done
for suite in core chains extended remainder scale format; do
  for file in "$suite-counts.csv" "$suite-examples.csv"; do
    cmp "raw/$file" "validation/$suite-repeat/$file"
  done
done
for file in aux-summary.csv aux-classes.csv aux-examples.csv; do
  cmp "raw/$file" "validation/aux-repeat/$file"
done
for prog in core-selftest extended-selftest double-rounding; do
  ${CC:-gcc} -O2 -std=c11 -Wall -Wextra -Werror -fno-strict-aliasing -fno-fast-math -ffp-contract=off "$prog.c" -o "$prog"
done
./core-selftest >raw/core-selftest.csv 2>raw/core-selftest.log
./extended-selftest >raw/extended-targeted.csv
./extended-selftest >validation/extended-targeted-repeat.csv
cmp raw/extended-targeted.csv validation/extended-targeted-repeat.csv
./double-rounding >raw/double-rounding-witnesses.csv
./double-rounding >validation/double-rounding-repeat.csv
cmp raw/double-rounding-witnesses.csv validation/double-rounding-repeat.csv
python3 validate-core.py
python3 summarize-core.py
python3 summarize-chains-extended.py
python3 summarize-candidates.py
python3 validate-final.py
if [[ ${1:-} == --with-benchmark ]]; then
  bash benchmark/run.sh
fi
printf 'CORRECTNESS: native runs complete; all repeated CSV byte-identical\n'
