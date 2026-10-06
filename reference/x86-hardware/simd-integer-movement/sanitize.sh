#!/usr/bin/env bash
# Original MIT supplemental undefined-behavior check. Run run.sh first.
set -euo pipefail
cd "$(dirname "$0")"
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || exit 2
mkdir -p core-build/sanitizer
flags=(-O1 -g -std=c11 -Wall -Wextra -mavx2 -fno-tree-vectorize -fno-tree-slp-vectorize -fsanitize=undefined -fno-sanitize-recover=undefined)
gcc "${flags[@]}" core.c core-build/core.S -o core-build/sanitizer/core
gcc "${flags[@]}" movement/runner.c movement/movement-generated.S -o core-build/sanitizer/movement
gcc "${flags[@]}" movement/gather.c movement/gather-generated.S -o core-build/sanitizer/gather
gcc "${flags[@]}" upper.c core-build/upper.S -o core-build/sanitizer/upper
gcc "${flags[@]}" strings/main.c strings/ops.S -o core-build/sanitizer/strings
gcc "${flags[@]}" crypto/main.c crypto/ops.S -o core-build/sanitizer/crypto
printf 'Undefined-behavior sanitizer: -fsanitize=undefined -fno-sanitize-recover=undefined\nEvery data stream below matches the optimized build gzip bytes exactly.\n' > SANITIZER-CHECKS.txt
for cls in movement permutation arithmetic logic shifts pack upper gather strings crypto; do
  if [[ $cls == permutation || $cls == arithmetic || $cls == logic || $cls == shifts || $cls == pack ]]; then cmd=(core-build/sanitizer/core "$cls"); else cmd=("core-build/sanitizer/$cls"); fi
  timeout 900 "${cmd[@]}" > "core-build/sanitizer/$cls.txt" 2> "core-build/sanitizer/$cls.log"
  gzip -n -9 -c "core-build/sanitizer/$cls.txt" > "core-build/sanitizer/$cls.txt.gz"
  cmp "out-$cls.txt.gz" "core-build/sanitizer/$cls.txt.gz"
  cat "core-build/sanitizer/$cls.log" >> SANITIZER-CHECKS.txt
  printf '%s: UBSan passed; output byte-identical\n' "$cls" >> SANITIZER-CHECKS.txt
done
cat SANITIZER-CHECKS.txt
