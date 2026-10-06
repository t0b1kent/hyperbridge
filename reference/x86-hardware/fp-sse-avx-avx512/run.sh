#!/usr/bin/env bash
# Build and run the original native hardware oracle. MIT License.
set -euo pipefail
cd -- "$(dirname -- "$0")"
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Requires Linux x86-64 native execution' >&2; exit 2; }
classes=("$@")
if ((${#classes[@]}==0));then classes=(arithmetic fma comparison approximation conversion rounding horizontal evex);fi
python3 generate.py "${classes[@]}"
gcc -O2 -std=gnu11 -Wall -Wextra -Werror -mgeneral-regs-only -c harness.c -o build/harness.o
gcc -O2 -std=gnu11 -Wall -Wextra -Werror -fno-fast-math -ffp-contract=off -frounding-math -c crosscheck.c -o build/crosscheck.o
gcc -c build/kernels.S -o build/kernels.o
gcc build/harness.o build/crosscheck.o build/kernels.o -lm -o build/reference
for class in "${classes[@]}";do
  ./build/reference "$class" > "build/out-$class.txt" 2> "out-$class.validation.txt"
  sha256sum "build/out-$class.txt" | sed 's|build/||' > "out-$class.sha256"
  gzip -n -9 -c "build/out-$class.txt" > "out-$class.txt.gz"
  ./build/reference "$class" > "build/repeat-$class.txt" 2> "build/repeat-$class.validation.txt"
  cmp "build/out-$class.txt" "build/repeat-$class.txt"
  gzip -n -9 -c "build/repeat-$class.txt" > "build/repeat-$class.txt.gz"
  cmp "out-$class.txt.gz" "build/repeat-$class.txt.gz"
  printf 'reproducibility: two native executions and gzip outputs are byte-identical\n' >> "out-$class.validation.txt"
  cat "out-$class.validation.txt"
  rm "build/repeat-$class.txt" "build/repeat-$class.txt.gz" "build/out-$class.txt"
done

python3 verify_encodings.py
python3 validate.py "${classes[@]}"
