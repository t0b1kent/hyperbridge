#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Requires native Linux x86-64' >&2; exit 2; }
mkdir -p build
python3 generate.py
gcc -std=c11 -O2 -fno-pie -no-pie -Wall -Wextra harness.c build/forms.S -o build/oracle
build/oracle --counts > expected-counts.txt
classes=(${*:-load-store arithmetic comparison remainder-scale transcendental stack environment traps})
for cls in "${classes[@]}"; do
  timeout 900 build/oracle "$cls" > "build/out-$cls.first.txt" 2> "build/out-$cls.first.log"
  timeout 900 build/oracle "$cls" > "build/out-$cls.second.txt" 2> "build/out-$cls.second.log"
  cmp "build/out-$cls.first.txt" "build/out-$cls.second.txt"
  gzip -n -9 -c "build/out-$cls.first.txt" > "out-$cls.txt.gz"
  gzip -n -9 -c "build/out-$cls.second.txt" > "build/out-$cls.second.txt.gz"
  cmp "out-$cls.txt.gz" "build/out-$cls.second.txt.gz"
  sha256sum "build/out-$cls.first.txt" | sed "s|build/out-$cls.first.txt|out-$cls.txt|" > "out-$cls.sha256"
  actual=$(grep -vc '^#' "build/out-$cls.first.txt")
  expected=$(awk -v cls="$cls" '$1==cls {sum+=$3} END {print sum+0}' expected-counts.txt)
  [[ $actual == "$expected" ]]
  { echo "class=$cls expected_rows=$expected actual_rows=$actual"; echo 'repeat_uncompressed=IDENTICAL repeat_compressed=IDENTICAL'; grep '^rows=' "build/out-$cls.first.log"; } > "out-$cls.validation.txt"
  if grep -q UNMAPPED "build/out-$cls.first.txt"; then echo "Unmapped environment pointer in $cls" >&2; exit 7; fi
  echo "VERIFIED $cls rows=$actual $(cat "out-$cls.sha256")"
done
if [[ $# == 0 ]]; then
  python3 validate_numeric.py --precision 320
  cp transcendental-crosscheck-samples.jsonl.gz build/crosscheck-320.jsonl.gz
  cp transcendental-crosscheck.json build/crosscheck-320.json
  python3 validate_numeric.py --precision 640
  cmp <(gzip -dc build/crosscheck-320.jsonl.gz) <(gzip -dc transcendental-crosscheck-samples.jsonl.gz)
  python3 - <<'PY'
import gzip,json
x=json.load(open('build/crosscheck-320.json'));y=json.load(open('transcendental-crosscheck.json'))
assert x['stats']==y['stats'] and x['skips']==y['skips']
n=sum(1 for _ in gzip.open('transcendental-crosscheck-samples.jsonl.gz','rb'))
open('numeric-validation.txt','w').write(f'C_arithmetic_and_conversion_mismatches=0\nhigh_precision_320_vs_640_bits=IDENTICAL_CORRECTLY_ROUNDED_BINARY80_RESULTS\ncompared_result_components={n}\n')
PY
  python3 analyze.py
fi
