#!/usr/bin/env bash
# Original MIT code.
set -euo pipefail
cd -- "$(dirname -- "$0")"
[[ $(uname -m) == x86_64 && $(uname -s) == Linux ]] || exit 2
classes=("$@"); if ((${#classes[@]}==0)); then classes=(shifts rotates double multiply divide bitscan bittest logic misc); fi
python3 generate_core.py
gcc -O2 -std=gnu11 -Wall -Wextra -fno-strict-aliasing core.c build/core.S -o build/core
for cls in "${classes[@]}"; do
 ./build/core "$cls" > "build/out-$cls.txt" 2> "out-$cls.validation.txt"
 ./build/core "$cls" > "build/repeat-$cls.txt" 2> "build/repeat-$cls.validation.txt"
 cmp "build/out-$cls.txt" "build/repeat-$cls.txt"
 cmp "out-$cls.validation.txt" "build/repeat-$cls.validation.txt"
 gzip -n -9 -c "build/out-$cls.txt" > "out-$cls.txt.gz"
 gzip -n -9 -c "build/repeat-$cls.txt" > "build/repeat-$cls.txt.gz"
 cmp "out-$cls.txt.gz" "build/repeat-$cls.txt.gz"
 sha256sum "build/out-$cls.txt" | sed 's|build/||' > "out-$cls.sha256"
 echo 'two native executions, validation summaries, and deterministic gzip bytes match' >> "out-$cls.validation.txt"
 cat "out-$cls.validation.txt"
 rm "build/out-$cls.txt" "build/repeat-$cls.txt" "build/repeat-$cls.txt.gz"
done
