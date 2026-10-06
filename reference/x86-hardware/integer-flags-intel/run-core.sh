#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Platform adapter only; original generator, matrices, output and inner repeats retained.
set -euo pipefail
cd -- "$(dirname -- "$0")"
[[ $(/usr/bin/uname -m) == x86_64 && $(/usr/bin/uname -s) == Darwin ]] || exit 2
classes=("$@"); if ((${#classes[@]}==0)); then classes=(shifts rotates double multiply divide bitscan bittest logic misc); fi
python3 generate_core.py
python3 macho_asm.py build/core.S build/core-macos.S ASSEMBLY-ADAPTER.json
/usr/bin/xcrun --sdk macosx --toolchain com.apple.dt.toolchain.XcodeDefault clang -arch x86_64 -O2 -std=gnu11 -Wall -Wextra -fno-strict-aliasing core.c build/core-macos.S -o build/core
for cls in "${classes[@]}"; do
 ./build/core "$cls" > "build/out-$cls.txt" 2> "out-$cls.validation.txt"
 ./build/core "$cls" > "build/repeat-$cls.txt" 2> "build/repeat-$cls.validation.txt"
 /usr/bin/cmp "build/out-$cls.txt" "build/repeat-$cls.txt"
 /usr/bin/cmp "out-$cls.validation.txt" "build/repeat-$cls.validation.txt"
 /usr/bin/gzip -n -9 -c "build/out-$cls.txt" > "out-$cls.txt.gz"
 /usr/bin/gzip -n -9 -c "build/repeat-$cls.txt" > "build/repeat-$cls.txt.gz"
 /usr/bin/cmp "out-$cls.txt.gz" "build/repeat-$cls.txt.gz"
 python3 raw_hash.py "build/out-$cls.txt" "out-$cls.txt" > "out-$cls.sha256"
 echo 'two native executions, validation summaries, and deterministic gzip bytes match' >> "out-$cls.validation.txt"
 cat "out-$cls.validation.txt"
 rm "build/out-$cls.txt" "build/repeat-$cls.txt" "build/repeat-$cls.txt.gz"
done
