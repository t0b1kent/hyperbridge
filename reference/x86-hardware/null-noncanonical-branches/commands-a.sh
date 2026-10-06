#!/bin/bash
# SPDX-License-Identifier: MIT
# Run from any directory. Writes Part A deliverables here and executables under /tmp.
set -euo pipefail
cd -- "$(dirname -- "$0")"
mkdir -p raw/a/build raw/a/run1 raw/a/run2
# Executables remain local; the submitted tree contains source and observations.
A_BUILD_DIR=${A_BUILD_DIR:-$(mktemp -d /tmp/oracle0010-a.XXXXXX)}
case "$A_BUILD_DIR" in /tmp/*) ;; *) printf 'A_BUILD_DIR must be under /tmp\n' >&2; exit 64 ;; esac
mkdir -p -- "$A_BUILD_DIR"
A_EXE="$A_BUILD_DIR/a-native"
{
  printf 'utc='; date -u +%Y-%m-%dT%H:%M:%SZ
  uname -srv
  uname -m
  grep -m1 '^model name' /proc/cpuinfo
  grep -m1 '^flags' /proc/cpuinfo
  cat /etc/os-release
  gcc --version | head -1
  as --version | head -1
  ld --version | head -1
} > raw/a/build/machine.txt
printf '#include <stdio.h>\nint main(void){return 0;}\n' > raw/a/build/m32-check.c
if gcc -m32 raw/a/build/m32-check.c -o "$A_BUILD_DIR/m32-check" >raw/a/build/m32-check.stdout 2>raw/a/build/m32-check.stderr; then
  printf 'm32_compile_exit=0\n' > raw/a/build/m32-check.status
else
  printf 'm32_compile_exit=%s\n' "$?" > raw/a/build/m32-check.status
fi
gcc -std=c11 -O2 -Wall -Wextra -Werror -fno-pie -no-pie \
  -fno-stack-protector -fcf-protection=none -Wl,--build-id=none \
  a-native.c a-native-forms.S -o "$A_EXE" \
  > raw/a/build/gcc.stdout 2> raw/a/build/gcc.stderr
sha256sum "$A_EXE" > raw/a/build/a-native.elf.sha256
file "$A_EXE" > raw/a/build/file.txt
nm -n "$A_EXE" > raw/a/build/symbols.txt
objdump -d -Mintel "$A_EXE" > raw/a/build/disassembly-64.txt
start=$(awk '$3=="a_compat_entry" {print "0x"$1}' raw/a/build/symbols.txt)
stop=$(python3 -c 'from pathlib import Path; print(hex(next(int(x.split()[0],16) for x in Path("raw/a/build/symbols.txt").read_text().splitlines() if x.split()[-1] == "a32_ret_branch") + 1))')
objdump -d -m i386 -Mintel --start-address="$start" --stop-address="$stop" "$A_EXE" > raw/a/build/disassembly-32.txt
for run in 1 2; do
  if timeout 120s "$A_EXE" "raw/a/run$run" > "raw/a/run$run/table.tsv" 2> "raw/a/run$run/stderr.txt"; then
    printf 'exit=0\n' > "raw/a/run$run/exit.txt"
  else
    status=$?; printf 'exit=%s\n' "$status" > "raw/a/run$run/exit.txt"; exit "$status"
  fi
done
cp raw/a/run1/table.tsv a-native.tsv
cp raw/a/run2/table.tsv a-native-repeat.tsv
cmp a-native.tsv a-native-repeat.tsv
python3 a-native-validate.py
sha256sum a-native.tsv a-native-repeat.tsv > a-native-repeat.sha256
find raw/a -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > a-native-raw.sha256
sha256sum a-native.c a-native-forms.S a-native-validate.py commands-a.sh a-native-LICENSE raw/a/build/a-native.elf.sha256 > a-native-source-build.sha256
