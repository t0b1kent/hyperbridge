#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
cd "$(dirname "$0")"
mkdir -p build
/usr/bin/xcrun --sdk macosx --toolchain com.apple.dt.toolchain.XcodeDefault clang -arch x86_64 -O2 -Wall -Wextra -mno-red-zone bmi.c -o build/bmi
build/bmi > build/bmi.first.txt 2> build/bmi.first.stats
build/bmi > build/bmi.second.txt 2> build/bmi.second.stats
/usr/bin/cmp build/bmi.first.txt build/bmi.second.txt
/usr/bin/cmp build/bmi.first.stats build/bmi.second.stats
/usr/bin/gzip -n -9 -c build/bmi.first.txt > out-09-bmi.txt.gz
/usr/bin/gzip -n -9 -c build/bmi.second.txt > build/bmi.second.txt.gz
/usr/bin/cmp out-09-bmi.txt.gz build/bmi.second.txt.gz
python3 raw_hash.py build/bmi.first.txt out-09-bmi.txt > out-09-bmi.sha256
cp build/bmi.first.stats bmi_CHECKS.txt
printf 'byte_identical_raw=yes\nbyte_identical_gzip=yes\n' >> bmi_CHECKS.txt
