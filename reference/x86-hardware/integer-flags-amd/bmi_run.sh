#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
cd "$(dirname "$0")"
mkdir -p build
gcc -O2 -Wall -Wextra -mno-red-zone bmi.c -o build/bmi
build/bmi > build/bmi.first.txt 2> build/bmi.first.stats
build/bmi > build/bmi.second.txt 2> build/bmi.second.stats
cmp build/bmi.first.txt build/bmi.second.txt
cmp build/bmi.first.stats build/bmi.second.stats
gzip -n -9 -c build/bmi.first.txt > out-09-bmi.txt.gz
gzip -n -9 -c build/bmi.second.txt > build/bmi.second.txt.gz
cmp out-09-bmi.txt.gz build/bmi.second.txt.gz
sha256sum build/bmi.first.txt | sed 's|build/bmi.first.txt|out-09-bmi.txt|' > out-09-bmi.sha256
cp build/bmi.first.stats bmi_CHECKS.txt
printf 'byte_identical_raw=yes\nbyte_identical_gzip=yes\n' >> bmi_CHECKS.txt
