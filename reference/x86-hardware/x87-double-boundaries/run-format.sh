#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
cd "$(dirname "$0")"
[[ $(uname -m) == x86_64 && $(uname -s) == Linux ]] || exit 2
out=${2:-raw}
mkdir -p "$out"
${CC:-gcc} -O2 -std=c11 -Wall -Wextra -fno-strict-aliasing -fno-fast-math -ffp-contract=off format-candidates.c -o format-candidates
timeout 900 ./format-candidates "${1:-1000000}" "$out"
