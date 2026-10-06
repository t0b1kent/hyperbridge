#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
cd "$(dirname "$0")"
[[ $(uname -m) == x86_64 && $(uname -s) == Linux ]] || exit 2
out=${2:-raw}
mkdir -p "$out"
${CC:-gcc} -O2 -std=c11 -Wall -Wextra -Werror -fno-strict-aliasing -fno-fast-math -ffp-contract=off remainder.c -o remainder
timeout 900 ./remainder "${1:-1000000}" "$out"
