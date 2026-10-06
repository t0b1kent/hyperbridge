#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
cd "$(dirname "$0")"
[[ $(uname -m) == x86_64 ]] || { echo 'requires native x86_64'; exit 2; }
mkdir -p raw
cc=${CC:-gcc}
"$cc" -O2 -std=c11 -Wall -Wextra -Werror -fno-strict-aliasing -fno-fast-math -ffp-contract=off core.c -o core
# arg1: sample count, arg2: number of opcodes (4 = first delivery, 7 = all)
timeout 900 ./core "${1:-1000000}" "${2:-7}" raw 2>raw/core-run.log
