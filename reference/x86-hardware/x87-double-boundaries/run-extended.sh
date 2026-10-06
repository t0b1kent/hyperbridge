#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
cd "$(dirname "$0")"
[[ $(uname -m) == x86_64 ]] || exit 2
mkdir -p raw
${CC:-gcc} -O2 -std=c11 -Wall -Wextra -fno-strict-aliasing -fno-fast-math -ffp-contract=off extended.c -o extended
timeout 900 ./extended "${1:-1000000}" raw 2>raw/extended-run.log
