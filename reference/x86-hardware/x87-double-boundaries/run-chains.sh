#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
cd "$(dirname "$0")"
[[ $(uname -m) == x86_64 ]] || exit 2
mkdir -p raw
${CC:-gcc} -O2 -std=c11 -Wall -Wextra -fno-strict-aliasing -fno-fast-math -ffp-contract=off chains.c -o chains
timeout 900 ./chains "${1:-1000000}" raw 2>raw/chains-run.log
