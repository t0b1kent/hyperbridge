#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
cd "$(dirname "$0")"
[[ $(uname -m) == x86_64 && $(uname -s) == Linux ]] || { echo 'Linux x86-64 required' >&2; exit 1; }
out="${2:-raw}"
mkdir -p "$out"
cc -std=c11 -O2 -Wall -Wextra -fno-strict-aliasing -fno-fast-math -frounding-math -msse2 -mno-avx -o /tmp/x87-aux-0024 aux.c
timeout 900 /tmp/x87-aux-0024 "${1:-1000000}" "$out"
