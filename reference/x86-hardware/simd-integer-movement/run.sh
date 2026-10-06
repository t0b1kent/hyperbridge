#!/usr/bin/env bash
# Original MIT code. Native source-to-result verification, priority classes first.
set -euo pipefail
cd "$(dirname "$0")"
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Native Linux x86-64 required; never run on the receiving Mac' >&2; exit 2; }
./movement-run.sh
./core-run.sh
./upper-run.sh
python3 core-verify.py
./movement-gather-run.sh
./strings-run.sh
./crypto-run.sh
python3 verify.py
