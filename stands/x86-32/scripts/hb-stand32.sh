#!/bin/sh
# No Wine, no build, no network; the selected runner owns native FEX execution.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$script_dir/../artifacts/stand32-20261001/gate.py" "$@"
