#!/bin/sh
# Own STAND-DIFF prototype. No Wine; does not build implicitly.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
case "${1:-}" in
  --quick|--full)
    exec python3 "$root/artifacts/stand-diff-stage4-20261001/gate.py" --adapter "$root/artifacts/stand-diff-stage6-20261002/fast_replay_flags.py" "$@"
    ;;
  *) exec python3 "$root/artifacts/stand-diff-20260930/span_diff.py" "$@" ;;
esac
