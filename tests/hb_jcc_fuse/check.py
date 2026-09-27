#!/usr/bin/env python3
"""Counts hb_diff_case_runner JSONL rows on stdin (interpreter vs JIT, rip compared).
  check.py --clean      : fail unless every row executed and matched
  check.py --mismatch   : fail unless at least one executed row mismatched (negative control)
Corpora: producer (CMP/SUB/TEST/AND, 8..64 bit, carry/overflow edges) + Jcc, from MacRunner's
flags lane (06-07.09.2026). Used for MACRUNNER_HB_JCC_FUSE_FULL."""
import json, sys
mode = sys.argv[1] if len(sys.argv) > 1 else '--clean'
rows = ok = bad = not_run = 0
for line in sys.stdin:
    if not line.startswith('{'):
        continue
    d = json.loads(line)
    rows += 1
    if d.get('ok'):
        ok += 1
    elif d.get('diff'):
        bad += 1
    else:
        not_run += 1
print(f'rows={rows} ok={ok} mismatch={bad} not_run={not_run}')
if mode == '--clean':
    sys.exit(0 if rows and ok == rows else 1)
sys.exit(0 if bad > 0 else 1)
