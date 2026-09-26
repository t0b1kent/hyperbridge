#!/usr/bin/env python3
"""Hardware SSE oracle, ARM64 acceptance of the native emitter: the JIT must never be worse
than the interpreter against the recorded x86 hardware answers.

Reads hb_diff_case_runner output (JSON lines with the "sse_oracle" block, see
runner_extension.h) on stdin. Counts, per case, (interpreter value ok, JIT value ok).
Exit 1 if any case has the interpreter right and the JIT wrong, or if no oracle rows were
seen (an empty run is not a pass). Cases where BOTH differ from hardware are reported, not
failed: on ARM64 they come from the host FP environment (x86 DAZ-only / FTZ-only / RC
have no exact FPCR equivalent without FEAT_AFP), which both executors share.
"""
import json
import sys
from collections import Counter


def main() -> int:
    counts = Counter()
    jit_only = []
    for line in sys.stdin:
        if not line.startswith('{'):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            counts['bad-json'] += 1
            continue
        oracle = row.get('sse_oracle')
        if not oracle:
            counts['no-oracle'] += 1
            continue
        key = ('interp_ok' if oracle['interp_values_ok'] else 'interp_bad') + '/' + \
              ('jit_ok' if oracle['jit_values_ok'] else 'jit_bad')
        counts[key] += 1
        if oracle['interp_values_ok'] and not oracle['jit_values_ok'] and len(jit_only) < 20:
            jit_only.append({'id': oracle['id'], 'code': row.get('code'), 'diff': row.get('diff')})
    rows = sum(v for k, v in counts.items() if '/' in k)
    print(json.dumps({'rows': rows, 'counts': dict(counts), 'jit_only_examples': jit_only}, ensure_ascii=False))
    if rows == 0 or counts['bad-json']:
        return 1
    return 1 if counts['interp_ok/jit_bad'] else 0


if __name__ == '__main__':
    sys.exit(main())
