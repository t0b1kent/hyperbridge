#!/usr/bin/env python3
"""Flag-liveness arms against the interpreter oracle (hb_diff_case_runner, rip compared, DIRECT_MEM=0).
  check.py <runner> <corpus> --arms | --flip
Arms: base (liveness off); own = FLAG_LIVENESS + FLAG_LIVENESS_OWN; imprecise = own + FLAG_LIVENESS_IMPRECISE;
flip = own + TEST_LIVENESS_FLIP (drops live notes before Jcc). Requirements: own and imprecise have exactly the
base mismatch set (the corpora carry known rip-only fault rows) and remove at least one note; flip adds mismatches.
Corpora: MacRunner registers lane (general x64 forms and the pinning corpus)."""
import json, os, re, subprocess, sys
runner, corpus, mode = sys.argv[1], sys.argv[2], sys.argv[3]
BASE = {'MACRUNNER_HB_JIT_DIRECT_MEM': '0', 'MACRUNNER_HB_JCC_FUSE_FULL': '2'}
OWN = {'MACRUNNER_HB_FLAG_LIVENESS': '1', 'MACRUNNER_HB_FLAG_LIVENESS_OWN': '1'}
def run(extra):
    env = dict(os.environ); env.update(BASE); env.update(extra)
    p = subprocess.run([runner], stdin=open(corpus), capture_output=True, text=True, env=env)
    bad = set()
    for line in p.stdout.splitlines():
        if not line.startswith('{'): continue
        d = json.loads(line)
        if not d.get('ok') and d.get('diff'): bad.add((d.get('seed'), d.get('code'), d.get('diff')))
    m = re.search(r'hb-flag-liveness-снято [^\n]*hits=(\d+)', p.stderr)
    return bad, int(m.group(1)) if m else 0
base, _ = run({})
name = os.path.basename(corpus)
if mode == '--flip':
    flip, _ = run({**OWN, 'MACRUNNER_HB_TEST_LIVENESS_FLIP': '1'})
    print(f'{name}: base={len(base)} flip={len(flip)} (live notes dropped before Jcc must be caught)')
    sys.exit(0 if len(flip - base) > 0 else 1)
own, own_hits = run(OWN)
imp, imp_hits = run({**OWN, 'MACRUNNER_HB_FLAG_LIVENESS_IMPRECISE': '1'})
print(f'{name}: base={len(base)} own={len(own)} removed={own_hits} imprecise={len(imp)} removed={imp_hits}')
sys.exit(0 if own == base and imp == base and own_hits > 0 and imp_hits >= own_hits else 1)
