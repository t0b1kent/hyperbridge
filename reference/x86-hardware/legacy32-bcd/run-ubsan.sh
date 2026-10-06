#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
cd -- "$(dirname -- "$0")"
cc -O2 -g -Wall -Wextra -Werror -fno-pie -no-pie -fno-stack-protector -fsanitize=undefined -fno-sanitize-recover=all oracle.c bridge.S build/ops.S -o build/oracle-ubsan
for group in bcd extra control; do
  build/oracle-ubsan "$group" > "build/$group.ubsan.txt" 2> "build/$group.ubsan.checks"
done
python3 - <<'PY'
from pathlib import Path
p=Path('.')
lines=['Undefined-behavior sanitizer audit (-fsanitize=undefined -fno-sanitize-recover=all).','Separate native sanitized executable, same generated compatibility stubs.','Fault IP comments differ with binary layout; compare all canonical instruction rows, not link addresses.']
for group in ['bcd','extra','control']:
    a=[x for x in (p/'build'/f'{group}.first.txt').read_bytes().splitlines() if not x.startswith(b'#')]
    b=[x for x in (p/'build'/f'{group}.ubsan.txt').read_bytes().splitlines() if not x.startswith(b'#')]
    assert a==b,group
    check=(p/'build'/f'{group}.ubsan.checks').read_text()
    assert 'runtime error' not in check and 'errors=0' in check
    lines.append(f'{group}: {len(a)} instruction rows byte-identical; '+check.splitlines()[0])
(p/'SANITIZER-CHECKS.txt').write_text('\n'.join(lines)+'\n')
print('\n'.join(lines))
PY
