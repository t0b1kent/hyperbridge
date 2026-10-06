#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
cd "$(dirname "$0")"
mkdir -p build
gcc -m32 -nostdlib -static -no-pie legacy32.S -o build/legacy32
file build/legacy32
readelf -h build/legacy32
python3 - <<'PY'
import subprocess, sys
try:
 p=subprocess.run(['build/legacy32'],check=False)
except OSError as e:
 print('Native i386 execution unavailable: errno=%d (%s)' % (e.errno, e.strerror))
 sys.exit(77)
print('Native i386 probe exit status:', p.returncode)
sys.exit(p.returncode)
PY
