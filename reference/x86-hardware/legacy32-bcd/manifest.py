#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Hash the flat deliverable, excluding transient build products and this manifest."""
from pathlib import Path
import hashlib
p=Path(__file__).resolve().parent
lines=[]
for item in sorted(p.iterdir()):
    if item.name=='FILE-SHA256.txt' or item.is_dir():
        continue
    if item.is_symlink():
        raise SystemExit('Refusing to manifest a symlink: '+item.name)
    lines.append(hashlib.sha256(item.read_bytes()).hexdigest()+'  '+item.name)
(p/'FILE-SHA256.txt').write_text('\n'.join(lines)+'\n')
print(f'Manifest: {len(lines)} delivered files')
