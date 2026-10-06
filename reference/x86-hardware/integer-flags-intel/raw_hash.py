#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The original SHA-256 convention: uncompressed bytes and logical .txt name."""
import hashlib
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
print(hashlib.sha256(source.read_bytes()).hexdigest() + '  ' + sys.argv[2])
