#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
"""Download the pinned public llvm-mingw release in CI."""
import pathlib
import tarfile
import urllib.request

VERSION = '20260505'
NAME = 'llvm-mingw-' + VERSION + '-ucrt-macos-universal'

if __name__ == '__main__':
    archive = pathlib.Path('build/llvm-mingw.tar.xz')
    archive.parent.mkdir(parents=True, exist_ok=True)
    url = 'https://github.com/mstorsjo/llvm-mingw/releases/download/' + VERSION + '/' + NAME + '.tar.xz'
    urllib.request.urlretrieve(url, archive)
    with tarfile.open(archive) as compressed:
        compressed.extractall('build', filter='data')
    print('build/' + NAME)
