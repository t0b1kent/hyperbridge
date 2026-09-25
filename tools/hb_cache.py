#!/usr/bin/env python3
"""HyperBridge persistent translation cache maintenance CLI."""

import argparse
import json
import shutil
import struct
from pathlib import Path

MAGIC = b"HBTC"
HEADER = struct.Struct("<4sIII")
META = struct.Struct("<IIIBBH")
KEY_SIZE = 48


def cache_file(root: Path) -> Path:
    return root / "translation-cache.bin"


def ensure(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = cache_file(root)
    if not path.exists():
        path.write_bytes(HEADER.pack(MAGIC, 2, 1, 0))
    return path


def scan(root: Path):
    path = ensure(root)
    stats = {"entries": 0, "bytes_stored": 0, "corrupt_entries_ignored": 0, "path": str(path)}
    data = path.read_bytes()
    if len(data) < HEADER.size:
        stats["corrupt_entries_ignored"] += 1
        return stats
    magic, version, abi, _ = HEADER.unpack_from(data, 0)
    stats.update({"format_version": version, "abi_version": abi})
    if magic != MAGIC or version != 2 or abi != 1:
        stats["corrupt_entries_ignored"] += 1
        return stats
    off = HEADER.size
    while off + META.size <= len(data):
        key_size, native_size, _steps, _valid, _unsupported, _reserved = META.unpack_from(data, off)
        off += META.size
        if key_size != KEY_SIZE or native_size > 128 * 1024 * 1024 or off + key_size + native_size > len(data):
            stats["corrupt_entries_ignored"] += 1
            break
        off += key_size + native_size
        stats["entries"] += 1
        stats["bytes_stored"] += native_size
    return stats


def main():
    parser = argparse.ArgumentParser(description="HyperBridge translation cache")
    parser.add_argument("--root", default="build/hyperbridge-cache")
    parser.add_argument("--stats", action="store_true")
    parser.add_argument("--clear", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    root = Path(args.root)
    if args.clear:
        shutil.rmtree(root, ignore_errors=True)
        ensure(root)
    result = scan(root)
    result["status"] = "PASS" if result.get("corrupt_entries_ignored", 0) == 0 else "PASS_WITH_CORRUPT_IGNORED"
    if args.json or args.stats or args.verify or args.clear:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
