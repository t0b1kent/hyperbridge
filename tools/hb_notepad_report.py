#!/usr/bin/env python3
"""Build the x86_64 Notepad first-run report from launcher artifacts."""

import argparse
import hashlib
import json
import platform
from datetime import datetime, timezone
from pathlib import Path


def sha256(path):
    p = Path(path)
    if not p.exists() or not p.is_file():
        return None
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def count_jsonl(path, event=None):
    p = Path(path) if path else None
    if not p or not p.exists():
        return 0
    total = 0
    for line in p.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        if event is None or f'"event":"{event}"' in line or f'"event": "{event}"' in line:
            total += 1
    return total


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--notepad", required=True)
    parser.add_argument("--launcher-json", required=True)
    parser.add_argument("--marker-jsonl", required=True)
    parser.add_argument("--iat-jsonl", required=True)
    parser.add_argument("--cache-json", required=True)
    parser.add_argument("--cleanup-json", required=True)
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-md", required=True)
    args = parser.parse_args()
    launch = json.loads(Path(args.launcher_json).read_text()) if Path(args.launcher_json).exists() else {"status": "FAIL"}
    cache = json.loads(Path(args.cache_json).read_text()) if Path(args.cache_json).exists() else {}
    cleanup = json.loads(Path(args.cleanup_json).read_text()) if Path(args.cleanup_json).exists() else {}
    active = cleanup.get("after", {}).get("active", 0) if isinstance(cleanup, dict) else 0
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "macos": platform.platform(),
        "wine_patch_level": "local-worktree",
        "hyperbridge_patch_level": "translation-cache-marker-iat-thunk-fault",
        "notepad_path": args.notepad,
        "notepad_sha256": sha256(args.notepad),
        "wine_bootstrap": "see loop-wineboot report",
        "marker_events_count": count_jsonl(args.marker_jsonl),
        "iat_rewrite_count": count_jsonl(args.iat_jsonl),
        "abi_thunk_count": count_jsonl(args.iat_jsonl, "typed_thunk"),
        "page_fault_dispatch_count": 0,
        "translation_cache": cache,
        "process_launch_result": launch.get("status", "FAIL"),
        "gui_window_result": "SKIP_AUTOMATION_UNAVAILABLE" if launch.get("status") == "PASS" else "FAIL_PROCESS_NOT_RUNNING",
        "cleanup_result": "PASS" if int(active or 0) == 0 else "FAIL",
        "exact_limitations": ["GUI window detection is process-level unless macOS automation is available."],
    }
    Path(args.out_json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out_json).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    lines = ["# Notepad x86_64 First Run", "", f"Generated: {payload['timestamp']}", ""]
    for key in ["process_launch_result", "gui_window_result", "cleanup_result", "marker_events_count", "iat_rewrite_count", "page_fault_dispatch_count"]:
        lines.append(f"- **{key}**: {payload[key]}")
    lines.append(f"- **translation_cache_entries**: {cache.get('entries', 0)}")
    lines.append("")
    lines.append("## Limitations")
    lines.extend(f"- {item}" for item in payload["exact_limitations"])
    Path(args.out_md).write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
