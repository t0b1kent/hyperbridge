#!/usr/bin/env python3
"""Probe the Phase G x86_64 Notepad gate without turning process birth into PASS."""

from __future__ import annotations

import argparse
import json
import os
import signal
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


OSASCRIPT_NOTEPAD_WINDOWS = [
    "osascript",
    "-e",
    'tell application "System Events" to get name of every window of every process whose name contains "notepad"',
]


def _decode_stream(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return value.decode("utf-8", errors="replace")


def run_capture(cmd: list[str], timeout: int = 10, env: dict[str, str] | None = None) -> dict[str, object]:
    started = time.monotonic()
    proc: subprocess.Popen[bytes] | None = None
    stdout = ""
    stderr = ""
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            start_new_session=True,
        )
        out, err = proc.communicate(timeout=timeout)
        rc = proc.returncode
        stdout = _decode_stream(out)
        stderr = _decode_stream(err)
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        rc = 124
        stdout = _decode_stream(exc.stdout)
        stderr = _decode_stream(exc.stderr)
        if proc is not None:
            terminate_process_group(proc)
            try:
                out, err = proc.communicate(timeout=3)
                stdout += _decode_stream(out)
                stderr += _decode_stream(err)
            except subprocess.TimeoutExpired:
                pass
        timed_out = True
    return {
        "command": cmd,
        "rc": rc,
        "stdout": stdout.strip(),
        "stderr": stderr.strip(),
        "duration_ms": int((time.monotonic() - started) * 1000),
        "timed_out": timed_out,
    }


def run_shell(script: str, timeout: int = 10, env: dict[str, str] | None = None) -> dict[str, object]:
    return run_capture(["/bin/bash", "-lc", script], timeout=timeout, env=env)


def cleanup(root: Path) -> dict[str, object]:
    script = root / "scripts" / "cleanup-wine-runtime.py"
    return run_capture([str(script), "--json", "--sample", "8"], timeout=20)


def cache_stats(root: Path, cache_root: Path) -> dict[str, object]:
    tool = root / "engine" / "hyperbridge" / "tools" / "hb_cache.py"
    return run_capture(["python3", str(tool), "--root", str(cache_root), "--stats", "--json"], timeout=10)


def json_stdout(result: dict[str, object]) -> dict[str, object]:
    try:
        return json.loads(str(result.get("stdout") or "{}"))
    except json.JSONDecodeError:
        return {}


def pgrep_notepad() -> dict[str, object]:
    result = run_shell("pgrep -f 'notepad.exe' || true", timeout=5)
    pids: list[int] = []
    for line in str(result.get("stdout", "")).splitlines():
        try:
            pids.append(int(line.strip()))
        except ValueError:
            pass
    result["pids"] = pids
    return result


def vmmap_rosetta_count(pids: list[int]) -> dict[str, object]:
    if not pids:
        return {
            "command": "vmmap $(pgrep -f notepad.exe) | grep -c rosetta",
            "rc": 1,
            "stdout": "",
            "stderr": "no notepad.exe pid was alive during probe",
            "count": None,
        }
    parts = []
    total = 0
    max_rc = 0
    for pid in pids:
        result = run_shell(f"vmmap {pid} 2>/dev/null | grep -c rosetta || true", timeout=12)
        out = str(result.get("stdout", "")).strip()
        try:
            count = int(out.splitlines()[-1]) if out else 0
        except ValueError:
            count = None
            max_rc = 1
        if count is not None:
            total += count
        parts.append({"pid": pid, "grep_count": count, "raw": result})
    return {
        "command": "vmmap $(pgrep -f notepad.exe) | grep -c rosetta",
        "rc": max_rc,
        "stdout": str(total),
        "stderr": "",
        "count": total,
        "per_pid": parts,
    }


def terminate_process_group(proc: subprocess.Popen[bytes]) -> dict[str, object]:
    events: list[str] = []
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        events.append("SIGTERM")
    except ProcessLookupError:
        events.append("SIGTERM_PROCESS_GONE")
    except PermissionError as exc:
        events.append(f"SIGTERM_PERMISSION_DENIED:{exc.errno}")
        try:
            proc.terminate()
            events.append("PROC_SIGTERM")
        except ProcessLookupError:
            events.append("PROC_SIGTERM_PROCESS_GONE")
        except PermissionError as inner:
            events.append(f"PROC_SIGTERM_PERMISSION_DENIED:{inner.errno}")
    time.sleep(1.5)
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
            events.append("SIGKILL")
        except ProcessLookupError:
            events.append("SIGKILL_PROCESS_GONE")
        except PermissionError as exc:
            events.append(f"SIGKILL_PERMISSION_DENIED:{exc.errno}")
            try:
                proc.kill()
                events.append("PROC_SIGKILL")
            except ProcessLookupError:
                events.append("PROC_SIGKILL_PROCESS_GONE")
            except PermissionError as inner:
                events.append(f"PROC_SIGKILL_PERMISSION_DENIED:{inner.errno}")
    try:
        rc = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        rc = None
    return {"events": events, "rc_after_terminate": rc}


def run_notepad_attempt(
    root: Path,
    notepad: Path,
    wine: Path,
    prefix: Path,
    cache_root: Path,
    report_dir: Path,
    label: str,
    timeout: int,
    probe_delay: float,
) -> dict[str, object]:
    stdout_path = report_dir / f"{label}.stdout.log"
    stderr_path = report_dir / f"{label}.stderr.log"
    marker_path = report_dir / f"{label}.markers.jsonl"
    iat_path = report_dir / f"{label}.iat.jsonl"
    env = os.environ.copy()
    env.update(
        {
            "WINEPREFIX": str(prefix),
            "DYLD_FALLBACK_LIBRARY_PATH": "/opt/homebrew/lib",
            "WINEDEBUG": "-all",
            "MACRUNNER_HB_X64_LOADER": "1",
            "MACRUNNER_HB_MARKER_TRACE": str(marker_path),
            "MACRUNNER_HB_IAT_TRACE": "1",
            "MACRUNNER_HB_IAT_TRACE_PATH": str(iat_path),
            "MACRUNNER_HB_CACHE_ROOT": str(cache_root),
        }
    )
    started = time.monotonic()
    with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
        proc = subprocess.Popen(
            [str(wine), str(notepad)],
            stdout=out,
            stderr=err,
            env=env,
            start_new_session=True,
        )
        time.sleep(probe_delay)
        alive_at_probe = proc.poll() is None
        pgrep = pgrep_notepad()
        pids = [pid for pid in pgrep.get("pids", []) if pid != os.getpid()]
        osascript = run_capture(OSASCRIPT_NOTEPAD_WINDOWS, timeout=8)
        vmmap = vmmap_rosetta_count(pids)
        if alive_at_probe:
            termination = terminate_process_group(proc)
        else:
            termination = {"events": ["PROCESS_EXITED_BEFORE_PROBE_END"], "rc_after_terminate": proc.returncode}
    cleanup_result = cleanup(root)
    return {
        "label": label,
        "command": [str(wine), str(notepad)],
        "pid": proc.pid,
        "alive_at_probe": alive_at_probe,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "rc": proc.returncode,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "stdout_tail": stdout_path.read_text(errors="replace")[-4000:] if stdout_path.exists() else "",
        "stderr_tail": stderr_path.read_text(errors="replace")[-4000:] if stderr_path.exists() else "",
        "marker_path": str(marker_path),
        "marker_events_count": count_lines(marker_path),
        "iat_path": str(iat_path),
        "iat_events_count": count_lines(iat_path),
        "pgrep": pgrep,
        "osascript": osascript,
        "vmmap_rosetta": vmmap,
        "termination": termination,
        "cleanup": cleanup_result,
    }


def count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for line in path.read_text(errors="replace").splitlines() if line.strip())


def cache_delta(before: dict[str, object], after: dict[str, object]) -> dict[str, object]:
    b = json_stdout(before)
    a = json_stdout(after)
    return {
        "before": b,
        "after": a,
        "entries_delta": int(a.get("entries", 0) or 0) - int(b.get("entries", 0) or 0),
        "hit_rate": None,
        "reason": "Wine/HyperBridge runtime cache hit/miss counters are not exposed for notepad.exe runs yet.",
    }


def pass_from_osascript(result: dict[str, object]) -> bool:
    if result.get("rc") != 0:
        return False
    out = str(result.get("stdout", ""))
    return bool(out.strip()) and "Notepad" in out


def build_report(payload: dict[str, object]) -> tuple[dict[str, bool], str]:
    attempts = payload["attempts"]
    warm = attempts[-1] if attempts else {}
    osascript_ok = pass_from_osascript(warm.get("osascript", {}))
    rosetta_count = warm.get("vmmap_rosetta", {}).get("count")
    rosetta_ok = rosetta_count == 0 and bool(warm.get("pgrep", {}).get("pids"))
    cache_hit_rate = payload.get("translation_cache", {}).get("hit_rate")
    cache_ok = isinstance(cache_hit_rate, (int, float)) and cache_hit_rate >= 0.80
    loop_text = str(payload.get("loop_wineboot", {}).get("stdout", ""))
    wineboot_ok = payload.get("loop_wineboot", {}).get("rc") == 0 and "pass=20 fail=0 hang=0" in loop_text
    cmd_ok = payload.get("cmd_echo", {}).get("rc") == 0 and "hi" in str(payload.get("cmd_echo", {}).get("stdout", ""))
    hyperbridge_ok = payload.get("hyperbridge_tests", {}).get("rc") == 0
    leftovers_ok = payload.get("assert_no_leftovers", {}).get("rc") == 0
    checks = {
        "osascript_window_shows_notepad": osascript_ok,
        "vmmap_rosetta_count_is_zero": rosetta_ok,
        "warm_cache_hit_rate_at_least_80_percent": cache_ok,
        "loop_wineboot_pass": wineboot_ok,
        "cmd_echo_pass": cmd_ok,
        "hyperbridge_tests_green": hyperbridge_ok,
        "no_wine_leftovers": leftovers_ok,
    }
    blocker = classify_blocker(payload)
    lines = [
        "# Notepad x86_64 First Run",
        "",
        f"Generated: {payload['timestamp']}",
        "",
        "## End Condition Evidence",
        "",
    ]
    for key, ok in checks.items():
        lines.append(f"- **{key}**: {'PASS' if ok else 'FAIL'}")
    lines.extend(
        [
            "",
            "## Required Command Outputs",
            "",
            "### osascript",
            "",
            "```text",
            str(warm.get("osascript", {}).get("stdout", "")) or str(warm.get("osascript", {}).get("stderr", "")),
            "```",
            "",
            "### vmmap Rosetta Count",
            "",
            f"- command: `{warm.get('vmmap_rosetta', {}).get('command', '')}`",
            f"- stdout: `{warm.get('vmmap_rosetta', {}).get('stdout', '')}`",
            f"- count: `{warm.get('vmmap_rosetta', {}).get('count')}`",
            "",
            "### Translation Cache",
            "",
            f"- hit_rate: `{cache_hit_rate}`",
            f"- reason: {payload.get('translation_cache', {}).get('reason', '')}",
            "",
            "## Blocker Classification",
            "",
            f"- category: `{blocker['category']}`",
            f"- evidence: {blocker['evidence']}",
            f"- next_root_fix: {blocker['next_root_fix']}",
            "",
            "## Experimental Bridge Probe",
            "",
            f"- rc: `{payload.get('bridge_probe', {}).get('rc')}`",
            f"- stderr: `{str(payload.get('bridge_probe', {}).get('stderr', '')).strip()[-600:]}`",
            "",
            "## Attempts",
            "",
        ]
    )
    for attempt in attempts:
        lines.extend(
            [
                f"### {attempt['label']}",
                "",
                f"- alive_at_probe: `{attempt['alive_at_probe']}`",
                f"- rc_after_cleanup: `{attempt['rc']}`",
                f"- notepad_pids: `{attempt.get('pgrep', {}).get('pids', [])}`",
                f"- marker_events_count: `{attempt.get('marker_events_count')}`",
                f"- iat_events_count: `{attempt.get('iat_events_count')}`",
                f"- stderr_tail: `{attempt.get('stderr_tail', '').strip()[-600:]}`",
                "",
            ]
        )
    return checks, "\n".join(lines) + "\n"


def classify_blocker(payload: dict[str, object]) -> dict[str, str]:
    stderr = "\n".join(str(a.get("stderr_tail", "")) for a in payload.get("attempts", []))
    bridge_stderr = str(payload.get("bridge_probe", {}).get("stderr", ""))
    if "aarch64-windows/ntdll.dll" in stderr and "c00000bb" in stderr:
        return {
            "category": "X86_64_HYPERBRIDGE_LOADER_ENTRYPOINT_MISSING",
            "evidence": "direct ARM64 Wine reaches the ARM64 ntdll load path and returns c00000bb before any x86_64 module marker/IAT/cache event is produced.",
            "next_root_fix": "Implement the arm64ec-x64-bridge/Wine loader handoff so AMD64 PE images are mapped to HyperBridge instead of being rejected by the ARM64 ntdll path.",
        }
    if "bridge launch not implemented yet" in bridge_stderr:
        return {
            "category": "ARM64EC_X64_BRIDGE_LAUNCH_NOT_IMPLEMENTED",
            "evidence": "experimental native bridge lane selects engine/bridge/arm64ec-x64-bridge, but that entrypoint exits with 'bridge launch not implemented yet'.",
            "next_root_fix": "Replace the bridge placeholder with a real Wine loader/HyperBridge process entrypoint and wire it into app.configurator lane selection.",
        }
    return {
        "category": "UNKNOWN",
        "evidence": "No recognized loader, bridge, GUI, Rosetta, or cache signature was found in the Phase G artifacts.",
        "next_root_fix": "Inspect reports/notepad-x86_64-first-run.json and promote the first concrete failure into a focused regression.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--notepad", required=True)
    parser.add_argument("--wine")
    parser.add_argument("--prefix")
    parser.add_argument("--cache-root")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--probe-delay", type=float, default=6.0)
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-md", required=True)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    notepad = Path(args.notepad).resolve()
    wine = Path(args.wine).resolve() if args.wine else Path(os.environ.get("MACRUNNER_WINE_BIN", root / "engine" / "wine" / "dist" / "bin" / "wine")).resolve()
    report_dir = Path(args.out_json).resolve().parent / "notepad-x86_64-first-run"
    report_dir.mkdir(parents=True, exist_ok=True)
    bottles_root = Path(os.environ.get("MACRUNNER_BOTTLES_ROOT", root / "bottles")).resolve()
    prefix = Path(args.prefix).resolve() if args.prefix else bottles_root / "notepad-x86_64-hyperbridge"
    cache_root = Path(args.cache_root).resolve() if args.cache_root else Path(os.environ.get("MACRUNNER_ARTIFACTS_ROOT", root / "artifacts")).resolve() / "notepad-x86_64-first-run" / "hyperbridge-cache"
    if prefix.exists():
        shutil.rmtree(prefix)
    prefix.mkdir(parents=True, exist_ok=True)
    cache_root.mkdir(parents=True, exist_ok=True)

    cleanup(root)
    env = os.environ.copy()
    env.update({
        "WINEPREFIX": str(prefix),
        "DYLD_FALLBACK_LIBRARY_PATH": "/opt/homebrew/lib",
        "WINEDEBUG": "-all",
        "MACRUNNER_HB_X64_LOADER": "1",
        "MACRUNNER_BOTTLES_ROOT": str(bottles_root),
        "MACRUNNER_HB_CACHE_ROOT": str(cache_root),
    })
    wineboot_timeout = int(os.environ.get("WINEBOOT_TIMEOUT", "180"))
    wineboot = run_capture([str(wine), "wineboot", "--init"], timeout=wineboot_timeout, env=env)
    cmd_echo = run_capture([str(wine), "cmd", "/c", "echo", "hi"], timeout=30, env=env)
    cache_before = cache_stats(root, cache_root)
    cold = run_notepad_attempt(root, notepad, wine, prefix, cache_root, report_dir, "cold", args.timeout, args.probe_delay)
    cache_after_cold = cache_stats(root, cache_root)
    warm = run_notepad_attempt(root, notepad, wine, prefix, cache_root, report_dir, "warm", args.timeout, args.probe_delay)
    cache_after_warm = cache_stats(root, cache_root)
    bridge_probe = run_capture(
        [
            "python3",
            "-m",
            "app.configurator",
            "--real",
            "--experimental",
            "--prefer-native",
            "--timeout",
            "5",
            str(notepad),
        ],
        timeout=15,
        env={
            **os.environ,
            "MACRUNNER_HB_X64_LOADER": "1",
            "MACRUNNER_BOTTLES_ROOT": str(bottles_root),
            "MACRUNNER_HB_CACHE_ROOT": str(cache_root),
        },
    )
    hyperbridge_tests = run_capture([str(root / "scripts" / "test-hyperbridge.sh")], timeout=120)
    loop_env = {
        **os.environ,
        "MACRUNNER_BOTTLES_ROOT": str(bottles_root),
        "WINEBOOT_TIMEOUT": os.environ.get("WINEBOOT_TIMEOUT", "180"),
    }
    loop_wineboot = run_capture([str(root / "scripts" / "loop-wineboot.sh")], timeout=420, env=loop_env)
    assert_no_leftovers = run_capture([str(root / "scripts" / "assert-no-wine-leftovers.sh")], timeout=30)

    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "root": str(root),
        "notepad_path": str(notepad),
        "wine": str(wine),
        "prefix": str(prefix),
        "cache_root": str(cache_root),
        "wineboot": wineboot,
        "cmd_echo": cmd_echo,
        "attempts": [cold, warm],
        "cache_before": json_stdout(cache_before),
        "cache_after_cold": json_stdout(cache_after_cold),
        "cache_after_warm": json_stdout(cache_after_warm),
        "translation_cache": cache_delta(cache_before, cache_after_warm),
        "bridge_probe": bridge_probe,
        "hyperbridge_tests": hyperbridge_tests,
        "loop_wineboot": loop_wineboot,
        "assert_no_leftovers": assert_no_leftovers,
    }
    checks, markdown = build_report(payload)
    payload["end_condition"] = checks
    payload["status"] = "PASS" if all(checks.values()) else "FAIL"

    Path(args.out_json).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    Path(args.out_md).write_text(markdown)
    print(json.dumps({"status": payload["status"], "end_condition": checks}, indent=2, sort_keys=True))
    return 0 if payload["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
