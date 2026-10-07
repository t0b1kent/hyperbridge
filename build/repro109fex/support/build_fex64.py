#!/usr/bin/env python3
"""Build the selected FEX64 source series. Network and builds require a cloud worker."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import runpy
import shutil
import signal
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

import native_layout
import public_archive
import archive_safety
import fex_notices

HERE = Path(__file__).resolve().parent
DEADLINE = None


def _check_message(expected, actual, note=''):
    def bounded(value):
        if isinstance(value, bytes):
            return 'bytes=' + str(len(value)) + '; prefix_hex=' + value[:32].hex()
        return repr(value)[:600]
    return str(note) + '; expected=' + expected + '; actual=' + repr(
        {key: bounded(value) for key, value in actual.items()})


def sha(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def load_lock(expected_patch_count=53):
    lock = json.loads((HERE / "fex64.lock.json").read_text())
    tools = json.loads((HERE / "tools.lock.json").read_text())
    if not ((_repro_check_0_0 := isinstance(lock, dict)) and (_repro_check_0_1 := isinstance(tools, dict))):
        raise AssertionError(_check_message('isinstance(lock, dict) and isinstance(tools, dict)', {'isinstance(lock, dict)': locals().get('_repro_check_0_0', 'NOT_EVALUATED'), 'isinstance(tools, dict)': locals().get('_repro_check_0_1', 'NOT_EVALUATED')}, 'validation failed'))
    if len(lock['patches']) != expected_patch_count or len(lock['submodules']) != 6:
        raise ValueError(f'Sealed source counts: expected={expected_patch_count}/6; actual={len(lock["patches"])}/{len(lock["submodules"])}')
    if len({p['path'] for p in lock['patches']}) != expected_patch_count:
        raise ValueError(f'Unique source patches: expected={expected_patch_count}; actual={len({p["path"] for p in lock["patches"]})}')
    for row in lock["patches"]:
        path = (HERE / row["path"]).resolve()
        if not ((_repro_check_3_0 := path.is_relative_to(HERE / 'source'))):
            raise AssertionError(_check_message('path.is_relative_to(HERE / "source")', {"path.is_relative_to(HERE / 'source')": locals().get('_repro_check_3_0', 'NOT_EVALUATED')}, "patch escaped source directory"))
        if not ((_repro_check_4_0 := sha(path)) == (_repro_check_4_1 := row['sha256'])):
            raise AssertionError(_check_message('sha(path) == row["sha256"]', {'sha(path)': locals().get('_repro_check_4_0', 'NOT_EVALUATED'), "row['sha256']": locals().get('_repro_check_4_1', 'NOT_EVALUATED')}, "patch checksum differs: " + row["path"]))
    return lock, tools


def source_digest(src):
    result = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                            cwd=src, check=True, capture_output=True).stdout
    names = sorted(set(x.decode() for x in result.split(b"\0") if x))
    files = {name: sha(src / name) for name in names if (src / name).is_file()}
    data = "".join(name + "\t" + files[name] + "\n" for name in sorted(files))
    return len(files), hashlib.sha256(data.encode()).hexdigest()


def verify_source(src, lock):
    count, digest = source_digest(src)
    if not ((_repro_check_5_0 := count) == (_repro_check_5_1 := lock['expected_source_files'])):
        raise AssertionError(_check_message('count == lock["expected_source_files"]', {'count': locals().get('_repro_check_5_0', 'NOT_EVALUATED'), "lock['expected_source_files']": locals().get('_repro_check_5_1', 'NOT_EVALUATED')}, f"source count differs: {count}"))
    if not ((_repro_check_6_0 := digest) == (_repro_check_6_1 := lock['expected_source_digest'])):
        raise AssertionError(_check_message('digest == lock["expected_source_digest"]', {'digest': locals().get('_repro_check_6_0', 'NOT_EVALUATED'), "lock['expected_source_digest']": locals().get('_repro_check_6_1', 'NOT_EVALUATED')}, "source digest differs"))
    for name, want in lock["bridge_source_sha256"].items():
        if not ((_repro_check_7_0 := sha(src / 'Source/Windows/UnixLib' / name)) == (_repro_check_7_1 := want)):
            raise AssertionError(_check_message('sha(src / "Source/Windows/UnixLib" / name) == want', {"sha(src / 'Source/Windows/UnixLib' / name)": locals().get('_repro_check_7_0', 'NOT_EVALUATED'), 'want': locals().get('_repro_check_7_1', 'NOT_EVALUATED')}, "bridge source differs: " + name))
    return {"files": count, "digest": digest, "bridge_files": 5}


def cloud_only():
    if not ((_repro_check_8_0 := platform.system()) == (_repro_check_8_1 := 'Darwin') and (_repro_check_8_2 := platform.machine()) == (_repro_check_8_3 := 'arm64')):
        raise AssertionError(_check_message('platform.system() == "Darwin" and platform.machine() == "arm64"', {'platform.system()': locals().get('_repro_check_8_0', 'NOT_EVALUATED'), "'Darwin'": locals().get('_repro_check_8_1', 'NOT_EVALUATED'), 'platform.machine()': locals().get('_repro_check_8_2', 'NOT_EVALUATED'), "'arm64'": locals().get('_repro_check_8_3', 'NOT_EVALUATED')}, "ARM64 macOS required"))
    if not ((_repro_check_9_0 := os.environ.get('GITHUB_ACTIONS')) == (_repro_check_9_1 := 'true') or (_repro_check_9_2 := os.environ.get('CI_BUILD_NUMBER'))):
        raise AssertionError(_check_message('os.environ.get("GITHUB_ACTIONS") == "true" or os.environ.get("CI_BUILD_NUMBER")', {"os.environ.get('GITHUB_ACTIONS')": locals().get('_repro_check_9_0', 'NOT_EVALUATED'), "'true'": locals().get('_repro_check_9_1', 'NOT_EVALUATED'), "os.environ.get('CI_BUILD_NUMBER')": locals().get('_repro_check_9_2', 'NOT_EVALUATED')}, "downloads and builds run only in the agreed cloud task"))
    if sys.version_info < (3, 9):
        raise ValueError('Cloud driver Python: expected>=3.9; actual=' + platform.python_version())
    if os.environ.get("GITHUB_ACTIONS") == "true":
        if not ((_repro_check_11_0 := platform.python_version()) == (_repro_check_11_1 := '3.13.7')):
            raise AssertionError(_check_message('platform.python_version() == "3.13.7"', {'platform.python_version()': locals().get('_repro_check_11_0', 'NOT_EVALUATED'), "'3.13.7'": locals().get('_repro_check_11_1', 'NOT_EVALUATED')}, "GitHub driver Python differs"))
    # HERE may refer to verified source inputs; publication belongs to the wrapper.
    repo = Path(__file__).resolve().parent.parent
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=repo, text=True)
    if not (not (_repro_check_13_0 := dirty)):
        raise AssertionError(_check_message('not dirty', {'dirty': locals().get('_repro_check_13_0', 'NOT_EVALUATED')}, "cloud task must start from a committed clean checkout"))


def download(row, destination, out):
    return public_archive.download(row, destination, out)


def extract(archive, destination, wheel=False, evidence=None):
    destination.mkdir()
    if wheel:
        with zipfile.ZipFile(archive) as stream:
            for entry in stream.infolist():
                if not ((_repro_check_17_0 := (destination / entry.filename).resolve().is_relative_to(destination.resolve()))):
                    raise AssertionError(_check_message('(destination / entry.filename).resolve().is_relative_to(destination.resolve())', {'(destination / entry.filename).resolve().is_relative_to(destination.resolve())': locals().get('_repro_check_17_0', 'NOT_EVALUATED')}, 'validation failed'))
            stream.extractall(destination)
    else:
        with tarfile.open(archive) as stream:
            members = stream.getmembers()
            graph = archive_safety.validate_tar(members)
            if evidence is not None:
                Path(evidence).write_text(json.dumps(graph, indent=2) + '\n')
            if callable(getattr(tarfile, 'data_filter', None)):
                stream.extractall(destination, members=members, filter="data")
            else:
                # The same complete graph check applies on Apple Python without data_filter.
                stream.extractall(destination, members=members)


def tool_event(out, name, stage, **extra):
    with (out / "tool-bootstrap.jsonl").open("a") as ledger:
        ledger.write(json.dumps({"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "monotonic_ns": time.monotonic_ns(), "tool": name, "stage": stage, **extra}) + "\n")


def macho_arm64(path):
    # Do not execute an x86-only tool through Rosetta. Bound header inspection.
    with path.open("rb") as stream:
        data = stream.read(4096)
    if len(data) < 8:
        return False
    magic = data[:4]
    thin = {b"\xcf\xfa\xed\xfe": "<", b"\xfe\xed\xfa\xcf": ">"}
    if magic in thin:
        return struct.unpack_from(thin[magic] + "I", data, 4)[0] == 0x0100000c
    fat = {b"\xca\xfe\xba\xbe": (">", 20), b"\xbe\xba\xfe\xca": ("<", 20),
           b"\xca\xfe\xba\xbf": (">", 32), b"\xbf\xba\xfe\xca": ("<", 32)}
    if magic not in fat:
        return False
    endian, stride = fat[magic]
    count = struct.unpack_from(endian + "I", data, 4)[0]
    if not 1 <= count <= 32 or 8 + count * stride > len(data):
        return False
    return any(struct.unpack_from(endian + "I", data, 8 + i * stride)[0] == 0x0100000c
               for i in range(count))


def tool_binary(tree, name):
    # Wheels may put executable payloads under package/data or *.data/scripts.
    # Archive SHA + native payload + unique real path is the invariant, not suffix.
    root = tree.resolve()
    candidates = {}
    observed = []
    for path in sorted(tree.rglob(name)):
        if not path.is_file():
            continue
        resolved = path.resolve()
        if not ((_repro_check_18_0 := resolved.is_relative_to(root))):
            raise AssertionError(_check_message('resolved.is_relative_to(root)', {'resolved.is_relative_to(root)': locals().get('_repro_check_18_0', 'NOT_EVALUATED')}, "tool executable escaped archive: " + name))
        native = macho_arm64(resolved)
        observed.append({"path": str(path.relative_to(tree)), "arm64_macho": native})
        if native:
            candidates.setdefault(resolved, path)
    if not ((_repro_check_19_0 := len(candidates)) == (_repro_check_19_1 := 1)):
        raise AssertionError(_check_message('len(candidates) == 1', {'len(candidates)': locals().get('_repro_check_19_0', 'NOT_EVALUATED'), '1': locals().get('_repro_check_19_1', 'NOT_EVALUATED')}, f"tool native executable count differs: {name}: {len(candidates)}; {observed}"))
    return next(iter(candidates.values()))


def toolchain_root(tree):
    root = tree.resolve()
    candidates = set()
    for path in tree.rglob("arm64ec-w64-mingw32-clang"):
        if path.parent.name == "bin" and path.is_file():
            if not ((_repro_check_20_0 := path.resolve().is_relative_to(root))):
                raise AssertionError(_check_message('path.resolve().is_relative_to(root)', {'path.resolve().is_relative_to(root)': locals().get('_repro_check_20_0', 'NOT_EVALUATED')}, "toolchain wrapper escaped archive"))
            candidates.add(path.parent.parent.resolve())
    if not ((_repro_check_21_0 := len(candidates)) == (_repro_check_21_1 := 1)):
        raise AssertionError(_check_message('len(candidates) == 1', {'len(candidates)': locals().get('_repro_check_21_0', 'NOT_EVALUATED'), '1': locals().get('_repro_check_21_1', 'NOT_EVALUATED')}, f"toolchain root count differs: {len(candidates)}"))
    selected = next(iter(candidates))
    required = ["clang", "ld.lld"] + [triple + "-" + command
        for triple in ["arm64ec-w64-mingw32", "aarch64-w64-mingw32"]
        for command in ["clang", "clang++", "windres", "dlltool", "ar"]]
    for name in required:
        path = selected / "bin" / name
        if not ((_repro_check_22_0 := path.is_file()) and (_repro_check_22_1 := path.resolve().is_relative_to(root))):
            raise AssertionError(_check_message('path.is_file() and path.resolve().is_relative_to(root)', {'path.is_file()': locals().get('_repro_check_22_0', 'NOT_EVALUATED'), 'path.resolve().is_relative_to(root)': locals().get('_repro_check_22_1', 'NOT_EVALUATED')}, "toolchain command missing/foreign: " + name))
        if not ((_repro_check_23_0 := os.access(path, os.X_OK))):
            raise AssertionError(_check_message('os.access(path, os.X_OK)', {'os.access(path, os.X_OK)': locals().get('_repro_check_23_0', 'NOT_EVALUATED')}, "toolchain command not executable: " + name))
    for name in ["clang", "ld.lld"]:
        if not ((_repro_check_24_0 := macho_arm64(selected / 'bin' / name))):
            raise AssertionError(_check_message('macho_arm64(selected / "bin" / name)', {"macho_arm64(selected / 'bin' / name)": locals().get('_repro_check_24_0', 'NOT_EVALUATED')}, "toolchain host tool has no ARM64: " + name))
    return selected


def prepare_archive(row, root, out):
    name = row["name"]
    archive = root / (name + ".archive")
    tree = root / name
    tool_event(out, name, "STARTED", expected_sha256=row["sha256"], expected_bytes=row["size"])
    try:
        transfer = download(row, archive, out)
        tool_event(out, name, "VERIFIED", sha256=sha(archive), bytes=archive.stat().st_size,
                   transport=transfer['transport'], attempts=len(transfer['attempts']))
        if row["format"] == "wheel":
            with zipfile.ZipFile(archive) as stream:
                members = stream.namelist()
        else:
            with tarfile.open(archive) as stream:
                members = stream.getnames()
        (out / ("tool-" + name + "-members.json")).write_text(json.dumps(members, indent=2) + "\n")
        extract(archive, tree, row["format"] == "wheel", out / ("tool-" + name + "-links.json"))
        tool_event(out, name, "EXTRACTED", members=len(members))
        return tree
    except Exception as exc:
        tool_event(out, name, "FAILED", error=str(exc)[:700])
        raise


def prepare_tool(row, root, out, bin_dir):
    tree = prepare_archive(row, root, out)
    try:
        selected = tool_binary(tree, row["name"])
        selected.chmod(selected.stat().st_mode | 0o111)
        (bin_dir / row["name"]).symlink_to(selected)
        tool_event(out, row["name"], "SELECTED", path=str(selected.relative_to(tree)),
                   binary_sha256=sha(selected))
    except Exception as exc:
        tool_event(out, row["name"], "FAILED", error=str(exc)[:700])
        raise


def run(argv, cwd, out, name, env, timeout=2400):
    if DEADLINE is not None:
        timeout = min(timeout, DEADLINE - time.monotonic())
        if timeout <= 0:
            raise RuntimeError('Cloud batch deadline reached before ' + name)
    with (out / (name + ".log")).open("xb") as log:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            rc = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            raise RuntimeError("owned build timeout: " + name) from None
    with (out / "commands.jsonl").open("a") as ledger:
        ledger.write(json.dumps({"phase": name, "argv": argv, "rc": rc}) + "\n")
    if not ((_repro_check_25_0 := rc) == (_repro_check_25_1 := 0)):
        raise AssertionError(_check_message('rc == 0', {'rc': locals().get('_repro_check_25_0', 'NOT_EVALUATED'), '0': locals().get('_repro_check_25_1', 'NOT_EVALUATED')}, f"{name} failed rc={rc}; full raw log preserved"))


def own_cmake_cache(build, expected):
    lines = (build / "CMakeCache.txt").read_text().splitlines()
    home = next(line.split("=", 1)[1] for line in lines if line.startswith("CMAKE_HOME_DIRECTORY:"))
    if not ((_repro_check_26_0 := Path(home).resolve()) == (_repro_check_26_1 := expected.resolve())):
        raise AssertionError(_check_message('Path(home).resolve() == expected.resolve()', {'Path(home).resolve()': locals().get('_repro_check_26_0', 'NOT_EVALUATED'), 'expected.resolve()': locals().get('_repro_check_26_1', 'NOT_EVALUATED')}, "CMake takes foreign source"))


def pe_header(path, ec=True):
    data = path.read_bytes()
    if not ((_repro_check_27_0 := data[:2]) == (_repro_check_27_1 := b'MZ')):
        raise AssertionError(_check_message('data[:2] == b"MZ"', {'data[:2]': locals().get('_repro_check_27_0', 'NOT_EVALUATED'), "b'MZ'": locals().get('_repro_check_27_1', 'NOT_EVALUATED')}, 'validation failed'))
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    if not ((_repro_check_28_0 := data[offset:offset + 4]) == (_repro_check_28_1 := b'PE\x00\x00')):
        raise AssertionError(_check_message('data[offset:offset + 4] == b"PE\\0\\0"', {'data[offset:offset + 4]': locals().get('_repro_check_28_0', 'NOT_EVALUATED'), "b'PE\\x00\\x00'": locals().get('_repro_check_28_1', 'NOT_EVALUATED')}, 'validation failed'))
    machine, count = struct.unpack_from("<HH", data, offset + 4)
    optional_size = struct.unpack_from("<H", data, offset + 20)[0]
    table = offset + 24 + optional_size
    if not ((_repro_check_29_0 := (table + count * 40)) <= (_repro_check_29_1 := len(data))):
        raise AssertionError(_check_message('table + count * 40 <= len(data)', {'table + count * 40': locals().get('_repro_check_29_0', 'NOT_EVALUATED'), 'len(data)': locals().get('_repro_check_29_1', 'NOT_EVALUATED')}, 'validation failed'))
    sections = [data[table + i * 40:table + i * 40 + 8].rstrip(b"\0").decode() for i in range(count)]
    # The accepted ARM64X image carries Machine=AMD64. Reuse the project guard.
    inspect_ec = runpy.run_path(str(HERE / "check-arm64ec-dist.py"))["pe_priznaki"]
    features = inspect_ec(path)
    if ec:
        if not ((_repro_check_30_0 := features) == (_repro_check_30_1 := (True, True, True)) and (_repro_check_30_2 := '.text') in (_repro_check_30_3 := sections)):
            raise AssertionError(_check_message('features == (True, True, True) and ".text" in sections', {'features': locals().get('_repro_check_30_0', 'NOT_EVALUATED'), '(True, True, True)': locals().get('_repro_check_30_1', 'NOT_EVALUATED'), "'.text'": locals().get('_repro_check_30_2', 'NOT_EVALUATED'), 'sections': locals().get('_repro_check_30_3', 'NOT_EVALUATED')}, "FEX64 has no complete EC metadata"))
    else:
        if not ((_repro_check_31_0 := machine) == (_repro_check_31_1 := 43620) and (_repro_check_31_2 := '.text') in (_repro_check_31_3 := sections)):
            raise AssertionError(_check_message('machine == 0xaa64 and ".text" in sections', {'machine': locals().get('_repro_check_31_0', 'NOT_EVALUATED'), '43620': locals().get('_repro_check_31_1', 'NOT_EVALUATED'), "'.text'": locals().get('_repro_check_31_2', 'NOT_EVALUATED'), 'sections': locals().get('_repro_check_31_3', 'NOT_EVALUATED')}, "WOW64 translator must be native ARM64 PE"))
    return {"machine": hex(machine), "sections": sections,
            "chpe": features[0], "hexpthk": features[1], "a64xrm": features[2]}


def prepare_build_tools(root, out, lock, tools, env):
    """Download, extract and select tools; do not import or execute any payload."""
    bin_dir = root / "bin"
    bin_dir.mkdir()
    for row in tools["tools"]:
        prepare_tool(row, root, out, bin_dir)
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
    tc_tree = prepare_archive({"name": "llvm-mingw", "format": "tar.xz", "url": lock["llvm_mingw_url"],
        "sha256": lock["llvm_mingw_sha256"], "size": lock["llvm_mingw_size"]}, root, out)
    try:
        tc = toolchain_root(tc_tree)
        tool_event(out, "llvm-mingw", "SELECTED", path=str(tc.relative_to(tc_tree.resolve())),
                   clang_sha256=sha(tc / "bin/clang"), wrappers=10, host_arm64_tools=2)
    except Exception as exc:
        tool_event(out, "llvm-mingw", "FAILED", error=str(exc)[:700])
        raise
    env["PATH"] = str(tc / "bin") + os.pathsep + env["PATH"]
    return tc


def build(out, lock, tools, source_overlay=None):
    cloud_only()
    out.mkdir(parents=True, exist_ok=True)
    if not (not (_repro_check_32_0 := (out / 'commands.jsonl').exists())):
        raise AssertionError(_check_message('not (out / "commands.jsonl").exists()', {"(out / 'commands.jsonl').exists()": locals().get('_repro_check_32_0', 'NOT_EVALUATED')}, "preserve prior result before a new run"))
    wow64 = lock.get("variant") == "fex32"
    root = Path(tempfile.mkdtemp(prefix="repro109-fex32-" if wow64 else "repro109-fex64-", dir=os.environ.get("RUNNER_TEMP", os.environ.get("TMPDIR"))))
    env = os.environ.copy()
    # Download authorization belongs to the orchestrator, not compiler children.
    for key in ['RESULTS_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN']:
        env.pop(key, None)
    env.update(LC_ALL="C", TZ="UTC", MACOSX_DEPLOYMENT_TARGET=lock["deployment_target"],
               CCACHE_DIR=str(root / "ccache"), CCACHE_BASEDIR=str(root), CCACHE_COMPILERCHECK="content")
    env.pop("CC", None)
    env.pop("CXX", None)
    xcode = subprocess.check_output(["xcodebuild", "-version"], text=True, env=env)
    profile = lock.get('cloud_profile')
    # Save actual platform bytes before validating, including a pre-product refusal.
    (out / 'xcode-version.raw.txt').write_text(xcode)
    if profile:
        version = re.fullmatch(r'Xcode (\d+)(?:\.\d+){0,2}', xcode.splitlines()[0])
        if not version or int(version.group(1)) != profile['xcode_major'] or len(xcode.splitlines()) != 2:
            raise ValueError('Xcode Cloud major differs; actual=' + repr(xcode.strip()))
    elif not ((_repro_check_33_0 := xcode.strip().splitlines()) == (_repro_check_33_1 := ['Xcode ' + lock['xcode'], 'Build version ' + lock['xcode_build']])):
        raise AssertionError(_check_message('xcode.strip().splitlines() == ["Xcode " + lock["xcode"], "Build version " + lock["xcode_build"]]', {'xcode.strip().splitlines()': locals().get('_repro_check_33_0', 'NOT_EVALUATED'), "['Xcode ' + lock['xcode'], 'Build version ' + lock['xcode_build']]": locals().get('_repro_check_33_1', 'NOT_EVALUATED')}, "select the pinned Xcode before starting this task"))
    clang = subprocess.check_output(["xcrun", "--find", "clang"], text=True, env=env).strip()
    clangxx = subprocess.check_output(["xcrun", "--find", "clang++"], text=True, env=env).strip()
    clang_version = subprocess.check_output([clang, "--version"], text=True, env=env)
    (out / 'apple-clang-version.raw.txt').write_text(clang_version)
    if not profile and not ((_repro_check_34_0 := lock['apple_clang_build']) in (_repro_check_34_1 := clang_version)):
        raise AssertionError(_check_message('lock["apple_clang_build"] in clang_version', {"lock['apple_clang_build']": locals().get('_repro_check_34_0', 'NOT_EVALUATED'), 'clang_version': locals().get('_repro_check_34_1', 'NOT_EVALUATED')}, "Apple compiler differs"))
    sdk_version = subprocess.check_output(["xcrun", "--sdk", "macosx", "--show-sdk-version"], text=True, env=env).strip()
    (out / 'sdk-version.raw.txt').write_text(sdk_version + '\n')
    if not ((_repro_check_35_0 := sdk_version) == (_repro_check_35_1 := lock['sdk'])):
        raise AssertionError(_check_message('sdk_version == lock["sdk"]', {'sdk_version': locals().get('_repro_check_35_0', 'NOT_EVALUATED'), "lock['sdk']": locals().get('_repro_check_35_1', 'NOT_EVALUATED')}, "SDK differs"))
    env["SDKROOT"] = subprocess.check_output(["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True, env=env).strip()
    run(["xcrun", "ld", "-v"], root, out, "apple-ld-version", env, timeout=30)
    apple_ld = (out / "apple-ld-version.log").read_text()
    apple_ld_identity = native_layout.verify_linker(apple_ld, profile['ld'] if profile else lock.get('linker_lc'))
    tc = prepare_build_tools(root, out, lock, tools, env)
    actual_tools = {}
    versions = {row["name"]: row["version"] for row in tools["tools"]}
    for name in ["cmake", "ninja", "ccache", "arm64ec-w64-mingw32-clang", "aarch64-w64-mingw32-clang"]:
        tool_name = name if name in versions else "llvm-mingw"
        try:
            phase = "tool-" + name + "-version"
            run([name, "--version"], root, out, phase, env, timeout=30)
            actual_tools[name] = (out / (phase + ".log")).read_text().splitlines()[0]
            if name in versions:
                if not ((_repro_check_36_0 := versions[name]) in (_repro_check_36_1 := actual_tools[name])):
                    raise AssertionError(_check_message('versions[name] in actual_tools[name]', {'versions[name]': locals().get('_repro_check_36_0', 'NOT_EVALUATED'), 'actual_tools[name]': locals().get('_repro_check_36_1', 'NOT_EVALUATED')}, "build tool version differs: " + name))
            tool_event(out, tool_name, "VERSION_PRESENT", command=name, version=actual_tools[name])
        except Exception as exc:
            tool_event(out, tool_name, "FAILED", error=str(exc)[:700])
            raise
    (out / "toolchain.json").write_text(json.dumps({"xcode": xcode, "apple_clang": clang_version, "apple_ld": apple_ld,
        "apple_ld_identity": apple_ld_identity,
        "python": sys.version, "tools": actual_tools, "host": platform.platform(),
        "sdk": sdk_version, "deployment_target": lock["deployment_target"],
        "cloud_profile": profile or 'PINNED_GITHUB',
        "exact_unmeasured_pins": profile['unmeasured_exact_pins'] if profile else []}, indent=2) + "\n")
    (out / 'effective-build.lock.json').write_text(json.dumps(lock, indent=2) + '\n')
    lock_name = "fex32.lock.json" if wow64 else "fex64.lock.json"
    shutil.copy2(HERE / lock_name, out / lock_name)
    shutil.copy2(HERE / "tools.lock.json", out / "tools.lock.json")
    fork = root / "macrunner-source"
    run(["git", "init", "-q", str(fork)], root, out, "own-repo-init", env)
    run(["git", "fetch", "-q", "--depth", "1", "https://github.com/t0b1kent/hyperbridge.git", lock["repo_source_revision"]], fork, out, "own-repo-fetch", env)
    run(["git", "checkout", "-q", "--detach", "FETCH_HEAD"], fork, out, "own-repo-checkout", env)
    if not ((_repro_check_37_0 := subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=fork, text=True).strip()) == (_repro_check_37_1 := lock['repo_source_revision'])):
        raise AssertionError(_check_message('subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=fork, text=True).strip() == lock["repo_source_revision"]', {"subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=fork, text=True).strip()": locals().get('_repro_check_37_0', 'NOT_EVALUATED'), "lock['repo_source_revision']": locals().get('_repro_check_37_1', 'NOT_EVALUATED')}, 'validation failed'))
    src = root / "src"
    if lock.get('build_native_stand'):
        import native_stand
        native_stand.verify_builder(fork, lock)
    run(["git", "init", "-q", str(src)], root, out, "source-init", env)
    run(["git", "fetch", "-q", "--depth", "1", lock["fex_repo"], lock["base"]], src, out, "source-fetch", env)
    run(["git", "checkout", "-q", "--detach", "FETCH_HEAD"], src, out, "source-checkout", env)
    if not ((_repro_check_38_0 := subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=src, text=True).strip()) == (_repro_check_38_1 := lock['base'])):
        raise AssertionError(_check_message('subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=src, text=True).strip() == lock["base"]', {"subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=src, text=True).strip()": locals().get('_repro_check_38_0', 'NOT_EVALUATED'), "lock['base']": locals().get('_repro_check_38_1', 'NOT_EVALUATED')}, 'validation failed'))
    public_patches = 0
    for i, row in enumerate(lock["patches"]):
        selected = HERE / row["path"]
        public = fork / "fex/patches" / selected.name.split("-", 1)[1]
        mapping = lock.get('public_patch_paths')
        if mapping is not None:
            name = mapping[row['path']]
            public = fork / name
            if (not isinstance(name, str) or Path(name).is_absolute() or '..' in Path(name).parts
                    or not public.is_file() or public.is_symlink()
                    or not public.resolve().is_relative_to(fork.resolve())
                    or sha(public) != row['sha256']):
                raise ValueError('Pinned public patch is missing or foreign')
            selected = public
            public_patches += 1
        elif i < 49:
            if not ((_repro_check_39_0 := sha(public)) == (_repro_check_39_1 := row['sha256'])):
                raise AssertionError(_check_message('sha(public) == row["sha256"]', {'sha(public)': locals().get('_repro_check_39_0', 'NOT_EVALUATED'), "row['sha256']": locals().get('_repro_check_39_1', 'NOT_EVALUATED')}, "public MacRunner patch differs"))
            selected = public
            public_patches += 1
        patch = str(selected)
        if not ((_repro_check_40_0 := sha(Path(patch))) == (_repro_check_40_1 := row['sha256'])):
            raise AssertionError(_check_message('sha(Path(patch)) == row["sha256"]', {'sha(Path(patch))': locals().get('_repro_check_40_0', 'NOT_EVALUATED'), "row['sha256']": locals().get('_repro_check_40_1', 'NOT_EVALUATED')}, "patch checksum differs"))
        run(["git", "apply", "--check", "--index", patch], src, out, f"patch-check-{i + 1:02d}", env)
        run(["git", "apply", "--index", "--whitespace=nowarn", patch], src, out, f"patch-{i + 1:02d}", env)
    verified = verify_source(src, lock)
    if source_overlay is not None:
        verified['candidate'] = source_overlay('prepared', src, lock, out, env)
    if lock.get('build_native_stand'):
        verified['native_patch_order'] = native_stand.write_order(src, lock, out)
    verified.update(own_repo_revision=lock["repo_source_revision"], public_patches=public_patches,
                    private_patches=len(lock["patches"])-public_patches)
    (out / "source-verification.json").write_text(json.dumps(verified, indent=2) + "\n")
    with (out / "wine-srcdir-guard.log").open("xb") as log:
        guard = subprocess.run(["sh", str(HERE / "check-build-srcdir.sh"), str(root)],
                               stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=10)
    if not ((_repro_check_41_0 := guard.returncode) in (_repro_check_41_1 := (0, 2))):
        raise AssertionError(_check_message('guard.returncode in (0, 2)', {'guard.returncode': locals().get('_repro_check_41_0', 'NOT_EVALUATED'), '(0, 2)': locals().get('_repro_check_41_1', 'NOT_EVALUATED')}, "copied foreign Wine Makefile detected"))
    (out / "source-guards.json").write_text(json.dumps({"wine_makefile_guard_rc": guard.returncode,
        "wine_makefile_coverage": "NOT_ENABLED_NO_WINE_BUILD" if guard.returncode == 2 else "PRESENT",
        "fex_guard": "CMAKE_HOME_DIRECTORY_AND_ALL_COMPILE_SOURCES_BEFORE_BUILD"}, indent=2) + "\n")
    for i, row in enumerate(lock["submodules"]):
        target = src / row["path"]
        run(["git", "init", "-q", str(target)], src, out, f"submodule-{i}-init", env)
        run(["git", "fetch", "-q", "--depth", "1", row["repo"], row["revision"]], target, out, f"submodule-{i}-fetch", env)
        run(["git", "checkout", "-q", "--detach", "FETCH_HEAD"], target, out, f"submodule-{i}-checkout", env)
        if not ((_repro_check_42_0 := subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=target, text=True).strip()) == (_repro_check_42_1 := row['revision'])):
            raise AssertionError(_check_message('subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip() == row["revision"]', {"subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=target, text=True).strip()": locals().get('_repro_check_42_0', 'NOT_EVALUATED'), "row['revision']": locals().get('_repro_check_42_1', 'NOT_EVALUATED')}, 'validation failed'))
    if source_overlay is not None:
        source_overlay('submodules', src, lock, out, env)
    mapped = " ".join("-f" + tag + "-prefix-map=" + str(src) + "=/hyperbridge/fex/src" for tag in ["file", "debug", "macro"])
    pe = root / ("wow64" if wow64 else "arm64ec")
    triple = "aarch64-w64-mingw32" if wow64 else "arm64ec-w64-mingw32"
    flags = ["-DCMAKE_BUILD_TYPE=Release", "-DMINGW_TRIPLE=" + triple, "-DENABLE_CCACHE=ON",
             "-DTUNE_CPU=none", "-DENABLE_LTO=OFF", "-DENABLE_JEMALLOC_GLIBC_ALLOC=OFF", "-DRANGES_NATIVE=OFF",
             "-DBUILD_TESTING=OFF", "-DFEX_WINE_DARWIN=ON", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", "-DCMAKE_INSTALL_PREFIX=/hyperbridge/fex/stage",
             "-DCMAKE_INSTALL_LIBDIR=aarch64-windows", "-DOVERRIDE_HASH=" + lock["override_hash"], "-DOVERRIDE_VERSION=",
             "-DCMAKE_C_FLAGS=" + mapped, "-DCMAKE_CXX_FLAGS=" + mapped,
             "-DCMAKE_SHARED_LINKER_FLAGS=-static -static-libgcc -static-libstdc++ -Wl,--file-alignment=4096,/mllvm:-align-loops=1 -Wl,--Xlink=/timestamp:" + str(lock["pe_link_timestamp"])]
    run(["cmake", "-S", str(src), "-B", str(pe), "-G", "Ninja",
         "-DCMAKE_TOOLCHAIN_FILE=" + str(src / "Data/CMake/toolchain_mingw.cmake"), *flags], root, out, "pe-configure", env)
    own_cmake_cache(pe, src)
    sources = [(Path(row["directory"]) / row["file"]).resolve()
               for row in json.loads((pe / "compile_commands.json").read_text())]
    foreign = [str(path) for path in sources if not path.is_relative_to(src.resolve())
               and not path.is_relative_to(pe.resolve())]
    if not (not (_repro_check_43_0 := foreign)):
        raise AssertionError(_check_message('not foreign', {'foreign': locals().get('_repro_check_43_0', 'NOT_EVALUATED')}, "foreign compile sources: " + repr(foreign[:5])))
    jobs = str(min(os.cpu_count() or 2, profile['jobs'] if profile else lock.get('build_jobs', 8)))
    run(["cmake", "--build", str(pe), "--parallel", jobs, "--target", "wow64fex" if wow64 else "arm64ecfex"], root, out, "pe-build", env)
    unix = root / "unixlib"
    unix_src = src / "Source/Windows/UnixLib"
    run(["cmake", "-S", str(unix_src), "-B", str(unix), "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
         "-DCMAKE_CXX_COMPILER=" + clangxx, "-DCMAKE_CXX_COMPILER_LAUNCHER=ccache",
         "-DCMAKE_OSX_ARCHITECTURES=arm64", "-DCMAKE_OSX_DEPLOYMENT_TARGET=" + lock["deployment_target"],
         "-DCMAKE_OSX_SYSROOT=" + env["SDKROOT"],
         "-DCMAKE_CXX_FLAGS=" + mapped], root, out, "unix-configure", env)
    own_cmake_cache(unix, unix_src)
    run(["cmake", "--build", str(unix), "--parallel", jobs, "--target", "wow64fex_unixlib" if wow64 else "arm64ecfex_unixlib", "macrunner_hwtso"], root, out, "unix-build", env)
    outputs = {
        "fex/aarch64-windows/xtajit.dll": pe / "Bin/xtajit.dll",
        "fex/aarch64-unix/libwow64fex.so": unix / "xtajit.so",
        "fex/aarch64-unix/xtajit.so": unix / "xtajit.so",
        "fex/aarch64-unix/libmacrunner-hwtso.dylib": unix / "libmacrunner-hwtso.dylib"
    } if wow64 else {
        "fex/aarch64-windows/xtajit64.dll": pe / "Bin/xtajit64.dll",
        "wine/lib/wine/aarch64-windows/libarm64ecfex.dll": pe / "Bin/xtajit64.dll",
        "fex/aarch64-unix/libarm64ecfex.so": unix / "xtajit64.so",
        "fex/aarch64-unix/xtajit64.so": unix / "xtajit64.so",
        "fex/aarch64-unix/libmacrunner-hwtso.dylib": unix / "libmacrunner-hwtso.dylib"
    }
    receipt = {}
    for name, built in outputs.items():
        selected = out / "engine" / name
        selected.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(built, selected)
        row = {"sha256": sha(selected), "bytes": selected.stat().st_size}
        if name.endswith(".dll"):
            row.update(pe_header(selected, ec=not wow64))
        receipt[name] = row
    (out / "outputs.json").write_text(json.dumps({"classification": "BUILT_SOURCE_ONLY_NOT_ACCEPTED_NOT_GOLDEN",
        "files": receipt, "ec_modules": 0 if wow64 else sum(name.endswith(".dll") for name in receipt),
        "unique_ec_binaries": 0 if wow64 else 1, "install": "skipped", "signing": "NOT_PERFORMED",
        "section_comparison": "PENDING", "work_preserved_in_cloud": str(root)}, indent=2) + "\n")
    fex_notices.collect_source_notices(src, out, lock)
    if lock.get('build_native_stand'):
        native_stand.build(fork, src, lock, root / 'native-stand', out, env, sys.modules[__name__], clang, clangxx)
    print(json.dumps({"status": "BUILT_SOURCE_ONLY_NOT_ACCEPTED_NOT_GOLDEN", "outputs": len(receipt), "ec_modules": 0 if wow64 else 2,
                      "unique_ec_binaries": 0 if wow64 else 1, "install": "skipped"}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--static-check", action="store_true")
    parser.add_argument("--verify-source", type=Path)
    parser.add_argument("--verify-pe", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    lock, tools = load_lock()
    if args.static_check:
        result = {"patches": 53, "submodules": 6, "tools": len(tools["tools"]), "downloads": 0, "builds": 0}
        if args.verify_source:
            result["accepted_source"] = verify_source(args.verify_source, lock)
        if args.verify_pe:
            result["accepted_pe"] = pe_header(args.verify_pe)
        print(json.dumps(result))
        return
    if not ((_repro_check_45_0 := args.out)):
        raise AssertionError(_check_message('args.out', {'args.out': locals().get('_repro_check_45_0', 'NOT_EVALUATED')}, "--out required"))
    cloud_only()
    args.out.mkdir(parents=True, exist_ok=True)
    start = time.time()
    status = {"classification": "NOT_GOLDEN", "status": "STARTED"}
    try:
        build(args.out, lock, tools)
        status["status"] = "BUILT_PENDING_SECTION_COMPARISON"
    except Exception as exc:
        status.update(status="FAILED", error=str(exc)[:700])
        raise
    finally:
        status["seconds"] = time.time() - start
        (args.out / "repro109-status.json").write_text(json.dumps(status, indent=2) + "\n")


if __name__ == "__main__":
    main()
