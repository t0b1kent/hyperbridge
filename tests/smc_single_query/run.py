#!/usr/bin/env python3
"""Link the generic differential fixture to an explicitly supplied built archive.

This does not build the engine, launch Wine, or read game files. Generated
sources, compiler output, execution output, and source pins stay in --output.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

BASE_COMMIT = "97068eaed1bf72c4aecc9100aae0e7fe2c06b320"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE_FILES = ("include/hb_memory.h", "src/hb_memory.c", "src/hb_runtime.c")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract(text, name):
    start = text.index("static const uint8_t* smc_bytes_current(")
    end = text.index("\nstatic uint64_t smc_hash_current(", start)
    return text[start:end].replace("smc_bytes_current(", name + "(", 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cc", default="clang")
    args = parser.parse_args()
    archive = args.archive.resolve(strict=True)
    if not archive.is_file():
        parser.error("--archive must be an existing built static archive")
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    receipt = {"base_commit": BASE_COMMIT, "passed": False, "commands": []}
    tracked = {rel: ROOT / rel for rel in SOURCE_FILES}
    tracked.update({"fixture/" + name: HERE / name
                    for name in ("fixture.c", "fixture-v2.c", "run.py")})
    before = {name: digest(path) for name, path in tracked.items()}
    archive_before = digest(archive)
    receipt["inputs_sha256"] = before
    receipt["archive_sha256"] = archive_before
    try:
        baseline = subprocess.run(
            ["git", "show", BASE_COMMIT + ":src/hb_runtime.c"], cwd=ROOT,
            capture_output=True, text=True, timeout=10, check=True).stdout
        candidate = (ROOT / "src/hb_runtime.c").read_text()
        (out / "smc-original.inc").write_text(
            extract(baseline, "smc_bytes_current_original"))
        (out / "smc-candidate.inc").write_text(
            extract(candidate, "smc_bytes_current"))
        receipt["extracted_sha256"] = {
            name: digest(out / name)
            for name in ("smc-original.inc", "smc-candidate.inc")}
        env = dict(os.environ)
        env["MACRUNNER_HB_GUEST32_SHARED_WINDOW"] = "0"
        receipt["hb_environment"] = {
            key: value for key, value in env.items()
            if key.startswith("MACRUNNER_HB_")}
        commands = [
            ("link", [args.cc, "-O2", "-Wall", "-Wextra", "-Werror",
                      "-std=c11", "-D_DARWIN_C_SOURCE",
                      "-I" + str(ROOT / "include"), "-I" + str(out),
                      str(HERE / "fixture-v2.c"), str(archive),
                      "-lpthread", "-lm", "-o", str(out / "fixture")]),
            ("fixture", [str(out / "fixture")]),
        ]
        for label, argv in commands:
            started = time.monotonic()
            with (out / (label + ".log")).open("wb") as log:
                result = subprocess.run(argv, cwd=ROOT, env=env, stdout=log,
                                        stderr=subprocess.STDOUT, timeout=30)
            receipt["commands"].append({"label": label,
                "returncode": result.returncode,
                "elapsed_s": time.monotonic() - started})
            if result.returncode:
                break
        receipt["passed"] = (len(receipt["commands"]) == 2 and
            all(item["returncode"] == 0 for item in receipt["commands"]))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        receipt["error"] = str(error)
    finally:
        receipt["inputs_unchanged"] = all(
            digest(path) == before[name] for name, path in tracked.items())
        receipt["archive_unchanged"] = digest(archive) == archive_before
        receipt["passed"] &= (receipt["inputs_unchanged"] and
                              receipt["archive_unchanged"])
        (out / "RESULT.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"output": str(out), "passed": receipt["passed"]}))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
