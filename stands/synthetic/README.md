# Synthetic CPU stand

A differential test of the HyperBridge CPU engine without Wine: the FEX core built from `fex/patches` executes short x86-64
fragments natively on Apple silicon, and every result is compared with a reference emulator.

- `generate.py` creates 408 cells: 51 x86-64 instruction forms × 8 fixed SplitMix64 seeds. Inputs, instructions and
  addresses are synthetic; no recorded application state or hardware tables are included.
- `runner.cpp` (with the small adapters next to it and `native-portability.patch`) builds a native FEXCore runner for
  Darwin from the same FEX sources and patch series as the engine.
- `compare.py` runs each cell in the runner and in the reference (Unicorn, installed from PyPI) and compares all 16
  general-purpose registers, RIP at the fragment boundary, XMM0–15, the upper halves of YMM0–15, the defined
  arithmetic flags, MXCSR, and the memory images before and after execution. Exit code 0 means every cell matched.
- `verify.py` requires two byte-identical `--quick` reports, then a negative control (`STAND_MUTATE_GPR=1` flips the
  low bit of RAX inside the runner) that must be reported as a mismatch.

## Running it

Apple silicon, macOS 15 or later, Apple clang, CMake, Ninja, Python 3.12+ and llvm-mingw 20260505 (`LLVM_MINGW` points
to it; `download_toolchain.py` fetches it in CI). From the repository root:

```sh
python3 -m venv build/stand-venv
build/stand-venv/bin/python -m pip install -r stands/synthetic/requirements.txt
CMAKE_BUILD_PARALLEL_LEVEL=2 bash fex/build.sh build/stand-fex
python3 stands/synthetic/build.py
build/stand-venv/bin/python stands/synthetic/verify.py --runner build/stand-native/cmake/Bin/stand_runner --out build/stand-reports
```

`compare.py --full` widens the seeds to 72 per form (3,672 cells). The workflow `.github/workflows/stand.yml` runs the
same steps on GitHub's Apple silicon runners for every change to `fex/**` or `stands/synthetic/**`.

## Limits

This is the native FEX core: no Wine, no Windows front end, no ARM64EC ABI. Undefined flags, VEX instructions, x87,
SSE exceptions and Windows exception delivery are not covered here; a synthetic pass does not replace the engine's
product gates.

## Licenses

Our code is MIT (`LICENSE`). Unicorn (GPL-2.0) and Capstone (BSD) are installed from PyPI as external dependencies and
are not redistributed. FEX sources are fetched by `fex/build.sh` and keep their own licenses.
