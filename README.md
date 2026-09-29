# HyperBridge

HyperBridge is the CPU layer of [MacRunner](https://github.com/t0b1kent/macrunner-app). It runs
Windows x86-64 and x86 user-mode code on Apple Silicon by translating it to native ARM64, and
plugs into ARM64 Wine through Wine's emulator interface.

Since 28 September 2026, HyperBridge has two parts:

- **The engine MacRunner ships: [FEX-Emu](https://github.com/FEX-Emu/FEX), ported to macOS.**
  [`fex/`](fex/README.md) holds MacRunner's port as a patch series on top of an exact upstream
  commit. The port covers `MAP_JIT` executable memory, W^X write scopes, 16 KiB host pages and a
  Darwin unix library, plus MacRunner's later fixes and switches. FEX is MIT-licensed and
  copyright its authors (see License).
- **The original HyperBridge translator in C** (`src/`, `adapter/`). It decodes guest
  instructions, lifts them to its own IR, and interprets the IR or compiles it with its JIT. It
  stays here as the research engine: its measured techniques, instruments and interpreter
  oracles are being carried over to the FEX-based engine behind switches.

## Status

Experimental. The measurements below are from one machine (Apple M1 Pro, macOS 27).

FEX-based engine (28 Sep 2026): Hollow Knight (Unity/Mono, x86-64) runs gameplay from a saved
game at 113–119 FPS in seven runs, close to the 120 Hz display limit. The main menu appears
37–42 s after launch. The full `fex/` series and the FEX in MacRunner 1.0.2 gave the same results. These results need a Wine fix for its address-space scan, the
`MACRUNNER_HB_MAPSCAN_SKIP` switch; without it the menu took 168 s. On the same scene, the C
translator gives 42–47 FPS, with the menu at about 55 s.

C translator, measured facts as of 2026-09-26:

- The engine builds as a static and a dynamic library on macOS 14+ (arm64) with
  `-Werror`, and ships with its unit and regression test suite (`make test`).
- Test status of this snapshot: `make test` passes completely. The main runner
  reports 516 passed and 0 failed; that count includes two skips: one test needs
  a Wine source tree next to the engine, and one covers an opt-in feature. All 42
  x87 suites report 0 failures, and the Python suite runs 41 tests.
- Inside MacRunner, with its fast JIT mode enabled, Hollow Knight (Unity/Mono,
  x86-64) reaches the language-selection screen in 53–57 seconds (four runs).
  With the JIT direct-memory path fully enabled (the default), the language
  menu is visible in the window 150–170 s after launch in two runs; FEX in the
  same harness shows it at about 160 s. Vertex-shader matrices in those runs
  contain no NaN or Inf values (0 of 360,440 constant buffers checked).
  Loading all managed assemblies takes 6.7–7.9 s there. An earlier measurement in
  the same setup gave about 2.2 s under FEX, and a Windows 11 ARM reference
  machine takes 0.24 s.
- The C translator is not at parity with FEX and is not production-ready.

## Layout

```
fex/          FEX-based engine: patch series on upstream FEX-Emu, build script, manifest
adapter/      Wine adapter: hyperbridge64.dll and hyperbridge64.so (partly LGPL)
bench/        xbench: x64 Windows microbenchmark for comparing x86 emulators
include/      public and internal headers
src/          decoder, lifter, IR, interpreter, ARM64 code generator, JIT, runtime
tests/        unit, regression and litmus tests (make test)
tools/        Python helpers for decoding, tracing, benchmarking and reports
third_party/  SoftFloat 3e and Cephes: separately licensed, see below
```

Most code comments are in Russian. They record why a decision was made and
which measurement supports it.

## Build

Requirements: macOS 14 or later on Apple Silicon, and Xcode Command Line Tools
(clang and make).

```sh
make          # libhyperbridge.a and libhyperbridge.dylib
make test     # unit and regression tests
```

The FEX-based engine is built with `fex/build.sh <work-dir>`. It needs
[llvm-mingw](https://github.com/mstorsjo/llvm-mingw) (`LLVM_MINGW=<toolchain root>`),
CMake and Ninja. The script fetches upstream FEX at the pinned commit, applies `fex/patches`,
and builds `xtajit64.dll` (ARM64EC), `xtajit.dll` (WOW64) and the two unix libraries. See
[fex/README.md](fex/README.md).

The Wine-side adapter, which connects the engine to Wine's emulator interface,
is in [adapter/](adapter/README.md). It builds against a Wine 11 ARM64EC tree
with MacRunner's ntdll changes, which is not part of this repository.

## License

The original HyperBridge code is released under the [MIT License](LICENSE),
Copyright (c) 2026 Timur Ravilov.

Third-party components keep their own licenses and notices:

| Component | Location | License |
| --- | --- | --- |
| FEX-Emu modifications (MacRunner's macOS port and fixes, as patches against upstream FEX) | `fex/patches/` | MIT. FEX-Emu is Copyright (c) 2019 Ryan Houdek and FEX contributors; the modifications are Copyright (c) 2026 the MacRunner contributors. FEX itself is fetched from upstream by `fex/build.sh`. |
| SoftFloat 3e (explicit-state variant, from the FEX-Emu source tree) | `third_party/softfloat/` | BSD 3-Clause, The Regents of the University of California. See [its notices](third_party/softfloat/THIRD-PARTY-NOTICES.md). |
| Cephes mathematical library (binary128 routines) | `third_party/cephes/` | BSD. See [its LICENSE](third_party/cephes/LICENSE). |
| Wine-derived adapter files: `adapter/src/cpu.c`, `adapter/src/hb_wine_unwind.h`, `adapter/src/wine/macrunner_hb_x64_packet.h` | `adapter/` | LGPL 2.1 or later, Alexandre Julliard. See [adapter/README.md](adapter/README.md) and [adapter/COPYING.LIB](adapter/COPYING.LIB). |

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for details. The MIT
license does not relicense these components.

`fex/patches/` modifies FEX-Emu source files, so it contains FEX code as diff context. FEX-Emu
does not accept AI-generated contributions, and these patches were developed with AI assistance
for MacRunner. They are downstream changes, not submitted to FEX-Emu, and FEX-Emu has not
reviewed or endorsed them.

In the C translator, some comments describe techniques used by QEMU, box64 and FEX-Emu, and
credit them by name. It implements those ideas itself. Apart from `third_party/` and
`fex/patches/`, this repository contains no code copied from those projects. The only code
taken from Wine is the three adapter files listed above.

Windows is a trademark of Microsoft. Apple and Apple Silicon are trademarks of
Apple Inc. HyperBridge is not affiliated with or endorsed by either company.
