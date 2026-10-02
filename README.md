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

## How HyperBridge compares

The same programs on one Mac (Apple M1 Pro, macOS 27), 29 September 2026: HyperBridge engine 0015 under
MacRunner's Wine, **Microsoft Prism** (Windows 11 on Arm in a Parallels Desktop virtual machine), the **FEX build
in CrossOver Preview**, and the **native macOS build** of a game. Loop times are nanoseconds per iteration, the
median of three alternating runs of [`xbench`](bench/xbench/); lower is better, the best value is in bold.

| | HyperBridge 0015 | Microsoft Prism | CrossOver Preview (FEX) | Native macOS |
| --- | ---: | ---: | ---: | ---: |
| `rep movsb`, 4 KB copy | **61** | 1 689 | 868 | — |
| x87 `fadd` | 16.3 | **1.00** | 114 | — |
| `cvttss2si` / `cvttsd2si` (float → integer) | **0.66 / 0.69** | 1.07 / 1.08 | 0.74 / 0.74 | — |
| `addsubps` | **0.97** | 2.40 | 0.99 | — |
| 10 other integer and SSE loops | same as CrossOver | 3–41 % slower | same as HyperBridge | — |
| `div r32` / `idiv r64` | 1.01 / 0.97 | 1.06 / 1.97 | **0.89 / 0.73** | — |
| `call`+`ret` / indirect `call` | 1.99 / 2.34 | **1.52 / 1.58** | 1.98 / 2.29 | — |
| SSE results matching x86 hardware (of 74) | 12 ¹ | **38** | 16 | — |
| SSE4.2, AES, PCLMULQDQ reported in `CPUID` | no ² | yes | yes | — |
| Hardware x86 memory ordering (TSO) | no ³ | not examined | yes | not needed |
| Hollow Knight start-up: Unity's own `Loaded All Assemblies` time | 2.22 s | 0.26 s | 0.41 s | **0.17 s** |
| Hollow Knight in King's Pass: FPS · CPU time per frame | 113–117 · 14.9–15.0 ms | not comparable (virtual GPU) | 113–119 · 15.4–16.1 ms | **120 · 6.4–6.8 ms** |

¹ Measured on the engine of MacRunner 1.0.2. The table is the September 29 snapshot, primarily engine 0015.
² Fixed since MacRunner 1.0.5 (September 30): `FEX_HOSTFEATURES=enablecrypto` exposes SSE4.2, AES,
PCLMULQDQ and SHA; the old table records the earlier build. ³ As of October 2, our Developer ID
provisioning profile carries Apple's cross-architecture-support entitlement, and a native probe succeeds. Hardware TSO
integration is in progress; speed has not been measured. The table used software ordering.

**Where HyperBridge is ahead.** `rep movsb` copies 14 times faster than in CrossOver's FEX and 28 times faster
than in Prism. x87 arithmetic runs 7 times faster than in CrossOver's FEX. Float → integer conversions are
7–11 % faster than in CrossOver's FEX. On the 13 simple integer and SSE loops, HyperBridge is as fast as
CrossOver's FEX or faster, and faster than Prism on all 13, by 3 % up to 2.5 times. In Hollow Knight's gameplay
it spends slightly less CPU time per frame than CrossOver's FEX.

**Where it is behind.** Hollow Knight starts much slower: Unity's assembly loading takes 2.2 s against 0.41 s
under CrossOver's FEX, and about four fifths of that gap is FEX's software memory ordering, which CrossOver can
replace with Apple's hardware mode (HyperBridge had no enabled hardware path in that measured build). In gameplay, HyperBridge
needs 2.2 times the native CPU time per frame and has more frame-time spikes. Prism needs 31–48 % less time per
call and return and 16 times less per x87 `fadd`, and matches x86 floating-point results more often.
CrossOver's FEX divides faster (engine 0019 closes most of the gap for `cqo; idiv` behind a switch) and reports
the Arm cryptography instructions to programs. These comparisons describe the September 29 builds;
they do not measure MacRunner 1.0.6 or the hardware-TSO work.

[Full results, conditions and limits →](COMPARISON.md)

## Status

Experimental. The measurements below are from one machine (Apple M1 Pro, macOS 27).

**Updated October 2, 2026.** The ordinary MacRunner development preview is **1.0.6**, released October 1,
with the FEX recipe 0001–0026. Since 1.0.3: 1.0.4 fixes Wine's server shared-memory mapping;
1.0.5 exposes crypto CPU features and fixes L3 reporting and unaligned shared-section loading;
1.0.6 enables x18 ABI trust, corrected DIV/IDIV exceptions and pre-exception EFLAGS restoration,
and adds an OpenGL profile for Hedon. The packaged x64 division probe matches all 88 Windows-on-ARM
reference cases. Floating-point and alias/W^X failures remain; this is not full x86 equivalence.

The Apple Developer account was approved on October 1. Our Wine loader is Developer ID-signed,
and Apple accepted a trial notarization on October 2. These changes are being prepared for the next
release; **released 1.0.6 remains signed ad hoc and not notarized**. Heroes III reached its main menu
on the signed loader on October 1, with a rare post-menu crash still open: **unreleased 32-bit
development**, not a compatibility claim for 1.0.6. Hardware TSO entitlement probes pass; integration
continues, without a speed claim.

A separate **1.0.6-indiana** experimental preview, released October 1, adds the GOG version of
Indiana Jones and the Great Circle through MoltenVK. Its notes report about 10–12 FPS at minimum
settings on M1 Pro, rendering issues and a GPU hang/session restart when firing a weapon.
**Ray tracing is experimental, not released.** [Release details and dated game checks →](https://github.com/t0b1kent/macrunner-app/blob/main/RELEASE_STATUS.md)

## How we test

As of October 2, three stands check bounded recorded inputs without starting games:

- **CPU, stages 4–6 (October 1–2):** 540,861 states from five titles. Stage 4 checked 499,487,
  found nine differing pairs and detected all six code-generation mutations. Stage 5 checked
  500,595 with six known engine mismatches and zero new ones after correcting two VEX reference
  gaps. Stage 6 adds independent MXCSR status rules, checked against 7,168 hardware-reference
  pairs / 14,336 executions with zero errors. The accepted-engine run has 651 known states
  (650 in the missing-status-flags class), zero new ones and matching full-repeat results.
  Block coverage is 59.9–96.9% by title, not full execution coverage. No EC/native ABI,
  SMC/aliases, cache lifetime, x87, unmasked #XM, flag writes to memory or FPS validation;
  19 reference gaps and 602 mapping failures remain. Recorded upper YMM halves are all zero.
- **32-bit, stage 1 (October 1):** 616 states from four titles, replayed at zero and a shifted
  8 TiB base; 296/296 PE probes equal at each base. Unicorn32 plus independent integer x87
  rules check 80-bit state and memory. Five mutations and six guards detected; the stand found
  pop-tag (22), sticky-invalid (4) and saved-tag (32) cases. Empty-slot bytes remain disputed.
  Coverage is small (105–194 blocks per title); this is not Wine startup, ABI, GPU or gameplay
  validation. The first-stage gate returns failure for known defects; a wall-clock timeout is retained.
- **Graphics (October 2):** native DXMT trace replay without Wine, 300 Hollow Knight / 191 Divinity /
  248 ABZU frames, three repeats per series. Two full series after the macOS 27.0.1 update gave
  4,434 exact comparisons against 27.0 truth; ten identity and six negative controls behaved as
  expected. One earlier Divinity frame differed in four RGB samples by ±1 (0.00027%); six later
  repeats did not reproduce it, and the cause is open. This checks selected D3D11 frames, not
  whole-game FPS, DirectX 12, Vulkan or ray tracing.

Known defects and reference gaps remain explicit; PASS means no new unclassified difference within
the checked scope. Our MIT CPU and 32-bit stand sources are in [`stands/`](stands/) in this
repository. The graphics recorder/player changes are a DXMT modification under LGPL-2.1-or-later; their
publication in [the DXMT fork](https://github.com/t0b1kent/dxmt) is being prepared. No game data or binaries are included.
[More results and limits →](https://github.com/t0b1kent/macrunner-app/blob/main/RELEASE_STATUS.md#how-we-test)

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

The original HyperBridge code is released under the [MIT License](LICENSE).
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
