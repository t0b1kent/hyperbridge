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

The same programs on one Mac (Apple M1 Pro, macOS 27). Loop rows: **5 October 2026**, the engine inside the published
[MacRunner 1.0.8](https://github.com/t0b1kent/macrunner-app/releases/tag/v1.0.8) package, **Microsoft Prism** (Windows 11 on Arm
in a Parallels Desktop virtual machine) and the **FEX build in CrossOver Preview**, measured in one session of alternating
runs of [`xbench`](bench/xbench/) (the same binary in all three). Loop times are nanoseconds per iteration; lower is
better, the best value is in bold (values within 2 % of the best share it). The Mac was busy with other work during the
session, so each value is the fastest of eight runs: other load can only slow a loop down. Prism and CrossOver did not
change since the quiet session of October 3, and they come out within 4 % of that day's values, except CrossOver's
`rep movsb` (738 against 855).

| | HyperBridge (MacRunner 1.0.8) | Microsoft Prism | CrossOver Preview (FEX) | Native macOS |
| --- | ---: | ---: | ---: | ---: |
| `rep movsb`, 4 KB copy | **52** | 1 617 | 738 | — |
| x87 `fadd` | 18.5 | **0.95** | 113 | — |
| `cvttss2si` / `cvttsd2si` (float → integer) | **0.65 / 0.66** | 1.02 / 1.00 | 0.71 / 0.71 | — |
| `addsubps` | **0.95** | 2.24 | **0.94** | — |
| 12 other integer and SSE loops | same as CrossOver (within 4 %) | 1 % faster to 39 % slower | same as HyperBridge | — |
| `div r32` / `idiv r64` | 2.16 / 1.96 ¹ | 1.03 / 1.95 | **0.88 / 0.70** | — |
| `call`+`ret` / indirect `call` | 1.91 / 2.20 | **1.47 / 1.48** | 1.91 / 2.22 | — |
| SSE results matching x86 hardware (of 74) | 12 ² | **38** | 16 | — |
| SSE4.2, AES, PCLMULQDQ reported in `CPUID` | yes (since 1.0.5) | yes | yes | — |
| Hardware x86 memory ordering (TSO) | yes, by default since 1.0.8 ³ | not examined | yes | not needed |
| Hollow Knight start-up: Unity's own `Loaded All Assemblies` time | 0.34–0.43 s ⁴ | 0.26 s | 0.41 s | **0.17 s** |
| Hollow Knight in King's Pass: FPS · CPU time per frame | not re-measured on 1.0.8 ⁵ | not comparable (virtual GPU) | 113–119 · 15.4–16.1 ms | **120 · 6.4–6.8 ms** |

¹ The exact overflow check (`MACRUNNER_FEX_DIV_OVERFLOW_DE=1`, on since 1.0.6) makes a division overflow raise the same
exception as on Windows. Since 1.0.8 `MACRUNNER_FEX_DIV_PROVEN_HIGH` (patch 0017, exact) is on as well: `cqo; idiv` went
from 3.01 ns in 1.0.7 to 1.96 ns. `div r32` did not change.
² Measured on the engine of MacRunner 1.0.2; not re-measured since. A switchable exact mode exists; it stays off by
default because it costs about 3 ns per SSE instruction.
³ Against 1.0.7, which ordered memory in software, Hollow Knight's main menu needs 23 % less CPU time per frame
(alternating runs, control spread 0.9 %). `MACRUNNER_FEX_HW_TSO=0` turns the hardware mode off.
⁴ October 5, two runs of the 1.0.8 engine code before the final packaging, with the start-up defaults that ship in 1.0.8
(1.23 s and 1.30 s without them; 2.22 s on September 29). Prism, CrossOver and native values are from September 29.
⁵ The September 29 measurement, on engine 0015 with software memory ordering, was 113–117 FPS and 14.9–15.0 ms.

**Where HyperBridge is ahead.** `rep movsb` copies about 14 times faster than in CrossOver's FEX and 31 times faster
than in Prism. x87 arithmetic runs 6 times faster than in CrossOver's FEX. Float → integer conversions are 7 % faster
than in CrossOver's FEX and 1.5 times faster than in Prism; `addsubps` is 2.4 times faster than in Prism. On the 12
other simple loops HyperBridge matches CrossOver's FEX within 4 % and is faster than Prism on 6 of them, by up to 39 %;
the other 6 are within 1 %.

**Where it is behind.** Prism needs 19 times less time per x87 `fadd`, 23 % less per call and return and 33 % less per
indirect call, and matches x86 floating-point results more often. `div r32` is 2.1 times faster in Prism and 2.5 times
faster in CrossOver's FEX; `idiv r64` now equals Prism but is 2.8 times faster in CrossOver's FEX (see ¹). Hollow
Knight's assembly loading is now in the range CrossOver's FEX showed on September 29 (0.41 s), still behind Prism
(0.26 s) and the native build (0.17 s).

**What changed since 1.0.7.** `idiv r64` is 35 % faster. x87 `fadd` is 16 % slower (18.5 ns against 15.9 ns); a
faster x87 path is in development. With the new start-up defaults Hollow Knight loads its assemblies in 0.34–0.43 s
against 1.23–1.30 s without them on the same engine code. The other loops are within about 4 % of the October 3 values,
which is below what two separate sessions can resolve.

[Full results, conditions and limits →](COMPARISON.md)

## Status

Experimental. The measurements below are from one machine (Apple M1 Pro, macOS 27).

**Updated October 5, 2026.** The current MacRunner development preview is
**[1.0.8](https://github.com/t0b1kent/macrunner-app/releases/tag/v1.0.8)**, with engine 0161.
The [patch series, shipped hashes and reproduction scope](fex/README.md) and the
[dated 1.0.8 measurements](COMPARISON.md#october-5-2026-macrunner-108) are recorded separately.

**October 3 snapshot:** [1.0.7](https://github.com/t0b1kent/macrunner-app/releases/tag/v1.0.7) was the first release signed
with a Developer ID and notarized by Apple. 32-bit Windows programs start (experimental): one Wine runtime and one signed
loader serve both 64-bit and 32-bit programs, and Heroes of Might and Magic III reaches its main menu (without sound, with
a shifted picture). .NET 6 games can start: Stardew Valley reaches its main menu. 16-bit `SHLD`/`SHRD` now set the carry
flag as hardware does. Floating-point and alias/W^X failures remain; this is not full x86 equivalence.

Prepared for 1.0.8 in that October 3 snapshot: **hardware x86 memory ordering (TSO)**, measured at 25–26 % less CPU time per frame in
Hollow Knight's menu and about 20 % less in ABZU, with Hollow Knight, Stardew Valley, ABZU, Divinity: Original Sin and
Heroes III reaching their menus on it; and a fix for 256-bit AVX register halves lost when translated code is restarted
after a self-modification check (it broke a .NET runtime check and a plain `memcpy`).

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

- **Synthetic CPU stand in CI (October 3):** 408 generated x86-64 cells, built from the published
  `fex/patches` on GitHub's Apple silicon runners and compared with Unicorn on every change to the patch series
  ([stands/synthetic](stands/synthetic/README.md)); two byte-identical runs and a negative control are required.

Known defects and reference gaps remain explicit; PASS means no new unclassified difference within
the checked scope. Our MIT CPU and 32-bit stand sources are in [`stands/`](stands/) in this
repository. The graphics recorder/player changes are a DXMT modification under LGPL-2.1-or-later and are
published in [the DXMT fork](https://github.com/t0b1kent/dxmt/tree/macrunner-trace-stand/docs/trace-stand) (branch `macrunner-trace-stand`). No game data or binaries are included.
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
