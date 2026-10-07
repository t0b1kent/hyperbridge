# HyperBridge compared

## October 7, 2026: MacRunner 1.0.9

MacRunner 1.0.9 ships engine 0227: the 64-bit translator of 1.0.8 with 32 more patches (integer division,
read-modify-write instructions, scalar SSE arithmetic, exact unaligned `lock` operations). Wine, graphics and the 32-bit
translator are unchanged. Games were not measured for this release.

**Instruction loops, October 7, one session on the two released packages.** Same Mac (Apple M1 Pro, macOS 27); the same
`xbench.exe` (SHA-256 `cc743db6…`). Each engine is the one inside its published MacRunner package (`xtajit64.dll`
`eb13ea53…` for 1.0.8, `ed14b28a…` for 1.0.9), started with the package's own settings under its own Wine; the Wine
build is byte-identical in the two packages. One alternating series, 12:30–12:40 local time, five runs per package
(order `8 9 9 8 8 9 9 8 8 9`).

The Mac was in use during the series (load average 5–12; before each run 62–73 % of the processor was idle). As on
October 5, the table gives **the fastest of the five runs** for each package — within a run, the fastest sample `xbench`
reports — and, next to it, the median of the five per-run minima. Values are ns per iteration; the last two rows are ns
per 4 KB copy and per `fadd`. Bold marks a value more than 2 % below the other package's.

| Loop | HyperBridge 1.0.8 | runs | HyperBridge 1.0.9 | runs | change |
| --- | ---: | ---: | ---: | ---: | ---: |
| empty loop (`dec`/`jnz`) | 0.671 | 5 (median of run minima 0.675) | 0.672 | 5 (median of run minima 0.684) | +0.1 % |
| `add` | 0.672 | 5 (median of run minima 0.673) | 0.670 | 5 (median of run minima 0.681) | -0.3 % |
| `imul` | 0.961 | 5 (median of run minima 0.964) | 0.964 | 5 (median of run minima 0.979) | +0.3 % |
| `cvttss2si` | 0.653 | 5 (median of run minima 0.665) | 0.652 | 5 (median of run minima 0.662) | -0.2 % |
| `cvtss2si` | 0.743 | 5 (median of run minima 0.743) | 0.744 | 5 (median of run minima 0.761) | +0.1 % |
| `cvttsd2si` (64-bit) | 0.654 | 5 (median of run minima 0.657) | 0.656 | 5 (median of run minima 0.664) | +0.3 % |
| `cvttps2dq` | 0.674 | 5 (median of run minima 0.679) | 0.673 | 5 (median of run minima 0.691) | -0.1 % |
| `cvtdq2ps` | 0.944 | 5 (median of run minima 0.947) | 0.943 | 5 (median of run minima 0.952) | -0.1 % |
| `addsubps` | 0.943 | 5 (median of run minima 0.956) | 0.943 | 5 (median of run minima 0.959) | +0.0 % |
| `addss` (dependent chain) | 1.569 | 5 (median of run minima 1.604) | **0.942** | 5 (median of run minima 0.949) | -40.0 % |
| `mulps` | 1.257 | 5 (median of run minima 1.274) | 1.258 | 5 (median of run minima 1.287) | +0.1 % |
| `pshufb` | 0.672 | 5 (median of run minima 0.687) | 0.677 | 5 (median of run minima 0.685) | +0.7 % |
| `xor edx,edx` + `div ecx` | 2.088 | 5 (median of run minima 2.092) | **0.918** | 5 (median of run minima 0.923) | -56.0 % |
| `cqo` + `idiv rcx` | 1.959 | 5 (median of run minima 1.962) | **0.806** | 5 (median of run minima 0.815) | -58.9 % |
| `crc32` | 0.943 | 5 (median of run minima 0.945) | 0.940 | 5 (median of run minima 0.953) | -0.3 % |
| `popcnt` | 0.785 | 5 (median of run minima 0.787) | 0.781 | 5 (median of run minima 0.798) | -0.5 % |
| `lock xadd` | 7.085 | 5 (median of run minima 7.181) | 7.051 | 5 (median of run minima 7.082) | -0.5 % |
| `call` / `ret` | 1.891 | 5 (median of run minima 1.912) | 1.887 | 5 (median of run minima 1.919) | -0.2 % |
| `call r11` (indirect) | 2.211 | 5 (median of run minima 2.235) | 2.216 | 5 (median of run minima 2.240) | +0.2 % |
| `rep movsb`, 4 KB copy | 52.4 | 5 (median of run minima 52.7) | **50.8** | 5 (median of run minima 51.8) | -3.1 % |
| x87 `fadd` | 18.5 | 5 (median of run minima 18.7) | 18.4 | 5 (median of run minima 18.7) | -0.7 % |

Three loops changed. `xor edx,edx` + `div ecx` went from 2.09 to 0.92 ns and `cqo` + `idiv rcx` from
1.96 to 0.81 ns: the common cases of a division now use the processor's own division directly, and the
cases that must raise a divide error are handled on a separate cold path (`MACRUNNER_FEX_DIV_FAST=1`). A dependent chain
of `addss` went from 1.57 to 0.94 ns: in the processor's x86-compatible mode the scalar operation keeps the
upper part of the register itself, so the separate merge step is gone (`MACRUNNER_FEX_HW_SCALAR_MERGE=1`). Of the other 18
loops, 17 are within 1 % of 1.0.8; `rep movsb` came out 3.1 % faster, which is inside the run-to-run spread.

The 1.0.8 package measured here agrees with its October 5 values within 4 % (largest difference: `div`,
2.09 against 2.16 ns), so the Prism and CrossOver columns of October 5 can be read next to the 1.0.9 column:
`div r32` 0.92 ns against 1.03 in Prism and 0.88 in CrossOver's FEX; `idiv r64` 0.81 against 1.95 and 0.70;
`addss` chain 0.94 against 1.60 and 1.56. Prism and CrossOver were not re-measured on October 7.

## October 5, 2026: MacRunner 1.0.8

MacRunner 1.0.8 ships engine 0161. This note records what was measured for it. The sections below are earlier
snapshots and keep their dates.

**In games (Apple M1 Pro).** In Hollow Knight's main menu the game process used **23 % less CPU time per rendered
frame than under 1.0.7** (alternating runs; two identical runs differed by 0.9 %). The frame rate was already at the
display's 120 Hz limit, so this is headroom, not a higher FPS number. With the new start-up defaults, the time from
launch to Hollow Knight's menu went from **31.1 s to 25.4 s** (two alternating pairs; identical runs differed by 0.3 s
and 0.8 s). ABZU's went from 32.6 s to 32.1 s (one pair, no repeat). These runs used the engine code before the final
release packaging; they were not repeated on the packaged build.

**Instruction loops, October 5, one session on the released package.** Same Mac (Apple M1 Pro, macOS 27); the same
`xbench.exe` (SHA-256 `cc743db6…`) in all three environments. HyperBridge is the engine inside the published MacRunner
1.0.8 package (`xtajit64.dll` `eb13ea53…`), started with the package's own settings, under its own Wine. Prism is
Windows 11 on Arm build 26200 in Parallels Desktop. CrossOver Preview 20260821 (`xtajit64.dll` `fc0f0a37…`), arm64
bottle. Two alternating series, 11:24–11:30 and 11:38–11:58 local time, eight runs per environment (orders
`P H C C H P P H C` and `P H C C H P H C P C P H P H C`).

The Mac was busy during both series (load average 7–13; before 12 of the 15 runs of the second series less than 60 % of
the processor was idle), and some single runs were slowed by half or more. Other load can only slow a loop down, so the table
gives **the fastest of the eight runs** for each environment — within a run, the fastest sample `xbench` reports — and,
next to it, the median of the eight per-run minima as a measure of how much the runs scattered. The same rule is applied
to all three environments. As a check of the method: Prism and CrossOver did not change since the quiet session of
October 3 (below), and their fastest values here are within 4 % of that day's medians, except CrossOver's `rep movsb`
(738 against 855). Values are ns per iteration; the last two rows are ns per 4 KB copy and per `fadd`.

| Loop | Prism | runs | HyperBridge 1.0.8 | runs | CrossOver | runs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| empty loop (`dec`/`jnz`) | 0.750 | 8 (median of run minima 0.772) | 0.680 | 8 (median of run minima 0.708) | **0.679** | 8 (median of run minima 0.704) |
| `add` | 0.751 | 8 (median of run minima 0.786) | **0.672** | 8 (median of run minima 0.724) | 0.676 | 8 (median of run minima 0.724) |
| `imul` | 0.962 | 8 (median of run minima 1.006) | 0.974 | 8 (median of run minima 1.020) | **0.959** | 8 (median of run minima 1.008) |
| `cvttss2si` | 1.016 | 8 (median of run minima 1.040) | **0.654** | 8 (median of run minima 0.708) | 0.707 | 8 (median of run minima 0.757) |
| `cvtss2si` | 1.024 | 8 (median of run minima 1.066) | 0.737 | 8 (median of run minima 0.776) | **0.710** | 8 (median of run minima 0.744) |
| `cvttsd2si` (64-bit) | 1.003 | 8 (median of run minima 1.058) | **0.659** | 8 (median of run minima 0.716) | 0.707 | 8 (median of run minima 0.750) |
| `cvttps2dq` | 0.747 | 8 (median of run minima 0.766) | 0.684 | 8 (median of run minima 0.714) | **0.669** | 8 (median of run minima 0.722) |
| `cvtdq2ps` | 0.958 | 8 (median of run minima 1.011) | 0.951 | 8 (median of run minima 0.990) | **0.939** | 8 (median of run minima 1.006) |
| `addsubps` | 2.237 | 8 (median of run minima 2.328) | 0.947 | 8 (median of run minima 0.986) | **0.938** | 8 (median of run minima 1.004) |
| `addss` (dependent chain) | 1.596 | 8 (median of run minima 1.656) | 1.580 | 8 (median of run minima 1.632) | **1.563** | 8 (median of run minima 1.682) |
| `mulps` | 1.272 | 8 (median of run minima 1.329) | 1.269 | 8 (median of run minima 1.334) | **1.252** | 8 (median of run minima 1.389) |
| `pshufb` | 0.753 | 8 (median of run minima 0.774) | 0.695 | 8 (median of run minima 0.708) | **0.680** | 8 (median of run minima 0.728) |
| `xor edx,edx` + `div ecx` | 1.031 | 8 (median of run minima 1.079) | 2.164 | 8 (median of run minima 2.199) | **0.880** | 8 (median of run minima 0.917) |
| `cqo` + `idiv rcx` | 1.949 | 8 (median of run minima 2.064) | 1.959 | 8 (median of run minima 2.065) | **0.704** | 8 (median of run minima 0.752) |
| `crc32` | **0.941** | 8 (median of run minima 1.019) | 0.945 | 8 (median of run minima 1.033) | 0.948 | 8 (median of run minima 1.018) |
| `popcnt` | 1.031 | 8 (median of run minima 1.072) | **0.784** | 8 (median of run minima 0.834) | 0.786 | 8 (median of run minima 0.831) |
| `lock xadd` | **7.017** | 8 (median of run minima 7.544) | 7.061 | 8 (median of run minima 7.494) | 7.109 | 8 (median of run minima 7.518) |
| `call` / `ret` | **1.472** | 8 (median of run minima 1.547) | 1.913 | 8 (median of run minima 1.999) | 1.911 | 8 (median of run minima 2.018) |
| `call r11` (indirect) | **1.481** | 8 (median of run minima 1.598) | 2.203 | 8 (median of run minima 2.325) | 2.219 | 8 (median of run minima 2.329) |
| `rep movsb`, 4 KB copy | 1 617 | 8 (median of run minima 1 721) | **52.0** | 8 (median of run minima 54.8) | 738 | 8 (median of run minima 871) |
| x87 `fadd` | **0.950** | 8 (median of run minima 1.040) | 18.5 | 8 (median of run minima 19.1) | 113 | 8 (median of run minima 117) |

Against the October 3 table for 1.0.7 (medians of three runs in a quiet session): `cqo` + `idiv rcx` went from 3.01 to
1.96 ns (patch 0017, `MACRUNNER_FEX_DIV_PROVEN_HIGH`, is on by default in 1.0.8), x87 `fadd` from 15.9 to 18.5 ns, and
the other loops are within about 4 %, which two separate sessions cannot resolve.

**Instruction loops, October 4.** Nanoseconds per loop iteration; the last row is nanoseconds for a whole 4 KB copy.
**The columns come from different machines**, so they are reference points, not a ranking:

- **HyperBridge**: the 1.0.8 engine (build 0160; 0161 adds only a code-buffer guard and a larger temporary buffer) on our M1 Pro, median of three runs.
- **Prism**: Windows 11 on Arm (25H2, build 26200) in Parallels Desktop on the same M1 Pro; one sample of 20 million
  iterations per loop (100,000 for the copy).
- **Rosetta 2**: cloud Macs with M2 Pro, macOS 15.7 and macOS 26.6; median of five samples on each.
- **Native x86**: an AMD EPYC 9V74 in a cloud Linux virtual machine, the same loops compiled natively; two runs.

| Loop | HyperBridge 1.0.8 | Prism | Rosetta 2 (macOS 15 / 26) | Native x86 (run 1 / run 2) |
| --- | ---: | ---: | ---: | ---: |
| `div`, 32-bit | 2.09 | 1.24 | 1.12 / 1.19 | 1.73 / 1.70 |
| `idiv`, 64-bit | 1.97 | 4.28 | 1.00 / 1.11 | 1.98 / 2.01 |
| `call` + `ret` | 1.90 | 1.68 | 0.94 / 1.00 | 1.40 / 1.48 |
| indirect `call` | 2.25 | 1.78 | 1.58 / 1.81 | 1.41 / 1.47 |
| x87 `fadd`, 53-bit precision | 18.3 | 1.09 | 20.3 / 23.6 | 2.05 / 1.94 ¹ |
| `rep movsb`, 4 KB copy | 52.2 | 1828 | 1489 / 1716 | 46.0 / 42.9 |

¹ The native x87 loop ran with the default 64-bit precision control word.

What limits these numbers:

- For `div`, `call` and indirect `call`, two identical HyperBridge runs differed by 6–10 %, so small differences in
  those rows mean nothing.
- Two fixes made during the 1.0.8 cycle are visible here: `rep movsb` went from 847 ns to 52 ns, and x87 `fadd` from
  110 ns to 18 ns. x87 code is still slow in this release; a faster path is in development.
- The fast `rep movsb` path does not yet restore the exact guest state if a page fault happens in the middle of the
  copy.
- The Prism and Rosetta listings behind these timings were not traced instruction by instruction, and the native x86
  machine reports neither its real clock frequency nor cycle counts.

[Patch contents, shipped defaults and what was reproduced byte for byte](fex/README.md).

## October 3, 2026: instruction loops on MacRunner 1.0.7

Same Mac; one session, 10:13–10:18 local time; nine alternating runs in the order Prism, HyperBridge, CrossOver,
CrossOver, HyperBridge, Prism, Prism, HyperBridge, CrossOver; the same `xbench.exe` (SHA-256 `cc743db6…`) everywhere.
HyperBridge is the engine shipped in MacRunner 1.0.7 (`xtajit64.dll` `ac3735d6…`), under its own Wine. Prism is
Windows 11 on Arm build 26200 in Parallels Desktop. CrossOver Preview 20260821 (`xtajit64.dll` `fc0f0a37…`), arm64
bottle. Values are the median of three runs, in ns per iteration; the spread is (max − min) / median.

| Loop | Prism | spread | HyperBridge 1.0.7 | spread | CrossOver | spread |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| empty loop (`dec`/`jnz`) | 0.739 | 5 % | 0.693 | 5 % | **0.688** | 3 % |
| `add` | 0.737 | 7 % | 0.684 | 5 % | **0.679** | 2 % |
| `imul` | **0.959** | 12 % | 0.981 | 4 % | 0.976 | 4 % |
| `cvttss2si` | 1.023 | 22 % | **0.674** | 5 % | 0.725 | 2 % |
| `cvtss2si` | 1.031 | 24 % | 0.757 | 5 % | **0.726** | 3 % |
| `cvttsd2si` (64-bit) | 1.021 | 20 % | **0.671** | 13 % | 0.725 | 3 % |
| `cvttps2dq` | 0.750 | 7 % | **0.680** | 3 % | 0.685 | 3 % |
| `cvtdq2ps` | 0.967 | 11 % | **0.938** | 6 % | 0.961 | 3 % |
| `addsubps` | 2.260 | 6 % | **0.952** | 4 % | 0.963 | 3 % |
| `addss` (dependent chain) | 1.613 | 10 % | **1.584** | 3 % | 1.601 | 3 % |
| `mulps` | 1.293 | 10 % | **1.266** | 4 % | 1.280 | 4 % |
| `pshufb` | 0.759 | 15 % | 0.688 | 3 % | **0.686** | 2 % |
| `xor edx,edx` + `div ecx` | 1.056 | 16 % | 2.077 | 4 % | **0.878** | 1 % |
| `cqo` + `idiv rcx` | 1.882 | 7 % | 3.011 | 8 % | **0.716** | 3 % |
| `crc32` | 0.941 | 13 % | **0.939** | 9 % | 0.960 | 3 % |
| `popcnt` | 1.002 | 11 % | **0.789** | 92 % | 0.810 | 8 % |
| `lock xadd` | **7.038** | 12 % | 7.132 | 76 % | 7.255 | 9 % |
| `call` / `ret` | **1.455** | 66 % | 1.909 | 69 % | 1.929 | 8 % |
| `call r11` (indirect) | **1.478** | 24 % | 2.235 | 97 % | 2.247 | 2 % |
| `rep movsb`, 4 KB copy | 1 572 | 18 % | **51.3** | 96 % | 855 | 3 % |
| x87 `fadd` | **0.940** | 28 % | 15.94 | 22 % | 111.4 | 3 % |

The large HyperBridge spreads in five rows come from one of its three runs, disturbed by background load (one-minute load
average 2.5–6 during the session); with three runs the median is not affected. Compared with the September 29 table,
HyperBridge is unchanged within noise except for division, which is slower (`div` 2.08 against 1.01 ns, `idiv` 3.01 against
0.97 ns); the prime suspect is the exact overflow check added in 1.0.6, and this is being investigated.

| Environment | What it is | Version measured |
| --- | --- | --- |
| **HyperBridge** | FEX-Emu with MacRunner's patch series ([`fex/`](fex/README.md)), under MacRunner's Wine | [engine 0015](https://github.com/t0b1kent/hyperbridge/releases/tag/engine-0015) (`xtajit64.dll` `c5f82c55…`), the engine of MacRunner 1.0.3. The floating-point checks used the engine of MacRunner 1.0.2 (`f718484b…`), as marked. |
| **Prism** | Microsoft's x86/x64 emulator in Windows 11 on Arm | Windows 11 on Arm, build 26200, in a Parallels Desktop virtual machine on the same Mac (4 virtual CPUs) |
| **CrossOver Preview** | CodeWeavers' Wine for Arm with its own FEX build | CrossOver Preview 20260821 (`xtajit64.dll` `fc0f0a37…`), arm64 bottle |
| **Native** | The game's own macOS build for Apple Silicon; no translation | Hollow Knight 1.5.12620 for macOS (arm64) |

## At a glance

Times are nanoseconds per loop iteration; lower is better. The best value in each row is in bold.

| | Prism | HyperBridge | CrossOver Preview | Native |
| --- | --- | --- | --- | --- |
| **13 simple integer and SSE loops** | Slowest: 3 % to 2.5× longer than HyperBridge | Equal to CrossOver on 11 loops (within 4 %); **7–11 % faster** on 2 float → integer conversions | Equal to HyperBridge on 11 loops | — |
| **Division** `div r32` / `idiv r64` | 1.06 / 1.97 | 1.01 / 0.97 | **0.89 / 0.73** | — |
| **Calls** `call`+`ret` / indirect `call` | **1.52 / 1.58** | 1.99 / 2.34 | 1.98 / 2.29 | — |
| **x87** `fadd` | **1.00** | 16.3 | 114 | — |
| **`rep movsb`**, 4 KB copy | 1 689 | **61** | 868 | — |
| **SSE cases matching x86 hardware** (of 74) | **38** | 12 (1.0.2 engine) | 16 | — |
| **Division exceptions** | Divide by zero and quotient overflow, Windows codes | Divide by zero; overflow behind an off-by-default switch | None | — |
| **SSE4.2, AES, PCLMULQDQ in `CPUID`** | Yes | No ² | Yes | — |
| **Hardware x86 memory ordering** | Not examined | No: ordering in software ³ | Yes | Not needed |
| **Hollow Knight start-up**: Unity's `Loaded All Assemblies` | 0.26 s | 2.22 s | 0.41 s | **0.17 s** |
| **Hollow Knight in King's Pass**: FPS · CPU time per frame | Not comparable (virtual GPU) | 113–117 FPS · 14.9–15.0 ms | 113–119 FPS · 15.4–16.1 ms | **120 FPS · 6.4–6.8 ms** |

² Historical result. Fixed since 1.0.5 (September 30) with `FEX_HOSTFEATURES=enablecrypto`;
SSE4.2, AES, PCLMULQDQ and SHA are advertised and execute. ³ Historical software-ordering build.
As of October 2, our Developer ID provisioning profile carries Apple's cross-architecture-support entitlement, and a native probe succeeds. Integration continues,
without a speed result. Neither footnote changes the measurements in this table.

## Hollow Knight

Hollow Knight 1.5.12620 (GOG): the Windows x86-64 build under HyperBridge 0015, Prism and CrossOver Preview's FEX, and the native macOS build of the same version (arm64). All builds use Unity 6000.0.61f1. The game settings are the same everywhere: 1280×720 window, V-Sync on, English.

### Start-up, timed by the game itself

Each environment started the game three times and ran to the main menu. The runs alternated: Prism, native, HyperBridge, CrossOver, then the reverse order, then the first order again. The upper rows are durations that Unity measures itself and prints to its log. The lower rows are times from launch to lines of that log, polled every 0.25 s. Each cell is the median of three runs, with the range in brackets.

| Unity reports | Prism | Native macOS | HyperBridge 0015 | CrossOver Preview (FEX) |
| --- | ---: | ---: | ---: | ---: |
| `Loaded All Assemblies` | 0.26 s [0.25–0.29] | **0.17 s** [0.16–0.19] | 2.22 s [2.16–2.39] | 0.41 s [0.41–0.49] |
| `Finished resetting the current domain` | 6 ms | **3 ms** | 175 ms | 6 ms |
| First `UnloadTime` | 1.2 ms | **0.33 ms** | 22.5 ms | 4.0 ms |
| First garbage collection (`Total`) | 3.3 ms | **1.2 ms** | 31.3 ms | 10.3 ms |
| **Time from launch to** | | | | |
| Mono start (`Mono path`) | **0.4 s** | 0.8 s | 4.1 s | 4.1 s |
| `Discovered supported languages` | 2.5 s | **1.6 s** | 16.3 s | 7.4 s |
| Main menu ¹ | 21.9 s | **15.8 s** | 43.0 s | 23.8 s |

¹ The main menu appears only after the game's GOG Galaxy sign-in has failed (there is no Galaxy service in these setups), so this time includes that wait.

Wine starts just as fast under HyperBridge as under CrossOver: Mono starts after 4.1 s in both. After that, HyperBridge takes 5.4 times as long as CrossOver's FEX to load the game's assemblies, and 3 to 6 times as long for the first garbage collections, although both engines are FEX-based and equal on simple instruction loops. A diagnostic run with FEX's software memory ordering switched off (`FEX_TSOENABLED=0`; not usable for playing, because x86 memory ordering is then not kept) brought `Loaded All Assemblies` from 2.24–2.30 s down to 0.77–0.82 s (two runs each, alternating), the domain reset from 0.17–0.19 s to 0.01–0.02 s and the main menu from 42 s to 29–31 s; the first garbage collection did not change. So the software ordering accounts for about four fifths of the assembly-loading gap to CrossOver (1.47 of 1.86 s) and about two thirds of the gap to the main menu; CrossOver's FEX can use Apple's hardware ordering (see Memory ordering below). The rest, and the slower garbage collection, are not yet explained.

### In King's Pass

The game loads the same save and stands in King's Pass; each environment ran twice, alternating: CrossOver, HyperBridge, HyperBridge without software ordering, native, native, HyperBridge without software ordering, HyperBridge, CrossOver. Frames come from the Metal HUD log, CPU time of the game process from `ps`, measured over about 70–120 s of gameplay. Prism is not listed: in a virtual machine its graphics are virtualized, so the numbers would not be comparable.

| Measurement (two runs) | Native macOS | HyperBridge 0015 | HyperBridge without software ordering ¹ | CrossOver Preview (FEX) |
| --- | ---: | ---: | ---: | ---: |
| Frame rate (limit 120) | **119.9 · 119.9 FPS** | 116.8 · 112.7 FPS | 118.5 · 118.9 FPS | 119.3 · 113.4 FPS |
| 99th percentile frame time | **8.3 · 8.3 ms** | 16.7 · 16.7 ms | 8.3 · 8.3 ms | 8.3 · 33.3 ms |
| CPU time of the game process per frame | **6.4 · 6.8 ms** | 14.9 · 15.0 ms | 11.2 · 11.0 ms | 16.1 · 15.4 ms |
| CPU time of `wineserver` per frame | — | 0.2 · 0.2 ms | 0.2 · 0.2 ms | 0.4 · 0.4 ms |
| GPU time per frame (median) | 2.2 · 2.2 ms | 3.5 · 3.5 ms | 3.5 · 3.5 ms | 6.0 · 2.0 ms |
| Resident memory (median) | **1 045 · 1 046 MiB** | 1 441 · 1 988 MiB | 1 549 · 1 710 MiB | 1 149 · 1 255 MiB |

¹ Diagnostic only: `FEX_TSOENABLED=0` drops x86 memory ordering, which programs rely on.

In gameplay HyperBridge spends slightly less CPU time per frame than CrossOver's FEX (14.9–15.0 against 15.4–16.1 ms) and 2.2 times as much as the native build. Without software ordering the same scene needs 11.0–11.2 ms, about a quarter less. That diagnostic drops required ordering and is not a hardware-TSO measurement; no hardware-mode speed result is established. The native build entered the game before the automatic key presses both times, so its start times are not comparable; its gameplay measurement is. Earlier single runs on the same engine gave 110 FPS (14.7 ms per frame) and, on the exact MacRunner 1.0.3 bundle under extra load, 107 FPS (15.4 ms).

## Instruction loops

One x64 Windows program, [`xbench`](bench/xbench/) (`xbench.exe` SHA-256 `cc743db6…`), runs 21 loops, each repeating one instruction pattern. It reports nanoseconds per iteration, including the loop's own `dec`/`jnz` (the "empty loop" row), as the median of 5 timings. Each environment ran the program three times, alternating: Prism, HyperBridge, CrossOver, CrossOver, HyperBridge, Prism, Prism, HyperBridge, CrossOver. The table gives the median of the three runs. The Mac was in normal use (load average 6 to 10), and the alternating order spreads that load over all three. Native code has no column, because the loops are x86 instructions.

| Loop | Prism | HyperBridge 0015 | CrossOver Preview |
| --- | ---: | ---: | ---: |
| Empty loop (`dec`/`jnz`) | 0.79 | **0.69** | 0.70 |
| `add`, dependent chain | 0.79 | **0.69** | 0.70 |
| `imul`, dependent chain | 1.03 | **0.99** | 1.00 |
| `cvttss2si` float → int32 | 1.07 | **0.66** | 0.74 |
| `cvtss2si` float → int32 | 1.08 | 0.77 | **0.74** |
| `cvttsd2si` double → int64 | 1.08 | **0.69** | 0.74 |
| `cvttps2dq`, 4 lanes | 0.78 | **0.69** | 0.70 |
| `cvtdq2ps`, 4 lanes | 1.03 | **0.97** | 0.99 |
| `addsubps`, dependent chain | 2.40 | **0.97** | 0.99 |
| `addss`, dependent chain | 1.69 | **1.61** | 1.67 |
| `mulps`, dependent chain | 1.34 | **1.31** | 1.32 |
| `pshufb`, dependent chain | 0.76 | **0.69** | 0.70 |
| `popcnt` | 1.06 | 0.82 | **0.81** |
| `lock xadd`, one thread | **7.38** | 7.50 | 7.43 |
| `xor edx,edx` + `div ecx` | 1.06 | 1.01 | **0.89** |
| `cqo` + `idiv rcx` | 1.97 | 0.97 | **0.73** |
| `crc32` | 1.00 | Not run: SSE4.2 not reported | **0.98** |
| `call` + `ret` | **1.52** | 1.99 | 1.98 |
| `call r11` (indirect) + `ret` | **1.58** | 2.34 | 2.29 |
| `rep movsb`, 4 KB copy | 1 689 | **61** | 868 |
| x87 `fadd`, dependent chain | **1.00** | 16.3 | 114 |

**How to read it.** Where HyperBridge and CrossOver differ by less than 4 %, their three runs overlap, so those loops count as equal. On `cvttss2si` and `cvttsd2si` the runs do not overlap: HyperBridge is 7–11 % faster. Prism, measured inside a virtual machine, is slower on simple loops and faster on calls, returns and x87. `lock xadd` costs the same everywhere.

**Division.** The division loops are slower in HyperBridge 0015 than in the engine of MacRunner 1.0.2. In a separate alternating series of the HyperBridge builds, the 1.0.2 engine took 0.86 ns (`div`) and 0.70 ns (`idiv`), and 0015 took 0.99 and 0.95 ns. With the division-exception switch `MACRUNNER_FEX_DIV_OVERFLOW_DE=1`, 0015 took 2.09 and 2.98 ns. The cause is HyperBridge's divide-by-zero check (patch 0011). The check splits the translated code before the division, so FEX no longer recognizes that the preceding `cqo` or `xor edx,edx` makes the upper half of the dividend predictable, and it emits a general division. Patch 0017 (engine 0019, switch `MACRUNNER_FEX_DIV_PROVEN_HIGH=1`) gives divisions directly after `cqo`, `cdq` or `xor edx,edx` the short path again: `cqo` + `idiv rcx` takes 0.78 ns instead of 0.97 (1.0.2 engine: 0.72). The `div ecx` loop is not covered, because a `mov eax` sits between `xor edx,edx` and the division.

**x87.** FEX computes x87 arithmetic in software with the full 80-bit precision. With `FEX_X87REDUCEDPRECISION=1`, which computes in 64-bit doubles and is off in MacRunner, the HyperBridge loop took 3.7 ns in a single run. The accuracy of that mode has not been checked.

## Exact x86 results

### Floating point (SSE)

A probe program runs 74 directed cases (plus 2 controls) and a sweep of 14 336 executions. The instructions are float and double to integer conversions (`CVTSS2SI`, `CVTTSS2SI`, `CVTSD2SI`, `CVTTSD2SI`, with 32- and 64-bit results) and `ADDSUBPS`/`ADDSUBPD`, in register and memory forms, under 16 MXCSR settings. Expected results were recorded on an Intel Xeon Platinum 8272CL in a KVM virtual machine; 11 of the directed cases use computed expectations. Each environment ran the probe twice with byte-identical output. The HyperBridge column is the engine of MacRunner 1.0.2 (`xtajit64.dll` `f718484b…`).

| | Prism | HyperBridge | CrossOver Preview |
| --- | ---: | ---: | ---: |
| Directed cases matching the hardware (of 74) | **38** | 12 | 16 |
| Directed cases that differ | 32 | 55 | 56 |
| Directed cases stopped by an invalid-instruction exception | 4 | 7 | 2 |
| Sweep: result value differs (of 14 336) | **848** | 3 024 | 2 832 |
| Sweep: MXCSR exception flags differ (of 14 336) | **5 544** | 7 296 | 7 296 |
| `ADDSUBPS`/`ADDSUBPD` return a NaN with a flipped sign | **0** | 2 176 | 2 048 |
| Sign of the default NaN (for example ∞ − ∞); hardware: `ffc00000` | `7fc00000` | `7fc00000` | **`ffc00000`** |

- **Exception flags.** No environment sets a flag that the hardware does not. HyperBridge and CrossOver set none of the MXCSR exception flags in the sweep. Prism sets the invalid-operation flag for conversions: 1 752 of the 7 296 executions in which the hardware sets a flag.
- **Denormals.** In 48 conversions with denormal inputs, all three differ from the hardware. Prism and HyperBridge ignore DAZ and apply FTZ to the input; CrossOver ignores DAZ.
- **Invalid-instruction exceptions** come from instructions that the environment does not report in `CPUID`: SHA and AVX-VNNI in Prism; CRC32, PCLMULQDQ, AES, SHA and AVX-VNNI in HyperBridge; AVX-VNNI in CrossOver. Programs that check `CPUID` do not use them.

### Division exceptions (#DE)

Probe programs divide by zero and make the quotient overflow with `DIV`/`IDIV`. They record the Windows exception and the address it points to. HyperBridge and CrossOver ran 15 register-operand cases (8, 32 and 64 bits): 3 zero divisors, 6 overflows and 6 controls. Prism ran 8- to 64-bit cases with register and memory operands, three times with identical output.

| Case | Prism | HyperBridge in MacRunner 1.0.2 | HyperBridge 0015 (MacRunner 1.0.3) | HyperBridge 0015 with `MACRUNNER_FEX_DIV_OVERFLOW_DE=1` | CrossOver Preview |
| --- | --- | --- | --- | --- | --- |
| Divisor 0 | `0xC0000094` at the `DIV` | No exception | `0xC0000094` at the `DIV` | `0xC0000094` at the `DIV` | No exception |
| Quotient too large | `0xC0000095` at the `DIV` | No exception | No exception | Exception at the `DIV`, code `0xC0000094` | No exception |

Prism gives the same codes to 64-bit programs and to 32-bit programs under WOW64. It reports a zero divisor as `0xC0000094` even when the quotient would also overflow. Where no exception is raised, the program continues with a wrong result. Real x86-64 Windows has not been measured here. HyperBridge engine 0019 (patch 0018) reports `0xC0000095` for the overflow case under the same switch: all 88 cases of Prism's probe then match Prism, including the registers at the fault. The switch was off by default in that snapshot. **October 1 update:** it is enabled in released MacRunner 1.0.6; its packaged x64 probe matches all 88 reference cases. This does not update the historical timing tables or prove 32-bit startup in 1.0.6.

### CPU features reported to programs

What a Windows x64 program sees in `CPUID`:

| Feature | Prism | HyperBridge (MacRunner 1.0.2 and 1.0.3) | CrossOver Preview |
| --- | :---: | :---: | :---: |
| SSE4.2 (includes `CRC32`) | Yes | **No** | Yes |
| AES | Yes | **No** | Yes |
| PCLMULQDQ | Yes | **No** | Yes |
| SHA | No | No | Yes |
| AVX, AVX2, FMA, F16C, BMI1, BMI2 | Yes | Yes | Yes |
| RDRAND | Yes | No | No |

HyperBridge (FEX) builds the x86 `CPUID` result from the Arm feature registers that Wine reports. In the measured 1.0.2/1.0.3 configurations, Wine omitted the Arm cryptography and CRC32 fields, hiding SSE4.2, AES, PCLMULQDQ and SHA. **September 30 update:** MacRunner 1.0.5 sets `FEX_HOSTFEATURES=enablecrypto` in its engine template. All four features are reported and execute; crypto known-answer checks pass 12 of 12. This is the released fix, retained in 1.0.6. The table above records the earlier builds.

## Memory ordering

x86 programs rely on a stronger memory ordering (TSO) than Arm processors guarantee. Apple Silicon has a hardware mode that gives x86 ordering. On macOS, this requires the cross-architecture-support entitlement and a valid provisioning profile.

- **CrossOver Preview** has it. Its Wine loader (`wine.app`, signed with CodeWeavers' Developer ID) carries the `com.apple.developer.cross-architecture-support` entitlement and an embedded provisioning profile. Its FEX libraries (`libarm64ecfex.so`, `libwow64fex.so`) call `thread_set_x86_64_compat` from a handler named `SetHardwareTSOControl`.
- **HyperBridge in the measured MacRunner build** orders memory in software, using FEX's TSO emulation (ordered loads and stores). In a process without the entitlement, `thread_set_x86_64_compat` fails on this Mac with `KERN_FAILURE`. **October 2 update:** the developer account was approved on October 1. Our Developer ID provisioning profile carries Apple's cross-architecture-support entitlement, and a native probe succeeds. Our Wine loader is Developer ID-signed; Apple accepted a trial notarization on October 2. Hardware-TSO integration into the engine continues. Released 1.0.6 remains signed ad hoc, and these preparation results do not change its distribution status or the measured engine here.
- The loops above barely touch memory, so they do not show this difference. How much of HyperBridge's CPU time in games the hardware mode would remove has not been measured.

## What this points to in HyperBridge

1. **CPU time per frame in games.** In Hollow Knight it is 2.2 times that of the native build. This is the main performance target.
2. **Hardware memory ordering**: the entitlement probe now passes; complete engine integration and measurement remain open (October 2).
3. **x87 arithmetic**: 16 times Prism's time per `fadd`.
4. **Calls and returns**: 30–50 % more time per call than Prism, the same as CrossOver.
5. **Division**: the historical engine 0019 work remains recorded above. The exception correction is enabled in 1.0.6; no new division timing is claimed.
6. **`CPUID`**: fixed since 1.0.5 through the translator's `enablecrypto` option.
7. **Floating-point exactness**: the sign of NaN in `ADDSUBPS`/`ADDSUBPD`, and the MXCSR exception flags.

Microbenchmarks measure single instruction patterns, not whole programs, and one Mac is not every Mac. The numbers on this page describe the builds and conditions listed above.

[HyperBridge](README.md) · [FEX-based engine](fex/README.md) · [xbench](bench/xbench/) · [MacRunner](https://github.com/t0b1kent/macrunner-app)
