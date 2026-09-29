# HyperBridge compared

**HyperBridge, Microsoft Prism, the FEX build in CrossOver Preview, and native macOS code, measured on one Mac.**

This page compares HyperBridge, the x86 → ARM64 engine of [MacRunner](https://github.com/t0b1kent/macrunner-app), with two other ways to run x86 Windows code on Arm and with a game's native macOS build. The same programs were used everywhere. For each result the page records what was measured and where the result stops applying.

**Test Mac:** MacBook Pro, Apple M1 Pro (8-core CPU), 32 GB, macOS 27.0 (26A428). **Date:** September 29, 2026.

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
| **SSE4.2, AES, PCLMULQDQ in `CPUID`** | Yes | No | Yes | — |
| **Hardware x86 memory ordering** | Not examined | No: ordering in software | Yes | Not needed |
| **Hollow Knight**, gameplay in King's Pass | Not measured | 110 FPS · 14.7 ms CPU per frame | Not measured | **113 FPS · 6.7 ms CPU per frame** |

## Hollow Knight

Hollow Knight 1.5.12620 (GOG): the Windows x86-64 build under HyperBridge 0015, and the native macOS build of the same version (arm64). Both use the same Unity version, 6000.0.61f1. Settings: 1280×720 window, V-Sync on, built-in 120 Hz display. Each run starts the game and loads the same save in King's Pass. Frames come from the Metal HUD log; CPU time of the game process comes from `ps`.

| Measurement | HyperBridge 0015 | Native macOS build |
| --- | ---: | ---: |
| First frame · main menu · gameplay after launch | 23.6 s · 43.7 s · 58.4 s | **3.8 s · 16.3 s · 27.2 s** |
| Frame rate in King's Pass (limit 120) | 110 FPS | **113 FPS** |
| Median / 95th / 99th percentile frame time | 8.33 / 8.34 / 25.0 ms | 8.33 / 9.40 / 16.7 ms |
| CPU time of the game process per frame | 14.7 ms (1.62 cores) | **6.7 ms (0.76 cores)** |
| CPU time of `wineserver` per frame | 0.6 ms | — |
| GPU time per frame (median) | 3.2 ms | **2.6 ms** |
| Resident memory (median) | 1 189 MiB | **1 051 MiB** |
| Gameplay sampled | 127 s | 57 s |

There was one run per build, and the Mac was in normal use during the runs. Both builds reach the display limit most of the time. HyperBridge uses 2.2 times the CPU time per frame and takes more than twice as long to reach gameplay. A second run on the exact MacRunner 1.0.3 bundle, with the Mac under extra load, gave 107 FPS and 15.4 ms per frame. A repeated series with alternating runs is planned. Prism and CrossOver have not been measured in this scene. Prism runs inside a virtual machine with virtualized graphics, so its frame rate would not be directly comparable.

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

**Division.** The division loops are slower in HyperBridge 0015 than in the engine of MacRunner 1.0.2. In a separate alternating series of the HyperBridge builds, the 1.0.2 engine took 0.86 ns (`div`) and 0.70 ns (`idiv`), and 0015 took 0.99 and 0.95 ns. With the division-exception switch `MACRUNNER_FEX_DIV_OVERFLOW_DE=1`, 0015 took 2.09 and 2.98 ns. The cause is HyperBridge's divide-by-zero check (patch 0011). The check splits the translated code before the division, so FEX no longer recognizes that the preceding `cqo` or `xor edx,edx` makes the upper half of the dividend predictable, and it emits a general division. Patch 0017, not yet in a release, gives divisions right after `cqo`, `cdq` or `xor edx,edx` the short path again; its speed has not been measured yet.

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

Prism gives the same codes to 64-bit programs and to 32-bit programs under WOW64. It reports a zero divisor as `0xC0000094` even when the quotient would also overflow. Where no exception is raised, the program continues with a wrong result. Real x86-64 Windows has not been measured here. HyperBridge patch 0018, not yet in a release, reports `0xC0000095` for the overflow case under the same switch. The switch is off by default.

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

HyperBridge (FEX) builds the x86 `CPUID` result from the Arm feature registers that Wine reports. MacRunner's Wine on macOS does not yet report the Arm cryptography and CRC32 features. As a result, SSE4.2, AES, PCLMULQDQ and SHA stay hidden, although the M1 Pro has the matching Arm instructions. A Wine change behind `MACRUNNER_WINE_ID_REGS_CRYPTO=1` fills these features in. It was checked with the same probe: all four features are reported, and the instructions run. The change is not in the 1.0.3 bundle yet.

## Memory ordering

x86 programs rely on a stronger memory ordering (TSO) than Arm processors guarantee. Apple Silicon has a hardware mode that gives x86 ordering. macOS lets an application use it only with an entitlement granted by Apple.

- **CrossOver Preview** has it. Its Wine loader (`wine.app`, signed with CodeWeavers' Developer ID) carries the `com.apple.developer.cross-architecture-support` entitlement and an embedded provisioning profile. Its FEX libraries (`libarm64ecfex.so`, `libwow64fex.so`) call `thread_set_x86_64_compat` from a handler named `SetHardwareTSOControl`.
- **HyperBridge in MacRunner** orders memory in software, using FEX's TSO emulation (ordered loads and stores). In a process without the entitlement, `thread_set_x86_64_compat` fails on this Mac with `KERN_FAILURE`. MacRunner's Apple Developer account is pending approval.
- The loops above barely touch memory, so they do not show this difference. How much of HyperBridge's CPU time in games the hardware mode would remove has not been measured.

## What this points to in HyperBridge

1. **CPU time per frame in games.** In Hollow Knight it is 2.2 times that of the native build. This is the main performance target.
2. **Hardware memory ordering**, once MacRunner has the Apple entitlement.
3. **x87 arithmetic**: 16 times Prism's time per `fadd`.
4. **Calls and returns**: 30–50 % more time per call than Prism, the same as CrossOver.
5. **Division**: patches 0017 (speed) and 0018 (Windows' overflow code) are awaiting release.
6. **`CPUID`**: report SSE4.2, AES, PCLMULQDQ and SHA through the Wine change already tested.
7. **Floating-point exactness**: the sign of NaN in `ADDSUBPS`/`ADDSUBPD`, and the MXCSR exception flags.

Microbenchmarks measure single instruction patterns, not whole programs, and one Mac is not every Mac. The numbers on this page describe the builds and conditions listed above.

[HyperBridge](README.md) · [FEX-based engine](fex/README.md) · [xbench](bench/xbench/) · [MacRunner](https://github.com/t0b1kent/macrunner-app)
