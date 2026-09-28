# fex/ — the FEX-based CPU engine of MacRunner

MacRunner runs x86-64 and x86 Windows programs on Apple Silicon through ARM64 Wine. Its CPU
engine is [FEX-Emu](https://github.com/FEX-Emu/FEX) (MIT), ported to macOS by the MacRunner
project. This directory holds that port as a patch series on top of an exact upstream commit.
Together with the translator in `src/`, it forms HyperBridge.

- Upstream: `https://github.com/FEX-Emu/FEX`, commit `fd141ed6d721d03062619e4702bca1a0c93b6dd9`
  (6 Aug 2026, right after the FEX-2608 release).
- Series: `patches/0001-…` to `patches/0013-…`, applied in order with `git am`.
- Build: `fex/build.sh <work-dir> [patch-count]` (llvm-mingw for the Windows halves, Xcode
  clang for the unix libraries). `MANIFEST.json` lists the expected output hashes.

## What the patches do

| Patch | Change | In MacRunner 1.0.2 |
|---|---|---|
| 0001 | Executable JIT memory through `MAP_JIT` on Darwin (16 KiB pages rule out `MAP_JIT|MAP_FIXED`) | yes |
| 0002 | unixlib handler 7 (`EnableJITExec`) and per-thread W^X write scopes around every JIT write | yes |
| 0003 | unixlib ABI marker `__fex_darwin_unixlib_abi` (Wine refuses a foreign companion library) | unix library only |
| 0004 | ARM64EC: load TEB Self for GS seeding (Darwin may clear x18); inline-SMC check per 16 KiB granule | yes |
| 0005 | InvalidationTracker works in 16 KiB host protection units | yes |
| 0006 | Code validation in writable pages under `mtrack`; call-ret stack cleared with `memset` on Windows | yes |
| 0007 | 16 KiB guards around the call-ret stack | yes |
| 0008 | Stale block links are not published; full parity at block entry points | no |
| 0009 | Elden Ring work: JIT statistics, `MACRUNNER_FEX_WRITABLE_VALIDATION` modes, ARM64EC TLS changes | no |
| 0010 | `MACRUNNER_FEX_PROT_KEEP`, `MACRUNNER_FEX_REVIVE`, `MACRUNNER_FEX_CODEBUF_MAX` (all default off) | no |
| 0011 | x87: division by zero raises the exception; SF in the x87 status word | no |
| 0012 | JIT map on Windows: `MACRUNNER_FEX_JITMAP_DIR` (with `FEX_BLOCKJITNAMING=1`) writes block names as `<guest module>+0x<offset>`; the flush interval works | no |
| 0013 | `GetSectionFilePath` converts the section path in a stack buffer instead of allocating from the process heap under `ThreadCreationMutex`; fixes a deadlock between DLL mapping on one thread and heap growth on another | no |

## Provenance of MacRunner 1.0.2

The FEX in MacRunner 1.0.2 was assembled from several development branches. On 28 Sep 2026
its source was reconstructed and the build was repeated:

- `xtajit64.dll` (ARM64EC) = patches 0001–0007, link timestamp 1788779472. The rebuild matched
  the unstripped release file byte for byte (`9aba4f22…`). The shipped file (`f718484b…`) is the
  same image after PE stripping.
- `xtajit.dll` (WOW64) = patches 0001–0002, link timestamp 1788779471. It also matched byte for
  byte (`deaf27be…`; shipped stripped: `52c00299…`).
- The unix libraries come from patch 0003. A rebuild with the current macOS SDK has the same
  exported symbols, the same 9 functions and the same 9 imports. It is not byte-identical because
  the release was linked with the macOS 26.5 SDK and linker.

A byte-exact rebuild needs the absolute source path and install prefix of the original build
machine, because they are embedded in the binaries. `build.sh` maps paths to a neutral prefix
instead, so its hashes differ from the release files. Its output is reproducible from run to
run.

## Rules for this series

- The code is MIT, like FEX. Each patch keeps the FEX copyright notices. MacRunner's
  modifications are also MIT.
- FEX-Emu does not accept AI-generated contributions (`CONTRIBUTING.md`: "No AI/ML/LLM/etc code
  contributions"). These patches were developed with AI assistance for MacRunner. They are
  downstream changes, and they are not submitted to FEX-Emu.
- FEX-Emu has not reviewed or endorsed this port. Please report issues with it to MacRunner,
  not to FEX-Emu.

## Profiling with the JIT map

Run the game with `FEX_BLOCKJITNAMING=1 FEX_GLOBALJITNAMING=1 MACRUNNER_FEX_JITMAP_DIR=<Windows directory>`.
Take a macOS `sample` of the game process, and capture `WINEDEBUG=+loaddll` if you also want native
PE modules named. Then run:

    python3 tools/fex_jit_attr.py <sample.txt> <jitmap dir> --loaddll <wine stderr> --dlldirs <dirs with the DLLs>

Every unnamed ("???") leaf is attributed to a JIT block of a guest module (`<module>+0x<offset>`), to
guest code outside known images (for example Mono-generated code), or to a native PE module.
Hollow Knight gameplay, main thread, 28 Sep 2026: 55 % UnityPlayer.dll, 41 % Mono-generated code,
2 % mono-2.0-bdwgc.dll, 0.5 % DXMT d3d11.dll, about 1 % Wine DLLs.
