# fex/ — HyperBridge, the FEX-based CPU engine of MacRunner

MacRunner runs x86-64 and x86 Windows programs on Apple Silicon through ARM64 Wine. Its CPU
engine is [FEX-Emu](https://github.com/FEX-Emu/FEX) (MIT), ported to macOS by the MacRunner
project. This directory holds that port as a patch series on top of an exact upstream commit.
Since 29 Sep 2026 the name HyperBridge refers to this FEX-based engine. The earlier translator in
`src/` stays in the repository; its interpreter is the reference side of the HB<->FEX oracle.

- Upstream: `https://github.com/FEX-Emu/FEX`, commit `fd141ed6d721d03062619e4702bca1a0c93b6dd9`
  (6 Aug 2026, right after the FEX-2608 release).
- Series: 55 patches in `patches/`, applied in file-name order: 0001–0049, 0055, 0056, 0065, 0075,
  0160 and 0161. MacRunner 1.0.8 ships this 64-bit chain and the separate [WOW64 chain](wow64/README.md).
  An EXPERIMENT label describes a source switch; the shipped defaults are specified below.
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
| 0014 | `MACRUNNER_FEX_DIV_OVERFLOW_DE` (default off): DIV/IDIV raise #DE also when the quotient does not fit, and the divisor is read once | no |
| 0015 | `MACRUNNER_FEX_SHLD16_CF` (default off): SHLD r/m16 with a count of 16 sets CF as x86 does (upstream `6646a5cc`) | no |
| 0016 | `MACRUNNER_FEX_NULL_HOST` (default off): a branch to guest address 0 takes the full lookup instead of jumping to host address 0, so the guest gets its own fault | no |
| 0017 | `MACRUNNER_FEX_DIV_PROVEN_HIGH` (default off): DIV/IDIV right after `xor edx,edx`, CDQ or CQO is a plain n-bit division; with 0014 the #DE test is only "divisor 0" (and INT_MIN / -1 for IDIV) | no |
| 0018 | With `MACRUNNER_FEX_DIV_OVERFLOW_DE`: Windows programs get `STATUS_INTEGER_OVERFLOW` (0xC0000095) for a quotient overflow and `STATUS_INTEGER_DIVIDE_BY_ZERO` (0xC0000094) for a zero divisor, as under Prism | no |
| 0019 | Darwin: no process-wide hardware TSO from a one-thread probe (the macOS mode is per thread and not inherited); software TSO stays until every thread is admitted | no |
| 0020–0025 | Translation reuse and invalidation experiments: REVIVE must not return stale translations, executable-range tracking, pre-exception PF/AF/DF kept across an exception, `MACRUNNER_FEX_RANGE_CACHE`, precise invalidation for Mono call targets (switches) | no |
| 0026 | `MACRUNNER_FEX_RA_NO_X16` for ARM64EC (Indiana Jones work; switch) | no |
| 0027–0031 | Code written through a second mapping (.NET): `ExecutableRangeInfo::NoTrap` and validation modes, `MACRUNNER_FEX_ALIAS_VIEWS`, `MACRUNNER_FEX_HOOK_GUARD` (switches) | no |
| 0032 | FEX diagnostic output works without Wine's buffer | no |
| 0033–0047 | Guarded x87: fast arithmetic through the host's double with a fall-back to the exact path, x87 tag/status/FIP handling, guarded subnormal loads, FST/FSTP stores and FSCALE; 0036–0037 are tests (all off by default) | no |
| 0048 | Floating-point switches default off; ARM64EC integer-width correction | no |
| 0049 | Hook and alias correctness switched on automatically when the .NET runtime (`coreclr.dll`, `clrjit.dll`) is mapped | no |
| 0055 | Darwin hardware TSO: enter the per-thread x86 compatibility mode at the Windows/host boundaries, retaining software ordering if admission fails; MacRunner 1.0.8 requests `MACRUNNER_FEX_HW_TSO=2`, `FEX_TSOENABLED=1` | no |
| 0056 | Spill the split upper AVX register halves before an inline self-modifying-code fault can restart the guest instruction from saved state; no new switch | no |
| 0065 | Restore independent MXCSR DAZ/FTZ state through Apple's compatibility AFPCR at load/restore and JIT entry/exit boundaries; distinct from Arm FEAT_AFP, requires native-thread admission; MacRunner 1.0.8 sets `MACRUNNER_FEX_APPLE_AFP=1` | no |
| 0075 | BLSR/BLSMSK: the CF zero-test uses the operand width, ignoring bits 63:32 for a 32-bit operand (upstream `635befb4`); no new switch | no |
| 0160 | After hardware-TSO admission, use single Q-register loads in the affected validation, spill/refill and copy paths; keep the software-TSO instruction path otherwise | no |
| 0161 | Size, align and protect the JIT code-buffer guard using the host page size, and reserve more initial temporary capacity on that path; MacRunner 1.0.8 sets `MACRUNNER_HB_JIT_HOST_GUARD=1` | no |

The third column above retains its historical meaning (MacRunner 1.0.2). All six new rows are shipped
in 1.0.8. Its `ENGINE.json` also sets `FEX_SMCCHECKS=mtrack`, `FEX_HOSTFEATURES=enablecrypto`,
`MACRUNNER_FEX_DIV_OVERFLOW_DE=1`, `MACRUNNER_FEX_SHLD16_CF=1`, `MACRUNNER_FEX_DIV_PROVEN_HIGH=1`,
`MACRUNNER_FEX_EFLAGS_KEEP=1`, `MACRUNNER_FEX_WRITABLE_VALIDATION=2`, `MACRUNNER_FEX_RANGE_CACHE=1`,
`MACRUNNER_FEX_CODEBUF_MAX=1`, `MACRUNNER_FEX_MONO_BP_PRECISE=1` and
`MACRUNNER_FEX_SUSPEND_BACKEDGE=1`. Hardware-TSO request/selection does not establish architectural
readback in a benchmark; see the dated limits in [COMPARISON.md](../COMPARISON.md).

## MacRunner 1.0.8: separate 32-bit chain and reproduction

The WOW64 additions are in [`wow64/patches/`](wow64/patches/), with an explicit
[`ORDER.txt`](wow64/ORDER.txt): 0070, 0071, the product port of 0052, 0050, 0053, then 0087.
They fix suspend/teardown locking, isolate the Darwin interrupt page, add cooperative backedge
continuations, and preserve the current context owner on Get/Set reentry. Apply them to a separate
tree after the common 0001–0049/0055/0056/0065/0075 base, followed by common 0160 and 0161.
They are deliberately outside `patches/`: CI applies that directory in lexical order, which is
not the WOW64 dependency order. [WOW64 instructions and verification](wow64/README.md).

On October 5 the 55-patch common series passed the same sequential `git apply --check` / `git apply`
test as CI on the pinned upstream. The separate WOW64 sequence also passed, including 0160/0161.
The local archive contained no populated submodules; no patch touches a submodule.

A clean Xcode Cloud Mac rebuilt both PE modules from the release source with our reproduction recipe (not yet published):
`xtajit64.dll` and `xtajit.dll` match the shipped 1.0.8 bytes exactly. The unix libraries match the
measured functions and material sections, but their whole-file hashes differ; this is not a
byte-exact native rebuild or a semantic proof. The cloud run was a diagnostic build: nothing was installed or
signed, and no game data was involved. Full output hashes, tools and scope are
in [`MANIFEST.json`](MANIFEST.json). The generic `build.sh` applies only `patches/`; it does not apply
the separate WOW64 chain or implement the complete release reproduction recipe. No byte-exact
1.0.8 result is promised from that script alone.

0014–0018 were checked with the HB<->FEX oracle (72 219 x86-64 cases plus 133 division idioms, FEXCore
built natively on macOS, one binary with the gates off and on): only the targeted cases change —
26 DIV/IDIV, 3 SHLD, 1 branch to address 0 — and 0017 changes no result. 0018 was checked under
MacRunner's Wine with a 64-bit probe of 88 DIV/IDIV cases (8 to 64 bits, register and memory operands):
with `MACRUNNER_FEX_DIV_OVERFLOW_DE=1` every exception code, fault flag and RAX/RDX value equals
Microsoft Prism's. Speed on this Mac (xbench, ns per iteration, three alternating runs, median): `cqo; idiv rcx` takes 0.969 ns
without gates, 0.783 ns with `MACRUNNER_FEX_DIV_PROVEN_HIGH=1` (the engine of MacRunner 1.0.2: 0.722 ns),
and 3.05 → 2.01 ns together with `MACRUNNER_FEX_DIV_OVERFLOW_DE=1`. The `div ecx` loop does not speed up
(1.01 ns): a `mov eax` sits between `xor edx,edx` and the division, and 0017 only recognizes the idiom
directly before it. Loops without division are unchanged by 0016–0019 (within 1 %).
Patches 0033 and 0035 carry a development-time label "not for publication"; they are published because the
MacRunner 1.0.7 binary contains them (off by default). For 1.0.7 the exact patched source is in the release's
source archive; binary reproduction from the series is not promised (hashes in `MANIFEST.json`).

Two clean `build.sh` builds of 0001–0019 are byte-identical (hashes in `MANIFEST.json`). The 0001–0015 build
is the engine of MacRunner 1.0.3.

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
