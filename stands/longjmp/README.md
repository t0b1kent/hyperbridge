<!-- SPDX-License-Identifier: MIT -->
# longjmp

An x86-64 Windows probe about the machine state after a non-local transfer: `setjmp`/`longjmp` from ucrtbase and msvcrt,
`RtlUnwindEx` with a `STATUS_LONGJUMP` record, `RtlRestoreContext` and `NtContinue`, at depths of 0, 1, 3 and 10 frames and
through several kinds of frames. 1,110 cells (IDs 950000-951109): 1,080 observation cells, 20 stress cells, 10 timing cells.
Every cell runs in a fresh child process under the probe's own watchdog; the probe prints observations and asserts no
expected values.

`run-windows.ps1` builds the single source file with a pinned llvm-mingw toolchain and, when the runner has it, with MSVC
(real `__try/__finally` frames exist only in that build), then runs `list`, the observation cells in ten ranges, `stress`
and `timing`. Each invocation has its own time limit; outputs, exit codes and build logs are kept as they are.
Timing numbers describe the hosted runner they were taken on and are not a performance claim.
