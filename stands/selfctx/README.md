<!-- SPDX-License-Identifier: MIT -->
# selfctx

A small x86-64 Windows probe about the context of the CALLING thread: what `GetThreadContext(GetCurrentThread())`, `NtGetContextThread`,
`SetThreadContext`, `NtSetContextThread` and `NtContinue` (with a context taken by `RtlCaptureContext`) do to and with the thread's own state.

An assembly stub puts the thread into a known state (callee-saved general registers, `XMM0`-`XMM15`, `ST0`-`ST2`, x87 control word `0x0c7f`,
`MXCSR` `0x9fc0`, optionally the upper halves of `YMM0`-`YMM15`), calls the API from the stub and captures the state again when control comes back.
After a Set that includes `CONTEXT_CONTROL` control resumes at a label inside the stub (the context's `Rip`/`Rsp` are patched to it).
Cells: Get with every `ContextFlags` set (control, integer, segments, floating point, debug, xstate, full, all, and pairs with debug registers),
Set with the context just obtained, Set with only `Dr0`-`Dr3`/`Dr7` changed, `EFlags` variants after a Set with control, `NtContinue`, and three load cells
(a checksum over flag-dependent arithmetic, doubles with DAZ, x87 and a backward `rep movsb`, with and without 100 000 Get/Set pairs of the own thread in between).

Each cell prints one line `CELL <id> <name> ok=0|1 ...`; `ok` encodes the contract (the state the x64 ABI keeps across a call is returned and restored exactly),
the other fields are raw values (`cfo`, segment registers, `EFlags`, debug registers, ...) for comparison between machines.
`selfctx list` prints `name<TAB>cell N`, `selfctx cell N` runs one cell, `selfctx all` runs all of them in one process.
The workflow builds the probe with a pinned toolchain on `windows-2022` and `windows-2025`, runs `list`, `all` and every cell separately and uploads the outputs.
