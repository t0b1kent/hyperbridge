<!-- SPDX-License-Identifier: MIT -->
# excdump

A small x86-64 Windows probe that prints, for each of about sixty cells, everything a vectored exception handler receives:
the whole `EXCEPTION_RECORD` (code, flags, address, parameter count, every `ExceptionInformation` slot) and the `CONTEXT`
(`ContextFlags`, `Rip`, `EFlags`, segment registers, `Dr0`-`Dr3`, `Dr6`, `Dr7`, `MxCsr`, x87 control/status/tag words,
`MxCsr_Mask`, `Rsp`, three general registers), the number of handler calls, and where execution went after the handler returned.

Cells cover: `int3` in different kinds of pages (image text, fresh RWX page, rewritten page, page edges), the other trap
instructions (`CD 03`, `F1`, `CD 2D`, `UD2`, `HLT`, `CLI`, port I/O, `RDMSR`, control/debug register moves), single-stepping
through `popfq` with the trap flag, guard pages, access violations (read/write/execute, unmapped, read-only, non-executable,
non-canonical), divide errors, misaligned SSE, `RaiseException`, `GetThreadContext` of a suspended thread and `RtlCaptureContext`.

All addresses are printed relative to the cell region or to the entry stack pointer, so two machines can be compared line by line.
`excdump list` prints the table, `excdump all` runs every cell in one process, `excdump cell N` runs one cell,
`excdump tsv` prints `name<TAB>arguments` for running each cell in its own process. The last line of `all` carries a checksum over the cell lines.

The workflow builds the probe with a pinned toolchain on `windows-2022` and `windows-2025`, runs `list`, `all` (twice) and every
cell separately, and uploads the outputs as an artifact. The probe writes nothing outside its output directory.
