<!-- SPDX-License-Identifier: MIT -->
# getctx

A small x86-64 Windows probe about what `GetThreadContext(GetCurrentThread())` and `NtGetContextThread` write into the caller's `CONTEXT`.
The buffer (0x4d0 bytes) and 256 guard bytes on each side are pre-filled with `0xA5`; after the call the probe prints which fields changed.
Cells 0-25: 13 `ContextFlags` sets x {Win32, Nt}. Cells 26-29: the buffer ends right before an inaccessible page (a DEBUG-only request must succeed and write only `Dr0`-`Dr7`).
Cells 30-31: a buffer filled by `RtlCaptureContext`, then a DEBUG-only request; every other field must stay unchanged.
The workflow builds the probe with a pinned toolchain on `windows-2022` and `windows-2025`, runs every cell in its own process and uploads the outputs.
