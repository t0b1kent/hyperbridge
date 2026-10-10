<!-- SPDX-License-Identifier: MIT -->
# machine-state

A single-file Windows x64 probe of machine-state instructions and exact traps: CPUID over a bounded leaf/subleaf window, XGETBV and instruction-set feature bytes,
segment/descriptor-table reads, LAR/LSL/VERR/VERW, flag instructions, software interrupts, privileged-instruction traps, prefix orders, memory faults, single-stepping and
`GetThreadContext`/`RtlCaptureContext` snapshots. Each trap-class cell runs in a fresh copy of the same executable (one cell per child process, 10 s limit); everything is
generated in the probe's own memory and handled by its own vectored exception handler. Dangerous writes (model-specific registers, control registers, I/O ports, table loads)
are listed but never executed.

`windows_probe.exe list` prints the cell table with a checksum; `cell N`, `range A B` and `all` run cells; `timing FILE.json` runs the separate timing section.
The workflow builds the probe with a pinned toolchain on `windows-2022` and `windows-2025`, runs the table, every class of cells and CPUID in chunks, then the timing section twice, and uploads the outputs.
The probe writes nothing outside its output directory.
