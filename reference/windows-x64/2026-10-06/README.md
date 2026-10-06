# Windows x86-64 reference: exception delivery

Raw outputs of the probes in [`stands/exceptions`](../../../stands/exceptions) from GitHub-hosted Windows x64 machines,
workflow run of October 6, 2026 (commit `d080968`). A real x86-64 processor and the real Windows kernel deliver every
exception here; this is the reference a translator is compared against.

| Archive | Processor | Files | Bytes | SHA-256 |
| --- | --- | ---: | ---: | --- |
| `windows-server-2022-intel-xeon-6973p-c.tar.gz` | Intel(R) Xeon(R) 6973P-C | 403 | 679140 | `8cf597121b2cf854e1ccc435622272101c1cfe64e589ed0e365a92a40899f79f` |
| `windows-server-2025-amd-epyc-9v74.tar.gz` | AMD EPYC 9V74 80-Core Processor | 403 | 682980 | `cbb19be3ede387298493b94782de9ba7d3c51aff3348c7fc03dcec8c27b9bbf3` |

Each archive holds `machine.txt` (processor, Windows build), `binaries-sha256.txt` (the probe binaries built in that run) and
one text file per cell under `v1/`, `v3/`, `v4/` with `outcomes.txt` listing every exit code. The probe binaries themselves
are not stored; rebuild them with the workflow.

Two facts read directly from these outputs, identical on both processors:

- `int 2d` raises `0x80000003` with one parameter; `ExceptionAddress` is the instruction address + 3 while the context
  `Rip` is the instruction address + 2, and the byte after the instruction is executed on resume.
- The handler receives `ContextFlags = 0x0010005f`.

A full cell-by-cell table against Windows on Arm emulation and HyperBridge will be added next to these archives.
