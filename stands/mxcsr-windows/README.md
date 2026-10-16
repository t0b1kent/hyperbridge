# MXCSR across Windows OS boundaries

`mxwin.c` raises a divide-by-zero in SSE, then reads MXCSR after a syscall, an API call, the CRT formatter, a structured
exception (with and without the handler editing `CONTEXT.MxCsr`), a new thread, `GetThreadContext`/`SetThreadContext` on a
suspended worker, `_statusfp`/`_clearfp`, a compiled division and an x87 division. Each output line is `<name> <hex>`.
`EXPECTED.txt` lists the architectural expectation for each line; lines marked `info` are OS- or CRT-specific and are recorded,
not judged. The workflow builds the probe with a pinned llvm-mingw as 64-bit and 32-bit (`-msse2`) and runs both on GitHub's
Windows runners. It is the Windows reference for a translator's MXCSR handling (HyperBridge `MACRUNNER_FEX_LAZY_MXCSR`).
