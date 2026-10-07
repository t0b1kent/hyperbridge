# Windows API stand: what real Windows returns for a few ordinary API corner cases

A small C probe for native Windows x86-64. It only uses documented, ordinary calls on its own process and on one child
it starts itself:

- `NtQueryInformationProcess` on the current process for several information classes and buffer lengths from 0 to 4096:
  the status, the returned length and which bytes of an initialised buffer were changed;
- a reserved (`SEC_RESERVE`) data section mapped as two views in the parent and one view in a child created before any
  page is committed: what each view reports through `VirtualQuery` after pages are committed with different protections,
  and whether a value written through one view is seen through the others.

`run-windows.ps1` compiles `probe.c` with MSVC (`cl.exe` must be on the path: an x64 developer shell), runs it with a
60-second limit and stores the raw output untouched: `raw.jsonl`, `raw.stderr.txt`, `run.json`, `compiler.txt`.
Nothing is installed and no system setting is changed.

```
.\run-windows.ps1 -OutputDirectory .\results
```

The workflow `stand-windows-api` runs it on GitHub-hosted Windows Server 2022 and 2025 machines; the raw files are kept
as run artifacts. The answers are the reference a Windows-compatibility layer has to match. MIT, see `LICENSE`.
