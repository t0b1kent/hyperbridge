# Named information queries: what Windows returns

A small reference stand. The probe calls `NtQueryInformationProcess`, `NtQueryObject` and four remaining
`NtQueryInformationThread` cells with a fixed, named list of information classes (`allowlist.json`) and records the
returned status, the returned length and how many bytes of the buffer changed. It never prints the returned data.

Scope, on purpose narrow:

- only classes that Wine implements and exercises in its own tests; no class ranges are generated;
- only the calling process and objects the probe created itself (an event, a temporary file, its own thread);
- query functions only; nothing is set or changed;
- call shapes as in the Wine tests: length 0, size - 1, size, size + 1 and a large buffer; a valid or NULL
  return-length pointer; a valid, NULL or reduced-access handle; two control class numbers, -1 and 0x7FFFFFFF.

Each class runs in its own child process with a 15 second limit. The run is repeated with two different fill patterns,
so a write of bytes equal to one pattern is still visible in the other.

The workflow builds the probe from this source with a pinned llvm-mingw on `windows-2022` and `windows-2025`, runs it as
a 64-bit and a 32-bit process and keeps the JSONL output and the built programs as the job artifact. No compiled files
are stored in the repository. The probe source was prepared with AI assistance as a diagnostic; it is not Wine code.
