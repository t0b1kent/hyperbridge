# Named queries on own objects: what Windows returns (stage 1b)

A companion to `stands/named-query`. The probe calls `NtQueryInformationToken`, `NtQuerySection`, `NtQueryEvent`,
`NtQueryMutant`, `NtQuerySemaphore`, `NtQueryInformationFile` and `NtQueryVolumeInformationFile` with a fixed, named list
of information classes (`allowlist.json`) and records the returned status, the returned length or I/O status block, and how
many bytes of the buffer changed. It never prints the returned data.

Scope, on purpose narrow:

- only classes that Wine implements and exercises in its own tests; no class ranges are generated;
- only objects the probe created itself: the token of its own process opened for query, an anonymous section, an event,
  a mutex, a semaphore and a temporary file that is deleted when closed;
- query functions only; nothing is set or changed; the registry and system-wide queries are not touched;
- call shapes as in the Wine tests: length 0, size - 1, size, size + 1 and a bounded large buffer; two control class
  numbers, -1 and 0x7FFFFFFF.

Each class runs in its own child process with a 15 second limit, and the run is repeated with two different fill patterns.
The workflow builds the probe from this source with a pinned llvm-mingw on `windows-2022` and `windows-2025`, runs it as a
64-bit and a 32-bit process and keeps the JSONL output and the built programs as the job artifact. No compiled files are
stored in the repository. The probe source was prepared with AI assistance as a diagnostic; it is not Wine code.
