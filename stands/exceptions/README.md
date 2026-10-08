# Exception delivery probes (Windows x86-64)

Published October 6, 2026. MIT-licensed source of small programs that deliberately raise processor exceptions and print
what a Windows x86-64 program observes: the exception code and parameters, the faulting address, the register and flag
context handed to vectored and structured handlers, and the x87/SSE state before and after a handled exception.

They exist to answer one question for an x86-to-ARM translator: *does a translated program see the same thing that it sees
on a real x86-64 processor under Windows?* The workflow in `.github/workflows/exceptions-windows.yml` builds the probes
with a pinned llvm-mingw toolchain and runs them on GitHub-hosted Windows x64 machines; the outputs are kept as workflow
artifacts and serve as the reference. The same binaries can then be run under a translator and compared field by field.

| Program | What it covers |
| --- | --- |
| `exception_context64-v1` | access violations, breakpoint, divide error, invalid opcode, privileged instructions, single step, guard page, `RaiseException`; context capture; flag bits |
| `exception_context64-v3` | 64 kinds: the above plus `int` forms, non-canonical addresses, misaligned SSE operands, debug registers set from a handler, x87 state across a handled exception, fast-fail |
| `exception_context64-v4` | the `int 2d` cells of v3 with a bounded stop, to tell apart "next byte skipped" from "next byte executed" |
| `eflags_highbits64` | which upper flag bits survive `pushfq`/`popfq` |
| `windows_process64-v5c` | 83 cells, one per process: what an ordinary (not debugged) process is told about itself — process and thread information classes, handle closing and handle flags, mitigation policies, system information, and the four clock sources |
| `thread_priority_starvation64` | five cells: a fixed amount of work on threads at normal, below-normal, lowest and idle priority while as many polling threads as there are processors spin, yield and sleep briefly; prints wall and CPU time per work thread. On Windows low-priority work still finishes; a layer that maps priorities onto strict host priorities can starve it |
| `stack-context64` | the flags and registers a handler is given for `RaiseException` and `RtlRaiseException` at sixteen caller stack depths (every aligned value of the low byte of the stack pointer), through vectored and structured handlers; stored byte for byte as measured |
| `stack-returns64` | the same sixteen stack depths, three callees (`RaiseException`, `RtlRaiseException`, `CloseHandle` on an invalid handle) and both handler mechanisms: besides the handler context it prints what the caller sees after the call returns through a continuing handler — flags, RAX, RDX, XMM0–XMM5 and the last error (64 handler rows, 96 return rows) |

`windows_process64-v5c.c`, `stack-context64.*` and `stack-returns64.*` are stored byte for byte as the measured revisions (the workflow writes their SHA-256 next to the
outputs), so they carry no per-file licence header; they are MIT-licensed like everything else in this directory.

## Running it yourself

On Windows x64 with llvm-mingw (release 20260505, UCRT, x86_64) unpacked:

```powershell
.\stands\exceptions\run-windows.ps1 -Toolchain C:\path\to\llvm-mingw-20260505-ucrt-x86_64 -Out C:\path\to\output
```

Every cell runs in its own process with a time limit. `outcomes.txt` in each output directory lists the exit code of every
run; the text files next to it hold the raw program output. `machine.txt` records the processor name and the Windows build.

## Limits

- GitHub-hosted machines are virtual machines; the processor model is whatever the pool provides and is recorded per run.
  Exception delivery is done by the real Windows kernel on a real x86-64 processor, but CPUID answers and timing may be
  shaped by the hypervisor.
- A green workflow means the probes ran, not that any translator matches them. The comparison is a separate step.
- No compiled files, game data or third-party code are stored here.


## MXCSR restore and SEH unwind

`mxcsr_restore64` records fault-time and post-SEH-unwind x87 control words and
MXCSR for two input families, each repeated twice in the same process:

- `reserved`: 30 records for LDMXCSR, FXRSTOR and XRSTOR with valid and reserved
  MXCSR bits, including the AMD misaligned-SSE bit when the host supports it.
- `request-bv`: 72 records for XRSTOR with request masks 0, 1, 2, 4, 6 and 7,
  XSTATE_BV 0 or 3, and valid or reserved MXCSR values.

Every case resets x87 and MXCSR before the instruction. The faulting instruction
lives in a noinline callee covered by the caller's SEH scope. The filter records
the context and selects EXCEPTION_EXECUTE_HANDLER, so the after-state measures
SEH unwind rather than a continue-execution handler. Each record is one bounded
WriteFile; outcomes and completion counts must also be checked. The two modes
test restore request semantics and exception transport; they do not duplicate
the arithmetic comparison probes under stands/mxcsr-family.

Windows Server 2022 and 2025 execute the same source and both modes. These are
two operating system references, not two versions of the executable. Hardware
MXCSR masks may differ; raw observations are retained without forcing equality.


### Object metadata lifecycle (object_family193)

Synthetic Event/Mutex/Semaphore objects, each named and unnamed, are queried
in a fixed call sequence: creation, repeat query, inherit/protect transitions,
duplicate, both live handles, duplicate close, flag removal, close, and an
invalid-handle control. Basic information is queried before handle flags;
this order is an explicit input because Windows reference bias can change
on queries as well as lifecycle operations. All 56 bytes are retained.
Each successful process produces exactly 60 snapshots and a completion line
with failures=0. Named-object collisions fail the fixture. The Windows runner
executes the same source twice; references are requested for Windows Server
2022 and 2025. This probe does not set expected pointer counts or pool charges
from one observed event and does not duplicate the arithmetic MXCSR probes.


### Pinned Windows x64 API context (pinned209)

This reuses the existing finite process probe and adds a Windows x64 ABI
assembly caller. The caller records an 80-byte entry containing RBX, R11,
R14, R15, EFLAGS, the first argument, RSP, the return address, and XMM1.
RBX/R11/R14/R15, flags, and XMM1 are seeded before the call; input records
and all handler context bytes are retained, without assuming an expected
context from an earlier executable.

Only four cells run in this variant: 2 (invalid CloseHandle with handle
tracing), 3 (invalid NtClose with handle tracing), 7 (invalid NtClose with
strict-handle policy enabled), and 77 (direct UnhandledExceptionFilter
with a captured context). Each runs in a fresh process twice, using exactly
`cell <number>`. The output directory is `process-pinned209`; it contains
eight stdout/stderr pairs, outcomes, source and binary SHA-256, and a
qualification JSON. The runner requires rc=0, the pinned209 version, the
80-byte API.ENTRY209 record, and the matching COMPLETE line for all eight
runs. Missing evidence or timeout makes this variant fail; raw evidence
is preserved.

References are requested for Windows Server 2022 and 2025 using identical
source on both systems. They distinguish input-dependent context fields
from implementation errors, and are not a game compatibility result.
Built Windows executables from these references must not be executed in
the translator environment. No game data, injection, debugger attachment,
or external process handle is used by the requested cells.


## Native object name/security sizes (254)

`src/object_marshal254.c` queries Basic, Name and owner/group/DACL security for six synthetic Event/Mutex/Semaphore handles (named and unnamed), then Basic again. It records the namespace name, returned lengths, security control, component lengths/offsets, ACL/ACE sizes and masks. It emits no SID values, account names or process data. The purpose is to explain Basic NameInfoSize/SecurityDescriptorSize and reference consumption from actual native marshaling, without fitting constants to samples.

The Windows runner compiles locally and runs two bounded30s repetitions into `object-marshal254`. Qualification requires rc0,6 INFO/NAME/SD/AFTER records and COMPLETE snapshots6/failures0 in each repetition. Source/binary/stdout hashes and raw stderr/outcomes are retained. Source-only publication; Windows-built executables must never be executed on the Mac. This is a Windows API reference, not a game test or release gate.


## Exception continuation nonvolatile family (268)

The source-only C/assembly pair extends pinned209 with all eight guest nonvolatile register seeds and a byte-exact after snapshot. Synthetic CloseHandle and direct NtClose tracing calls run in eight modes: SEH unwind, unchanged VEH continue, R14/R15 edits, nested CloseHandle, R12/R13 edits, RSI/RDI edits, RBP edit, RBX edit. The existing exception record/context dumper is retained. Windows compiles locally and records32 bounded30s runs (two repeats of16 cells) in process-continue268, preserving stdout/stderr, outcomes and source/binary hashes. Qualification checks complete entry/after snapshots, without assuming which register edits survive a native API epilogue. Windows binaries must not be executed on the Mac. No game code or game data.

Combined315 retains both reference families and matches continuation268 build flags to the local console fixture: $probe includes -fms-extensions, -fno-vectorize and -fno-slp-vectorize. The two output directories have independent hashes, qualification and COMPLETE records.

## PF354 and NV341 reference requests

These two existing synthetic probes have unchanged C and assembly sources.
Both use ordered flags -O1 -g0 -static -fms-extensions -fno-stack-protector
-fno-vectorize -fno-slp-vectorize -Wl,--no-insert-timestamp; PF354 also links
-lntdll. The runner saves source, binary and compiler hashes, effective flags,
raw stdout/stderr, process outcomes and qualification for each family.

* pf-count-0-3-354: two separate runs, each with 128 return rows and 96 handler
  context rows. It exercises RaiseException counts 0 and 3, RtlRaiseException
  and ordinary invalid CloseHandle, VEH/SEH, at 16 stack depths. CloseHandle
  has no handler entry in this probe. Compare EFLAGS at identical callee entry
  RSP and arguments, preserving the raw fixed-input table separately.
* process-nv341: 32 separate runs: two repeats, cells 2/3 and modes 8 through
  15. The 120-byte API entry and 256-byte API return snapshots include the
  nonvolatile GPRs and XMM6 through XMM15. Modes 14/15 edit only XMM6/XMM15.

Qualification establishes collection completeness, not value correctness or
engine acceptance. Compare these outputs against local runs before selecting
a runtime change. There are no games, game data or emulator changes here.
