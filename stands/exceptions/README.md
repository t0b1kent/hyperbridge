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
