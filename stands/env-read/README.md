# env-read: what a Windows x64 program can observe without asking the system

A small self-contained diagnostic program, `envread.c`. It reads only its own process, changes nothing and knows
nothing about any other program. It exists to compare three sides: a real x86-64 Windows machine, Wine on
Rosetta 2, and an x86-64 -> ARM64 translator running Wine. The goal is ordinary environment fidelity: a program
should not be able to tell a compatibility layer from Windows by looking at its own memory and registers.

This probe was written with AI assistance. It is a diagnostic tool, not a specification: treat every value it prints
as an observation of one machine, and check the field tables in the source against your own reference before
relying on a name.

## What it records

One JSON object per line: `{"c":"<cell>","v":"<normalised value>","raw":"0x..."}`. All numbers are hexadecimal.

| Cells | What is read |
|---|---|
| `entry.*` | every general register, flags, MXCSR, the x87 control and status words, segment selectors and XMM0-XMM5 exactly as they are at the process entry point |
| `peb.*`, `teb.*` | named fields of the process and thread environment blocks, then every other non-zero word (`peb.+0x...`), copied before the program calls anything |
| `ldr.*` | the three loader lists in order, flags and load counts of each module |
| `heap.*` | signature, `Flags` and `ForceFlags` of the process heap and of every heap listed in the PEB |
| `params.*` | flags and standard handles of the process parameters |
| `usd.*`, `usdraw.*` | the shared user data page at `0x7ffe0000`: raw bytes of the first 0x800 bytes, named fields, which words changed during the run |
| `ret.<call>.<pass>.*` | what is left in RAX, RCX, RDX, R8-R11, EFLAGS, XMM0-XMM5, MXCSR and the x87 state right after a call returns, plus the last-error and last-status values and the bytes written to the output buffer |
| `clk.*` | one second and several short loops seen through every clock at once: the three times of the shared page, `GetTickCount64`, `QueryPerformanceCounter`, `GetSystemTimeAsFileTime`, `RDTSC` |
| `cpuid.*`, `cpu.*` | a few CPUID leaves, segment selectors, `XGETBV`, `RDTSCP`, `RDRAND`, `LSL`/`LAR`, `SMSW`, `SIDT`, `SGDT`, `SLDT`, `STR` (an instruction that raises an exception is recorded as `exception:<code>`) |
| `api.*` | five ordinary API answers kept next to the raw reads for cross-checking |

### Registers after a call

The calls are made through one assembly routine. Before the call every volatile register that carries no argument
is filled with a pattern, XMM0-XMM5 are filled with patterns, MXCSR is set to `0x1f80`, and the status flags are
either all clear (passes `A` and `C`) or all set (pass `B`). The first instruction after the call stores RAX; the
following ones store the rest without touching the flags. A register that still holds what it held before the
call is printed as `kept`.

Calls: `CloseHandle` and `NtClose` with a handle that does not exist, adding and removing a vectored handler,
`NtQueryInformationProcess` classes 7, 30 and 31, `GetThreadContext` of the current thread for the debug registers,
`QueryPerformanceCounter`, `GetTickCount`, `VirtualQuery`, `VirtualProtect`, `Sleep(0)`, `SwitchToThread`,
`NtQuerySystemInformation` class 5 with a small buffer, and a few more of the same kind (see `do_pass` in the source).

### Normalisation

Addresses differ between machines and between runs, so every pointer-like value is reduced to a class:
`exe:<x|w|r>`, `mod:<module>:<x|w|r>` (section kind), `stack`, `stack-below` / `stack:call-frame+<n>` (relative to
the stack pointer at the call), `heap`, `teb+<offset>`, `peb+<offset>`, `usd+<offset>`, `private`, `mapped`, `image`.
Identifiers are printed as `id:mod4=<n>`. `raw` keeps the original value.

## Reading the result

* Cells with `.noisy.` in the name are raw times and counters. They are expected to differ everywhere.
* The parity and adjust flags in `EFLAGS` after a call depend on addresses. Compare `eflags` without bits 2 and 4.
* A value that looks stable in three runs of one binary can still depend on the layout of the image; a second build
  of the same source is the cheapest way to see that.
* `params.Length`, `params.MaximumLength` and the standard handles describe how the program was started.
* Hosted CI machines are virtual: the hypervisor bit and name in `cpuid.*` describe those machines, not Windows.

## Running

```powershell
.\run-windows.ps1 -OutputDirectory C:\some\new\directory
```

The script builds with the installed Visual Studio clang-cl and lld-link, runs the program three times with a time
limit and keeps every stdout, a small identity record and `result.json`. It downloads nothing.

The program uses no C runtime and includes no headers, so the same source also builds with llvm-mingw:

```sh
x86_64-w64-mingw32-clang -O1 -ffreestanding -fno-builtin -fno-stack-protector -mno-stack-arg-probe \
  -nostdlib -Wl,-e,envread_entry -Wl,--subsystem,console -o envread.exe envread.c -lkernel32
```
