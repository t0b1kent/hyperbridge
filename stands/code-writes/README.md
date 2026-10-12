# A program that writes into its own code

Source-only probe. No prebuilt executable or recorded runtime data is included.

`smc_scenarios.c` builds a few machine instructions in freshly allocated memory,
runs them, changes them and runs them again. It asks one question in several
shapes: after a program has changed its own code, does the next execution see
the new bytes, and does the program see the memory protections it set itself?

| case | what it does |
|---|---|
| S1A | a function changes an operand in its caller, then returns into it. Mode 0: the caller is reached by a new thread through a direct jump that another thread executed first. Modes 1 and 2 are controls (direct call; one thread). |
| S1B | one thread spins in a loop while another thread changes an operand inside that loop |
| S2A | what `VirtualQuery` and `VirtualProtect` report for an executable and writable page after its code ran |
| S2B | read+execute, then read+write+execute, write, restore the reported old protection, run; then one write while the page is read+execute |
| S3  | one thread keeps calling a function; another repeats 2000 times: make writable, change an operand, make read+execute |
| S4  | writing into executed code with `NtWriteVirtualMemory`, `NtReadVirtualMemory` and `WriteProcessMemory` |
| S5  | one instruction writes into the page it is executed from: `adc`, `sbb`, `pop`, `rep movsb` |

Output lines that do not start with `#` contain no addresses and no timings,
so runs on different systems can be compared byte for byte. Lines starting
with `#` carry timings and are informational. `SUMMARY` lines count the runs
that behaved as the instruction set defines.

Run `run-windows.ps1` on native Windows x86-64 with a local Visual Studio and
Clang installation. It performs no downloads, builds the probe outside the
source directory, runs it once and keeps stdout, stderr, the exit code and the
SHA-256 of the source and of the executable.

The probe touches only its own process: memory it allocated itself, its own
threads and its own vectored exception handler. It was prepared with the help
of AI tools for diagnostics and is not a test-suite patch.
