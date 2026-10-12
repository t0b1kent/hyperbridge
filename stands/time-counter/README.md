# time-counter: how RDTSC and the other clocks of a Windows x64 process behave

A small self-contained program, `tsc_probe.c`. It reads only its own clocks and CPUID; it knows nothing about any
other program. It exists to compare three sides: a real x86-64 Windows machine, Wine on Rosetta 2, and an
x86-64 -> ARM64 translator.

## What it prints

`CELL <name> key=value ...` lines are raw observations. `INV <name>=<value>` lines are short facts meant to be
compared between sides.

| Cell | What is measured |
|---|---|
| `cpuid` | vendor, brand string, family/model, TSC / RDTSCP / invariant-TSC bits, hypervisor bit and name, leaves 15h and 16h |
| `pairs` | two RDTSC reads with nothing between them, 2 000 000 times: how often the two values are equal, the smallest and typical step |
| `lowbits` | one read per loop iteration with a little varying work between reads: which low bits ever change, the greatest common divisor of all steps |
| `tight` | a tight loop of reads: how many distinct values, the longest run of equal values |
| `rate` | RDTSC ticks per second measured against QueryPerformanceCounter, six 100 ms windows |
| `qpc` | the same pair test for QueryPerformanceCounter |
| `clocks_ms` | one second measured by every clock at once: QPC, RDTSC, GetTickCount64, the two shared-page times, three system-time calls |
| `kusd`, `qpc_formula` | performance-counter fields of the shared user page |
| `rdtscp` | RDTSCP right after RDTSC, and the processor number it reports |
| `cputime` | one busy thread for 400 ms: thread and process CPU time against wall time |
| `threads` | four threads take turns reading RDTSC under a lock: does the value ever go backwards or repeat |

## What the numbers mean and what they do not

The frequencies, the brand string and the hypervisor name describe the machine and are expected to differ between
machines. The pair, low-bit and tight-loop cells describe the counter itself: on a hardware counter consecutive
reads are expected to differ and every low bit is expected to change; a translator that derives the counter from a
slower host timer shows equal consecutive reads and may show low bits that never change.

Hosted CI machines are virtual: the hypervisor bit is set there and the hypervisor is named. That is a property of
those machines, not of Windows.

## Running

```powershell
.\run-windows.ps1 -OutputDirectory C:\some\new\directory
```

The script builds with the installed Visual Studio clang-cl, runs the program once with a time limit and keeps
stdout, stderr and a small identity record. It downloads nothing.
