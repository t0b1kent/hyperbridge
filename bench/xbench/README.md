# xbench

A small x64 Windows program for comparing x86 emulators on Arm: HyperBridge under MacRunner's Wine,
Microsoft Prism, the FEX build in CrossOver, or any other environment that runs x64 Windows programs.

Each test is a tight inline-assembly loop of one instruction pattern (`add`, `imul`, float/integer
conversions, `addsubps`, `div`/`idiv`, `crc32`, `lock xadd`, direct and indirect `call`/`ret`,
`rep movsb`, x87 `fadd` and others). The result is nanoseconds per loop iteration, including the
loop's own `dec`/`jnz` (see the `empty` test). Every test runs 5 times after a calibration pass; the
median, minimum and maximum are printed. `crc32` is skipped when `CPUID` does not report SSE4.2.

## Build

With [llvm-mingw](https://github.com/mstorsjo/llvm-mingw) 20260505 (UCRT):

```sh
x86_64-w64-mingw32-clang -O2 -static -Wl,--no-insert-timestamp -o xbench.exe xbench.c
```

This reproduces the binary used for the published measurements byte for byte:
`xbench.exe` SHA-256 `cc743db65a9f249c016e37f0150e1862bf2023db139196e2d3c23c762b639cb4`.

## Run

Run `xbench.exe` in each environment with nothing else demanding on the machine, and alternate the
environments (A B C C B A A B C) instead of running all repetitions of one environment in a row:
machine load changes results by more than many of the differences being measured.

Output lines start with `bench:`:

```
bench: begin version=1 brand="Unknown ARM CPU" sse42=0
bench: name=empty          iters=224701020    ns_median=   0.691 ns_min=   0.674 ns_max=   1.001
...
bench: end
```

Results for HyperBridge, Prism and CrossOver Preview on an Apple M1 Pro: [HyperBridge compared](../../COMPARISON.md).
