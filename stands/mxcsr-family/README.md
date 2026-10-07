# MXCSR family stand: which exception flags real x86 processors set on SSE compares and tiny results

A native x86-64 probe with twelve synthetic IEEE-754 cases (no captured program data):

- `UCOMISD`, `COMISD`, `UCOMISS`, `COMISS` with subnormal, zero, quiet-NaN and signalling-NaN operands;
- `MULSS` producing a tiny inexact result followed by `ADDSS` with zero;
- `ADDSS` and `SUBSS` with an inexact result.

Each case starts from `MXCSR = 0x1f80`, runs one instruction (or the two-instruction pair) and records the resulting
`MXCSR`, the arithmetic result and `RFLAGS`. The probe prints one JSON line per case and the CPUID vendor string.
The question it answers: does the denormal-operand flag (`DE`, bit 1) appear on compares with a subnormal operand,
and do the precision/underflow flags follow IEEE-754 on every vendor.

## Run

```
clang -O2 -Wall -Wextra -Werror -msse2 -mno-red-zone probe.c -o probe-bin && ./probe-bin
```

The workflow `stand-mxcsr-family` runs it on an Intel machine (`macos-15-intel`) and on Linux runners.
MIT, see the header of `probe.c`.
