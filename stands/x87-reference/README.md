# x87 reference stand: what a real x86 processor returns for x87 instructions

A native Linux x86-64 probe. It executes real x87 instructions on the processor it runs on and records the exact
bits of every result: the register stack, the status word and the stored memory image.

- precision control 53 and 64 bits, all four rounding modes, all exceptions masked;
- `FADD FSUB FMUL FDIV FSQRT FPREM FPREM1 FRNDINT FSCALE FXTRACT FABS FCHS`;
- loads `FLD m32/m64/m80`, `FILD m16/m32/m64`; stores `FST/FSTP`, `FIST/FISTP`, `FISTTP`;
- `FSIN FCOS FSINCOS FPTAN FPATAN FYL2X FYL2XP1 F2XM1` with control words `027F` and `037F`;
- inputs are fixed bit patterns: neighbours of representable values, the limits of binary32/binary64/extended,
  signed zeros, infinities, quiet and signalling NaNs with payloads, unsupported encodings, stack faults.

549,696 rows per run. `run.sh` builds the probe, runs it twice, requires the two tables to be byte-identical and
writes `output/raw.csv.gz` with its SHA-256. `validate.py` re-derives the exactly representable cases with integer
arithmetic; `compare_cpu.py` compares two tables row by row.

## Why

A translator that computes x87 arithmetic in host `double` is only correct under conditions. The table gives the
counterexamples bit for bit, for example:

- precision control 53 does not narrow the exponent: `DBL_MAX * 2` stays finite in an x87 register, and
  `DBL_TRUE_MIN / 2` stays non-zero;
- double rounding when the result lands in the binary64 subnormal range, even after `FSTP m64`
  (`1ff0000000000004 * 1ffffffffffffffe`: x87 then store gives `0008000000000002`, SSE2 `MULSD` gives `0008000000000001`);
- `FLD m64` of a subnormal raises the denormal flag, loading the equal extended value does not.

## Results so far

| Processor | Environment | Result |
|---|---|---|
| AMD EPYC 9V74 (Zen 4) | Linux, KVM guest | 549,696 rows, two runs identical |
| AMD Ryzen 9 9900X (Zen 5) | Linux 6.8, bare metal | byte-identical table (SHA-256 `e986ba25415c7def…`) |
| Intel | GitHub-hosted runner | pending (workflow `stand-x87-reference-linux-x86`) |

Transcendental instructions are the place where processors from different vendors are expected to differ in the last
bits; the Intel column will show exactly where.

## Run

```
bash run.sh full
```

Linux x86-64, GCC, coreutils, gzip. No downloads. The probe and the scripts are MIT (see `LICENSE`).
