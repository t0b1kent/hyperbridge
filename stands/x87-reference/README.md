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

Two different tables exist — one per vendor (34 runs: 32 GitHub-hosted jobs, one cloud guest, one bare-metal machine,
each run repeated twice with a byte-identical result):

| Table (SHA-256 of `raw.csv`) | Processors |
|---|---|
| `e986ba25415c7def…` | AMD EPYC 7763 (Zen 3), AMD EPYC 9V74 (Zen 4), AMD EPYC 9V45 (Zen 5), AMD Ryzen 9 9900X (Zen 5, bare metal) |
| `96998229cca1db03…` | Intel Xeon Platinum 8370C (Ice Lake), Intel Xeon Platinum 8573C (Emerald Rapids) |

Three AMD generations agree bit for bit, and the two Intel generations agree bit for bit. AMD and Intel differ in
6,278 of 549,696 rows, and every one of them is a transcendental instruction:

| Instruction | Rows that differ | Rows measured |
|---|---:|---:|
| `fyl2x` | 2,760 | 16,928 |
| `fpatan` | 2,162 | 16,928 |
| `fyl2xp1` | 1,200 | 16,928 |
| `fsincos` | 62 | 184 |
| `fsin` | 36 | 184 |
| `fcos` | 34 | 184 |
| `fptan` | 22 | 184 |
| `f2xm1` | 2 | 184 |

The status word differs in 6,276 of those rows, the value in `st0` in 1,152 and `st1` in 10. Arithmetic, loads, stores,
`fprem`, `fscale`, `fxtract` and the stack-fault cases are identical on all six processors (0 differing rows).

For a translator this means: x87 arithmetic has one right answer, and for transcendental instructions "matches real
hardware" has to name the vendor.

## Run

```
bash run.sh full
```

Linux x86-64, GCC, coreutils, gzip. No downloads. The probe and the scripts are MIT (see `LICENSE`).

## Part B: sticky exception flags across compares and integer stores

Part A seeds the status word only for one `FADD` (group `seeded-status`): all six exception flags survive on every
processor measured. Part B (`probe_b.c`, `run_b.sh`, `validate_b.py`) asks the same question for the instructions
that translators handle by hand: `FCOM FCOMP FUCOM FUCOMP FCOMI FCOMIP FUCOMI FUCOMIP FTST` on 14 × 14 operand
pairs (zeros, ±1, 1.5, 2, `DBL_MAX`, 2^53, infinities, quiet and signalling NaN, two integer-overflow values) and
`FIST/FISTP m16/m32/m64`, `FISTTP` on the same 14 values, each under five status-word seeds: none, `IE` alone, all six
sticky flags, `C1` alone, `C1` plus all six. The seed is written into an `FXSAVE` image and reloaded with `FXRSTOR`,
exactly as Part A does. Rows carry the same columns as Part A; for `FCOMI*` `memory_bits` holds the low 32 bits of
`RFLAGS` after the compare (`ZF PF CF`), for `FIST*` the stored integer. `validate_b.py` checks four architectural
rules without touching the raw data: seeded exception flags are still set afterwards (stickiness); ordered compares
raise `IE` on any NaN and unordered ones only on a signalling NaN; `C3 C2 C0` and `ZF PF CF` follow the ordering
(all three set when unordered); `C1` is cleared by compares; invalid integer stores set `IE`, exact in-range stores do not.
About 12,000 rows per run; `run_b.sh` runs the probe twice and requires byte-identical tables, like Part A.

```
bash run_b.sh
```
