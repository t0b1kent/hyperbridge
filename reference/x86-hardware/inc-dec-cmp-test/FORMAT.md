# 0031: native x86-64 INC/DEC/ADD1/SUB1/CMP/TEST flags

Captured and verified on 2026-10-05. **PASS: 492,832 data rows, zero defined-flag discrepancies, two complete runs byte-identical.**

This is an original MIT-licensed native probe. No emulator, Wine, Mac, remote user computer, or CI/Actions runner was used. The local cloud guest ran the delivered ELF x86-64 executable directly. CPUID reports **AuthenticAMD, AMD EPYC 9V74 80-Core Processor, family 25 / model 17 / stepping 1**, CPUID.1 EAX `0x00a10f11`. The hypervisor bit is set and the hypervisor vendor is **KVMKVMKVM**. The kernel is **Linux 6.18.44 x86_64**. This is a virtualized cloud measurement, not a bare-metal or separate Intel-machine measurement. CPUID and ELF identity document the execution environment; they are not physical-host attestation.

## Files and counts

The four root CSV files are the first measured run. The corresponding files under `repeat/` are a second, separate execution of the same executable. Counts exclude the one-line header in each file.

| Section | CSV | Data rows |
|---|---|---:|
| A | `A-inc-dec.csv` | 100,832 |
| B | `B-add1-sub1.csv` | 100,832 |
| C | `C-memory-cmp-test.csv` | 289,120 |
| D | `D-high-byte.csv` | 2,048 |
| Total | | **492,832** |

- A: INC and DEC each have 50,416 rows
- B: ADD1 and SUB1 each have 50,416 rows
- C: byte CMP and byte TEST each have 131,072 rows; word CMP imm8, word CMP imm16 and dword CMP imm8 each have 8,992 rows
- D: INC AH and DEC CH each have 1,024 rows

`capture-run1.log` and `repeat/capture-run2.log` record CPUID, kernel, compiler, seed, flag-seed round trips, row counts, and completion. No hostname, IP address, environment-variable dump, or credential is recorded. `validation.json` checks numerical formulas and exact coverage/order. `encoding-validation.json`, `disassembly-proof.txt`, and `independent-audit/` provide actual-binary and independent numerical evidence. `SHA256SUMS` covers every delivered regular file below this machine directory except itself.

## CSV contract

Exactly seven columns, UTF-8/ASCII, LF newlines, one header:

```
op,width,flags_in,a,b,result,flags_out
```

All six numeric columns are hexadecimal with a `0x` prefix; `width` is in **bits** (`0x8`, `0x10`, `0x20`, `0x40`). Operands/results use sixteen hex digits. Flags contain only `CF=0x001`, `PF=0x004`, `AF=0x010`, `ZF=0x040`, `SF=0x080`, `OF=0x800`; mask `0x8d5`.

- A and D: `a` is the input register value; `b=0` is an unused unary-operand placeholder; `result` is the hardware register result truncated to its tested width
- B: `b=1` is the literal encoded immediate; `result` is the hardware register result truncated to width
- C: `a` is the memory value and `b` is the **raw encoded immediate**, before sign extension. `CMP_M16_IMM8` and `CMP_M32_IMM8` sign-extend `b` from 8 bits to the operand width. `CMP_M16_IMM16` uses the full raw 16-bit immediate
- CMP and TEST do not store a result. Consequently, C `result` is an explicitly **calculated, non-stored temporary**: `(a - effective_b) mod 2^width` for CMP and `a & b` for TEST. It is not described as a hardware destination write. Hardware flags are directly measured. The actual backing memory is reread and verified unchanged after every C execution, including the surrounding bytes of its 64-bit storage object
- D operation names are `INC_AH` and `DEC_CH`; they identify the actual legacy high-byte registers

## Complete deterministic sampling and order

Four A/B/D incoming states, in order: `0x000`, `0x8d5`, `0x001`, `0x8d4`. Two C incoming states: `0x000`, `0x8d5`. A separate native POPFQ/PUSHFQ round trip verifies all four states before each capture begins.

The ordered boundary list is exactly:

```
0, 1, 2, 0xf, 0x10, 0x7f, 0x80, 0xff, 0x100,
0x7fff, 0x8000, 0xffff, 0x10000, 0x7fffffff,
0x80000000, 0xffffffff, 0x100000000,
0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff
```

**Duplicate policy:** retain every entry and every random draw, in order. Truncation can create duplicate boundaries, and random samples can repeat previous values. No deduplication or resampling occurs. Thus every wider register form gets exactly 20 boundary entries plus 4,096 draws, not 20 unique boundaries.

PRNG: SplitMix64 with base seed **`0x0031c0ffee123456`**. All state arithmetic wraps modulo `2^64`. Each draw first increments state by `0x9e3779b97f4a7c15`; apply `(z xor (z >> 30)) * 0xbf58476d1ce4e5b9`, then `(z xor (z >> 27)) * 0x94d049bb133111eb`, then return `z xor (z >> 31)`. Truncate the returned value, not the state.

- A/B: operation order INC, DEC or ADD1, SUB1; widths 8,16,32,64; then operand; then the four incoming states. Byte operands are all integers 0..255. Wider operands are the truncated boundary list followed by 4,096 draws, freshly seeded with `base_seed xor width`. INC, DEC, ADD1 and SUB1 therefore receive identical ordered input samples at each width
- C byte forms: CMP then TEST; `a=0..255` outer loop, `b=0..255` inner loop, followed by the two incoming states. Every 256×256 combination is measured in both states
- C wide forms: word/imm8, word/imm16, dword/imm8. First take the Cartesian product of the 20 boundary entries truncated to the memory width and the same 20 entries truncated to immediate width (400 pairs, including duplicates). Then take 4,096 random pairs. Fresh seed for each form is `base_seed xor (width << 8) xor immediate_width`. Consume one draw for `a`, then one for raw `b`; measure each pair in both flag states
- D: INC AH then DEC CH; `a=0..255`; then the four incoming states

## Native capture and exact instructions

`probes.S` is generated by `generate_asm.py`, compiled as standalone assembly, and linked without LTO. The compiler cannot insert flag-writing instructions into a capture interval.

Each probe reads original RFLAGS with PUSHFQ, changes **only** the six requested status bits in that saved image, and loads it with POPFQ. All other bits, including the architecturally fixed reserved bit 1 and the original control bits, retain their original image. It does not load a fabricated flags word such as zero or all ones. Only user-modifiable status flags are intentionally changed. The original flags image is restored on return after the measurement is saved.

The tested register instruction is followed **immediately** by PUSHFQ; only then is the snapshot moved to a register and masked. The memory wrapper ends with POPFQ and a flag-neutral indirect JMP to a literal instruction stub. The stub executes the memory-immediate instruction followed immediately by PUSHFQ. Its immediate is embedded in executable text; no register-equivalent substitute is used.

| Native form | Exact leading bytes | Literal stubs |
|---|---|---:|
| CMP byte [RDI], imm8 | `80 3F ib` | 256 |
| TEST byte [RDI], imm8 | `F6 07 ib` | 256 |
| CMP word [RDI], imm8 | `66 83 3F ib` | 256 |
| CMP word [RDI], imm16 | `66 81 3F iw` | 65,536 |
| CMP dword [RDI], imm8 | `83 3F ib` | 256 |

The byte register forms use DIL; larger forms use DI/EDI/RDI. INC AH is `FE C4`; DEC CH is `FE CD`, with no REX prefix. The independent ELF parser verifies all 66,560 memory stubs and table pointers, all 16 register forms, the two high-byte forms, and adjacency to the capture instruction. All 2,048 high-byte rows match corresponding low-byte results and all six flags.

## Reference formulas and undefined flags

`verify.py` independently reconstructs every input row. Let `M=2^width`, `r=(a±effective_b) mod M`, and let `s(x)` interpret an operand as a signed width-bit integer. CF is unsigned carry for addition or unsigned borrow for subtraction. OF is whether `s(a)±s(b)` falls outside `[-M/2, M/2-1]`. AF is carry/borrow across the low nibble. PF is even population count in `r & 0xff`; ZF is `r==0`; SF is the result's top bit. INC/DEC take the other five flags from addition/subtraction by one and preserve incoming CF. TEST uses the AND temporary, clears CF/OF, and computes PF/ZF/SF.

**Only TEST AF is undefined among the requested flags for these instructions.** It is preserved in the raw six-bit CSV snapshot and explicitly excluded from the mismatch mask (`0x8c5` for TEST, `0x8d5` for other forms). On this processor AF was 0 in all 131,072 TEST rows, including all 65,536 rows seeded with AF=1. This is an observed processor result, not a portable guarantee. The two captures also agree on this undefined bit. No other discrepancy from documented defined behavior was found.

The primary architectural references are the [Intel SDM, Volume 2, October 2024 revision 085](https://cdrdv2-public.intel.com/835757/325383-sdm-vol-2abcd.pdf), entries ADD, SUB, INC, DEC, CMP and TEST, and the [AMD APM Volume 3 publication page](https://docs.amd.com/v/u/en-US/24594_3.37). Exact pages, source retrieval details, and AMD indexed-source caveats are in `independent-audit/DOCUMENTATION.md`. The audit did not substitute an uninspected current revision for its directly retrieved Intel edition.

## Rebuild and reproduce

Requirements: native Linux x86-64, GCC/GNU assembler, Python 3.10+, and standard POSIX utilities. The capture used GCC 14.2.0 and Python 3.12.14. No third-party Python packages or downloaded software are needed.

Run from this directory:

```sh
sh build.sh
python3 independent-audit/validate_independent.py . --repeat repeat
python3 independent-audit/audit_elf.py probe
sha256sum -c SHA256SUMS
```

`build.sh` overwrites capture outputs in this directory and `repeat/`; use a copy if preserving the original delivery. GCC command:

```sh
gcc -O2 -std=c11 -Wall -Wextra -Werror -fno-pie -no-pie \
  -Wl,--build-id=none -o probe probe.c probes.S
```

The generator sets a stable assembly FILE symbol (`probes.S`), so two builds with the capture compiler were also verified to produce byte-identical ELF files. The manifest verifies the delivered files, not arbitrary recompiled binaries on a different compiler. Rebuilding elsewhere may change binary hashes while leaving CSV results identical. The public dataset, original source, generator, validators, logs, and documentation are covered by `LICENSE`.
