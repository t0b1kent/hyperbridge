# Independent audit: task 0031

**PASS — 492,832 measured rows; no defined-status-flag discrepancies.**

Audited 2026-10-05 on the cloud x86-64 machine. This review used an independently written Python numerical/coverage checker and a separate standard-library ELF parser. It did not call or import the recorder's validator. The numerical checker derives overflow with signed-range bounds, AF with low-nibble carry/borrow, CF with unsigned range/ordering, and PF by low-byte population count.

## Coverage and repeatability

| Section | Data rows | Independent checks |
|---|---:|---|
| A: INC/DEC | 100,832 | All 256 byte inputs; 20 truncated boundary entries plus 4,096 deterministic samples at each wider width; four input flag states |
| B: ADD1/SUB1 | 100,832 | Exactly the same ordered operands and four flag states as A |
| C: memory CMP/TEST | 289,120 | 131,072 byte CMP rows; 131,072 byte TEST rows; 8,992 rows for each of three wider CMP forms |
| D: INC AH/DEC CH | 2,048 | Every byte input in four states; all outputs and all six captured bits match corresponding low-byte A rows |
| **Total** | **492,832** | **Zero formula errors; zero sampling/coverage errors** |

The checker reconstructs the complete ordered input sequence, including the published SplitMix64 seed `0x0031c0ffee123456`, width-specific seed derivation, 20 retained boundary entries (duplicates after truncation intentionally remain), and all random pairs. It checks the exact CSV header, hexadecimal numeric fields, flag mask, raw immediate values, results, and all defined flags. It compares each CSV directly as bytes with the second run: all four files are identical.

The final generator explicitly emits `.file "probes.S"` to remove GCC temporary-object filename variation from the ELF symbol string table. After that reproducibility fix, the reviewer reran both independent validators on the final packaged-layout data and final binary: PASS. A separate reviewer compiler/link invocation using the documented build options produced a byte-identical ELF, and running that rebuilt ELF for a third native capture produced all four canonical CSVs byte-for-byte unchanged. `rebuild.json` records these checks.

Input flag states `0x000`, `0x8d5`, `0x001`, `0x8d4` have successful POPFQ/PUSHFQ round-trip self-checks in both recorder logs. A separately compiled reviewer round-trip probe also confirmed all four states.

## Native instruction and capture audit

The delivered binary is little-endian ELF64 `EM_X86_64`. Source and actual disassembly agree. Every register form was inspected, and the independent ELF parser checks exact bytes following the seed POPFQ and before PUSHFQ:

- INC/DEC use DIL, DI, EDI, RDI at 8/16/32/64 bits
- ADD/SUB execute literal immediate 1 at all four widths
- High-byte instructions are exactly `FE C4` (INC AH) and `FE CD` (DEC CH), with no REX prefix attached
- For register forms, no instruction intervenes between POPFQ and the tested opcode, or between the opcode and PUSHFQ
- Memory dispatch is POPFQ, flag-neutral JMP RDX, the literal memory-immediate opcode, then immediate PUSHFQ; no flag-writing instruction occurs in that interval
- Masking and original-flag restoration occur only after captured RFLAGS has been saved

All **66,560** native memory-immediate stubs and every dispatch-table pointer were independently checked, not merely a sample:

| Form | Exact operand encoding | Stubs checked |
|---|---|---:|
| CMP byte [RDI], imm8 | `80 3F ib` | 256 |
| TEST byte [RDI], imm8 | `F6 07 ib` | 256 |
| CMP word [RDI], imm8 | `66 83 3F ib` | 256 |
| CMP word [RDI], imm16 | `66 81 3F iw` | 65,536 |
| CMP dword [RDI], imm8 | `83 3F ib` | 256 |

These are actual memory-immediate forms, not register substitutes. The checker verifies each embedded immediate against the dispatch index and verifies the return jump target. The word/dword imm8 tests use signed extension; validation explicitly reconstructs negative immediates `0x80`–`0xff`.

The complete backing 64-bit memory object is reread after every CMP/TEST and compared with its pre-call value. This check survives compilation: `memrow` calls `probe_memory`, then compares `QWORD PTR [rsp+0x18]` against the saved object before proceeding.

## Result and undefined-flag semantics

A/B/D `result` fields are captured register results. CMP and TEST do not write a destination; C `result` is explicitly a **calculated temporary** (`a - sign_extended_b` or `a & b`, truncated), not a measured destination write. The actual flags are hardware-captured and the unchanged memory is checked separately. CSV `b` stores the raw encoded immediate.

The only undefined bit among these tested six-bit outputs is **TEST AF**. It is excluded from defined-flag validation but retained in the raw capture. On this machine it was zero in every one of 131,072 TEST rows, including 65,536 rows with incoming AF=1. This is an observation, not a portable guarantee. The two runs also agree on the undefined observed bit.

INC/DEC preserve incoming CF and overwrite the other five bits; ADD/SUB/CMP update all six; TEST clears CF/OF and computes SF/ZF/PF. No measured defined-bit exception was found. See `DOCUMENTATION.md` for the Intel and AMD primary sources and retrieval caveats.

## Provenance and scope

CPUID reports AuthenticAMD, AMD EPYC 9V74 80-Core Processor, EAX `0x00a10f11`, family 25, model 17, stepping 1. Kernel: Linux 6.18.44 x86_64. Hypervisor bit is set and CPUID reports KVM. This is native x86-64 code in a virtualized cloud guest; it is not a claim of bare-metal measurement or of an independent Intel hardware run.

An audit found an initial metadata-only family/model decoding error: extending the family before checking the base-family condition suppressed model extension. The recorder was corrected, rebuilt, and both captures rerun before this final audit. Current CPUID identification is correct; the captured tables pass.

## Reproduce this audit

From an audit directory containing these files, with `MACHINE` set to the packaged recorder directory (canonical first capture at its root, second capture in `repeat/`):

```sh
python3 validate_independent.py "$MACHINE" --repeat "$MACHINE/repeat" > validation.json
python3 audit_elf.py "$MACHINE/probe" > opcodes.json
cc -std=c11 -O2 -Wall -Wextra -Werror -mno-red-zone -o seed_roundtrip seed_roundtrip.c
./seed_roundtrip
```

Audited source/binary SHA-256:

```text
7be3a14829e8184edfc29ce638ea20fba587aac93ffe858a97f33010283c0534  probe.c
232592695eefeef2628c8fdfe890019ff36cb80488f443ed0d4da3550569a530  generate_asm.py
351608293ce15be0638629f88639df75bc632262b69e0fbf8b403d06fa580d51  probes.S
5c2cd3a6e79e4a53a56faa4bd7a73a81e3dcc17d063c81ba22a3935c2a4a82e5  probe
```

CSV hashes and per-operation/width/state counts are in `validation.json`; exact opcode checks are in `opcodes.json`.
