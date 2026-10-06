# NEW0035 RMW encoding definitions

`rmw.py` is MIT-licensed and exposes `forms()`. It supplies instruction bytes and
metadata to the generic native Linux harness; it does not execute instructions.
All memory destinations are `[rdi]`. Width fields are bytes; names use bits.

## Coverage

466 definitions, comprising 364 legal encodings and 102 deliberately invalid
LOCK encodings:

| Family | Definitions |
|---|---:|
| ADD/OR/ADC/SBB/AND/SUB/XOR: register, full immediate, sign-extended imm8 | 154 |
| INC/DEC/NOT/NEG | 32 |
| ROL/ROR/RCL/RCR/SHL/SHR/SAR: implicit 1, immediate 3, CL | 168 |
| SHLD/SHRD: immediate 1, immediate 3, CL | 36 |
| XCHG | 8 |
| XADD | 8 |
| CMPXCHG: initially equal and unequal accumulator | 16 |
| BTS/BTR/BTC: register and immediate bit index | 36 |
| CMPXCHG8B/CMPXCHG16B: initially equal and unequal accumulator pair | 8 |

Every family has no-LOCK and LOCK variants. LOCK is deliberately marked illegal
for shifts and rotates, including SHLD/SHRD. A no-LOCK memory XCHG remains
implicitly locked. SHL also covers the synonymous SAL mnemonic; there is no
separate SAL encoding. SHLD/SHRD and bit operations do not have byte forms.

Definition counts by operand size: 8-bit 86; 16-bit 124; 32-bit 124;
64-bit 128; 128-bit 4.

## Harness contracts

- Honor integer `regs` and `flags` overrides before executing the instruction
- Honor optional `initial` as full-operand hex; omitted means the harness's
  default repeated `11` bytes
- ADC/SBB/RCL/RCR request flags `0x203`, specifically initial CF=1
- CL-count cases explicitly set RCX=3
- Bit operations force RBX=3, making the indexed bit belong to this operand
- BTS/BTC use repeated `11`; BTR uses repeated `19`, so BTR clears a set bit
- CMPXCHG match cases preserve untouched high bits of RAX while setting its
  compared low portion to the repeated `11` operand
- CMPXCHG8B match cases set low EDX:EAX to `11111111:11111111`, retaining high
  halves in the initial full registers so fault/restart preservation is visible
- CMPXCHG16B match cases use full RDX:RAX of repeated `11`; every CMPXCHG16B
  definition has `alignment=16`
- Feature tags `cx8` and `cx16` follow Linux CPU-flag spelling
- `asm` is supplementary GNU-as Intel-syntax validation metadata

The wide compare/exchange initial-match annotation describes only the initial
execution. Handler mutation and second-execution modes can change whether the
comparison matches. Record the actual resulting success/failure in each mode.

The register source is RBX/EBX/BX/BL. Wide compare/exchange replacement is
RCX:RBX or ECX:EBX. Unless overridden, registers follow the parent's defaults:
RAX=0x1122334455667788, RBX=0xa1b2c3d4e5f60718, RCX=3,
RDX=0x99aabbccddeeff00.

Full immediates use 80 /digit ib (byte operands) or 81 /digit iw/id. A 64-bit
operand uses sign-extended imm32, not a nonexistent imm64 encoding. Wider
operands also get the distinct 83 /digit sign-extended imm8 encoding. Negative
immediates exercise the actual sign-extension semantics. Prefixes match GNU as:
operand-size `66`, then LOCK `f0`, then any REX.W `48`.

## Independent validation

Run `python3 verify_rmw_encodings.py`. GNU assembler 2.44 independently assembled
the Intel-syntax specification and matched every legal encoding byte-for-byte.
For all 102 intentional illegal LOCK encodings, the verifier independently
assembles the corresponding legal unlocked instruction and inserts only the
LOCK prefix; it does not claim assembler acceptance of the illegal instruction.

Observed validation: 466 definitions checked, zero byte mismatches.

SHA-256 of `rmw.py` at validation:
`47fcb1ae2b37f14d302022f78b1ae769d22dc144352881e395f365c50f45cd5d`.

This validation establishes encoding agreement, not hardware behavior or
partial-write/restart results. Those must come from the parent's native probe.
