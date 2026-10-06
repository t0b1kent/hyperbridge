# Coverage and exact accounting

All requested 64-bit-mode mnemonics and permitted operand widths are executed. Architecture classifications below distinguish undefined flags/results from values checked by the C model; they are not general claims about the observed CPU behavior. Empirical behavior appears in RULES.md with measured counts.

“Forms” below means generated width/form/count-or-immediate configurations, not a claim that every one has different opcode bytes. A CL configuration is repeated per raw count. All counts include duplicate labeled operand positions and both actual initial flags.

| Instruction | Widths | Configurations | Data rows | Architecturally undefined or special flags/results |
|---|---|---:|---:|---|
| SHL | 8/16/32/64 | 496 | 21,824 | AF for nonzero count; OF except count 1; CF for count >= width (nonzero masked count) |
| SAL | 8/16/32/64 | 496 | 21,824 | Same instruction encoding/undefined flags as SHL |
| SHR | 8/16/32/64 | 496 | 21,824 | AF for nonzero count; OF except count 1; CF for count >= width (nonzero masked count) |
| SAR | 8/16/32/64 | 496 | 21,824 | AF for nonzero count; OF except count 1 |
| ROL | 8/16/32/64 | 496 | 21,824 | OF except masked count 1; masked count 0 leaves flags unchanged |
| ROR | 8/16/32/64 | 496 | 21,824 | OF except masked count 1; masked count 0 leaves flags unchanged |
| RCL | 8/16/32/64 | 496 | 21,824 | OF except masked count 1; masked count 0 leaves flags unchanged |
| RCR | 8/16/32/64 | 496 | 21,824 | OF except masked count 1; masked count 0 leaves flags unchanged |
| SHLD | 16/32/64 | 384 | 371,712 | AF for nonzero count, OF except 1; result/arithmetic flags undefined when masked count > width |
| SHRD | 16/32/64 | 384 | 371,712 | AF for nonzero count, OF except 1; result/arithmetic flags undefined when masked count > width |
| MUL | 8/16/32/64 | 4 | 3,872 | PF, AF, ZF, SF |
| IMUL1 | 8/16/32/64 | 4 | 3,872 | PF, AF, ZF, SF |
| IMUL2 | 16/32/64 | 3 | 2,904 | PF, AF, ZF, SF |
| IMUL3 | 16/32/64 | 40 | 38,720 | PF, AF, ZF, SF |
| DIV | 8/16/32/64 | 4 | 87,128 | CF, PF, AF, ZF, SF, OF after successful division; #DE captured independently |
| IDIV | 8/16/32/64 | 4 | 87,128 | CF, PF, AF, ZF, SF, OF after successful division; #DE captured independently |
| BSF | 16/32/64 | 3 | 2,904 | CF, PF, AF, SF, OF; destination undefined if source=0 |
| BSR | 16/32/64 | 3 | 2,904 | CF, PF, AF, SF, OF; destination undefined if source=0 |
| TZCNT | 16/32/64 | 3 | 2,904 | PF, AF, SF, OF |
| LZCNT | 16/32/64 | 3 | 2,904 | PF, AF, SF, OF |
| POPCNT | 16/32/64 | 3 | 2,904 | None; ZF computed, others cleared |
| BT | 16/32/64 | 48 | 8,712 | PF, AF, SF, OF; ZF unaffected |
| BTS | 16/32/64 | 48 | 8,712 | PF, AF, SF, OF; ZF unaffected |
| BTR | 16/32/64 | 48 | 8,712 | PF, AF, SF, OF; ZF unaffected |
| BTC | 16/32/64 | 48 | 8,712 | PF, AF, SF, OF; ZF unaffected |
| AND | 8/16/32/64 | 4 | 3,872 | AF |
| OR | 8/16/32/64 | 4 | 3,872 | AF |
| XOR | 8/16/32/64 | 4 | 3,872 | AF |
| TEST | 8/16/32/64 | 4 | 3,872 | AF |
| CMPXCHG | 8/16/32/64 | 4 | 85,184 | None; arithmetic flags from accumulator minus destination |
| XADD | 8/16/32/64 | 4 | 3,872 | None; arithmetic flags from sum |
| BSWAP16 | 16 | 1 | 44 | 16-bit result undefined; flags unaffected |
| CMPXCHG8B | 64 | 1 | 21,296 | None; ZF computed, other arithmetic flags unaffected |
| CMPXCHG16B | 128 | 1 | 21,296 | None; ZF computed, other arithmetic flags unaffected |

## Counts checked before and after execution

| Class | Native configurations | Predicted and observed rows | Actual traps | Gzip bytes |
|---|---:|---:|---:|---:|
| shifts | 1984 | 87,296 | 0 | 331,574 |
| rotates | 1984 | 87,296 | 0 | 406,083 |
| double | 768 | 743,424 | 0 | 2,394,061 |
| multiply | 51 | 49,368 | 0 | 155,979 |
| divide | 8 | 174,256 | 100,856 | 659,726 |
| bitscan | 15 | 14,520 | 0 | 40,846 |
| bittest | 192 | 34,848 | 0 | 126,596 |
| logic | 16 | 15,488 | 0 | 48,602 |
| misc | 11 | 131,692 | 0 | 410,882 |
| 09-bmi | 540 | 286,616 | 0 | 874,072 |

Total: 1,624,804 actual data rows; 5,448,421 compressed result bytes (limit 60,000,000).

Independent `verify_data.py` checks every configuration against these products, not just grand totals:
- shifts: 4 mnemonics × 2 forms × sum over w=8,16,32,64 of (2w+2 counts) ×22×2 = 87,296; rotates use the same product
- double: 2 mnemonics ×3 widths ×64 counts ×2 forms ×22²×2 = 743,424
- multiply: (8 one-operand +3 two-operand +40 three-operand/immediate configurations) ×22²×2 = 49,368
- divide: 8 forms×22³×2 +2 signedness forms×(20+20+20+21 nonzero divisor positions)×4 boundary quotients×3 offsets×2 flags =174,256
- bitscan: 5 mnemonics×3 widths×22²×2 =14,520
- bittest: 4 mnemonics×3 widths×[register indices 22×(22+15)×2 + memory indices 22×15×2 +14 immediate/memory configurations×22×2] =34,848
- logic: 4 mnemonics×4 widths×22²×2 =15,488
- misc: (4 CMPXCHG widths + CMPXCHG8B + CMPXCHG16B)×22³×2 +4 XADD widths×22²×2 +22×2 BSWAP16 =131,692

Division boundaries construct low/high limbs of q×divisor+offset modulo twice the operand width, with q = signed maximum, signed minimum, unsigned maximum, and unsigned maximum+1; offset=-1,0,+1. All arithmetic that may wrap during construction uses unsigned 128-bit addition, avoiding C signed overflow. These supplement, rather than replace, all low/divisor/high Cartesian patterns.

## C-defined-semantics checks

No undefined architectural bit is treated as a specification requirement. All captured initial flag values and non-arithmetic low-16 flags are checked independently. Each validation file distinguishes result checks from flag checks: undefined BSF/BSR zero-source destinations and undefined 16-bit double-shift results are not counted as defined-result checks. Successful DIV/IDIV have no defined arithmetic flags to check. Traps verify exact preserved operand registers and arithmetic flags against their saved context. Raw output repeat, diagnostic repeat and compressed output repeat comparisons all succeeded.

### shifts

```
class=shifts forms=1984 expected_rows=87296 measured_rows=87296 traps=0
C_defined_result_checks=87296 mismatches=0
C_defined_flag_checks=87296 mismatches=0
capture_and_nonarithmetic_flag_checks=87296 mismatches=0
two native executions, validation summaries, and deterministic gzip bytes match
```

### rotates

```
class=rotates forms=1984 expected_rows=87296 measured_rows=87296 traps=0
C_defined_result_checks=87296 mismatches=0
C_defined_flag_checks=87296 mismatches=0
capture_and_nonarithmetic_flag_checks=87296 mismatches=0
two native executions, validation summaries, and deterministic gzip bytes match
```

### double

```
class=double forms=768 expected_rows=743424 measured_rows=743424 traps=0
C_defined_result_checks=627264 mismatches=0
C_defined_flag_checks=627264 mismatches=0
capture_and_nonarithmetic_flag_checks=743424 mismatches=0
two native executions, validation summaries, and deterministic gzip bytes match
```

### multiply

```
class=multiply forms=51 expected_rows=49368 measured_rows=49368 traps=0
C_defined_result_checks=49368 mismatches=0
C_defined_flag_checks=49368 mismatches=0
capture_and_nonarithmetic_flag_checks=49368 mismatches=0
two native executions, validation summaries, and deterministic gzip bytes match
```

### divide

```
class=divide forms=8 expected_rows=174256 measured_rows=174256 traps=100856
C_defined_result_checks=174256 mismatches=0
C_defined_flag_checks=100856 mismatches=0
capture_and_nonarithmetic_flag_checks=174256 mismatches=0
two native executions, validation summaries, and deterministic gzip bytes match
```

### bitscan

```
class=bitscan forms=15 expected_rows=14520 measured_rows=14520 traps=0
C_defined_result_checks=14080 mismatches=0
C_defined_flag_checks=14520 mismatches=0
capture_and_nonarithmetic_flag_checks=14520 mismatches=0
two native executions, validation summaries, and deterministic gzip bytes match
```

### bittest

```
class=bittest forms=192 expected_rows=34848 measured_rows=34848 traps=0
C_defined_result_checks=34848 mismatches=0
C_defined_flag_checks=34848 mismatches=0
capture_and_nonarithmetic_flag_checks=34848 mismatches=0
two native executions, validation summaries, and deterministic gzip bytes match
```

### logic

```
class=logic forms=16 expected_rows=15488 measured_rows=15488 traps=0
C_defined_result_checks=15488 mismatches=0
C_defined_flag_checks=15488 mismatches=0
capture_and_nonarithmetic_flag_checks=15488 mismatches=0
two native executions, validation summaries, and deterministic gzip bytes match
```

### misc

```
class=misc forms=11 expected_rows=131692 measured_rows=131692 traps=0
C_defined_result_checks=131648 mismatches=0
C_defined_flag_checks=131692 mismatches=0
capture_and_nonarithmetic_flag_checks=131692 mismatches=0
two native executions, validation summaries, and deterministic gzip bytes match
```

## Class 9

The full per-command class-9 forms/rows/manual-undefined flags table and C counts are reproduced below.


“Forms” counts encoded width/forms: two register forms per mnemonic, except RORX, which has 256 immediates×2 widths=512 forms. BEXTR control sweeps remain register forms. Memory-source forms, alternative register allocations and upper-half zero-extension above the reported operand width were not separately measured. Non-arithmetic low-16 flags are checked unchanged on every row. There were no execution traps in this class.

| Instruction | Forms | Manual-undefined arithmetic flags | Rows | C defined matches | C defined mismatches |
|---|---:|---|---:|---:|---:|
| ANDN | 2 | AF, PF | 1,936 | 1,936 | 0 |
| BEXTR | 2 | AF, PF, SF | 244,464 | 244,464 | 0 |
| BLSI | 2 | AF, PF | 88 | 88 | 0 |
| BLSMSK | 2 | AF, PF | 88 | 88 | 0 |
| BLSR | 2 | AF, PF | 88 | 88 | 0 |
| BZHI | 2 | AF, PF | 1,936 | 1,936 | 0 |
| MULX | 2 | None; arithmetic flags unchanged | 1,936 | 1,936 | 0 |
| PDEP | 2 | None; arithmetic flags unchanged | 1,936 | 1,936 | 0 |
| PEXT | 2 | None; arithmetic flags unchanged | 1,936 | 1,936 | 0 |
| RORX | 512 | None; arithmetic flags unchanged | 22,528 | 22,528 | 0 |
| SARX | 2 | None; arithmetic flags unchanged | 1,936 | 1,936 | 0 |
| SHLX | 2 | None; arithmetic flags unchanged | 1,936 | 1,936 | 0 |
| SHRX | 2 | None; arithmetic flags unchanged | 1,936 | 1,936 | 0 |
| ADCX | 2 | None; CF updated, other arithmetic flags unchanged | 1,936 | 1,936 | 0 |
| ADOX | 2 | None; OF updated, other arithmetic flags unchanged | 1,936 | 1,936 | 0 |
| **Total** | **540** | | **286,616** | **286,616** | **0** |

C checks use unsigned modulo-width arithmetic, unsigned 128-bit products/sums, independent bit-by-bit PDEP/PEXT reference loops, extraction truncation and the architecturally specified shift-count masks. The defined-flags mask excludes every manual-undefined flag. Empirical rules are checked separately and do not affect the defined-semantics result.


## Not covered and why

- Class 11: DAA, DAS, AAA, AAS, AAM and AAD have zero executed rows. Static no-libc i386 compilation succeeds, but native execution returns errno 8 (Exec format error). This is the task’s explicitly allowed unavailable case. See legacy_REPORT.md/legacy_CHECKS.txt; no emulation, packages or fabricated legacy results.
- The legacy probe is only a compatibility probe; it is not a complete decimal-instruction generator. If a later host permits i386 execution, those exhaustive sweeps remain new work.
- Arbitrarily huge full-pattern memory bit indices are outside the controlled allocation; memory offsets use the fifteen documented negative/positive boundaries. Register indices do include all 22 pattern positions.
- Alternate register allocations, LOCK variants, memory-source variants beyond the specifically requested bit-string and CMPXCHG8B/16B forms, non-#DE fault types and upper-register bits above the operand width are not enumerated.
- Initial arithmetic flag states are the task’s paired all-clear/all-set patterns, not every one of 64 flag combinations.
- No Intel-vs-AMD portability claim is made from this single machine. Exact repeatability is measured on the reported exposed CPU.

## License and provenance

All submitted generator/harness/model/analyzer code is original MIT-licensed code. No third-party source was fetched or embedded. Only the local compiler/assembler and already installed standard tools were used.
