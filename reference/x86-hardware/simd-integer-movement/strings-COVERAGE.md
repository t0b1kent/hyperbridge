# Class 8: native string comparisons

Original MIT implementation. All data rows are emitted by actual instructions; no rows are synthesized or patched. Run `bash strings-run.sh` from this directory. The script generates assembly, compiles, verifies every target opcode in disassembly, executes twice with a 900-second limit, compares raw text and `gzip -n` bytes, and saves a SHA-256 of the decompressed text.

## Exact coverage

| Mnemonic | Encodings | Operand locations | Immediate forms | Cases per form | Rows |
|---|---|---|---:|---:|---:|
| PCMPESTRI | legacy, VEX.128 | register, aligned m128, m128+1 | 1,536 | 88 | 135,168 |
| PCMPESTRM | legacy, VEX.128 | register, aligned m128, m128+1 | 1,536 | 88 | 135,168 |
| PCMPISTRI | legacy, VEX.128 | register, aligned m128, m128+1 | 1,536 | 72 | 110,592 |
| PCMPISTRM | legacy, VEX.128 | register, aligned m128, m128+1 | 1,536 | 72 | 110,592 |
| Total | | | **6,144** | | **491,520** |

Every encoding/location combination uses all 256 imm8 values, including ignored bit 7. There are no VEX.256 string-comparison instructions in scope. Byte and word signed/unsigned modes, all aggregation/polarity/output modes, and both directions of index selection are thereby included.

## Inputs and format

- Cases 0–67: lengths 0–16, four variants per length: equal zero-terminated strings; a differing nonzero byte; an interior zero in both strings with nonzero trailing data; an interior zero in the second string and a differing byte
- Cases 68–71: fixed nonzero byte/range patterns, including 01/7f/80/ff and 55/aa
- Explicit-only cases 72–87: (-1,1), (1,-1), (-8,8), (8,-8), (-16,16), (16,-16), (-17,17), (17,-17), (-255,255), (255,-255), (17,16), (16,17), (32,0), (0,32), (INT_MIN,INT_MAX), (INT_MAX,INT_MIN)
- This is a fixed reduced set, not the full Cartesian product of strings and lengths. Explicit length values count elements (bytes or words according to imm8); implicit termination is computed at the selected element width
- For index instructions, width is 32, X1 is ECX before execution (8 hex digits), and the primary result is ECX after (8 hex digits). YMM0_BEFORE/YMM0_AFTER supplementary fields preserve full 256-bit implicit-register snapshots
- For mask instructions, width is 128, X1 is full YMM0 before execution, and the primary result is full YMM0 after (64 hex digits each). ECX_AFTER is a supplementary 32-bit field
- X2 is the first string register, displayed as full256-bit YMM1. X3 is full256-bit YMM2 for register operands or the actual128-bit m128 bytes for memory operands. FLAGS contains low 16 RFLAGS. LA/LB and ECX0 are printed on every row. MEM=0/1/2 identifies register/aligned/+1 unaligned source
- Flags start at 0202. All source registers are captured and checked unchanged. YMM upper halves are nonzero fixed poison before each instruction

## Independent checks and limits

All 491,520 result rows are independently modeled in original scalar C: 122,880 each for equal-any, ranges, equal-each, and equal-ordered. Checks cover explicit/implicit lengths, signedness, polarity, index/mask encoding, full destination, ECX, and all captured flags. All pass.

The equal-ordered model compares each starting position element by element, applies validity rules, and limits comparisons to the finite 128-bit operand window. There are no unmodeled numerical rows and no fault rows. Any unexpected fault makes the program return failure.

Undefined-behavior sanitization also passes, and sanitized native output is byte-identical to normal output; see `strings-SANITIZER.txt`. Reproduce with `bash strings-sanitize.sh` after the normal run.

`strings-encoding-validation.json` verifies 6,144 actual machine-code targets, immediate bytes, memory/register forms, and VEX prefix/L bits. `strings-manifest.json` lists each generated form and its precomputed row count. `strings-validation.txt` contains execution counts. `crypto-machine.txt` records the same native machine's CPUID/XCR0 evidence. Build outputs and raw repetitions are disposable and should not be included in the delivery archive.

`strings-format-validation.json` records a per-row grammar audit: X1 and the primary result are the actual destination at its declared width; scalar and supplementary register field lengths are checked. The native run script executes this audit automatically.

For memory-source forms X3 is the actual 16-byte m128 operand, not an unused YMM2 backing-register snapshot. Register sources are still printed as complete 256-bit YMM values.
