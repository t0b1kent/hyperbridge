# Class 9: native crypto and scalar miscellaneous

Original MIT implementation. Run `bash crypto-run.sh`. Every data row executes the named instruction, including unaligned cases that genuinely raise SIGSEGV. The script generates and verifies machine-code targets, runs twice with a 900-second limit, compares raw text and `gzip -n` bytes, and hashes the decompressed result.

## Exact forms and rows on the recorded CPUID

All vector forms have register, aligned memory, and +1 unaligned memory source variants. Eight fixed cyclic pattern pairs per form avoid a full Cartesian product.

| Instruction | Encodings | Forms | Rows | Independent scalar checks | Fault rows |
|---|---|---:|---:|---:|---:|
| AESENC | legacy128, VEX128, VEX256 | 9 | 72 | 64 | 8 |
| AESENCLAST | legacy128, VEX128, VEX256 | 9 | 72 | 64 | 8 |
| AESDEC | legacy128, VEX128, VEX256 | 9 | 72 | 64 | 8 |
| AESDECLAST | legacy128, VEX128, VEX256 | 9 | 72 | 64 | 8 |
| AESIMC | legacy128, VEX128 | 6 | 48 | 40 | 8 |
| AESKEYGENASSIST, all 256 imm8 | legacy128, VEX128 | 1,536 | 12,288 | 10,240 | 2,048 |
| PCLMULQDQ, all 256 imm8 | legacy128, VEX128, VEX256 | 2,304 | 18,432 | 16,384 | 2,048 |
| SHA1RNDS4, all 256 imm8 | legacy128 | 768 | 6,144 | 6,144 | 0 |
| SHA1NEXTE | legacy128 | 3 | 24 | 24 | 0 |
| SHA1MSG1 | legacy128 | 3 | 24 | 24 | 0 |
| SHA1MSG2 | legacy128 | 3 | 24 | 24 | 0 |
| SHA256RNDS2 | legacy128 | 3 | 24 | 24 | 0 |
| SHA256MSG1 | legacy128 | 3 | 24 | 24 | 0 |
| SHA256MSG2 | legacy128 | 3 | 24 | 24 | 0 |
| CRC32 | r32 with byte/word/dword, r64 with byte/qword; register and both memory alignments | 15 | 120 | 120 | 0 |
| MOVBE load | 16/32/64, both memory alignments | 6 | 48 | 48 | 0 |
| MOVBE store | 16/32/64, both memory alignments | 6 | 48 | 48 | 0 |
| **Total** | | **4,695** | **37,560** | **33,424** | **4,136** |

VAES-256, VPCLMULQDQ-256 and SHA forms are gated by their actual CPUID bits. They are all advertised and all captured on this machine. There is no VEX SHA, no 256-bit AESIMC/AESKEYGENASSIST, and no EVEX request in this task. POPCNT belongs to task 0002 and is intentionally not repeated.

## Inputs and format

Eight patterns are zero, all ones, repeated 01, repeated 80, repeated 7f, alternating 55/aa, numbered bytes, and the fixed arithmetic byte pattern a7+37*i. First and second pattern indices differ by 3 modulo 8; the implicit SHA XMM0 pattern differs by 5. The first destination upper half is separately poisoned before every form. No randomness or dates.

The standard slots always use X1 = actual destination before and primary result = actual destination after:

- Vectors: width is 128 or 256. X1 is YMM1 before, primary result is YMM1 after. Legacy/unary sources use X2 and X3=-; SHA256RNDS2 uses its real implicit XMM0 as X3. VEX binary forms use first source (aliased destination) as X2 and second source as X3. YMM0/source preservation snapshots are named supplementary fields. Registers display full256 bits and memory inputs use their actual operand width
- CRC32: width is destination GPR width (32 or 64). X1 and primary result use exactly that many bits, X2 uses source width. SRC_BITS records the 8/16/32/64 source width
- MOVBE load: width and X1/result are destination GPR width, 16/32/64; X2 is the corresponding actual source-memory bytes
- MOVBE store: width is memory destination width, 16/32/64. X1 is actual memory before, X2 is the source GPR at that width, and primary result is actual memory after
- All scalar rows include GPR64_BEFORE/GPR64_AFTER supplementary fields, preserving complete native register snapshots and visibility of partial-write/zero-extension behavior. Memory forms also include MEM_AFTER at the operand width
- MEM=0/1/2 means register/aligned/+1-unaligned memory. No addresses are printed

Fault rows retain the actual destination snapshot in the primary result position and append FAULT, SOURCE_AFTER, TRAP and ERROR metadata. Full actual YMM1/YMM0/YMM2 values come from Linux SA_SIGINFO ucontext XSAVE; missing or unfamiliar images fail the run rather than substituting expected values.

AES models use a scalar, algorithmically generated GF(2^8) S-box and inverse; round, inverse-round, keygen-assist and inverse-mix calculations are original code. PCLMUL uses bitwise polynomial multiplication. CRC32C uses its reflected polynomial bit loop. MOVBE uses a scalar byte-reversal loop and checks the complete surrounding memory buffer. SHA-1/SHA-256 rounds and message schedules use original scalar uint32_t recurrences, rotations, additions, and Boolean operations, including SHA256RNDS2’s implicit XMM0 words. Auto-vectorization and SLP vectorization are disabled during compilation.

All 33,424 nonfault rows, including all 6,288 SHA rows, pass independent scalar checks. All 4,136 fault rows separately pass expected-fault checks and validate their actual captured destination/source/implicit registers and unchanged memory. These are genuine SIGSEGV/#GP trap 13, error 0 snapshots, not prefills. There are no unmodeled successful rows. Fault-state checks are reported separately from numerical checks.

Undefined-behavior sanitization passes, with byte-identical native output; see `crypto-SANITIZER.txt`. Reproduce with `bash crypto-sanitize.sh` after the normal run.

`crypto-encoding-validation.json` verifies every actual target opcode, immediate byte, encoding prefix, vector length, and source location. `crypto-manifest.json` lists forms and precomputed counts; `crypto-validation.txt` lists actual counts. `crypto-machine.txt` records CPUID/XCR0/compiler/native execution evidence. No software emulator or packages were used. Build outputs and raw repetitions are disposable.

`crypto-format-validation.json` records a per-row grammar audit: X1 and the primary result are the actual destination at its declared width; scalar and supplementary register field lengths are checked. The native run script executes this audit automatically.

Canonical vector sources: legacy and VEX unary forms have X2 as their actual register/memory source and X3=-, except SHA256RNDS2 whose implicit XMM0 is X3. VEX three-operand AES/PCLMUL forms print the actual first source (which aliases the destination in this experiment) as X2 and second source as X3. Memory inputs use their operand size; register inputs are full YMM snapshots. The preservation-only YMM0 and source snapshots are named extras after the primary result.
