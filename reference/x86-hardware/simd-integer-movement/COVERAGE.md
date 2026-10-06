# Coverage

| Task class | Output | Generated forms | Native rows | Complete scalar numerical comparisons | Fault rows |
|---|---|---:|---:|---:|---:|
| 1 movement/widening | out-movement.txt.gz | 13,051 | 174,861 | 174,483 | 378 |
| 2 permutation/blend | out-permutation.txt.gz | 28,578 | 117,552 | 107,952 | 9,600 |
| 3 arithmetic | out-arithmetic.txt.gz | 2,778 | 20,592 | 18,296 | 2,296 |
| 4 logic/compare/tests | out-logic.txt.gz | 201 | 4,824 | 4,320 | 504 |
| 5 shifts | out-shifts.txt.gz | 7,782 | 65,040 | 64,720 | 320 |
| 6 packs | out-pack.txt.gz | 36 | 864 | 768 | 96 |
| 7 gathers | out-gather.txt.gz | 64 | 6,336 | 4,032 | 2,304 |
| 8 string compares | out-strings.txt.gz | 6,144 | 491,520 | 491,520 | 0 |
| 9 crypto/misc | out-crypto.txt.gz | 4,695 | 37,560 | 33,424 | 4,136 |
| 10 upper rules | out-upper.txt.gz + every vector class | 2 instructions | 256 | 256 | 0 |
| **Total** | | **63,331** | **919,405** | **899,771** | **19,634** |

The form count follows each generator's explicit definition. Core/string/crypto memory alignments are separate assembled forms; movement and gather reuse one instruction over multiple address scenarios. Class 10 has two target instructions and sixteen separately observed YMM registers. Counts are not represented as a uniform ISA-form taxonomy.

## Exact command inventories

- movement-COVERAGE.md, movement-manifest.tsv and movement-counts.tsv: every requested movement/widening/broadcast/extract/insert/mask family, register and legal memory forms, all controls 0–255
- core-COVERAGE.md and core-inventory.json: complete command lists for permutation/blend, integer arithmetic, logic/compare/flag tests, shifts and packs; all 150 immediate-byte groups cover 0–255
- gather-COVERAGE.md, gather-manifest.tsv and gather-counts.tsv: eight gather mnemonics × VEX L=0/1 × scale 1/2/4/8, including negative indices, masked protected addresses and genuine partial completion on fault
- strings-COVERAGE.md and strings-manifest.json: four string operations × legacy/VEX128 × register/aligned/+1-memory × all 256 controls, lengths 0–16, interior zeros, explicit negative/oversized lengths, full result/ECX/flags
- crypto-COVERAGE.md and crypto-manifest.json: CRC32 all legal width pairs, AES and keygen, PCLMUL, all seven SHA mnemonics, MOVBE load/store; all applicable immediate values 0–255, including all selectors and ignored bits
- upper.c and upper-generate.py: VZEROUPPER/VZEROALL, all YMM0–15, eight fixed initial register files

Every class prints full destination-before/after vectors, exposing legacy preservation and VEX write-zeroing. Instructions without a vector destination are explicitly distinguished. The linked opcode audits verify encoding/immediate inventories rather than trusting the source spelling alone.

## Numerical verification and exact omissions

All **899,771 nonfaulting rows** receive full independent scalar C comparisons. This includes every equal-ordered string and SHA row; no successful numerical subset is unmodeled. All **19,634 fault rows** receive separate actual-context/state-invariant checks. The fault checks are explicitly separate from numerical success comparisons. Every per-family counterexample/mismatch count is zero.

The canonical prefix always uses actual destination-before/result and destination width, with GPR results printed at their architectural width. Full YMM/full64 and memory-preservation evidence is supplemental. For inaccessible masked-store destination spans, the primary value is explicitly UNKNOWN and actual readable prefixes are printed separately. This is a required representational limit of inaccessible memory, not a missing instruction or invented observation. Encoding widths and full vector register snapshots remain visible even when they differ from the destination width.

No requested mnemonic, legal SSE/VEX128/VEX256 operand family or required immediate value is omitted on the recorded CPU. All source-memory forms include aligned and one-byte-misaligned cases. All mask/gather families include disabled inaccessible lanes in user-owned guard mappings and record whether they fault. SHA/VAES/VPCLMUL features are advertised and captured.

Input sampling is deliberately finite and documented by family. No full Cartesian product, every possible mask/index/register allocation, alternate 32-bit address-size/segment/prefix encoding, MMX, EVEX/AVX-512-only instruction, privileged operation or unrelated non-temporal movement is claimed. POPCNT is in task 0002. Where an ISA has no VEX256 form (for example string comparisons or AESIMC), no nonexistent form is fabricated.
