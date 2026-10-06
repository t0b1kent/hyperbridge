# EVEX Stage 2 inventory and limits

`forms_evex.py` is original MIT-licensed code. It describes 13,452 native register
forms, covering 178 distinct mnemonics. These are additional Stage 2 forms, not
substitutes for the required legacy SSE/VEX outputs.

## Scope

The inventory covers AVX-512F, AVX-512VL and AVX-512DQ forms supported by this
machine. Packed forms use all legal 128-, 256- and 512-bit vector lengths;
scalar forms use XMM registers. Conversions whose source and destination have
different lengths use their architectural operand sizes. `width` is the wider
operand's vector length. The full width of the vector destination is printed,
including upper zeroing when its meaningful converted elements are narrower.

- Arithmetic: ADD, SUB, MUL, DIV, MIN, MAX and SQRT, each PS/PD/SS/SD
- FMA3: FMADD/FMSUB/FNMADD/FNMSUB, each 132/213/231 and PS/PD/SS/SD;
  FMADDSUB/FMSUBADD, each order and PS/PD (no scalar encodings exist)
- Comparisons: VCMPPS/PD/SS/SD, all 32 predicates, mask-register results;
  VCOMISS/SD and VUCOMISS/SD, with and without SAE, flag results
- All packed conversions between F32/F64 and signed/unsigned I32/I64 supported
  by F/VL/DQ, truncating and rounding forms; scalar signed/unsigned I32/I64
  conversions in both directions; scalar and packed F32/F64 conversions;
  VCVTPH2PS and VCVTPS2PH
- Every requested AVX-512-only family, with all PS/PD/SS/SD variants:
  VRCP14, VRSQRT14, VGETEXP, VGETMANT, VSCALEF, VRNDSCALE, VREDUCE, VRANGE,
  VFIXUPIMM and VFPCLASS

| Family | Forms | Immediate coverage |
|---|---:|---|
| VRCP14 | 44 | none |
| VRSQRT14 | 44 | none |
| VGETEXP | 64 | none |
| VGETMANT | 240 | 0–15 |
| VSCALEF | 124 | none |
| VRNDSCALE | 2,160 | all 0–255 |
| VREDUCE | 2,160 | all 0–255 |
| VRANGE | 240 | 0–15 |
| VFIXUPIMM | 2,160 | all 0–255 |
| VFPCLASS | 2,076 | all 0–255 |

The full per-mnemonic totals can be reproduced with `python3 forms_evex.py`.
There are 3,240 scalar forms and 10,212 packed forms. By vector length, there
are 6,060 128-bit, 2,820 256-bit and 4,572 512-bit forms.

## Bounded control cross-product

Mask-register K1 supplies each tested writemask; K2 is the explicit destination
for comparisons/classification. The representative active-lane mask patterns
are zero, all lanes and alternating lanes starting with lane zero. Duplicate
patterns are removed for scalar forms. Vector destinations test both merging
and zeroing; mask destinations have no architectural `{z}` encoding and always
clear inactive result bits. The all-active form is still explicitly masked
with K1; no separate K0/unmasked encoding is added for these instructions.
Non-maskable scalar GPR conversions and COMIS/UCOMIS use no writemask.

For each instruction that accepts embedded rounding, all four RN/RD/RU/RZ-SAE
values are included. SAE-only instructions include normal and SAE forms.
These controls occur at legal lengths: scalar or 512-bit vector, not 128/256-bit
packed forms. Exactly representable I32/U32-to-F64 conversions ignore embedded
rounding controls; their redundant ignored-ER encoding aliases are omitted. The dataset contains 540 forms for each of the four rounding
controls and 368 SAE-only forms; 10,924 forms use neither.

For immediate instructions, every immediate listed above is included in the
base all-active, merge, non-SAE form. Additional mask, zeroing and rounding/SAE
cross-products use the two endpoint immediates: 0 and 31 for VCMP, 0 and 15 for
VGETMANT/VRANGE, 0 and 255 for VRNDSCALE/VREDUCE/VFIXUPIMM/VFPCLASS, and 0 and 7
for VCVTPS2PH. Consequently this is not the full Cartesian product of all
immediates and all controls. For non-immediate instructions, all listed
representative mask/zeroing/rounding combinations are included.

VCVTPS2PH covers 0–7: bits 2: 0 determine its rounding selection, and upper
immediate bits are architecturally ignored. VGETMANT and VRANGE cover 0–15;
only the specified low-nibble domain is tested. VGETMANT high bits are specified
as Must Be Zero. Reserved encodings and redundant high-bit aliases are not enumerated.
All 256 values are retained for VRNDSCALE and VREDUCE, including the scale
nibble and rounding/suppression field.

## Inputs and result representation

The shared harness supplies input values and MXCSR modes. Each immediate form
requests a 16-case sample (`cases=16`) to bound the complete artifact size;
non-immediate forms defer to the harness's Stage 2 default. The generator does
not claim exhaustive scalar Cartesian products for Stage 2. At a 64-case
default and 13 MXCSR values, the inventory predicts 5,322,720 execution rows
before any documented global size reduction. The authoritative final row
counts and sampling policy are recorded by the shared generator and coverage
report.

For comparisons and classification, X1 is the initial 64-bit K2 value, and the
result is a 64-bit K2 image. K1 is separately printed. COMIS/UCOMIS uses the
shared two-byte flag representation, `(LAHF << 8) | OF`. Integer GPR
conversions distinguish 32-bit and 64-bit destinations using operand sizes and
`gpr_bits`; the mnemonic is kept unchanged. Unsigned integers use the same raw
bit-pattern generator types as signed integers, with signedness determined
by the instruction, not the textual hexadecimal representation.

VFIXUPIMM includes X1/A as a true value input and marks its table operand C as
integer bits (32-bit lanes for PS/SS, 64-bit lanes for PD/SD). The meaningful
fixup table occupies each lane's low 32 bits. The harness repeats each response code 0–15 into all eight table nibbles.
Scalar case c uses c%16; packed lane j uses (c+j)%16. Every response code is
covered, but all 2^32 mixed tables are not enumerated. FMA also includes A/B/C as value inputs.

## Explicit exclusions and non-existent encodings

- Only register operands are tested. Memory operands, broadcast, alignment,
  page faults, masked-memory fault suppression and memory access side effects
  are outside this module's scope
- Writemasks are the representative patterns above, not all 2^N masks. Tests
  use K1 and result K2 rather than every physical mask-register number
- There is no separate unmasked copy of an instruction already tested with
  an all-active K1; inactive upper mask bits and complement-alternating masks
  are not separate variants
- Immediate/control cross-products and Stage 2 input tuples are sampled as
  described above, rather than pretending to be exhaustive
- VROUNDPS/PD/SS/SD, VRCPPS/SS, VRSQRTPS/SS, HADD/HSUB/ADDSUB and DPPS/DPPD do
  not have direct EVEX encodings. Their legacy/VEX tests belong to Stage 1;
  the applicable new EVEX alternatives are covered here
- AVX-512ER VRCP28/VRSQRT28 and AVX-512FP16 instructions are not supported by
  this host and are excluded. Half-storage conversion VCVTPS2PH/VCVTPH2PS is
  included and does not require AVX-512FP16
- BF16 arithmetic/conversions, VNNI, integer-only SIMD, vector moves,
  permutations, boolean operations and AVX10 additions are outside the task's
  requested F/VL/DQ floating-point families. Some other extensions may appear
  in the machine's CPUID flags; that is not a claim that they were tested
- This inventory validates native instruction encodings. It does not itself
  claim numerical-reference checks or repeated-output determinism; those are
  performed by the shared harness and reported separately

## Encoding and native smoke validation

All 13,452 generated forms assembled successfully with GNU assembler 2.44.
All were then individually executed on the actual host under MXCSR 0x1f80
using fresh source operands, with signal recovery enabled. There were zero
SIGILL, SIGFPE or SIGSEGV events in this legality smoke test. Disassembly
checked every target instruction: 13,452 of 13,452 have the EVEX prefix byte
0x62. This matters for scalar operations that can otherwise silently assemble
as VEX. The explicit assembler `{evex}` selector is used on unmasked forms
when neither an opmask nor embedded rounding already forces EVEX.

The standalone smoke-test source generator and validation logs are in
`evex-build/`; the generator recreates its C and assembly. These tests cover
syntax/encoding/legal execution only and do not replace the shared harness's
exceptional-value result files. `verify_encodings.py` independently checks all
Stage 1 and Stage 2 instruction encodings without executing them.

ISA reference: [Intel AVX-512 instructions and programming reference](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-avx-512-instructions.html).
