# Conversion inventory and integration

The native MIT-licensed `forms_conversion.py` defines **92 forms**: **28 SSE**
(including six SSE/MMX conversions), **30 ordinary VEX/AVX**, and **34 F16C**.
There are 40 distinct mnemonics. Counts include scalar GPR operand sizes and
F16C control values as separate forms.

| Family | SSE forms | VEX forms |
|---|---:|---:|
| Scalar float/double | 2 | 2 |
| Packed float/double | 2 | 4 |
| Scalar signed integer to float/double | 4 | 4 |
| Scalar float/double to signed integer, CVT and CVTT | 8 | 8 |
| Packed signed dword to float/double | 2 | 4 |
| Packed float/double to signed dword, CVT and CVTT | 4 | 8 |
| SSE/MMX signed dword conversions | 6 | 0 |
| F16C binary16 conversions | 0 | 34 |
| **Total** | **28** | **64** |

## Register semantics

- Every form includes initial destination A. Legacy scalar conversions preserve
  A's unused lanes. VEX scalar conversions copy unused lanes from B and convert
  C; all pairs of the relevant typed scalar samples are selected by `axes`.
- Vector width is the encoding width. Narrowing double/half conversions may
  consume YMM but write XMM; widening conversions may consume XMM but write YMM.
  `sizes` and `out_bytes` retain these distinctions and print whole registers.
- Scalar integer results print exactly 4 or 8 bytes. `gpr_bits` distinguishes
  the two operand-size encodings without changing the architectural mnemonic.
  `result_reg` identifies EAX/RAX or MM0 where applicable.
- For MMX destinations the report width is 64. MMX sources occupy 8 bytes even
  though the destination is XMM. `cvtpi2ps` preserves the high 64 XMM bits.
- `pre` loads native GPR/MMX operands. `post` runs after the default vector
  store, records GPR/MMX results, and executes EMMS where needed. Trap recovery
  must restore the saved machine context and skip only the tested instruction,
  then execute `post`, allowing an unchanged destination to be observed.
- F16C narrowing covers both widths and immediate values 0–15. Low bits 0–2
  select immediate/MXCSR rounding; bit 3 is ignored and is explicitly exercised.
  Bits 4–7 are also ignored and their redundant encodings are not enumerated.

## Input requirements for the shared harness

Types `f16`, `f32`, `f64`, `i32`, and `i64` must have distinct typed corpora.
Signed integer corpora need extrema and both signs near 2^24 and 2^53, including
neighbors; floating corpora need the signed 32-/64-bit range boundaries,
half-integer rounding boundaries, and the task's NaNs/denormals/infinities.

Half input vectors need signed zeros, ones, infinities, distinct signed quiet
and signaling NaNs, minimum/maximum subnormal, minimum normal and maximum finite.
F32 narrowing inputs should also include both signs and neighboring float
representables around these raw patterns:

- `33000000`, `33800000`: 2^-25 and 2^-24
- `387fc000`, `387fe000`, `38800000`: half normal/subnormal boundary
- `477fe000`, `477ff000`, `47800000`: 65504, 65520 and 65536

For packed conversions, inject an exceptional value into each consumed lane,
including every non-low lane. A source XMM register with only its low half
consumed should still be printed in full so ignored upper lanes are visible.

## Explicit exclusions

- EVEX, masks, zeroing, embedded rounding/SAE, packed signed qwords, unsigned
  integer conversions, and AVX-512-FP16 conversion families are Stage 2.
  There are no SSE/VEX packed signed-qword or unsigned-integer counterparts.
- Legacy non-VEX half conversion instructions do not exist in F16C.
- Memory-source/destination encodings, alignment/page faults, and register
  alias permutations are not separate numerical instruction forms here; this
  register-based oracle tests MXCSR/FP behavior with distinct input registers.
- x87, AMD 3DNow! and newer non-SSE/non-VEX ISA conversion families are outside
  the specified Stage 1 SSE/AVX scope.
- No rounding-control variants are dropped: CVTT is represented independently
  of CVT, and all forms use the shared harness's complete MXCSR configurations.

## Primary ISA references

Inventory and register semantics were checked against Intel's
[SDM Volume 1 conversion inventory](https://cdrdv2-public.intel.com/843827/253665-sdm-vol-1-dec-24.pdf),
[SDM Volume 2 instruction reference](https://cdrdv2-public.intel.com/789581/325383-sdm-vol-2abcd.pdf),
and the [Intel F16C programming reference](https://www.intel.com/content/dam/develop/external/us/en/documents/319433-024-697869.pdf).
The code is original project code; no third-party implementation was copied.

## Definition validation

All 92 generated `pre`/instruction/`post` sequences assembled successfully with
the local `cc` assembler frontend. Metadata validation checked unique
mnemonic/encoding/width/immediate/GPR-size keys, operand-axis bounds, three-slot
type/size lists, and output sizes. This definition check did not execute an
instruction oracle or run any existing task.
