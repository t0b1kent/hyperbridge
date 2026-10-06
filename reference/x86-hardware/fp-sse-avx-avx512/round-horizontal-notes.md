# Stage 1 rounding and horizontal/dot form definitions

`forms_round_horizontal.py` contains original MIT-licensed descriptor-generation
code. It has no imports, CPU probes, or execution side effects. The parent harness
is responsible for compiling/executing descriptors, selecting inputs, checking CPU
and OS AVX availability, initializing MXCSR for every trial, and recording traps.

## Form counts

| Family | SSE 128 | VEX 128 | VEX 256 | Total |
| --- | ---: | ---: | ---: | ---: |
| ROUNDPS, ROUNDPD, immediates 0–15 | 32 | 32 | 32 | 96 |
| ROUNDSS, ROUNDSD, immediates 0–15 | 32 | 32 | 0 | 64 |
| HADDPS/PD, HSUBPS/PD, ADDSUBPS/PD | 6 | 6 | 6 | 18 |
| DPPS, immediates 0–255 | 256 | 256 | 256 | 768 |
| DPPD, immediates 0–255 | 256 | 256 | 0 | 512 |
| **Total** | **582** | **582** | **294** | **1,458** |

The class totals are **160 rounding** and **1,298 horizontal** descriptors. Here
`horizontal` includes ADDSUB and dot products, following task class 7.

## Immediate coverage

- ROUND bits 1:0 select explicit rounding when bit 2 is clear. Bit 2 requests the
  MXCSR rounding mode; bit 3 suppresses reporting of the precision exception.
  All 16 low-nibble values are retained, even when bit 2 makes bits 1:0 irrelevant.
  Bits 7:4 are ignored and are not enumerated, as the task explicitly requests
  16 ROUND control values.
- DPPS and DPPD include all 256 immediate bytes. DPPD ignores bits 7:6 and 3:2;
  those encodings intentionally remain in the corpus, including redundant masks.
- A DPPS 256-bit instruction computes independently within each 128-bit half;
  its immediate is applied to both halves. Horizontal 256-bit arithmetic also
  keeps its horizontal pairs within their 128-bit halves.

## Operand and harness contract

- A is the old destination in XMM/YMM0; B is in XMM/YMM1; C is in XMM/YMM2.
  GNU AT&T assembly writes operands in the reverse order of the descriptor slots.
- Legacy horizontal/dot arithmetic reads A and B (`nops=2`, `axes=[0,1]`).
  Its VEX counterpart reads B and C (`nops=3`, `axes=[1,2]`).
- Packed ROUND reads B (`nops=2`, `axes=[1]`) in both encodings.
- Legacy scalar ROUND rounds B's low element and preserves A's other XMM bits;
  A must still be initialized and printed, but only B is a numerical test axis.
- VEX scalar ROUND merges the upper elements from B and rounds C's low element
  (`nops=3`, `axes=[1,2]`). In AT&T syntax the form is, for example,
  `vroundss $15, %xmm2, %xmm1, %xmm0`.
- `lane` is the element size in bytes (4 for single and 8 for double), and
  `width` is the vector-register width in bits. Scalar forms use width 128.
- Immediate-bearing descriptors provide an integer `imm`. Non-immediate
  horizontal descriptors omit `imm`; their assembly has no immediate operand.
- `feature` is `sse3` for legacy HADD/HSUB/ADDSUB, `sse4.1` for legacy ROUND/DP,
  and `avx` for all VEX forms. AVX execution needs OS-enabled XMM/YMM state as
  well as the hardware flag; that is the harness's responsibility.
- Preserve distinguishable initial destination and source patterns. On a trap,
  verify the entire destination remains unchanged; otherwise scalar merge bits
  must come from the source identified above. An instruction's 128-bit descriptor
  does not, by itself, observe upper YMM state; full YMM capture is necessary if
  the harness claims to verify VEX upper-half clearing versus legacy preservation.

## Exclusions

- No legacy SSE 256-bit encodings exist.
- ROUNDSS/ROUNDSD have no defined 256-bit scalar forms.
- VDPPD has no 256-bit form; DPPD is supplied only in SSE 128 and VEX 128.
- EVEX/AVX-512, VRNDSCALE, embedded rounding and SAE belong to Stage 2 and are
  intentionally outside this module.
- These definitions enumerate register-register forms. Memory operand encodings,
  alignment/fault behavior, and register-alias combinations are not separately
  varied by this shared fixed-register harness.

Result rows and checksums are produced by the parent harness, not this module.

## Definition validation

- Every one of the 1,458 emitted assembly strings was accepted by GNU assembly
  through GCC 14.2.0 in an assembly-only check; no instructions were executed.
- Python checks passed for the exact class and encoding counts above, descriptor
  uniqueness, every requested immediate range, legal widths, representative AT&T
  source ordering, and deterministic output with fresh dictionaries/axis lists.
- Feature-gate counts are 576 `sse4.1`, 6 `sse3`, and 876 `avx` forms.
- These checks validate definitions and assembly syntax; hardware results, trap
  behavior, input-product counts, and numerical validation belong to the shared
  execution harness and are not claimed by this module-level validation.
