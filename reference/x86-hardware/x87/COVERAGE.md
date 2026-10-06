# Coverage

All requested stages are implemented. Counts are computed before execution in harness.c and checked per form after execution by analyze.py. Every form uses twelve FCWs unless its per-case trap FCW unmasks one exception.

| Class | Forms | Rows | Compressed bytes |
|---|---:|---:|---:|
| arithmetic | 46 | 441,024 | 2,281,933 |
| comparison | 20 | 200,880 | 950,132 |
| environment | 17 | 3,672 | 38,595 |
| load-store | 31 | 56,700 | 241,731 |
| remainder-scale | 6 | 65,496 | 355,432 |
| stack | 12 | 2,592 | 22,364 |
| transcendental | 8 | 83,736 | 708,030 |
| traps | 16 | 192 | 2,215 |

## Exact bounded sampling

- Unary binary80: all 86 explicitly named bit patterns. First 30 are the special set, including signed zero/one/infinity, two QNaNs/two SNaNs with distinct surviving payloads, positive/negative denormals and min/max normals, both signs of pseudo-denormals/unnormals/pseudo-infinities, and two pseudo-NaNs.
- Binary register forms: all 30×30 special pairs, plus 2×86 boundary/value pairs with ±1, plus 36 constructed ties/adjacent half-ULP pairs (24/53/64-bit precision, both signs). NaN slot 1 flips payload bit 8 so same-source patterns remain distinguishable after quieting without forcing one operand to always have the larger payload.
- Memory arithmetic/comparisons: 30×28 special binary80/float-memory pairs or 30×12 binary80/integer-memory pairs, plus 86 rotating boundary cases per form. FLD memory covers every 28 float32/64 or 86 binary80 input; FILD covers 12 integer patterns per width.
- Packed BCD: 12 explicitly specified valid, signed, invalid-nibble and ignored-bit encodings. FBSTP sees all 86 binary80 values.
- Transcendentals: unary 86 special/boundary + 481 deterministic grid/near-π/extreme inputs each. F2XM1 rescales the 385-point central grid by 1/8, giving 385 ordinary in-domain inputs; the remaining out-of-domain and extreme samples are retained. Binary transcendental forms use 30×30 special pairs plus 481 grid pairs with recognizable signed integer second operands.
- FPREM/FPREM1: normal binary set plus 16 deterministic finite large-exponent pairs × exactly 64 linked steps, including incomplete and completed reductions for every FCW. Status is reset between linked instructions without altering the logical operand bytes; TOP is zero for these non-popping forms.
- Stack: each listed command at occupied depths 0…8, with both clean FSW and an explicitly declared sticky-status seed (needed to test FNCLEX). All eight post-registers, physical full FTW, abridged FTW and TOP are reported.
- Environment: every save/restore form, nine representative update/control operations, all occupied depths 0…8, two initial condition-code patterns, all twelve FCWs. Restore source bytes use public pointer sentinels; saved addresses are mapped to labels/offsets. Both legacy 108-byte and 512-byte layouts are covered, including FXSAVE64/FXRSTOR64 and legacy-address FXSAVE/FXRSTOR.
- Traps: eight triggers (six exception classes plus stack under/overflow) × two waiting probes (FWAIT, FLD1) × twelve FCWs. Other exception classes remain masked, status starts clean; the trigger is followed by a non-waiting pre-trap snapshot.

## Deliberate limits / nonexistent forms

- No non-popping FST m80 or FIST m64 encoding exists; these names are not silently emitted as a different instruction. FSTP m80, FISTP m64 and FISTTP m64 are covered.
- Fixed supported register samples use ST0/ST1 for arithmetic/comparison and ST0/ST3/ST7 for representative stack operations rather than enumerating all eight register-index encodings. Stack depths, overflow and underflow are covered independently. No requested mnemonic family or legal requested memory width is omitted.
- No 32-bit executable or emulation: the requested instructions run in native 64-bit mode, as permitted by TASK.md. Host reports a hypervisor; this is disclosed in MACHINE.txt.
- Exhaustive 2^80 operand patterns, every NaN payload, all BCD invalid-digit permutations, and every possible environment bit pattern are outside the bounded sample. Equal-payload opposite-sign NaN priority is not established.
- Environment reserved bytes and literal process addresses are not delivered. Meaningful fields and full80 saved registers are preserved and exact pointer categories/offsets are explicit.
- C and high-precision models validate selected ordinary/domain-valid rows; they do not generate or replace any native output. High-precision checks focus on PC64/nearest and report discrepancies instead of requiring transcendentals to be correctly rounded.

## Per-form native rows

| Class | Form | Rows |
|---|---|---:|
| load-store | FLD_m32 | 336 |
| load-store | FST_m32 | 1,032 |
| load-store | FSTP_m32 | 1,032 |
| load-store | FLD_m64 | 336 |
| load-store | FST_m64 | 1,032 |
| load-store | FSTP_m64 | 1,032 |
| load-store | FLD_m80 | 1,032 |
| load-store | FSTP_m80 | 1,032 |
| load-store | FILD_m16 | 144 |
| load-store | FIST_m16 | 1,032 |
| load-store | FISTP_m16 | 1,032 |
| load-store | FISTTP_m16 | 1,032 |
| load-store | FILD_m32 | 144 |
| load-store | FIST_m32 | 1,032 |
| load-store | FISTP_m32 | 1,032 |
| load-store | FISTTP_m32 | 1,032 |
| load-store | FILD_m64 | 144 |
| load-store | FISTP_m64 | 1,032 |
| load-store | FISTTP_m64 | 1,032 |
| load-store | FBLD_m80 | 144 |
| load-store | FBSTP_m80 | 1,032 |
| load-store | FLD1 | 12 |
| load-store | FLDZ | 12 |
| load-store | FLDPI | 12 |
| load-store | FLDL2T | 12 |
| load-store | FLDL2E | 12 |
| load-store | FLDLG2 | 12 |
| load-store | FLDLN2 | 12 |
| load-store | FLD_ST1 | 13,296 |
| load-store | FST_ST1 | 13,296 |
| load-store | FSTP_ST1 | 13,296 |
| arithmetic | FADD_ST0_ST1 | 13,296 |
| arithmetic | FADD_ST1_ST0 | 13,296 |
| arithmetic | FADDP_ST1_ST0 | 13,296 |
| arithmetic | FADD_m32 | 11,112 |
| arithmetic | FADD_m64 | 11,112 |
| arithmetic | FIADD_m16 | 5,352 |
| arithmetic | FIADD_m32 | 5,352 |
| arithmetic | FSUB_ST0_ST1 | 13,296 |
| arithmetic | FSUB_ST1_ST0 | 13,296 |
| arithmetic | FSUBP_ST1_ST0 | 13,296 |
| arithmetic | FSUB_m32 | 11,112 |
| arithmetic | FSUB_m64 | 11,112 |
| arithmetic | FISUB_m16 | 5,352 |
| arithmetic | FISUB_m32 | 5,352 |
| arithmetic | FSUBR_ST0_ST1 | 13,296 |
| arithmetic | FSUBR_ST1_ST0 | 13,296 |
| arithmetic | FSUBRP_ST1_ST0 | 13,296 |
| arithmetic | FSUBR_m32 | 11,112 |
| arithmetic | FSUBR_m64 | 11,112 |
| arithmetic | FISUBR_m16 | 5,352 |
| arithmetic | FISUBR_m32 | 5,352 |
| arithmetic | FMUL_ST0_ST1 | 13,296 |
| arithmetic | FMUL_ST1_ST0 | 13,296 |
| arithmetic | FMULP_ST1_ST0 | 13,296 |
| arithmetic | FMUL_m32 | 11,112 |
| arithmetic | FMUL_m64 | 11,112 |
| arithmetic | FIMUL_m16 | 5,352 |
| arithmetic | FIMUL_m32 | 5,352 |
| arithmetic | FDIV_ST0_ST1 | 13,296 |
| arithmetic | FDIV_ST1_ST0 | 13,296 |
| arithmetic | FDIVP_ST1_ST0 | 13,296 |
| arithmetic | FDIV_m32 | 11,112 |
| arithmetic | FDIV_m64 | 11,112 |
| arithmetic | FIDIV_m16 | 5,352 |
| arithmetic | FIDIV_m32 | 5,352 |
| arithmetic | FDIVR_ST0_ST1 | 13,296 |
| arithmetic | FDIVR_ST1_ST0 | 13,296 |
| arithmetic | FDIVRP_ST1_ST0 | 13,296 |
| arithmetic | FDIVR_m32 | 11,112 |
| arithmetic | FDIVR_m64 | 11,112 |
| arithmetic | FIDIVR_m16 | 5,352 |
| arithmetic | FIDIVR_m32 | 5,352 |
| arithmetic | FSQRT | 1,032 |
| arithmetic | FABS | 1,032 |
| arithmetic | FCHS | 1,032 |
| arithmetic | FRNDINT | 1,032 |
| comparison | FCOM_ST1 | 13,296 |
| comparison | FCOM_m32 | 11,112 |
| comparison | FCOM_m64 | 11,112 |
| comparison | FCOMP_ST1 | 13,296 |
| comparison | FCOMP_m32 | 11,112 |
| comparison | FCOMP_m64 | 11,112 |
| comparison | FUCOM_ST1 | 13,296 |
| comparison | FUCOMP_ST1 | 13,296 |
| comparison | FCOMPP | 13,296 |
| comparison | FUCOMPP | 13,296 |
| comparison | FCOMI_ST1 | 13,296 |
| comparison | FCOMIP_ST1 | 13,296 |
| comparison | FUCOMI_ST1 | 13,296 |
| comparison | FUCOMIP_ST1 | 13,296 |
| comparison | FICOM_m16 | 5,352 |
| comparison | FICOM_m32 | 5,352 |
| comparison | FICOMP_m16 | 5,352 |
| comparison | FICOMP_m32 | 5,352 |
| comparison | FTST | 1,032 |
| comparison | FXAM | 1,032 |
| remainder-scale | FPREM | 13,296 |
| remainder-scale | FPREM1 | 13,296 |
| remainder-scale | FSCALE | 13,296 |
| remainder-scale | FXTRACT | 1,032 |
| remainder-scale | FPREM_ITER | 12,288 |
| remainder-scale | FPREM1_ITER | 12,288 |
| transcendental | FSIN | 6,804 |
| transcendental | FCOS | 6,804 |
| transcendental | FSINCOS | 6,804 |
| transcendental | FPTAN | 6,804 |
| transcendental | F2XM1 | 6,804 |
| transcendental | FPATAN | 16,572 |
| transcendental | FYL2X | 16,572 |
| transcendental | FYL2XP1 | 16,572 |
| stack | FLD1_DEPTH | 216 |
| stack | FSTP_ST0_DEPTH | 216 |
| stack | FADDP_ST1_ST0_DEPTH | 216 |
| stack | FCOMPP_DEPTH | 216 |
| stack | FFREE_ST0_DEPTH | 216 |
| stack | FFREE_ST3_DEPTH | 216 |
| stack | FINCSTP_DEPTH | 216 |
| stack | FDECSTP_DEPTH | 216 |
| stack | FXCH_ST1_DEPTH | 216 |
| stack | FXCH_ST7_DEPTH | 216 |
| stack | FNINIT_DEPTH | 216 |
| stack | FNCLEX_DEPTH | 216 |
| environment | FNSTENV | 216 |
| environment | FLDENV | 216 |
| environment | FNSAVE | 216 |
| environment | FRSTOR | 216 |
| environment | FXSAVE64 | 216 |
| environment | FXRSTOR64 | 216 |
| environment | FXSAVE | 216 |
| environment | FXRSTOR | 216 |
| environment | TRACE_FNOP | 216 |
| environment | TRACE_FLD1 | 216 |
| environment | TRACE_FADD_ST0_ST1 | 216 |
| environment | TRACE_FLD_m32 | 216 |
| environment | TRACE_FST_m64 | 216 |
| environment | TRACE_FCOMI_ST1 | 216 |
| environment | TRACE_FNCLEX | 216 |
| environment | TRACE_FNINIT | 216 |
| environment | TRACE_FLDCW | 216 |
| traps | IE_FWAIT | 12 |
| traps | IE_FLD1 | 12 |
| traps | DE_FWAIT | 12 |
| traps | DE_FLD1 | 12 |
| traps | ZE_FWAIT | 12 |
| traps | ZE_FLD1 | 12 |
| traps | OE_FWAIT | 12 |
| traps | OE_FLD1 | 12 |
| traps | UE_FWAIT | 12 |
| traps | UE_FLD1 | 12 |
| traps | PE_FWAIT | 12 |
| traps | PE_FLD1 | 12 |
| traps | STACK_UNDERFLOW_FWAIT | 12 |
| traps | STACK_UNDERFLOW_FLD1 | 12 |
| traps | STACK_OVERFLOW_FWAIT | 12 |
| traps | STACK_OVERFLOW_FLD1 | 12 |
