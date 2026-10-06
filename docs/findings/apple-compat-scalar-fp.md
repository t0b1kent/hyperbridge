# Scalar FP lane merging in Apple compatibility mode

## Measured

October 5, 2026, Apple M1 Pro, macOS 27, native ARM64 probe. Three recorded arms (outside, compat, compat with FPCR low bits requested), 402 rows total. FADD/FSUB/FMUL/FDIV, single and double precision, retained upper lanes from Rn for all three destination aliases in compatibility mode. When both inputs were NaNs, Rn was selected for all tested qNaN/sNaN pairs. FSQRT, SCVTF and FCVT cleared the upper lanes. The 114 finite low-lane checks had zero failures. FEAT_AFP sysctl was zero and FPCR[2:0] did not retain the requested bits. See [raw CSV and source](evidence/README.md).

## Conclusion

For the tested binary arithmetic forms, Apple compatibility mode supplies the lane-preservation behavior needed by legacy scalar SSE without a separate insert instruction. This is an Apple mode observation, not evidence of architectural FEAT_AFP support on M1.

## Limits

The observation alone does not establish correct min/max, denormal handling, exception flags or packed operations, nor performance. Other chips and OS releases need independent checks.

## What would refute it

A tested alias losing upper lanes or selecting the wrong NaN, or a mismatch against native x86 under the same control state, would refute that form's single-instruction lowering.

## Where it is fixed in our series

Candidate **0171**, `MACRUNNER_FEX_HW_SCALAR_MERGE`, uses the measured merge behavior. Released **0065** concerns AFPCR/MXCSR restoration and does not implement this optimization. Candidate 0171 is outside the 1.0.8 released series.
