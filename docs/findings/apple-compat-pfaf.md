# Apple compatibility mode exposes PF/AF in NZCV

## Measured

October 5, 2026, Apple M1 Pro, macOS 27.0.1, original native ARM64 probe in an entitled test process. One explicit control/compatibility capture: 64 operand pairs × 32/64-bit widths × ADDS/SUBS/CMP/CMN/ANDS × two modes = 1,280 rows. After successful `thread_set_x86_64_compat(1)`, NZCV[26] matched parity in 640/640 rows; NZCV[27] matched auxiliary carry in 512/512 arithmetic rows. ANDS AF is undefined and was excluded. Without the call, both bits were zero in all 640 rows. MSR retained all four PF/AF combinations in compatibility mode.

A separate signal matrix ran 120,000 cases with 80,000 delivered signals: BRK/null-load between ADDS and MRS, opposite flags generated in the handler, ordinary return and explicit sigreturn. Mismatch counts were zero. Raw capture contains 192 samples and complete counters, not every intermediate case. See [probe sources and captures](evidence/README.md).

## Conclusion

The measured Apple mode can carry parity and auxiliary carry in hardware. A source-derived concern about signal return losing these bits did not reproduce on this system.

## Limits

This is not a guarantee for other chips/OS versions, arbitrary Mach context edits or Wine/FEX conversion paths. Narrow-width sequences and instructions that partially modify flags require their own audit. No application speed claim follows from this probe.

## What would refute it

A valid same-instruction capture with a PF/AF mismatch, or loss across a supported context/signal boundary, would refute that use of the mode.

## Where it is fixed in our series

Candidate **0170**, `MACRUNNER_FEX_HW_PFAF`, adds hardware-backed flag handling and admission checks. It is outside the released 1.0.8 patch series; software behavior remains necessary when admission fails.
