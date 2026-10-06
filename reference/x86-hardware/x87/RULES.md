# Empirical x87 rules on this CPU

All counts below are obtained by analyze.py from immutable native output rows. They describe this CPU and this sample, not a promise about every x87 implementation. A failed hypothesis remains visible with counterexamples in validation-summary.json. Hardware results are never modified by these analyses.

## Measurement isolation

These deterministic rows use a documented interruption filter based only on measured thread context-switch changes, TSC_AUX migration and a fixed 5,000-TSC-tick capture bound, with at most 128 attempts. Intentional SIGFPE cases are latency-exempt. No result field determines acceptance. Unfiltered pointer-loss observations, scheduler/signal probes and 100-run filtered stability evidence are separately delivered; see NOTES.md and capture-interference-evidence.json. These claims concern isolated windows, not arbitrary OS scheduling behavior.

## Counted hypotheses

- `arithmetic_C1_iff_magnitude_rounded_up`: 15,984 supporting rows; 0 contradictory rows
- `unsupported_arithmetic_negative_indefinite_and_IE`: 24,192 supporting rows; 0 contradictory rows
- `invalid_arithmetic_negative_indefinite_and_IE`: 360 supporting rows; 0 contradictory rows
- `NaN_QQ_quiet_preferred_else_larger_significand`: 288 supporting rows; 0 contradictory rows
- `NaN_QQ_IE_iff_signaling`: 288 supporting rows; 0 contradictory rows
- `NaN_QS_quiet_preferred_else_larger_significand`: 288 supporting rows; 0 contradictory rows
- `NaN_QS_IE_iff_signaling`: 288 supporting rows; 0 contradictory rows
- `NaN_SQ_quiet_preferred_else_larger_significand`: 288 supporting rows; 0 contradictory rows
- `NaN_SQ_IE_iff_signaling`: 288 supporting rows; 0 contradictory rows
- `NaN_SS_quiet_preferred_else_larger_significand`: 288 supporting rows; 0 contradictory rows
- `NaN_SS_IE_iff_signaling`: 288 supporting rows; 0 contradictory rows
- `sqrt_C1_iff_magnitude_rounded_up`: 408 supporting rows; 0 contradictory rows
- `negative_sqrt_indefinite_and_IE`: 360 supporting rows; 0 contradictory rows
- `frndint_C1_iff_magnitude_rounded_up`: 768 supporting rows; 0 contradictory rows
- `NaN_compare_IE_rule`: 22,128 supporting rows; 0 contradictory rows
- `NaN_compare_unordered_flags`: 22,128 supporting rows; 0 contradictory rows
- `full_FTW_empty_tags_match_logical_STACK`: 51,648 supporting rows; 0 contradictory rows
- `abridged_FTW_matches_full_FTW`: 6,456 supporting rows; 0 contradictory rows
- `environment_restore_preserves_seeded_pointers_in_legacy_view`: 864 supporting rows; 0 contradictory rows
- `FNSAVE_resets_x87`: 216 supporting rows; 0 contradictory rows
- `masked_trace_FXSAVE_reports_zero_FOP_FIP_FDP`: 1,944 supporting rows; 0 contradictory rows
- `float_store_C1_iff_magnitude_rounded_up`: 3,072 supporting rows; 0 contradictory rows
- `integer_store_C1_iff_magnitude_rounded_up`: 4,986 supporting rows; 0 contradictory rows
- `remainder_value_exact_for_completed_bounded_inputs`: 17,640 supporting rows; 0 contradictory rows
- `remainder_quotient_bits_absolute_low3`: 17,640 supporting rows; 0 contradictory rows
- `remainder_all_fixed64_chains_terminate_C2_clear`: 384 supporting rows; 0 contradictory rows
- `stack_overflow_IE_SF_C1_negative_indefinite`: 12 supporting rows; 0 contradictory rows
- `stack_underflow_IE_SF_C1zero_pop`: 12 supporting rows; 0 contradictory rows
- `stack_top_adjust_keeps_physical_full_tags`: 432 supporting rows; 0 contradictory rows
- `FNINIT_resets_x87`: 216 supporting rows; 0 contradictory rows
- `FNCLEX_clears_exception_SF_ES_B_preserves_CCs`: 216 supporting rows; 0 contradictory rows
- `all_unmasked_exceptions_deferred_to_next_waiting_probe`: 192 supporting rows; 0 contradictory rows
- `trap_state_equals_preprobe_hardware_snapshot`: 192 supporting rows; 0 contradictory rows
- `trap_has_ES_and_B_set`: 192 supporting rows; 0 contradictory rows

## Two-NaN selection

For the six ST0/ST1 arithmetic forms, a quiet NaN wins over a signaling NaN. When both inputs have the same quiet/signaling class, the larger significand wins and signaling results are quieted. The original signs/payloads remain observable. Equal-magnitude opposite-sign tie priority is not established by this sample. Slot payload tags use bit 8, so they do not dominate all original payload ordering.

- QQ: rows=288, ST0=216, ST1=72, IE=0
- QS: rows=288, ST0=288, ST1=0, IE=288
- SQ: rows=288, ST0=0, ST1=288, IE=288
- SS: rows=288, ST0=72, ST1=216, IE=288

## Invalid operations and pseudo formats

The negative binary80 indefinite is `ffffc000000000000000`. Defined invalid arithmetic and negative square roots are checked above independently of NaN/unsupported operands. Pseudo encodings are not silently canonicalized by the generator. The following tuples are literal `(result, FSW & 047f)` observations, aggregated across signs and FCWs; complete status/tag words remain in the raw rows. `FLD m80`/`FSTP m80` and sign-bit operations may preserve encodings which arithmetic rejects.

- pseudo-NaN, FABS: (7fff0000000000006666, 0000) × 12; (7fff4000000000005555, 0000) × 12
- pseudo-NaN, FCHS: (7fff0000000000006666, 0000) × 12; (ffff4000000000005555, 0000) × 12
- pseudo-NaN, FLD_m80: (7fff4000000000005555, 0000) × 12; (ffff0000000000006666, 0000) × 12
- pseudo-NaN, FSQRT: (ffffc000000000000000, 0001) × 24
- pseudo-NaN, FSTP_m32: (ffc00000, 0001) × 24
- pseudo-NaN, FSTP_m64: (fff8000000000000, 0001) × 24
- pseudo-NaN, FSTP_m80: (7fff4000000000005555, 0000) × 12; (ffff0000000000006666, 0000) × 12
- pseudo-NaN, FXAM: (7fff4000000000005555, 0000) × 12; (ffff0000000000006666, 0000) × 12
- pseudo-denormal, FABS: (00008000000000000001, 0000) × 24
- pseudo-denormal, FCHS: (00008000000000000001, 0000) × 12; (80008000000000000001, 0000) × 12
- pseudo-denormal, FLD_m80: (00008000000000000001, 0000) × 12; (80008000000000000001, 0000) × 12
- pseudo-denormal, FSQRT: (20008000000000000000, 0022) × 9; (20008000000000000001, 0022) × 1; (20008000000000000800, 0022) × 1; (20008000010000000000, 0022) × 1; (ffffc000000000000000, 0001) × 12
- pseudo-denormal, FSTP_m32: (00000000, 0030) × 9; (00000001, 0030) × 3; (80000000, 0030) × 9; (80000001, 0030) × 3
- pseudo-denormal, FSTP_m64: (0000000000000000, 0030) × 9; (0000000000000001, 0030) × 3; (8000000000000000, 0030) × 9; (8000000000000001, 0030) × 3
- pseudo-denormal, FSTP_m80: (00008000000000000001, 0000) × 12; (80008000000000000001, 0000) × 12
- pseudo-denormal, FXAM: (00008000000000000001, 0400) × 12; (80008000000000000001, 0400) × 12
- pseudo-infinity, FABS: (7fff0000000000000000, 0000) × 24
- pseudo-infinity, FCHS: (7fff0000000000000000, 0000) × 12; (ffff0000000000000000, 0000) × 12
- pseudo-infinity, FLD_m80: (7fff0000000000000000, 0000) × 12; (ffff0000000000000000, 0000) × 12
- pseudo-infinity, FSQRT: (ffffc000000000000000, 0001) × 24
- pseudo-infinity, FSTP_m32: (ffc00000, 0001) × 24
- pseudo-infinity, FSTP_m64: (fff8000000000000, 0001) × 24
- pseudo-infinity, FSTP_m80: (7fff0000000000000000, 0000) × 12; (ffff0000000000000000, 0000) × 12
- pseudo-infinity, FXAM: (7fff0000000000000000, 0000) × 12; (ffff0000000000000000, 0000) × 12
- unnormal, FABS: (40004000000000000101, 0000) × 12; (40004000000000000202, 0000) × 12
- unnormal, FCHS: (40004000000000000202, 0000) × 12; (c0004000000000000101, 0000) × 12
- unnormal, FLD_m80: (40004000000000000101, 0000) × 12; (c0004000000000000202, 0000) × 12
- unnormal, FSQRT: (ffffc000000000000000, 0001) × 24
- unnormal, FSTP_m32: (ffc00000, 0001) × 24
- unnormal, FSTP_m64: (fff8000000000000, 0001) × 24
- unnormal, FSTP_m80: (40004000000000000101, 0000) × 12; (c0004000000000000202, 0000) × 12
- unnormal, FXAM: (40004000000000000101, 0000) × 12; (c0004000000000000202, 0000) × 12

## C1 and rounding

The counted C1 hypotheses compare against exact rational arithmetic in a stated bounded finite domain (binary80 value exponent used in the integer significand representation −256…256), excluding overflow/underflow/invalid results. “Rounded up” here means increased magnitude, including a more-negative rounded result. It does not mean numerically toward +∞. Sqrt is checked using the exact squared rounded result. Store rounding is checked separately from arithmetic. The counts and any contradictions above delimit each claim. Undefined condition codes outside these checks remain hardware observations, not universal rules.

## Constants by rounding control

RC 0=nearest-even, 1=down, 2=up, 3=toward-zero. Each tuple has three supporting PC variants; disagreement across precision controls would produce multiple results below.

- FLD1, RC=0: 3fff8000000000000000 (3 rows)
- FLD1, RC=1: 3fff8000000000000000 (3 rows)
- FLD1, RC=2: 3fff8000000000000000 (3 rows)
- FLD1, RC=3: 3fff8000000000000000 (3 rows)
- FLDL2E, RC=0: 3fffb8aa3b295c17f0bc (3 rows)
- FLDL2E, RC=1: 3fffb8aa3b295c17f0bb (3 rows)
- FLDL2E, RC=2: 3fffb8aa3b295c17f0bc (3 rows)
- FLDL2E, RC=3: 3fffb8aa3b295c17f0bb (3 rows)
- FLDL2T, RC=0: 4000d49a784bcd1b8afe (3 rows)
- FLDL2T, RC=1: 4000d49a784bcd1b8afe (3 rows)
- FLDL2T, RC=2: 4000d49a784bcd1b8aff (3 rows)
- FLDL2T, RC=3: 4000d49a784bcd1b8afe (3 rows)
- FLDLG2, RC=0: 3ffd9a209a84fbcff799 (3 rows)
- FLDLG2, RC=1: 3ffd9a209a84fbcff798 (3 rows)
- FLDLG2, RC=2: 3ffd9a209a84fbcff799 (3 rows)
- FLDLG2, RC=3: 3ffd9a209a84fbcff798 (3 rows)
- FLDLN2, RC=0: 3ffeb17217f7d1cf79ac (3 rows)
- FLDLN2, RC=1: 3ffeb17217f7d1cf79ab (3 rows)
- FLDLN2, RC=2: 3ffeb17217f7d1cf79ac (3 rows)
- FLDLN2, RC=3: 3ffeb17217f7d1cf79ab (3 rows)
- FLDPI, RC=0: 4000c90fdaa22168c235 (3 rows)
- FLDPI, RC=1: 4000c90fdaa22168c234 (3 rows)
- FLDPI, RC=2: 4000c90fdaa22168c235 (3 rows)
- FLDPI, RC=3: 4000c90fdaa22168c234 (3 rows)
- FLDZ, RC=0: 00000000000000000000 (3 rows)
- FLDZ, RC=1: 00000000000000000000 (3 rows)
- FLDZ, RC=2: 00000000000000000000 (3 rows)
- FLDZ, RC=3: 00000000000000000000 (3 rows)

## Remainders, comparisons, stack and exceptions

FPREM/FPREM1 single-step rows include C2=1 partial reduction. Sixteen deterministic large finite pairs per command additionally run exactly 64 steps each, for all twelve FCWs; all terminal C2 checks and low quotient-bit hypotheses are counted above. Fixed continuation after completion is deliberate and exposes how the next completed remainder changes quotient bits.

- FPREM: C2_set=1104, C2_clear=12192
- FPREM1: C2_set=1104, C2_clear=12192
- FPREM1_ITER: C2_set=5868, C2_clear=6420
- FPREM_ITER: C2_set=5868, C2_clear=6420

FCOM-family quiet/signaling invalid-flag differences and unordered flags are counted above. FCOMI/FUCOMI snapshots retain CF/PF/AF/ZF/SF/OF; tested unordered comparisons clear OF/SF/AF while setting CF/PF/ZF. Stack tests cover all depths 0…8 and a separate sticky-status seed set. FFREE, TOP movement, exchanges, FNINIT and FNCLEX preserve literal full tags and every logical register.

Every unmasked trap includes the kernel-provided fault-time FSW and full80 register image, signal code, exact named faulting instruction, and a non-waiting FXSAVE immediately after the trigger. Signal return only masks pending exceptions and jumps past the probe; the exported TRAP record uses the untouched captured fault image. Full FTW is reconstructed on the same hardware from the saved abridged tag/register image; the same reconstruction was byte-compared against FNSTENV in every non-trapping record.

- DE_FLD1: rows=12, SIGFPE=12, probe=12, trigger=0, signal_code_5=12
- DE_FWAIT: rows=12, SIGFPE=12, probe=12, trigger=0, signal_code_5=12
- IE_FLD1: rows=12, SIGFPE=12, probe=12, trigger=0, signal_code_7=12
- IE_FWAIT: rows=12, SIGFPE=12, probe=12, trigger=0, signal_code_7=12
- OE_FLD1: rows=12, SIGFPE=12, probe=12, trigger=0, signal_code_4=12
- OE_FWAIT: rows=12, SIGFPE=12, probe=12, trigger=0, signal_code_4=12
- PE_FLD1: rows=12, SIGFPE=12, probe=12, trigger=0, signal_code_6=12
- PE_FWAIT: rows=12, SIGFPE=12, probe=12, trigger=0, signal_code_6=12
- STACK_OVERFLOW_FLD1: rows=12, SIGFPE=12, probe=12, trigger=0, signal_code_7=12
- STACK_OVERFLOW_FWAIT: rows=12, SIGFPE=12, probe=12, trigger=0, signal_code_7=12
- STACK_UNDERFLOW_FLD1: rows=12, SIGFPE=12, probe=12, trigger=0, signal_code_7=12
- STACK_UNDERFLOW_FWAIT: rows=12, SIGFPE=12, probe=12, trigger=0, signal_code_7=12
- UE_FLD1: rows=12, SIGFPE=12, probe=12, trigger=0, signal_code_5=12
- UE_FWAIT: rows=12, SIGFPE=12, probe=12, trigger=0, signal_code_5=12
- ZE_FLD1: rows=12, SIGFPE=12, probe=12, trigger=0, signal_code_3=12
- ZE_FWAIT: rows=12, SIGFPE=12, probe=12, trigger=0, signal_code_3=12

## Environment pointer and opcode updates

Both FXSAVE and legacy FNSTENV views are recorded. FXSAVE FOP/FIP/FDP on this CPU are zero in all sampled masked traces even while legacy FNSTENV reports the updated values; they are meaningful in the pending unmasked trap snapshots. This difference must not be mistaken for an absence of hardware pointer updates. `instruction` and `probe` denote exact assembly labels; `memory+N` is the exact operand offset; seed/restore tokens name public synthetic sentinels. No process address is exported. Unknown pointer values cause validation failure.

Below each tuple is `(FX FOP,FIP,FDP ; legacy FOP,FIP,FDP)`. FXSAVE/FNSAVE memory images additionally report their saved fields and register bytes in the rows.

- FLDENV: ('000', 'zero', 'zero', '456', 'restore-ip', 'restore-dp') × 216
- FNSAVE: ('000', 'zero', 'zero', '000', 'zero', 'zero') × 216
- FNSTENV: ('000', 'zero', 'zero', '321', 'seed-ip', 'seed-dp') × 216
- FRSTOR: ('000', 'zero', 'zero', '456', 'restore-ip', 'restore-dp') × 216
- FXRSTOR: ('000', 'zero', 'zero', '456', 'restore-ip', 'restore-dp') × 216
- FXRSTOR64: ('000', 'zero', 'zero', '456', 'restore-ip', 'restore-dp') × 216
- FXSAVE: ('000', 'zero', 'zero', '321', 'seed-ip', 'seed-dp') × 216
- FXSAVE64: ('000', 'zero', 'zero', '321', 'seed-ip', 'seed-dp') × 216
- TRACE_FADD_ST0_ST1: ('000', 'zero', 'zero', '0c1', 'instruction', 'seed-dp') × 216
- TRACE_FCOMI_ST1: ('000', 'zero', 'zero', '3f1', 'instruction', 'seed-dp') × 216
- TRACE_FLD1: ('000', 'zero', 'zero', '1e8', 'instruction', 'seed-dp') × 216
- TRACE_FLDCW: ('000', 'zero', 'zero', '321', 'seed-ip', 'seed-dp') × 216
- TRACE_FLD_m32: ('000', 'zero', 'zero', '106', 'instruction', 'memory+0') × 216
- TRACE_FNCLEX: ('000', 'zero', 'zero', '321', 'seed-ip', 'seed-dp') × 216
- TRACE_FNINIT: ('000', 'zero', 'zero', '000', 'zero', 'zero') × 216
- TRACE_FNOP: ('000', 'zero', 'zero', '1d0', 'instruction', 'seed-dp') × 216
- TRACE_FST_m64: ('000', 'zero', 'zero', '516', 'instruction', 'memory+0') × 216

## Independent C checks

- arithmetic:C-double-PC53-nearest: 5,825 comparisons
- arithmetic:C-long-double: 30,920 comparisons
- load-store:C-conversion-PC53-nearest: 861 comparisons
- load-store:C-long-double: 3,454 comparisons
- Mismatches: 0. Full mismatch list: numeric-crosscheck.json. PC53 arithmetic requires exact double-representable inputs and compares SSE double expressions; PC64 compares C long-double expressions for all four rounding modes.
- No double-rounding mismatch was observed in the explicitly eligible sample; this is not proof that double rounding cannot occur. Nonrepresentable input values, extreme exponents, and special values are skipped by these C-expression checks, but remain in the hardware tables.

## Correctly rounded transcendental crosschecks

Installed mpmath 1.3.0, 640-bit arithmetic; binary80 nearest-even rounding with subnormals. Only PC64/nearest native rows are compared; every comparison and exact input/output bit string is in transcendental-crosscheck-samples.jsonl.gz. Signed-zero FPATAN branches are handled explicitly. The “ordinary” bucket includes inputs next to multiples of π/2 and π, where relative/ULP errors can be large despite small absolute errors. “Large” means |input| ≥ 2^20. F2XM1 is checked only inside [−1,1]; domain/range skips are enumerated in the JSON report.

- FSIN/sin/ordinary: n=499, exactly rounded=425, within 1 ULP=465, >1 ULP=34, maximum distance=1376283091369227077 ULP
- FSIN/sin/large: n=42, exactly rounded=0, within 1 ULP=0, >1 ULP=42, maximum distance=1373791356063477329 ULP
- FCOS/cos/ordinary: n=499, exactly rounded=393, within 1 ULP=459, >1 ULP=40, maximum distance=1376283091369227077 ULP
- FCOS/cos/large: n=42, exactly rounded=0, within 1 ULP=0, >1 ULP=42, maximum distance=383215036661557324 ULP
- FSINCOS/cos/ordinary: n=499, exactly rounded=393, within 1 ULP=459, >1 ULP=40, maximum distance=1376283091369227077 ULP
- FSINCOS/sin/ordinary: n=499, exactly rounded=425, within 1 ULP=465, >1 ULP=34, maximum distance=1376283091369227077 ULP
- FSINCOS/cos/large: n=42, exactly rounded=0, within 1 ULP=0, >1 ULP=42, maximum distance=383215036661557324 ULP
- FSINCOS/sin/large: n=42, exactly rounded=0, within 1 ULP=0, >1 ULP=42, maximum distance=1373791356063477329 ULP
- FPTAN/tan/ordinary: n=499, exactly rounded=342, within 1 ULP=437, >1 ULP=62, maximum distance=1376283091369227077 ULP
- FPTAN/tan/large: n=42, exactly rounded=0, within 1 ULP=0, >1 ULP=42, maximum distance=1369251761978482056 ULP
- F2XM1/exp2m1/ordinary: n=429, exactly rounded=416, within 1 ULP=429, >1 ULP=0, maximum distance=1 ULP
- FPATAN/atan2/ordinary: n=699, exactly rounded=688, within 1 ULP=699, >1 ULP=0, maximum distance=1 ULP
- FPATAN/atan2/large: n=34, exactly rounded=34, within 1 ULP=34, >1 ULP=0, maximum distance=0 ULP
- FYL2X/ylog2x/ordinary: n=349, exactly rounded=347, within 1 ULP=349, >1 ULP=0, maximum distance=1 ULP
- FYL2X/ylog2x/large: n=17, exactly rounded=17, within 1 ULP=17, >1 ULP=0, maximum distance=0 ULP
- FYL2XP1/ylog2p1/ordinary: n=503, exactly rounded=495, within 1 ULP=503, >1 ULP=0, maximum distance=1 ULP
- FYL2XP1/ylog2p1/large: n=17, exactly rounded=17, within 1 ULP=17, >1 ULP=0, maximum distance=0 ULP

The large trigonometric ULP distances are actual discrepancies against the independent reference, not discarded failures. ULP distance here is the integer distance in the ordered finite binary80 representable-value sequence, accounting for exponent boundaries. A high-precision convergence check is recorded in numeric-validation.txt.
