# Core empirical rules (this CPU only)

All counts below are read from the actual native output files. Every stated rule has zero observed counterexamples in the listed sample; this does not claim exhaustive input proof.

- arithmetic_legacy_upper_preserve_support: 4592; counterexamples: 0
- arithmetic_vex128_upper_zero_support: 6888; counterexamples: 0
- fault_destination_preservation_support: 12816; counterexamples: 0
- logic_legacy_upper_preserve_support: 960; counterexamples: 0
- logic_vex128_upper_zero_support: 1440; counterexamples: 0
- oversized_shift_elements: 299388; counterexamples: 0
- oversized_shift_rows: 43665; counterexamples: 0
- pack_legacy_upper_preserve_support: 192; counterexamples: 0
- pack_vex128_upper_zero_support: 288; counterexamples: 0
- permutation_legacy_upper_preserve_support: 19200; counterexamples: 0
- permutation_vex128_upper_zero_support: 38160; counterexamples: 0
- pshufb_high_mask_bytes: 2910; counterexamples: 0
- pshufb_high_mask_rows: 180; counterexamples: 0
- shifts_legacy_upper_preserve_support: 21120; counterexamples: 0
- shifts_vex128_upper_zero_support: 21800; counterexamples: 0

Oversized logical shifts produce zero elements; oversized arithmetic right shifts produce the sign fill. PSHUFB zeroes every selected byte whose control high bit is one. Packed 256-bit shuffle/unpack/pack operations in the task that are lane-local agree with the scalar lane-local model. Legacy writing forms preserve YMM[255:128]; VEX-128 writing forms clear it. PTEST/VPTEST/VTEST do not write any vector register, so their VEX encodings preserve the entire input vector rather than zeroing an imaginary destination. Actual alignment-fault rows preserve all destination bits.

The apparent “VEX always zeros upper bits” shorthand applies only when an instruction writes the XMM destination. Stores, flag tests and instructions with only GPR results must be considered separately. All 256 VZEROUPPER/VZEROALL register observations pass their scalar rule: 128 observations preserve the low half/clear the high half, and 128 clear the full YMM register.
