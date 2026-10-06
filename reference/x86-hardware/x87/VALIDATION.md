# Final validation

- All 156 generated target instructions independently decoded; zero mnemonic/encoding mismatches. Reverse subtract/divide forms and pop orientation additionally checked by ordinary C expressions.
- All eight classes, 854,292 records, rebuilt from final sources and executed twice. Raw bytes and deterministic gzip bytes match; exact per-form/per-FCW counts match the precomputed manifest.
- Raw and compressed hashes independently checked against the previous stable audit snapshot; the compiler-clobber and capture-isolation changes did not change accepted native result bytes.
- 41,060 C arithmetic/conversion comparisons, zero mismatches. Arithmetic references distinguish C long double at PC64/four RCs from C double at PC53/nearest. Conversion reference types and eligibility are explicit in source and report labels.
- 4,753 transcendental components compared with correctly rounded binary80 values; references at 320 and 640 bits agree exactly. Hardware inaccuracies remain visible with per-component ULP distances and aggregate counts.
- All 192 unmasked exceptions occur at the following FWAIT/FLD1 probe. Fault-time full80 image, FSW, abridged tags and all logical stack values equal the immediately pre-probe hardware snapshot. All non-trapping full tags agree with hardware reconstruction.
- All 384 fixed-64-step remainder chains end with C2 clear. Completed finite quotient/remainder checks agree in 17,640 records.
- 100 isolated environment runs are byte-identical. Unfiltered interference and independent scheduler/signal reproductions are retained and discussed, rather than hidden. The published timing/migration/context-counter guard never tests output values, retries whole initial-state trials, and fails after 128 attempts.
- Final source/capture/pointer-normalization/tag mapping and hash review found no remaining blocker. The environment's hypervisor and the isolated-window condition remain explicit limitations.

Detailed reproducible evidence: out-*.validation.txt, numeric-validation.txt, encoding-validation.json, validation-summary.json, numeric-crosscheck.json, transcendental-crosscheck.json, capture-stress-validation.txt and capture-interference-evidence.json.
