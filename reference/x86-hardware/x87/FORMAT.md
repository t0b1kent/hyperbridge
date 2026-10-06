# Native x87 hardware reference

All three TASK.md stages are implemented in original MIT sources. Hardware executes every result row; the C and high-precision models only validate selected rows. No emulator, downloaded source or edited/reconstructed result line is used. The host exposes a hypervisor flag; hardware identity and tool versions are in MACHINE.txt.

## Reproduce in one command

```
bash run.sh
```

Requires native Linux x86-64 with RDTSCP and invariant TSC, GCC, Python 3 with the already-installed mpmath module, gzip, binutils and GNU timeout. No packages were installed. This regenerates assembly/input manifests, compiles the native harness, runs every class twice, compares raw and deterministic compressed bytes, checks counts, independently crosschecks C arithmetic/conversions, verifies high-precision rounding convergence at 320/640 bits, and rebuilds COVERAGE.md/RULES.md and JSON audits. Build intermediates stay in build/ and are excluded from delivery. Each native class has a 900-second timeout. To rerun one class without the aggregate numeric audit, use e.g. `bash run.sh load-store`.

Each out-CLASS.sha256 hashes the UNCOMPRESSED out-CLASS.txt, matching work/0001's convention. COMPRESSED-SHA256.txt separately hashes the delivered .txt.gz files. Stage-1 interim v1 used explicitly named .txt.gz hashes; v2 and this final format use .txt raw hashes. No hardware record was changed to resolve that packaging convention.

## Delivered content

- generate.py, harness.c, run.sh: original hardware corpus sources
- forms.json, inputs.json, expected-counts.txt: exact forms, input bits and precomputed row counts
- out-*.txt.gz, out-*.sha256, out-*.validation.txt: eight hardware classes, hashes and repeat/count evidence
- numeric_crosscheck.c, validate_numeric.py: independently compiled C expressions/conversions and mpmath correctly rounded binary80 reference
- numeric-crosscheck.json, transcendental-crosscheck.json, transcendental-crosscheck-samples.jsonl.gz, numeric-validation.txt: full selected validation evidence
- context_switch_probe.c, signal_context_probe.c and their observations; capture-interference-evidence.json and capture-stress-validation.txt: transparent interruption/isolation evidence
- analyze.py, validation-summary.json, encoding-validation.json: counted empirical hypotheses, per-form instruction decoding and structural audit
- COVERAGE.md, RULES.md, PROGRESS.md, MACHINE.txt, NOTES.md, LICENSE, DONE.md (only when final checks pass)

## Native capture contract

Each test starts from a freshly restored FXSAVE64 image: all twelve precision/rounding FCWs, masked exceptions, clean FSW, and known occupied registers. Trap tests unmask one exception class. Explicit control-state tests use declared condition/sticky-status seeds to test FNINIT/FNCLEX/save/restore behavior; these exceptions to the clean-state convention are identified by case and metadata. No C floating-point calculation initializes hardware inputs: all input bits are fixed integers.

The out-of-line assembly wrapper restores the input, seeds arithmetic RFLAGS, executes the single tested instruction, and captures FXSAVE64 then FNSTENV. These snapshots neither pop nor round any register. FTW is the full two-bit-per-PHYSICAL-register word. ST0/ST1 and STACK metadata are in LOGICAL stack order, with TOP from FSW; empty registers are shown as `empty`. Every non-trap record additionally compares its full FNSTENV tag word against hardware reconstruction via FXRSTOR64, including nonzero TOP, special values and stack faults. The inline reconstruction helper explicitly clobbers every affected XMM/x87 compiler register.

NaN input slot 1 flips payload bit 8, distinguishing even same-pattern input NaNs after quieting. Its small tag does not dominate all payload orderings. This improves the final sampling from the first stage-1 snapshot while retaining exactly the same row counts; final hashes supersede those interim hashes.

For SIGFPE, a non-waiting FXSAVE immediately after the exception trigger captures pre-probe state. The next instruction is exactly FWAIT or FLD1. The signal handler copies the kernel fault image untouched before masking pending exceptions and advancing saved RIP past the probe for recovery. The exported TRAP row uses the captured fault image, not the recovery state. A full FTW is reconstructed on hardware from the captured abridged tag/register image; the reconstruction method is verified against every non-trapping snapshot. Signal code and trigger/probe location are explicit.

## Interruption isolation and its limits

Masked legacy pointer fields can be lost across OS/signal save/restore on this AMD host. The delivered corpus measures isolated instruction windows: unchanged thread context-switch counters, no TSC_AUX migration and at most 5,000 TSC ticks around the full restore/instruction/snapshots window. A rejected whole window is rerun from exactly the original input, at most 128 attempts, with explicit failure rather than a missing case. No result value participates in acceptance. A slower host may exhaust this published bound; the program fails explicitly rather than silently relaxing it. Intentional SIGFPE cases are latency-exempt while retaining the counter guard. Timing/rejection diagnostics are kept out of deterministic output.

This condition is independently supported by scheduler/signal probes and 100 identical filtered environment stress runs. The separate unfiltered diagnostic corpus found ten actual pointer-loss captures, all slow windows; their untouched rows and timings are delivered in capture-interference-evidence.json. See NOTES.md and the original probe sources/results for the evidence and remaining attribution limits. This is an isolated-instruction reference; arbitrary OS/host interference is separately documented rather than presented as deterministic CPU behavior.

## Record format

The first fields follow TASK.md:

```
NAME FCW_BEFORE ST0 ST1 MEMORY_OPERAND -> [TRAP] ST0 ST1 MEMORY_RESULT FSW FTW FLAGS
```

All values are hardware bit patterns in fixed-width most-significant-byte-first hex. FLAGS exists only for FCOMI/FUCOMI families and masks CF/PF/AF/ZF/SF/OF (08d5); those six bits are initially set so clearing is observable. `-` means no applicable operand/result. Initial input ST2…ST7 use exact integers 3…8 when occupied, unless a restore case supplies the explicitly displayed memory image.

Stack, environment, remainder-chain and trap records append self-describing `KEY=value` fields. Environment addresses are never printed as machine pointers: exact instruction/probe labels, memory+offset and named public input sentinels are used. Unknown addresses fail validation. Both the FX and legacy environment views are reported because this CPU suppresses FX FOP/FIP/FDP in masked cases while FNSTENV retains meaningful updates. SAVED_* fields contain the save instruction's memory result (including full80 saved registers), replacing a monolithic environment MEMORY_RESULT hex field whose pointers and reserved bytes would be nonportable. Restore input memory is literal hex because its pointer values are fixed public sentinels. See RULES.md for field-specific empirical behavior.

## Scope and limits

COVERAGE.md gives every mnemonic/form/count and the exact bounded sampling policy. No requested instruction family or architecturally existing requested memory width is omitted. In particular, non-popping FST m80 and FIST m64 do not exist; the actual FSTP m80 and FISTP/FISTTP m64 encodings are covered. Register-index permutations, every possible bit pattern, equal-payload opposite-sign NaN priority, and all environment reserved bits are not claimed exhaustive. Transcendental discrepancies against correctly rounded values are reported, including large errors near multiples of π and for large arguments; they are not discarded.

Read PROGRESS.md and DONE.md for completion status.
