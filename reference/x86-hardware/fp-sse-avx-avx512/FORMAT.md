# x86 native floating-point instruction reference

Original MIT-licensed C, Python and assembly-generation code for MacRunner / HyperBridge. Results are produced only by executing the exact target instructions on the recorded native Linux x86-64 CPU. The machine is virtualized (CPUID hypervisor flag), but no instruction emulator was used. No packages or third-party source code were downloaded for this submission.

## Rebuild in one command

```sh
./run.sh
```

Requires Linux x86-64, GCC, Python 3, gzip, sha256sum and an assembler supporting AVX-512. It builds the generator, executes all eight result classes twice, checks raw and timestamp-free gzip byte equality, writes decompressed SHA-256 hashes, validates counts and the 60,000,000-byte gzip budget, and refreshes COVERAGE.md/inventory.json/validation-summary.json. Individual classes can be rebuilt, for example:

```sh
./run.sh arithmetic fma comparison approximation
```

Native CPU and OS vector-state requirements are checked before any class prints results. Missing capabilities produce an explicit UNAVAILABLE exit, never emulated or invented results. The shared EVEX harness additionally requires AVX512BW for full-width KMOVQ mask capture; packed 128/256 EVEX forms require AVX512VL. All implemented forms were available on this machine. MACHINE.txt records CPU model/flags, kernel and compiler, without hostname, network addresses or credentials.

## Result files and interpretation

`out-<class>.txt.gz` contains one row per actual execution. `out-<class>.sha256` hashes the decompressed stream; `out-<class>.validation.txt` records expected/observed rows, traps, destination-preservation checks, ordinary C cross-checks and repeatability. `inventory.json` contains the complete form descriptors and predicted row counts. `COVERAGE.md` maps each mnemonic and encoding to form/row counts and explicitly lists omissions.

X1 is the real destination before execution (or first comparison source for COMIS); X2/X3 follow Intel operand order. Missing X3 is `-`. Hex values print most-significant byte/lane first. Operand registers are complete at the declared 128/256/512-bit width, except asymmetric conversion operands and GPR/MMX operands, whose actual byte widths are recorded in the form descriptor and reflected in printed hex lengths. EVEX narrowing conversions also expose destination zero-extension through the declared observation width. Results in GPRs are exactly 32 or 64 bits; mask results are 64 bits, including inactive high bits.

Scalar unused lanes contain distinct destination/source sentinel patterns. Legacy scalar arithmetic preserves destination high lanes; VEX/EVEX scalar source-merging behavior is therefore directly visible. COMIS/UCOMIS output is `(LAHF_AH << 8) | OF`, matching the supplied task convention; the initialized flags would print `d701`. For EVEX COMIS the required metadata fields show `k=0 z=0`, because those forms do not use a writemask.

## MXCSR and real unmasked exceptions

Every individual target instruction is immediately preceded by LDMXCSR with clean status bits. The 13 settings are:

- `1f80`: nearest, all masked
- `3f80`, `5f80`, `7f80`: the other three rounding modes
- `1fc0`, `9f80`, `9fc0`: DAZ, FTZ, both
- `1f00`, `1e80`, `1d80`, `1b80`, `1780`, `0f80`: invalid, denormal, divide-by-zero, overflow, underflow, precision individually unmasked

The SIGFPE handler verifies the fault occurred at the exact tested instruction and captures MXCSR from the Linux signal context before changing anything. It masks exceptions only in the saved continuation context and moves RIP to the label immediately after the single faulting instruction. `sigreturn` restores the actual fault-time register file; normal native output stores then capture the preserved destination. A TRAP row prints the original fault-time MXCSR, not the handler's continuation mask. Every trapped vector/GPR/MMX/mask destination is compared byte-for-byte with its initialized value; COMIS preserved flags are checked independently. No trap result is synthesized or substituted from the input. Unexpected faults terminate the run.

## Inputs and bounded sampling

The 16 core IEEE values are ±0, ±1, 2, ±infinity, signed quiet/signalling NaNs with distinguishable payloads, minimum/maximum subnormal, minimum normal, and signed finite maxima. Additional explicit float/double values cover every boundary listed in tasks/0002, arithmetic overflow/underflow/inexact cases, signed minimum-normal/subnormal values, neighboring one, and binary16 rounding/range boundaries. Signed/unsigned integer inputs include extrema and the 2^24/2^53 representability transitions. Binary16 inputs have their own raw-bit corpus.

Quiet and signalling NaNs remain distinguishable after setting the quiet bit. For binary32/64, class namespace bits lie above all operand/lane tag bits. Binary16 dedicates two non-quiet payload bits to four classes and seven bits to source/lane identity. All 384 possible binary16 class/source/lane combinations remain 384 unique payload patterns after quieting. The current results supersede early payload-colliding snapshots.

- Stage 1 scalar forms cross all 16 core values on every true input axis: 16 or 256 or 4,096 tuples, followed by 64 deterministic boundary tuples. Overwritten destination low bits do not introduce an axis; required preserved/copied high bits retain visible sentinel patterns. Forms that deliberately include an otherwise-unused low source retain that axis in the inventory
- Stage 1 packed forms use 64 deterministic mixed-lane cases: 48 typed-corpus rotations plus 12 isolated non-low-lane NaN cases (quiet/signalling, each source) and 4 mixed-NaN cases. Each typed lane and source receives distinct values/payload tags
- EVEX non-immediate forms use 64 cases. Scalar sources cycle through every typed-corpus value while retaining distinct high-lane sentinels. Packed forms follow the 64-case mixed-lane rule
- EVEX immediate forms use 16 cases. Scalar sources cycle all 16 special values with fixed source offsets. Packed forms use 12 mixed-special vectors plus isolated signalling NaN in lane 1 of each source and one mixed-NaN case
- VFIXUPIMM's integer table source uses each of the 16 response codes, repeated into all 8 table nibbles; scalar case `c` uses code `c %16`, packed lane `j` uses `(c+j) %16`. This covers every response code without enumerating all 2^32 mixed tables
- Every meaningful immediate value is included. EVEX extra mask/zero/rounding/SAE combinations use endpoint immediates; intermediate immediates use all-active merge/non-SAE. Non-immediate forms exercise all prescribed controls. Redundant ignored-ER encodings of exact I32/U32-to-F64 conversions and ignored immediate-bit aliases are omitted; VGETMANT high immediate bits are specified Must Be Zero. See evex-notes.md for exact rules

This bounded Stage 2 input/control sampling keeps all requested instruction mnemonics and legal widths while staying below 60 MB compressed. It does not claim exhaustive EVEX scalar Cartesian combinations or full packed/control cross-products. Exhaustive Stage 1 scalar special-value products are retained.

## Verification

Each class was run natively twice, with byte-identical raw streams and gzip output (`gzip -n -9`). Predicted rows are calculated from the form inventory before execution and independently re-counted from the gzip streams. Select ordinary results are computed separately using C `float`/`double` arithmetic and `fma` with contraction disabled: 1,601 arithmetic plus 2,292 FMA rows, zero mismatches. All trap-preservation checks pass. Validation includes NaN quieting-payload uniqueness, native instruction encoding disassembly and scalar high-lane preservation; no software floating-point model supplies the result rows.

See COVERAGE.md and validation-summary.json for final counts and compressed size. Unsupported encodings, intentional scope exclusions and sampling limits are enumerated explicitly rather than counted as covered. Source modules and generators are authoritative; build/ and evex-build/ are reproducible local intermediates and need not be transferred.
