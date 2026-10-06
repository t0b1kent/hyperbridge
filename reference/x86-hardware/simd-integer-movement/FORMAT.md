# Native SSE / AVX / AVX2 integer and data-movement reference

Task classes **1–10** are implemented. This is a hardware reference from the AMD EPYC 9V74 identified in MACHINE.txt and crypto-machine.txt: **919,405 rows**, **7,339,822 compressed result bytes**, under the 60 MB limit. No software emulator or outside source code is used. The provider VM advertises a hypervisor; the programs execute its native x86-64 instruction stream directly, without claiming bare-metal provenance.

## Rebuild and execute

```
bash run.sh
```

Run only on native Linux x86-64 with OS-enabled YMM state and the recorded CPU features (AVX2/SSE4.2/AES/PCLMUL/SHA/VAES/VPCLMUL). **Do not execute on the receiving Mac or under emulation.** Required tools are GCC/cc, GNU binutils, Python 3, gzip and coreutils. Each binary invocation has a 900-second timeout. No network, package installation, external source or dependencies are downloaded.

The command regenerates assembly and manifests from original MIT source, compiles, audits linked opcodes and controls, executes every class twice, compares deterministic gzip/raw output, verifies expected counts and raw hashes, and enforces the compressed-size budget. The priority classes 1–6 and 10 run first, followed by gathers, strings and crypto. SOURCE-VERIFICATION.txt records an additional clean source-only one-command rebuild: no generated assembly/headers/manifests, binaries, caches or results were copied, and every output matched the submitted bytes.

The scalar C checks are compiled with tree and SLP vectorization disabled. They validate measurements; they never supply, patch or replace an instruction-result row. All classes also passed a separate UBSan build with identical output (SANITIZER-CHECKS.txt); reproduce with bash sanitize.sh after run.sh. Input values and reductions are fixed, without timestamps or randomness.

## Files and conventions

- out-CLASS.txt.gz: native result stream, gzip -n with no timestamp
- out-CLASS.sha256: SHA-256 of the **decompressed out-CLASS.txt**, not the gzip file
- validation-summary.json: exact rows, raw hashes and compressed/uncompressed sizes
- COVERAGE.md and family COVERAGE reports: command-by-command encodings/forms/rows, sampled inputs and exact omissions
- RULES.md and family RULES reports: empirical behavior, support counts and counterexamples
- Manifests, opcode audits and validation logs: precomputed form counts and linked instruction checks
- LICENSE: original code is MIT; generators and harnesses are supplied; build/cache/raw repetitions are omitted from transfer archives

The canonical prefix is name[imm] destination_width X1 X2 X3 -> RESULT. X1 and the first result are the actual destination before and after: full 256-bit YMM snapshots for vector destinations, width-sized hex values for GPR/memory destinations, and captured low16 flags for PTEST/VTEST. String index forms use ECX32. Vector register values always print all 256 bits, high byte first, even when the destination width is 128. Width describes the destination; encoding width is separate form metadata/name suffixes. Actual source values occupy X2/X3; absent sources are -. Named auxiliary evidence follows the primary result, including additional blend masks, full64 GPR preservation, full-YMM source/implicit-register snapshots, flags and fault details.

UNKNOWN explicitly marks a full memory value that cannot be read because part or all of its span lies in a guard page. It never substitutes for a register result. Actual readable memory prefixes are separately printed with ACCESSIBLE_BYTES; zero bytes are not fabricated for inaccessible primary memory values. This affects 270 masked-store destination rows. Gather MEM_INPUT candidate-lane placeholders are separately labeled by VALID_LANES; they are not primary destination results. No addresses are printed. Family reports and format auditors specify these additional fields.

Actual alignment and protected-memory faults remain in the reference. Signal handlers capture fault-time vector/GPR/flag context or return through sigreturn into the exact wrapper continuation; only the tested instruction is skipped when needed. Protected tests access exclusively the process's own mmap allocation and guard pages. No external or kernel memory is accessed.

## Verification limits

**899,771 nonfaulting rows receive complete independent scalar numerical comparisons. All 19,634 actual fault rows separately receive fault-context/state-invariant comparisons. Every check passes. There are no unmodeled successful rows.** Equal-ordered strings and all SHA operations have original scalar models; fault observations are not misrepresented as successful numerical results. All 919,405 canonical prefixes, per-family destination mappings and raw hashes are checked.

All requested legal SSE/VEX128/VEX256 mnemonic/operand/immediate families are retained where those encodings exist. MMX, EVEX/AVX-512-only forms, privileged instructions, redundant register/prefix/address-size aliases, unrelated non-temporal moves and exhaustive input Cartesian products are outside the scope. POPCNT is intentionally left to task 0002.
