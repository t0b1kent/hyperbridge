# Native x86 hardware references

Measured reference corpora and original MIT probes, prepared October 6, 2026. Each directory describes its processor, measured scope, text formats, repetition checks and reproduction command. The AMD corpora were measured in a cloud VM; the Intel corpus is a distinct macOS x86 runner. These data are observations of those exposed machines, especially for architecturally undefined behavior.

- [fp-sse-avx-avx512](fp-sse-avx-avx512/README.md): 15,410 native forms; 8,773,024 rows; 391,157 preserved SIGFPE destinations. Two byte-identical captures; 3,893 C crosschecks with zero mismatches.
- [integer-flags-amd](integer-flags-amd/README.md): 1,624,804 rows in classes 1–10, two byte-identical captures; zero defined-semantics mismatches.
- [x87](x87/README.md): 156 forms; 854,292 native records; two byte-identical captures; 41,060 C checks and 4,753 high-precision components checked at 320/640 bits.
- [legacy32-bcd](legacy32-bcd/README.md): 696,928 native rows; 274 traps; 4,840 cross-mode pairs; two byte-identical captures and zero defined-semantics mismatches.
- [simd-integer-movement](simd-integer-movement/README.md): 919,405 rows in all ten classes; 899,771 numerical comparisons and 19,634 fault/state checks; zero mismatches; repeated raw/gzip results match.
- [native-loop-timing](native-loop-timing/README.md): 26 loops, two runs, five samples per loop in each run; one thread pinned to logical CPU 0.
- [x87-double-boundaries](x87-double-boundaries/README.md): 701,961,852 cases including 700 million random trials and boundary inputs; seven deterministic correctness suites repeated byte-for-byte. Timing is not byte-reproducible.
- [inc-dec-cmp-test](inc-dec-cmp-test/README.md): 492,832 data rows per run: A 100,832; B 100,832; C 289,120; D 2,048. Two complete captures have identical CSV bytes.
- [write-fault-rmw-part-a](write-fault-rmw-part-a/README.md): Addendum A: 264 measured page-cross continuation-2 cells (176 requested-core + 88 additional legal variants); two identical captures. Another 264 cache-line-only/half-RO cells are explicit N/A.
- [integer-flags-intel](integer-flags-intel/README.md): 1,624,804 integer rows, compared across first/repeat captures by the runner comparison report; raw streams are retained. See FORMAT.md for the tested matrix.

Part B of the write-fault/concurrent split-lock submission and the unfinished exception-class submission are excluded. Correctness results are not cross-machine performance rankings. Archives contain only original source/text, never ELF, PE, object files or captured proprietary code.

The Intel-advertised runner's two anti-translation sysctl fields were UNKNOWN; its native backend is inferred from runner provenance, not independently proven by those fields. The dataset README preserves this distinction. The AMD native instruction captures and the separate Windows hardware reference have their own recorded provenance.

- [null-noncanonical-branches](null-noncanonical-branches/README.md): independently accepted section A, 50 Linux hardware cells repeated byte-for-byte; the unsuccessful Wine section B is excluded.
