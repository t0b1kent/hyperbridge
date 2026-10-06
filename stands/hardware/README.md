# Hardware correctness gates

The `hardware-gates.yml` workflow builds the published FEX patch series on
native `macos-15` ARM64, then checks authored hardware tables through the native
runner. It does not require Wine, game files, recorded game execution, memory
images or a private repository. Nothing is sent to upstream FEX.

Inputs are `candidate.json`, plain translator patches and `arms.json` in a reviewed
candidate directory. `arms.json` is parsed data, never shell code. The supplied
`release-1.0.8` candidate has no extra patches and identical off/on environments:
it is the initial A/A composition. Later candidates may vary one environment key.
The patch series and candidate bytes are hashed, and each runner bundle carries
its source, toolchain, host and output identity. Binary products are CI artifacts.

The build reuses `fex/build.sh` with `FEX_PREPARE_ONLY=1` (PE/WOW64 build and install
skipped) and the synthetic stand's native CMake recipe. The hardware frontend adds
the existing SIMD fault-state reconstruction and per-thread HW-TSO admission.
Dependencies are fetched from upstream with their own licenses; none are vendored
here. `capstone==5.0.7` verifies assembled instruction boundaries. SIMD instructions
are assembled from the authored encoding descriptions during the build, and the
complete form-to-instruction-byte map must match the historical accepted SHA.

Pushes affecting the series or stand run quick automatically; manual dispatch
selects quick/full, and the weekly Monday 03:17 UTC schedule runs full. Automatic
runs create an ephemeral `published-ci` candidate pinned to the current series;
manual `release-1.0.8` retains its original pin for local/cloud qualification.
`actions/cache` stores the FEXCore ccache under a patch-series fingerprint, with
separate accepted/negative keys and frontend/candidate suffixes. Cache hits do not
skip correctness gates. Compiler/source changes remain part of ccache's own key.

Each component has one quick job and four modulo-distributed full jobs per arm:
hwflags 2,204 / 1,624,804 rows; hwsimd 3,021 / 919,405 rows. One runner per shard,
native build parallelism two. Each job has a 30-minute limit; shards stop after a
23-minute budget between batches. Completion within 30 minutes remains unmeasured
until the first cloud run; queue delay is not covered by a job timeout.

`hardware-gates-RESULT/RESULT.json` and `VERDICT.txt` are the aggregate result.
Cell artifacts preserve raw states, native logs, row comparisons, counts, CPU
user/system seconds and hashes. Missing/duplicated/truncated cells or changed
inputs fail the aggregate. The merger restores filename + numeric line order.
`serial_canonical_sha256` hashes that complete stream (flags comparison records;
SIMD `{key, comparison}` records). For full, `canonical_sha256` reproduces the
historical local two-part contract: alternate serial rows into two SHA-256 streams,
then hash their JSON list for flags or their concatenated hex for SIMD. These two
logical parts are independent of the actual number of cloud shards. Quick uses
the serial fingerprint directly. `fingerprint_contract` and `local_part_sha256`
make the encoding explicit; unequal hash formats must not be compared directly.

To correct aggregation without repeating native work, dispatch the same candidate
and mode with `reuse_run` set to the original completed run ID. Only plan and
verdict run; the merger downloads `hardware-cell-*` from that run and verifies
their candidate identity, coverage and raw evidence hashes. The original run and
its FAIL remain preserved.

The second build applies `controls/div-overflow-disabled.patch` to the translator.
Its quick hwflags result must be complete and FAIL with new **defined** errors.
A timeout, failed build, missing output or infrastructure error cannot satisfy the
control. The artifact keeps the original FAIL; the final verdict records
`FAIL_AS_EXPECTED` only when this condition is met.

Tables are our own measured instruction inputs/results: AMD EPYC 9V74 Zen4 flags
and SIMD; Intel flags from accepted run 37123100337 (four matching accepted repeats,
one copy stored). `data/MANIFEST.json` pins every file. The Intel data is preserved
separately; the accepted AMD registry is never applied to Intel observations.
The two compressed known-row files contain only synthetic hardware comparisons.
Defined errors are never admitted; the existing manual registry allows only exact
known undefined/fault deltas or repairs. No candidate can extend that registry.
`reviewed-flags.json` changes one historical private path to a basename; its
original hash is recorded in `known-hwflags.json`. Numerical rules are unchanged.

The existing limitations remain: one AMD processor's partial gather order,
270 SIMD rows with unavailable full memory results, and the lower masked-gather
blind region caused by macOS 16 KiB pages. These are not credited as full equality.

Local equality targets are in `data/local-reference.json`. They are historical
receipts, not proof that the new public build or cloud host is identical. Use
`compare.py --component hwflags --local LOCAL.semantic.jsonl.gz --cloud CLOUD.semantic.jsonl.gz --out comparison.json`
(or `hwsimd`) for differing/missing row counts and the first twenty differences.
Do not diagnose CPU causality from a hash alone. Hardware PASS is correctness
coverage only; it says nothing about game acceptance or FPS.

The initial no-patch A/A candidate also requires matching off/on fingerprints and
the recorded local hashes. Candidate runs still report local-hash differences,
but a deliberate repair is judged by the original comparison rules.

Protocol tests: `python3 -m unittest discover -s stands/hardware/tests -v`.
These use tiny artificial records and launch no guest code.
