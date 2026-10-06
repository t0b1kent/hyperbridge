# Synthetic instruction cost

`hardware-gates` builds `codegen_runner` from the candidate's FEXCore objects and
measures 26 authored assembly shapes: the 21 forms in the root `COMPARISON.md`
and five linked-list, array, call and integer-division kernels. Inputs are
assembled afresh with Clang. There are no application captures or saved states.

## Submit a candidate and read its cost

1. Supply plain source patches over the current `fex/patches` series and two
   literal environment maps, `off` and `on`. Declare at most one differing key.
   Include no binary, captured input, personal path or credential.
2. Prepare `stands/hardware/candidates/<neutral-name>/` using the
   [hardware candidate contract](../hardware/README.md): `candidate.json` pins
   the base-series hash and ordered patch hashes; `arms.json` contains the maps.
   Give the coordinator the local commit and candidate path for publication review.
3. The coordinator publishes and dispatches `hardware-gates.yml`, selecting that
   candidate and `mode=quick`, with `reuse_run` empty. A push alone tests the
   published series; it does **not** select an overlay candidate automatically.
4. Download `instruction-cost-RESULT` from that run:

   ```sh
   gh run download RUN_ID -R t0b1kent/hyperbridge -n instruction-cost-RESULT -D cost-result
   ```

5. Read `TABLE.md` and `RESULT.json`: `rows[].off/on.arm_per_guest`,
   `arm_instructions`, `guest_instructions`, `host_code_bytes`; `on_minus_off`
   exposes the candidate key's static delta. Check A/A, features and the
   comparison status before interpreting the numbers. ENGINE-108, ARITH,
   SHORT-SEQ, X87-FAST and DIV use this same path; no local FEX build is needed.

Each arm is compiled twice in a fresh process. The artifact
`instruction-cost-RESULT` contains generated assembly, object files, exact input
requests, native output and feature logs, `RESULT.json` and `TABLE.md`. Generated
objects and native binaries are artifact-only, never repository inputs.

ARM instructions are decoded with pinned Capstone from FEX debug subblock ranges.
Allocation bytes, emitted code bytes and translated guest instructions are
separate fields. This is **static reachable entry-region cost**, including its
exit machinery. It excludes dynamically reached callees and shared helper
bodies; it does not count executed iterations. A change in translated guest
coverage makes a baseline comparison INCOMPARABLE, rather than improving a ratio.

Compilation nanoseconds are noisy VM reference measurements. Guest execution is
NOT_RUN; these values are not execution latency, throughput, native performance
or game FPS. Hardware correctness remains the separate hwflags/hwsimd gate.

The first qualification emits BASELINE_REQUIRED, with no no-growth claim. Later
pushes compare against the newest measured, successful main `hardware-gates`
run among the last 20 successful runs; artifacts must still exist. The workflow
uses only read access. The baseline commit, source identity, feature description
and both sets of environment keys remain in the receipt. Host/features or input
changes are INCOMPARABLE. Either ARM instruction or code-byte growth is GROWTH
and fails this job; A/A drift also fails. Off/on deltas are always reported.
Review intentional growth and changed configurations explicitly; this gate does
not establish causality across different compositions.

The frontend still needs its first cloud qualification. To run the inexpensive
protocol/generator tests (no FEX build or execution):

```sh
python3 -m unittest discover -s stands/instruction-cost -p 'test_*.py'
```
