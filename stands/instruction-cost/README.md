# Synthetic instruction cost

`hardware-gates` builds `codegen_runner` from the candidate's FEXCore objects and
measures 26 authored assembly shapes: the 21 forms in the root `COMPARISON.md`
and five linked-list, array, call and integer-division kernels. Inputs are
assembled afresh with Clang. There are no application captures or saved states.

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
