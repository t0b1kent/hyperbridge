# Store-through guest register forwarding

`MACRUNNER_HB_REG_FORWARD=1` and `MACRUNNER_HB_XMM_FORWARD=1` independently
enable the final ARM64 pass in `src/hb_reg_forward.c`. Both default to zero;
both, and `MACRUNNER_HB_TEST_REG_FORWARD_FLIP`, enter the persistent cache key.

The pass replaces a repeated GPR LDR X/W or XMM LDR Q with a register move or
NOP. Every store remains byte-for-byte intact. It allocates no runtime host
registers and does not change native code size, relocations or fault offsets.
Canonical ctx is therefore available at the same observation points as before.
LDR W always becomes a W move, even to itself, to retain zero extension.

Knowledge is an equality between a physical host register and an exact ctx
range. Host writes and overlapping ctx stores invalidate it. Full stores can
establish a new equality. Partial GPR/XMM writes cannot establish a full-width
fact. Non-overlapping STP lazy-flag stores preserve knowledge. Other aliasing
stores, calls, unclassified instructions, branches and every direct branch
target clear both value maps. A separate CFG analysis proves x19 still denotes
ctx: an early failure epilogue does not contaminate the successful guard path.
The analysis covers both successors and backward edges conservatively.

The initial scope is ordinary x64 frames. SRA, lean/remapped frames, private
EXEC and i386 bypass the pass. It runs after re-emission, all internal branch
fixups and closing deferred epilogues. Knowledge can span consecutive guest
instructions and straight-line portions of merged units. It starts empty at
each compilation and at the canonical body entry (+16); nothing carries across
independently compiled blocks or transit edges.

Only full 128-bit Q values enter the vector map. Scalar S/D transfers, integer
lane stores and partial MOVSS/MOVSD updates invalidate overlapping values.
YMM/ZMM upper storage has different ctx offsets; helper calls implementing
upper-state, MMX or x87 operations clear knowledge. Native SIMD gates still
choose the original emitters. Native floating arithmetic can have NaN helper
branches and joins on every operation, leaving no inter-instruction XMM reuse.
Extending that case needs a common physical result register on both the native
and helper paths (including a reload on the rare helper path), with a proof at
the join and renewed NaN/FPCR/fault checks. It is an internal implementation
boundary, not a missing external dependency. Scalar S/D load forwarding would
also need its own upper-lane semantics; a Q move is not an equivalent substitute.

Validation lives in `make reg-forward-test` (also part of `make test`): exact
ARM64 words, all four gate combinations of a deterministic JIT/interpreter
corpus, helper/partial/upper-state/fault/SMC cases, the stale-value negative
control, ALU/memory and SIMD differential suites, hardware SSE oracle, fused
Jcc corpus and flag boundaries. The negative gate deliberately retains an old
GPR association through host arithmetic and partial ctx writes; the differential corpus must fail with
exit 1, while setup failures and crashes are not accepted as detection.

Build `tests/hb_reg_forward_bench`, then run
`python3 tools/hb_reg_forward_measure.py --output results.json` under the lane's
required background priority. The driver records fresh-process AB/BA samples,
spread and static ctx load/store counts; optional `--emitdump` and `--gamegates`
use the coordinator's tools through bash. A timing difference without changed
emitted loads is a negative measurement control, not evidence of acceleration.

Deferred stores are a separate second stage. The coordinator's leaf samples
attribute GPR+XMM stores to 4.8% of the main thread and 6.3% of the worker;
these shares are only an opportunity estimate, not a speedup prediction.
Implementing that stage requires dirty-register maps at every fault, helper,
interpreter boundary and exit, agreement with SRA and transit ABI, and precise
guest-instruction state reconstruction for partial writes and faults. This
change deliberately pays none of that state-recovery cost.
