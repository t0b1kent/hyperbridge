# Direct body-to-body chaining

The four experimental gates default to **0** and participate in the persistent
translation cache key. They can be measured independently.

| Gate (prefix `MACRUNNER_HB_`) | Effect |
| --- | --- |
| `CHAIN_BODY_ENTRY` | Guarded trampolines skip `MOV x19,x0` at the target. The baseline already shared the canonical 48-byte frame and skipped its three STPs. |
| `CHAIN_NO_COUNTERS` | Remove native block/step accounting and deadline checks. Count C dispatches and entry-block IR sizes instead. Only unlimited x64 runs are admitted; finite limits return `HB_ERR_INVALID_ARG` before execution. |
| `CHAIN_LAZY_PC` | Patch explicitly marked direct exits before PC publication to one `B target_body`; publish PC/RIP before C helpers and cold exits. This gate includes the direct-edge/guard removal, so its measurement is not a PC-store-only measurement. |
| `CHAIN_SKIP_NOP` | Cold primary/secondary slots execute two branches instead of nine NOPs. |

Use all four for the complete direct-edge path. A direct edge enters at byte 16,
after the canonical prologue, and precedes the successor's SRA fills. Dirty SRA
state is spilled before the edge. Frameless/remapped and saved-SRA frames are
not linked to incompatible frames; they retain dispatcher or existing compatible
paths. Conditional branches retain their condition evaluation and local branch.
An arbitrary indirect target still requires the IC/L1 lookup and guard.
IC, L1 and CALLRET probes also require a compatible source frame, and their
targets must match the entire canonical prologue, including the context register.
This fixes mixed lean/helper-frame transitions even when the new gates are off.

Direct branches use explicit incoming/outgoing lists. Eviction restores the cold
branch before reclaiming code, including self edges, with work proportional to
the affected edges and independent of `UNCHAIN_WALK`. This path requires a
MAP_JIT thread permission toggle or a permanent split-WX alias. Other arenas use
the existing trampoline path. Stored cache blobs contain unpatched edge markers;
the cache key includes the guest address, so embedded guest literals do not move.
Existing links remain subject to revocation after runtime chaining is disabled;
the current switch value only controls admission of new links.

With `CHAIN_NO_COUNTERS`, `hb_exec_result_t.counters_are_dispatches` distinguishes
the approximate accounting units. `execution_started` is a conservative progress
witness: guest memory may have changed after native entry even with zero retired
instructions, or during an interpreter fallback prefix. Consumers must use
`hb_exec_result_has_progress()` to decide whether
replay is allowed. The Wine adapter must be rebuilt with the extended result
structure. A register snapshot cannot undo stores from a completed predecessor.

Native faults resolve host PC through the precise instruction map and publish
both PC and RIP before interpreter recovery. The existing native-memory fault
veto disables SRA inside faultable blocks; predecessor SRA state is committed by
the edge spill. Marker payloads are harmless MOVZ XZR instructions so that native
fault/flag/register scanners cannot mistake metadata for guest memory accesses.
There is no execution of Wine or a game in these tests.

## Validation and measurement

`make test` includes the random chain corpus, each side of Jcc, CALL/RET/RET imm,
indirect jumps, memory/stack, eviction, all-state comparison, precise third-block
RO fault/retry, finite-limit compatibility with accounting enabled, and the
`TEST_TRANSIT_FLIP` negative control. The latter corrupts RAX only on a taken
direct edge and must produce a differential failure rather than merely crash.
Forced codegen failure also checks that an interpreter store followed by a fault
preserves the progress witness before the first native entry.

`tests/hb_zero_transit_evict_test` inspects machine words immediately after
revocation, before reuse, and checks ordinary, lean, scratch-SRA, saved-SRA and
remapped-context variants. Saved-SRA/remapped variants prove their actual frame
instructions and verify that incompatible direct links are refused.
`make tests/hb_zero_transit_bench` builds a separate four-block loop benchmark.
The Python runner alternates AB/BA pairs and reports every sample and dispersion.
`hb_zero_transit_bench MODE N DUMP_DIR` also saves the warmed native arena.
`tests/hb_zero_transit_static.py OFF_DUMP ON_DUMP` uses Capstone to trace the
actual matching unconditional edge through the trampoline and target accounting.
The initial measurement is **35 instructions versus 1**, without attributing
frame push/pop instructions to a baseline path that never executed them.

Run expensive work under `taskpolicy -b nice -n 15` while the coordinator's game
measurement lock exists. Background-core microbenchmarks under shared load do
not predict game FPS. The coordinator should check startup/menu, gameplay and
scene transitions, exception delivery, cache invalidation/restitch and IC/RET
behaviour with the rebuilt adapter and gates enabled.
