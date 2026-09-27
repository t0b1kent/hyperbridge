# Experimental profile-guided core checkpoint

This is an unselected source checkpoint based on
`97068eaed1bf72c4aecc9100aae0e7fe2c06b320`. Performance evaluation is preliminary.
It does not establish the 120 FPS target or change the selected game runtime.
The source changes are limited to `include/hb_memory.h`, `src/hb_memory.c`, and
`src/hb_runtime.c`. No Wine adapter or CAS proposal is included.

## Changes and limits

When both terminal-diagnostic consumers are disabled, the runtime returns before
terminal classification and its lazily cached first-transfer work. Trace-only
guest-address parsing also happens after the trace eligibility checks. The
functional dispatch and chain paths keep their existing behavior.

The SMC direct-hash path first tries one readable-region pointer query. A
successful query avoids the preceding redundant span walk. A failed query takes
the complete previous fallback, including its existing fault-packet behavior.
The new query performs no memory dereference, user callback, or last-fault write;
it can still update the memory lookup cache and diagnostic counters. The existing
`MACRUNNER_HB_SMC_DIRECT_HASH` gate remains default-off. This does not establish a
new concurrent-memory lifetime guarantee: raw-pointer dereference retains the
existing direct-hash assumptions.

## Evidence that motivated the work

A bounded instrumented HyperBridge startup contained a 22.066-second interval
between HUD updates with only three frame-counter increments. Resource counters
covered 20.465 seconds inside it and measured about 1.434 CPU cores on average.
The compact map recorded 140,336 body publications and 85,770,248 emitted bytes
in that interval. One 128 MiB arena capacity reset was real, and 76,069 guest
entries were republished within the same runtime lifetime after it.

Those publication counts are not CPU costs. Only 120 of 4,358 primary-thread
wall-inclusive samples had compilation ancestry (2.75%). A
runtime responsible for most publications also owned stable generated-code
addresses sampled on that thread, but the map did not record the publishing
thread. The evidence does not attribute the full pause to recompilation.
Generated bodies, ordinary runtime work, memory helpers, and lookup work remain
relevant. Disabled terminal diagnostics still appeared in the steady profile;
removing their unused classification work is a bounded, concrete change.

The instrumented FEX reference did not contain a rendered steady-state window.
Its first HUD observation was about 14.648 seconds after the actual profiler
trace ended. Resource counters during the trace measured about 1.017 CPU cores,
with substantial kernel time, and symbolicated stacks concentrated in mapping
and thread-stack allocation paths. A profiler-associated signal-resume stack was
also observed. This establishes neither profiler causation nor a comparable
steady-state performance result; an ordinary control is needed. Wall-inclusive
sample fractions are not CPU totals or FPS measurements.

## Retained validation

All validation below predates this source-only checkpoint preparation. No new
native tests or game jobs were started while preparing this branch.

| Validation | Result |
| --- | --- |
| Retained core suite, decoded-source off and on | 516 passed, 0 failed in each mode |
| Decoded-source focused controls, source off/on and merge off/on | 45, 55, 94, and 118 checks; no failures |
| Generic SMC differential fixture, including extended memory controls | 381 checks, 0 failures |
| Core-only provider with the retained adapter | Four Wine checks passed |

The archive and source identities are recorded in `manifest.json`. The core-only
provider used the unchanged retained adapter; the separately proposed CAS adapter
was excluded. Ordinary unprofiled A/B/A final-minute observations were 48.81 FPS
and 49.65 FPS for the retained baseline, and 50.55 FPS for this candidate. That
is 1.8–3.6% above the two controls, not a statistical significance result. The
saved-English scene is inferred from the game log, not visually reconfirmed;
background system activity was not controlled. The candidate remains unselected
and the 120 FPS goal is unmet. Existing licenses,
third-party notices, and attribution remain unchanged. Logs, native binaries,
game bytes, local paths, and raw profiles are intentionally absent.

The generic test sources and their portable invocation are in
`tests/smc_single_query/README.md` at the repository root.
