# WIP source backup — 27 September2026

This branch preserves reviewed, locally tested source work. It is **not the final combined engine and has not been game-tested as a combined package**. It continues commit `330c7bbfd7cb9baa9e448f0b47a25f38066c399d`; the previous branch and its two untracked validation logs remain intact.

## Engine snapshot

The repository's `include/`, `src/` and `Makefile` match the frozen minor-work-elision core, built locally as archive SHA256 `aad9d7379241518d93a29b96fbe87c047976478fd131fd07f5c97567882fae43`. The archive is not included. File hashes are in [manifest.json](manifest.json).

The snapshot includes the earlier scalar-FP/store forwarding and fault-PC correction, exact native-entry code-witness consumer, copied memory-metadata cache, and the later fetch/terminal-scan/x87 work removal. Existing third-party code, license files, adapter source and synthetic tests are retained. This backup does not include the new Wine witness producer or final adapter integration. Entry-witness admission still requires that separately reviewed production bridge; absence must retain fallback behavior.

The exact local snapshot passed the retained516-test core suite with all inherited `MACRUNNER_` variables removed, then `MACRUNNER_HB_STATIC_REGS=0`, `SMC_PROTECT=0`, `DECODED_SOURCE=1`, `METADATA_SNAPSHOT=1`, `SCALAR_FP_FORWARD=1`, `SCALAR_FP_STORE_FORWARD=1`, `GPR_WRITE_THROUGH=0`, and `PURE_FLAG_STORES=0` (each abbreviated key has the same `MACRUNNER_HB_` prefix). Entry-witness was unset/default off. Enabling entry-witness retains seven documented cache/promotion feature-expectation failures; this is not relabeled an original-suite pass. Dedicated entry/fault/route and metadata controls were separately run on their frozen bases. No rebuild or new gameplay measurement was performed for this Git backup.

## Separate companion patches

Both patches are preserved verbatim and **not applied** to the engine snapshot:

- [Local GPR forwarding and dead flag stores](patches/local-state-forwarding-01.patch): same-offset native-word changes, canonical GPR stores retained, conservative memory/helper/branch barriers, cooperative context-export contract. Independent default-off gates are `MACRUNNER_HB_GPR_WRITE_THROUGH` and `MACRUNNER_HB_PURE_FLAG_STORES`. Four native gate arms passed516 tests plus focused fault/callback/emission controls. Local archive pin: `7fe3e4ff54951b9a9c21ad378b17525d917b5eee9b08ad8754aee7a382cd0fc6`.
- [Typed ABI plans and small stack scratch, v2](patches/typed-abi-plan-01.patch): includes the required signal fences. Gates `MACRUNNER_HB_TYPED_ABI_PLAN` and `MACRUNNER_HB_TYPED_ABI_SCRATCH` default off. Five production-object arms passed55,048 checks with identical architectural output. No verified current gameplay caller exists; this is typed-API work, not a demonstrated game speedup.

The patches were checked for applicability, not integrated or rebuilt together. Arena preservation and precise-state integration remain outside this backup. It does not claim completion of all eight backlog items or a whole-game performance improvement. No proprietary Wine objects, compiled binaries, game assets/bytes, saves, user logs or credentials are included in this checkpoint delta.
