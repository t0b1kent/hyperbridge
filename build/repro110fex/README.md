# FEX c12 translator from pinned sources (REPRO-110)

This directory is a copy of `build/repro109fex` (the recipe that reproduces the 1.0.9 translator byte for byte) with the
smallest set of changes needed for the 1.1.0 c12 source state. The 1.0.9 recipe is left untouched.

What differs from `repro109fex`, and where each difference is pinned (all in `recipe.lock.json`):

| Difference | Pin |
|---|---|
| c12 source = 1.0.9 product source + one delta (38 files changed, 8 added) | `post_tail`: `c12/c12-delta.patch`, applied after the public c9 tail and the two source tests |
| Expected source tree after submodules | `c12/PRODUCT-MANIFEST.json` (6936 files, every SHA-256) |
| Product environment defaults | `c12/ENGINE.json` (80 values) |
| `OVERRIDE_HASH` | `override_hash` |
| Extra compile definition `MACRUNNER_PROT_4K=1` for both PE modules | `extra_cflags` |
| Both PE modules (`xtajit64.dll`, `xtajit.dll`) are built from the same patched tree | `variants` |
| Link timestamps | `pe_link_timestamp` |
| Accepted c12 translator bytes | `reference_pe_sha256` |

Byte comparison is **report only** in this recipe: the first cloud run of a new source state must return its evidence
(`release-bytes-report.json` with the hash of every PE section) instead of stopping on a difference. Nothing is signed,
installed or rewritten.

Offline checks: `python3 -I -B build/repro110fex/build.py --check-inputs`, then `test_release_bytes.py`,
`test_recipe.py`, `test_stages.py` (each needs `REPRO109_TEST_TMP` pointing to an existing scratch directory).
