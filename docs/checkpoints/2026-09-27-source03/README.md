# Tested source checkpoint — 27 September 2026

This branch preserves the exact core source family used for the first matched
Hollow Knight decoder-source measurement:38.12FPS with the new switch off and
46.90FPS with it on. The change removes repeated validation of unrelated bytes
beyond the decoded instruction prefix. It is disabled by default.

Run the portable native checks on macOS ARM64:

```
python3 tests/source03_checkpoint/verify.py
```

The source snapshot includes the helper-PC correction, optional immediate/lazy
exact SMC snapshots, denied-chain-work pruning and owned decoder provenance.
It is a backup of the tested candidate, not a claim that every difference from
the current main branch is ready to merge. Existing repository tests and adapter
source remain available; the adapter was not rebuilt or changed for this result.
The tested Wine provider was linked with the retained adapter object identified
in the manifest below. Building the repository adapter anew requires its existing
documented Wine development dependencies and separate validation.

The portable command reproduces516 native checks per source-gate state and the
focused source-provenance matrix. The520-per-architecture hardware corpus,8 Wine
cases and3685 adversarial checks were separate local validations; those numbers
are evidence records, not tests silently executed by this command.

See SOURCE03-REVIEW.md, SOURCE03-RESULTS.md and manifest.json here. Full raw game
logs, saved user configuration and runtime packages remain local. The FPS result
is one matched pair; scene was inferred from saved English settings and game log.
The120FPS target and full gameplay/concurrent SMC parity remain unfinished.

Retained adapter object SHA256:
`c7dd9c0cbfd797cc39a76609fbfc404dee66b4820496e2be6a7df1f4c13ed4dd`.
