# Generic SMC read-query controls

These source fixtures compare the retained baseline and candidate
`smc_bytes_current` functions against the real memory implementation. All test
bytes are synthetic; no game files or proprietary code are included. The source
files retain their original content and are covered by the repository license.

On the supported macOS ARM64 development host, first build the engine separately
with its normal build procedure. Then explicitly run:

```sh
python3 tests/smc_single_query/run.py --archive libhyperbridge.a --output build/smc-single-query
```

The output directory must not already exist. The runner links one fixture with a
30-second limit and runs it with a separate 30-second limit. It does not build
the engine or start Wine. It extracts the baseline function from the fixed
checkpoint commit recorded in the runner, so that commit must remain available
locally. Archive and source hashes are recorded; a successful run also requires
that those inputs remain unchanged. The supplied archive must be built from the
candidate sources; a hash by itself does not establish that relationship.

The fixtures cover DIRECT_HASH off/on, single-region direct reads, unaligned
ranges, adjacent-region fallback, unreadable or absent metadata, last-fault
packet preservation, mutation/unmap/remap/protection changes, address overflow,
real guest32 mirror boundaries, and metadata-readable host PROT_NONE memory.
The PROT_NONE direct-pointer cases compare returned pointers without dereferencing
them. They test equivalence of the existing raw-pointer contract, not safety
against a concurrent host unmap or protection change.

The retained candidate archive passed 381 assertions with no failures. The new
portable runner received source-only validation during checkpoint preparation;
that is distinct from the already completed fixture execution.
