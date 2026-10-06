# Integer Flags Intel

1,624,804 integer rows, compared across first/repeat captures by the runner comparison report; raw streams are retained. See COVERAGE.md and RULES.md for the tested matrix.

## Machine and method

Advertised Intel Core i7-8700B @ 3.20 GHz, native x86-64 macOS runner. Native target instructions were executed; the AMD captures expose a hypervisor and are not bare-metal claims. The Intel capture is a separate runner. No software instruction emulator is a hardware reference.

## Format and limits

The AMD flag corpus ported to Mach-O. The runner reported GenuineIntel, family 6/model 58/stepping 10, the i7-8700B brand string, Darwin 24.6.0 x86_64 and a hypervisor. Both `process_translated` and `arm64_capable` were UNKNOWN. Its admission script reported INTEL_READY from the available vendor/OS/architecture fields and rejected explicit value 1 in either translation/ARM field; it did not reject UNKNOWN. Native Intel execution is therefore inferred from that runner provenance, not independently proven by those two checks. Do not discard this gap or treat the brand as a verified physical silicon model. Undefined flags are empirical. MACHINE.json retains only the relevant allowlisted CPU/OS/check fields; no runner environment is included.

MANIFEST.json records bundle SHA-256, original SHA-256 and decompressed text SHA-256. Source and small metadata files are byte-identical copies. Large tables are tar.gz containers holding the original text or original gzip text stream. Every container is below 50,000,000 bytes. Only source and UTF-8 text payloads are included. Numeric streams are not rewritten.

## Repeat

Extract each archive in this directory (including subdirectories) before executing the source:

```sh
find . -name "*.tar.gz" -exec tar -xzf {} \;
bash run.sh
```

Use native x86 hardware with the required features, GCC/binutils (Clang/Mach-O for the Intel runner), Python 3 and gzip. Consult source scripts and FORMAT/COVERAGE files for per-suite prerequisites; x87 high-precision validation uses mpmath. Reproduction overwrites generated outputs: use a copy of the directory. Timing depends on scheduling and host frequency; correctness repeats do not make timing reproducible.

## License

Original reference contributors’ code and these notes are MIT licensed. Included LICENSE files retain their notices. No compiled probe, third-party implementation or runner environment is included.
