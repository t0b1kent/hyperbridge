# Fp Sse Avx Avx512

15,410 native forms; 8,773,024 rows; 391,157 preserved SIGFPE destinations. Two byte-identical captures; 3,893 C crosschecks with zero mismatches.

## Machine and method

AMD EPYC 9V74 (Zen 4), Linux x86-64 cloud VM. Native target instructions were executed; the AMD captures expose a hypervisor and are not bare-metal claims. The Intel capture is a separate runner. No software instruction emulator is a hardware reference.

## Format and limits

SSE/AVX/AVX-512 arithmetic, comparison, conversion, rounding, FMA, horizontal and approximation operations. The exact input/control matrix and excluded forms are in COVERAGE.md and FORMAT.md.

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
