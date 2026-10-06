# Write Fault Rmw Part A

Addendum A: 264 measured page-cross continuation-2 cells (176 requested-core + 88 additional legal variants); two identical captures. Another 264 cache-line-only/half-RO cells are explicit N/A.

## Machine and method

AMD EPYC 9V74 (Zen 4), Linux x86-64 cloud VM. Native target instructions were executed; the AMD captures expose a hypervisor and are not bare-metal claims. The Intel capture is a separate runner. No software instruction emulator is a hardware reference.

## Format and limits

Page-cross locked RMW faults and continuation after a handler changes memory. No partial write in the 264 measured cells; resumed operations used the handler-written value. The full RMW JSONL/CSV captures permit checking the slice. Part B (two-thread concurrency) is unfinished and excluded. Scalar/vector tables are not supplied; summary files describing them are excluded. A cache-line-only split inside one 4 KiB page cannot give half RO and half RW with page-granular mprotect.

MANIFEST.json records bundle SHA-256, original SHA-256 and decompressed text SHA-256. Source and small metadata files are byte-identical copies. Large tables are tar.gz containers holding the original text or original gzip text stream. Every container is below 50,000,000 bytes. Only source and UTF-8 text payloads are included. Numeric streams are not rewritten.

## Repeat

Extract each archive in this directory (including subdirectories) before executing the source:

```sh
find . -name "*.tar.gz" -exec tar -xzf {} \;
cd source && python3 build.py && ./probe35 rmw
```

Use native x86 hardware with the required features, GCC/binutils (Clang/Mach-O for the Intel runner), Python 3 and gzip. Consult source scripts and FORMAT/COVERAGE files for per-suite prerequisites; x87 high-precision validation uses mpmath. Reproduction overwrites generated outputs: use a copy of the directory. Timing depends on scheduling and host frequency; correctness repeats do not make timing reproducible.

## License

Original reference contributors’ code and these notes are MIT licensed. Included LICENSE files retain their notices. No compiled probe, third-party implementation or runner environment is included.
