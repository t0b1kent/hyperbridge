# Legacy32 Bcd

696,928 native rows; 274 traps; 4,840 cross-mode pairs; two byte-identical captures and zero defined-semantics mismatches.

## Machine and method

AMD EPYC 9V74, Linux x86-64 cloud VM, existing ring-3 compatibility selector 0x23. Native target instructions were executed; the AMD captures expose a hypervisor and are not bare-metal claims. The Intel capture is a separate runner. No software instruction emulator is a hardware reference.

## Format and limits

32-bit BCD and legacy instructions executed within a 64-bit process. No LDT modification or instruction emulator. BOUND/INTO and AAM divide-by-zero traps are included. Architectural undefined bits remain measured, CPU-specific observations.

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
