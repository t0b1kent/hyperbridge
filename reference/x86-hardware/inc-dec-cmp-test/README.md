# Inc Dec Cmp Test

492,832 data rows per run: A 100,832; B 100,832; C 289,120; D 2,048. Two complete captures have identical CSV bytes.

## Machine and method

AMD EPYC 9V74, family 25/model 17/stepping 1, Linux 6.18.44 x86-64 KVM guest. Native target instructions were executed; the AMD captures expose a hypervisor and are not bare-metal claims. The Intel capture is a separate runner. No software instruction emulator is a hardware reference.

## Format and limits

INC/DEC, ADD/SUB by one, memory CMP/TEST and high-byte registers. Four flag seeds; exhaustive byte values/pairs and deterministic wider samples (seed 0x0031c0ffee123456). Defined results match all rows. TEST AF is undefined and excluded from mismatch checks; it measured zero. CMP/TEST result is a calculated temporary, while hardware flags and unchanged memory are observed.

MANIFEST.json records bundle SHA-256, original SHA-256 and decompressed text SHA-256. Source and numerical data are byte-identical copies. FORMAT.md removes one redundant Russian status sentence; MANIFEST.json retains its original and public hashes. Large tables are tar.gz containers holding the original text or original gzip text stream. Every container is below 50,000,000 bytes. Only source and UTF-8 text payloads are included. Numeric streams are not rewritten.

## Repeat

Extract each archive in this directory (including subdirectories) before executing the source:

```sh
find . -name "*.tar.gz" -exec tar -xzf {} \;
bash build.sh
```

Use native x86 hardware with the required features, GCC/binutils (Clang/Mach-O for the Intel runner), Python 3 and gzip. Consult source scripts and FORMAT/COVERAGE files for per-suite prerequisites; x87 high-precision validation uses mpmath. Reproduction overwrites generated outputs: use a copy of the directory. Timing depends on scheduling and host frequency; correctness repeats do not make timing reproducible.

## License

Original reference contributors’ code and these notes are MIT licensed. Included LICENSE files retain their notices. No compiled probe, third-party implementation or runner environment is included.
