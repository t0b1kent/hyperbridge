# c34r translator source delta (MacRunner 1.1.4, 32-bit only)

`release114_source.py` applies one more sealed profile after the c33r profile. The c33r
fex32 inventory (6,953 files) is the exact preimage and is verified before any file is
replaced; the c34r inventory (6,954 files) is verified afterwards. An unexpected file or
symlink refuses the operation. The 64-bit translator is unchanged.

The delta replaces 24 sources and adds one (`FEXCore/include/FEXCore/Core/G3CrtWatch.h`)
under `FEXCore/` and `Source/Windows/WOW64/`. Every postimage is stored byte-exact in
`c34r/source/fex32/`. It carries the 32-bit x87 speed series, the narrow pre-shift and
tier-2 paths, the FXAM class fix and the integer-32 gate; all of them are selected by
`MACRUNNER_*` environment keys read at run time, and the shipped `ENGINE.json` sets the
defaults. Compiler, platform, flags and PE link timestamp are the c33r pins.

`reference_pe_sha256` is the SHA-256 of the `xtajit.dll` produced by the maintainer's own
build of this tree. The comparison in `release_bytes.py` stays report-only: a cloud build
records its result next to that value and nothing is rewritten.
