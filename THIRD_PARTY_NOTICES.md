# Third-party notices

HyperBridge's original code is licensed under the MIT License (see `LICENSE`).
The components below are included under their own licenses. Their notices are
preserved in every source file and in the files referenced here. The MIT license
of HyperBridge does not replace or relicense them.

## SoftFloat 3e (explicit-state variant)

- Location: `third_party/softfloat/`
- Origin: the `External/SoftFloat-3e` directory of the FEX-Emu source tree,
  commit `fd141ed6d721d03062619e4702bca1a0c93b6dd9`. That directory contains an
  explicit-state variant of Berkeley SoftFloat Release 3e by John R. Hauser.
- Copyright: The Regents of the University of California.
- License: BSD 3-Clause. The full conditions and disclaimer are in each source
  file and in `third_party/softfloat/THIRD-PARTY-NOTICES.md`. That file also
  records the single local correction to the donor sources.
- FEX-Emu is not a runtime dependency of HyperBridge.

## Cephes mathematical library

- Location: `third_party/cephes/`
- Origin: Stephen L. Moshier's Cephes library (https://www.netlib.org/cephes/).
  Only the binary128 routines that HyperBridge uses are included.
- License: BSD, as stated in `third_party/cephes/LICENSE`, together with the
  original Cephes permission notice quoted there.

## Wine (adapter files)

- Location: `adapter/src/cpu.c`, `adapter/src/hb_wine_unwind.h`,
  `adapter/src/wine/macrunner_hb_x64_packet.h`.
- Origin: Wine (https://www.winehq.org/): `dlls/xtajit64/cpu.c`, the ntdll unwind
  definitions and declarations from `dlls/ntdll/unixlib.h`, modified for
  HyperBridge.
- Copyright: Alexandre Julliard (2020, 2023, 2024) and the MacRunner authors for
  the modifications.
- License: GNU Lesser General Public License, version 2.1 or later. The notice
  is kept at the top of each file; the full text is in `adapter/COPYING.LIB`.
  `hyperbridge64.dll`, built from `adapter/src/cpu.c`, is covered by the LGPL.

## Techniques credited in comments

Source comments name QEMU, box64 and FEX-Emu where HyperBridge uses a technique
that one of those projects also uses, for example the dual-mapped JIT arena or
the lookup cache in front of the block table. HyperBridge implements these
techniques itself. Apart from `third_party/`, no code from those projects is
included in this repository.

## FEX-Emu (the FEX-based engine in `fex/`)

- Location: `fex/patches/` holds MacRunner's modifications as patches. `fex/build.sh` fetches
  FEX itself from https://github.com/FEX-Emu/FEX at commit
  `fd141ed6d721d03062619e4702bca1a0c93b6dd9`.
- Copyright: Copyright (c) 2019 Ryan Houdek and FEX contributors. The modifications are
  Copyright (c) 2026 the MacRunner contributors.
- License: MIT (FEX's `LICENSE`). The patches keep FEX's per-file notices.
- FEX-Emu has not reviewed or endorsed these modifications, and they are not contributions to
  FEX-Emu.

The FEX binaries built from `fex/` (`xtajit64.dll`, `xtajit.dll`) statically link these
components of the FEX source tree. A binary distribution must carry their notices:

| Component | Path in FEX | License |
| --- | --- | --- |
| {fmt} | `External/fmt` | MIT, Copyright (c) 2012 - present, Victor Zverovich and {fmt} contributors |
| xxHash | `External/xxhash` | BSD 2-Clause, Copyright (c) 2012-2021 Yann Collet |
| unordered_dense | `External/unordered_dense` | MIT, Copyright (c) 2022 Martin Leitner-Ankerl |
| range-v3 | `External/range-v3` | Boost Software License 1.0 |
| rpmalloc | `External/rpmalloc` | Public domain dedication, with an MIT-style permission notice for jurisdictions that need it |
| tiny-json | `External/tiny-json` | MIT, Copyright (c) 2018 Rafa Garcia |
| cpp-optparse | `Source/Common/cpp-optparse` | MIT (see its `LICENSE`) |
| Cephes | `External/cephes` | BSD (see above) |
| SoftFloat 3e | `External/SoftFloat-3e` | BSD 3-Clause (see above) |
