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

## Techniques credited in comments

Source comments name QEMU, box64 and FEX-Emu where HyperBridge uses a technique
that one of those projects also uses, for example the dual-mapped JIT arena or
the lookup cache in front of the block table. HyperBridge implements these
techniques itself. Apart from `third_party/`, no code from those projects is
included in this repository.
