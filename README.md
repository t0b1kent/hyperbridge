# HyperBridge

HyperBridge is an independent CPU translator that runs Windows x86-64 and x86
user-mode code on Apple Silicon by translating it to native ARM64. It is the
CPU engine of [MacRunner](https://github.com/t0b1kent/macrunner-app), where it
plugs into ARM64 Wine through Wine's emulator interface, in the same slot that
FEX occupies in other Wine builds.

The engine is written in C. It decodes guest instructions, lifts them to its own
intermediate representation (IR), and then either interprets the IR or compiles
it to ARM64 with its JIT.

## Status

Experimental. Measured facts as of 2026-09-26:

- The engine builds as a static and a dynamic library on macOS 14+ (arm64) with
  `-Werror`, and ships with its unit and regression test suite (`make test`).
- Test status of this snapshot: the main runner reports 516 passed and 0 failed.
  That count includes two skips: one test needs a Wine source tree next to the
  engine, and one covers an opt-in feature. All x87 suites pass except
  `hb_x87_transcendental_guest_test`. That suite fails 7,680
  of 10,245,570 checks, all of them FSCALE with an integer exponent of −32768 in
  the x86 interpreter path. This is a known open defect.
- Inside MacRunner, with its fast JIT mode enabled, Hollow Knight (Unity/Mono,
  x86-64) reaches the language-selection screen in 53–57 seconds (four runs).
  With the JIT direct-memory path fully enabled (the default), the language
  menu is visible in the window 150–170 s after launch in two runs; FEX in the
  same harness shows it at about 160 s. Vertex-shader matrices in those runs
  contain no NaN or Inf values (0 of 360,440 constant buffers checked).
  Loading all managed assemblies takes 6.7–7.9 s there. An earlier measurement in
  the same setup gave about 2.2 s under FEX, and a Windows 11 ARM reference
  machine takes 0.24 s.
- HyperBridge is not yet at parity with FEX and is not production-ready.

## Layout

```
adapter/      Wine adapter: hyperbridge64.dll and hyperbridge64.so (partly LGPL)
include/      public and internal headers
src/          decoder, lifter, IR, interpreter, ARM64 code generator, JIT, runtime
tests/        unit, regression and litmus tests (make test)
tools/        Python helpers for decoding, tracing, benchmarking and reports
third_party/  SoftFloat 3e and Cephes: separately licensed, see below
```

Most code comments are in Russian. They record why a decision was made and
which measurement supports it.

## Build

Requirements: macOS 14 or later on Apple Silicon, and Xcode Command Line Tools
(clang and make).

```sh
make          # libhyperbridge.a and libhyperbridge.dylib
make test     # unit and regression tests
```

The Wine-side adapter, which connects the engine to Wine's emulator interface,
is in [adapter/](adapter/README.md). It builds against a Wine 11 ARM64EC tree
with MacRunner's ntdll changes, which is not part of this repository.

## License

The original HyperBridge code is released under the [MIT License](LICENSE),
Copyright (c) 2026 Timur Ravilov.

Third-party components keep their own licenses and notices:

| Component | Location | License |
| --- | --- | --- |
| SoftFloat 3e (explicit-state variant, from the FEX-Emu source tree) | `third_party/softfloat/` | BSD 3-Clause, The Regents of the University of California. See [its notices](third_party/softfloat/THIRD-PARTY-NOTICES.md). |
| Cephes mathematical library (binary128 routines) | `third_party/cephes/` | BSD. See [its LICENSE](third_party/cephes/LICENSE). |
| Wine-derived adapter files: `adapter/src/cpu.c`, `adapter/src/hb_wine_unwind.h`, `adapter/src/wine/macrunner_hb_x64_packet.h` | `adapter/` | LGPL 2.1 or later, Alexandre Julliard. See [adapter/README.md](adapter/README.md) and [adapter/COPYING.LIB](adapter/COPYING.LIB). |

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for details. The MIT
license does not relicense these components.

Some comments describe techniques used by QEMU, box64 and FEX-Emu, and credit
them by name. HyperBridge implements those ideas itself. Apart from
`third_party/`, this repository contains no code copied from those projects.
The only code taken from Wine is the three adapter files listed above.

Windows is a trademark of Microsoft. Apple and Apple Silicon are trademarks of
Apple Inc. HyperBridge is not affiliated with or endorsed by either company.
