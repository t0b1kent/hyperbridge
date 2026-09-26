# Wine adapter

This directory connects the HyperBridge engine to ARM64 Wine. When an ARM64EC
Wine process meets x86-64 code, Wine hands it to the emulator DLL behind the
`xtajit64` interface. That is the slot FEX fills in other Wine builds; this
adapter fills it with HyperBridge.

It has two halves:

| Half | Output | Sources | What it does |
| --- | --- | --- | --- |
| PE (ARM64EC builtin DLL) | `hyperbridge64.dll` | `src/cpu.c`, `src/xtajit64.spec`, `src/hb_ec_entry.inc` | Entry to and exit from x86-64 code, context conversion, exception dispatch and unwinding, system calls. |
| Unix | `hyperbridge64.so` | `src/unixlib.c` and the headers in `src/` | Runs the engine: guest memory access through Wine's pages, fault handling, translation-cache invalidation when Wine reports memory changes. |

## Requirements

- The engine, built at the repository root with `make` (`../libhyperbridge.a`,
  `../include`).
- A Wine 11 ARM64EC build that carries MacRunner's ntdll changes for the
  HyperBridge packet interface (`src/wine/macrunner_hb_x64_packet.h`). Stock
  Wine does not have them, so this adapter does not run on stock Wine. That Wine
  tree is not part of this repository.
- llvm-mingw with ARM64EC support for the PE half.

## Build

```sh
WINE_INCLUDE=<wine>/include WINE_OBJDIR=<wine-build> NTDLL_SO=<wine-build>/dlls/ntdll/ntdll.so \
    ./build_unix.sh
LLVM_MINGW=<llvm-mingw>/bin WINE_INCLUDE=<wine>/include WINE_OBJDIR=<wine-build> \
    WINE_PE_LIBS=<dir with arm64ec libntdll.a and libwinecrt0.a> ./build_pe.sh
```

Both scripts print the SHA-256 of what they built. Install `hyperbridge64.so`
into Wine's `lib/wine/aarch64-unix` directory and `hyperbridge64.dll` into
`lib/wine/aarch64-windows` and the prefix's `C:\windows\system32`. Wine picks
the x86-64 emulator from the default value of the registry key
`HKLM\Software\Microsoft\Wow64\amd64` (normally `xtajit64.dll`); set it to
`hyperbridge64.dll`. `MACRUNNER_XTAJIT64_BACKEND=jit` selects the JIT backend.

## License

Three files are derived from Wine and stay under the GNU Lesser General Public
License, version 2.1 or later (see [COPYING.LIB](COPYING.LIB)). Their original
copyright notices are kept at the top of each file:

| File | Origin |
| --- | --- |
| `src/cpu.c` | Wine `dlls/xtajit64/cpu.c`, Copyright 2024 Alexandre Julliard |
| `src/hb_wine_unwind.h` | Wine ntdll unwind definitions, Copyright 2023 Alexandre Julliard |
| `src/wine/macrunner_hb_x64_packet.h` | declarations from Wine `ntdll/unixlib.h`, Copyright 2020 Alexandre Julliard |

Consequently `hyperbridge64.dll`, which is built from `src/cpu.c`, is covered by
the LGPL. The other files in this directory are original MacRunner code under
the repository's MIT license.
