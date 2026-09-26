#!/bin/bash
# PE half of the Wine adapter: out/hyperbridge64.dll (ARM64EC builtin DLL).
#
# Set:
#   LLVM_MINGW    llvm-mingw bin/ directory with arm64ec-w64-mingw32-gcc
#   WINE_INCLUDE  Wine source include/ directory
#   WINE_OBJDIR   Wine build directory (provides include/ and tools/winegcc/winegcc)
#   WINE_PE_LIBS  directory with the ARM64EC libntdll.a and libwinecrt0.a of that build
set -euo pipefail
cd "$(dirname "$0")"
: "${LLVM_MINGW:?set LLVM_MINGW to the llvm-mingw bin/ directory}"
: "${WINE_INCLUDE:?set WINE_INCLUDE to the Wine source include/ directory}"
: "${WINE_OBJDIR:?set WINE_OBJDIR to the Wine build directory}"
: "${WINE_PE_LIBS:?set WINE_PE_LIBS to the directory with libntdll.a and libwinecrt0.a}"
mkdir -p obj out tmp cache
export PATH="$LLVM_MINGW:/usr/bin:/bin:/usr/sbin:/sbin" LANG=C LC_ALL=C ZERO_AR_DATE=1 \
    TMPDIR="$PWD/tmp" TMP="$PWD/tmp" TEMP="$PWD/tmp" CLANG_MODULE_CACHE_PATH="$PWD/cache"
"$LLVM_MINGW/arm64ec-w64-mingw32-gcc" -c -o obj/cpu.o src/cpu.c -Isrc -I"$WINE_OBJDIR/include" -I"$WINE_INCLUDE" \
    -I../include -D__WINESRC__ -D_CRTIMP= -I"$WINE_INCLUDE/msvcrt" -D_MSVCR_VER=0 -D__WINE_PE_BUILD -Wall \
    -Wdeclaration-after-statement -Wempty-body -Wignored-qualifiers -Winit-self -Wstrict-prototypes -Wtype-limits \
    -Wunused-but-set-parameter -Wvla -Wwrite-strings -Wpointer-arith -fuse-ld=lld --no-default-config \
    -fno-strict-aliasing -Wno-microsoft-enum-forward-reference -Wabsolute-value -ffunction-sections -fms-extensions \
    -DUSE_COMPILER_EXCEPTIONS -ffp-exception-behavior=maytrap -gdwarf-4 -g -O2 -MMD -MF obj/cpu.d
"$WINE_OBJDIR/tools/winegcc/winegcc" -o out/hyperbridge64.dll --wine-objdir "$WINE_OBJDIR" -b arm64ec-w64-mingw32 \
    -Wl,--wine-builtin -shared src/xtajit64.spec -nodefaultlibs obj/cpu.o "$WINE_PE_LIBS/libntdll.a" \
    "$WINE_PE_LIBS/libwinecrt0.a" --no-default-config
shasum -a 256 out/hyperbridge64.dll
