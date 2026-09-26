#!/bin/bash
# Unix half of the Wine adapter: out/hyperbridge64.so.
#
# Build the engine first (`make` at the repository root), then set:
#   WINE_INCLUDE  Wine source include/ directory
#   WINE_OBJDIR   Wine build directory (its include/ holds generated headers)
#   NTDLL_SO      the built aarch64-unix ntdll.so to link against
# The Wine tree must carry MacRunner's ntdll changes for the HyperBridge packet
# interface (src/wine/macrunner_hb_x64_packet.h); stock Wine does not.
set -euo pipefail
cd "$(dirname "$0")"
: "${WINE_INCLUDE:?set WINE_INCLUDE to the Wine source include/ directory}"
: "${WINE_OBJDIR:?set WINE_OBJDIR to the Wine build directory}"
: "${NTDLL_SO:?set NTDLL_SO to the built aarch64-unix ntdll.so}"
mkdir -p obj out
clang -std=gnu23 -c -o obj/unixlib.o src/unixlib.c -Isrc -I"$WINE_OBJDIR/include" -I"$WINE_INCLUDE" -I../include \
    -D__WINESRC__ -D_CRTIMP= -DWINE_UNIX_LIB -Wall -Wdeclaration-after-statement -Wempty-body \
    -Wignored-qualifiers -Winit-self -Wstrict-prototypes -Wtype-limits -Wunused-but-set-parameter -Wvla \
    -Wwrite-strings -Wpointer-arith -pipe -fcf-protection=none -fvisibility=hidden -fno-stack-protector \
    -fno-strict-aliasing -fPIC -fasynchronous-unwind-tables -arch arm64 -mmacosx-version-min=14.0 -O2 \
    -DIS_WOW64_BUILD -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -MMD -MF obj/unixlib.d
clang -o out/hyperbridge64.so -dynamiclib -install_name @rpath/libhyperbridge_xtajit_v1.so \
    -Wl,-rpath,@loader_path/ obj/unixlib.o "$NTDLL_SO" ../libhyperbridge.a -arch arm64 -mmacosx-version-min=14.0
shasum -a 256 out/hyperbridge64.so
