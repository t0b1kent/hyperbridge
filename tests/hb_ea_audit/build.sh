#!/bin/sh
# Linux x86-64 only: builds the real C emitter as an emit-only executable.
set -eu
T=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
R=${HB_EA_REPO:-$(CDPATH= cd -- "$T/../.." && pwd)}
OUT=${1:-"$T/out/emitter"}
SOURCE=${2:-"$R/src/hb_arm64_codegen.c"}
CC=${CC:-clang}
[ "$(uname -s)" = Linux ] || { echo 'This emit/oracle harness requires Linux x86-64, not a native Mac execution.' >&2; exit 2; }
[ "$(uname -m)" = x86_64 ] || { echo 'The oracle must run natively on x86-64.' >&2; exit 2; }
[ -f "$SOURCE" ] && [ -f "$R/include/hb_context.h" ] || { echo 'Set HB_EA_REPO to the HyperBridge repository root.' >&2; exit 2; }
mkdir -p "$(dirname -- "$OUT")"
"$CC" "$T/hb_ea_live_emit.c" "$R/src/hb_env.c" "$R/src/hb_gates_tbl.c" "$R/src/hb_probe.c" \
 -o "$OUT" -std=gnu11 -D_GNU_SOURCE "${HB_EA_BUILD_OPT:--O0}" -Wno-unused-function \
 -ffunction-sections -fdata-sections -Wl,--gc-sections -no-pie \
 -I"$R/include" -I"$T/shims" \
 -DHB_HOST_CALL_TARGET=17 -DHB_HOST_CALL_RESULT=16 -DHB_LOOP_COUNT=7 \
 "-DHB_SOURCE=\"$SOURCE\"" -ldl "$T/stubs.c"
