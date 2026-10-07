#!/bin/bash
# Build the FEX-based CPU engine of MacRunner/HyperBridge from upstream FEX-Emu plus the
# patch series in fex/patches.
#
#   fex/build.sh <work-dir> [patch-count]
#
#   patch-count   apply only the first N patches (default: all). 7 = the FEX of MacRunner 1.0.2.
#
# Environment:
#   LLVM_MINGW            llvm-mingw toolchain root (tested: llvm-mingw-20260505-ucrt-macos-universal)
#   FEX_UPSTREAM          FEX git URL or local mirror (default: https://github.com/FEX-Emu/FEX.git)
#   FEX_SUBMODULE_MIRROR  optional directory with local clones of the six submodules, laid out as in
#                         the FEX tree (External/fmt, ..., Source/Common/cpp-optparse)
#   FEX_PREPARE_ONLY=1    prepare the pinned source and patch series, skip all binary builds
#
# Outputs in <work-dir>/out: xtajit64.dll (ARM64EC), xtajit.dll (WOW64), xtajit64.so and xtajit.so
# (host unix libraries), plus SHA256SUMS.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=${1:?usage: fex/build.sh <work-dir> [patch-count]}
count=${2:-}
if [ "${FEX_PREPARE_ONLY:-0}" = 1 ]; then
  llvm_mingw=${LLVM_MINGW:-}
else
  llvm_mingw=${LLVM_MINGW:?set LLVM_MINGW to the llvm-mingw toolchain root}
fi
upstream=${FEX_UPSTREAM:-https://github.com/FEX-Emu/FEX.git}
base=fd141ed6d721d03062619e4702bca1a0c93b6dd9

mkdir -p "$work"
work=$(cd "$work" && pwd)
src=$work/src
if [ -n "$llvm_mingw" ]; then export PATH="$llvm_mingw/bin:$PATH"; fi
export LC_ALL=C TZ=UTC

if [ ! -d "$src/.git" ]; then
  git clone --no-checkout "$upstream" "$src"
  git -C "$src" checkout -q --detach "$base"
  for pair in \
    "External/rpmalloc:1d85c246cd827ead6865f4f880d4fef53f2b1864" \
    "External/fmt:1be298e1bd68957e4cd352e1f676f00e07dcfb57" \
    "External/xxhash:e626a72bc2321cd320e953a0ccf1584cad60f363" \
    "External/range-v3:ca1388fb9da8e69314dda222dc7b139ca84e092f" \
    "External/unordered_dense:3234af2c03549bc85656bfd3a86993bf1cd8aef1" \
    "Source/Common/cpp-optparse:9f94388a339fcbb0bc95c17768eb786c85988f6e"; do
    sub=${pair%%:*}; rev=${pair#*:}
    if [ -n "${FEX_SUBMODULE_MIRROR:-}" ]; then
      rmdir "$src/$sub" 2>/dev/null || true
      git clone -q --no-checkout "$FEX_SUBMODULE_MIRROR/$sub" "$src/$sub"
      git -C "$src/$sub" checkout -q --detach "$rev"
    else
      git -C "$src" submodule update --init -- "$sub"
    fi
    test "$(git -C "$src/$sub" rev-parse HEAD)" = "$rev"
  done

  patches=()
  if [ -f "$here/PATCH-ORDER.txt" ]; then
    while IFS= read -r patch_name || [ -n "$patch_name" ]; do
      case "$patch_name" in ""|\#*) continue ;; esac
      test -f "$here/patches/$patch_name"
      patches+=("$here/patches/$patch_name")
    done < "$here/PATCH-ORDER.txt"
  else
    patches=("$here"/patches/*.patch)
  fi
  if [ -n "$count" ]; then patches=("${patches[@]:0:$count}"); fi
  # Patches up to 0049 are mailbox files (git format-patch) and keep their author and date.
  # Later patches are published as plain diffs, byte-identical to the MacRunner release source
  # archive; they are applied and recorded with a fixed identity and date so the result is the
  # same on every machine.
  for p in "${patches[@]}"; do
    if head -n 1 "$p" | grep -q '^From [0-9a-f]\{40\} '; then
      GIT_COMMITTER_NAME="fex/build.sh" GIT_COMMITTER_EMAIL="build@localhost" \
        git -C "$src" am -q --keep-non-patch --committer-date-is-author-date "$p"
    else
      git -C "$src" apply --index "$p"
      GIT_AUTHOR_NAME="fex/build.sh" GIT_AUTHOR_EMAIL="build@localhost" \
      GIT_COMMITTER_NAME="fex/build.sh" GIT_COMMITTER_EMAIL="build@localhost" \
      GIT_AUTHOR_DATE="2026-10-05T00:00:00Z" GIT_COMMITTER_DATE="2026-10-05T00:00:00Z" \
        git -C "$src" commit -q -m "$(basename "$p" .patch)"
    fi
  done
fi
git -C "$src" log --oneline -1
if [ "${FEX_PREPARE_ONLY:-0}" = 1 ]; then
  printf '%s\n' 'Source prepared; PE/WOW64/UnixLib build and install skipped.'
  exit 0
fi

# Embedded __FILE__ paths are mapped to a neutral prefix; link timestamps are fixed.
configure() {
  triple=$1; dir=$2; stamp=$3
  cmake -S "$src" -B "$dir" -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE="$src/Data/CMake/toolchain_mingw.cmake" \
    -DMINGW_TRIPLE="$triple" -DENABLE_CCACHE=OFF -DTUNE_CPU=none -DENABLE_LTO=OFF \
    -DENABLE_JEMALLOC_GLIBC_ALLOC=OFF -DRANGES_NATIVE=OFF -DBUILD_TESTING=OFF -DFEX_WINE_DARWIN=ON \
    -DCMAKE_INSTALL_PREFIX=/hyperbridge/fex/stage -DCMAKE_INSTALL_LIBDIR=aarch64-windows \
    -DOVERRIDE_HASH="$(git -C "$src" rev-parse HEAD)" -DOVERRIDE_VERSION= \
    "-DCMAKE_C_FLAGS=-fmacro-prefix-map=$src=/hyperbridge/fex/src" \
    "-DCMAKE_CXX_FLAGS=-fmacro-prefix-map=$src=/hyperbridge/fex/src" \
    "-DCMAKE_SHARED_LINKER_FLAGS=-static -static-libgcc -static-libstdc++ -Wl,--file-alignment=4096,/mllvm:-align-loops=1 -Wl,--Xlink=/timestamp:$stamp"
}
configure arm64ec-w64-mingw32 "$work/arm64ec" 1788779472
cmake --build "$work/arm64ec" --target arm64ecfex
configure aarch64-w64-mingw32 "$work/wow64" 1788779471
cmake --build "$work/wow64" --target wow64fex
cmake -S "$src/Source/Windows/UnixLib" -B "$work/unixlib" -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=26.0
cmake --build "$work/unixlib"

mkdir -p "$work/out"
cp "$work/arm64ec/Bin/xtajit64.dll" "$work/wow64/Bin/xtajit.dll" "$work/unixlib/xtajit64.so" "$work/unixlib/xtajit.so" "$work/out/"
(cd "$work/out" && shasum -a 256 xtajit64.dll xtajit.dll xtajit64.so xtajit.so | tee SHA256SUMS)
