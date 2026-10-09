#!/bin/bash
# Full source-built Wine consumer on GitHub macos-26, existing same-repo input.
set -euo pipefail
out=${1:?fresh results directory required}
bundle=${2:?pinned llvm22-macos-results.tar.gz required}
repo=$(cd "$(dirname "$0")/.." && pwd -P)
python=${REPRO109_PYTHON:-python3}
[ "${GITHUB_ACTIONS:-}" = true ]
[ "${GITHUB_REPOSITORY:-}" = t0b1kent/hyperbridge ]
[ -f "$bundle" ] && [ ! -L "$bundle" ]
[ ! -e "$out" ]
run_id=${GITHUB_RUN_ID:?cloud run identifier required}
attempt=${GITHUB_RUN_ATTEMPT:-1}
work="${RUNNER_TEMP:?disposable cloud work required}/repro109-wine-sourcebuilt26-$run_id-$attempt"
[ ! -e "$work" ]
export DEVELOPER_DIR=/Applications/Xcode_26.6.app/Contents/Developer
mkdir -p "$out"
rc=0
"$python" -B -I "$repo/build/repro109wine/build_full.py" \
  --profile github-macos26-arm64 --compiler-bundle "$bundle" \
  --build --work "$work" --jobs 2 > "$out/full-driver.log" 2>&1 || rc=$?
printf '%s\n' "$rc" > "$out/build-rc.txt"
for part in reports deps/reports moltenvk/reports wine/reports; do
  if [ -d "$work/$part" ]; then
    mkdir -p "$out/$part"
    cp -R "$work/$part/." "$out/$part/"
  fi
done
for part in wine/engine/wine/dlls/win32u wine/engine/wine/build/dlls/win32u wine/engine/wine/build/include; do
  case "$part" in
    wine/engine/wine/dlls/win32u) name=win32u-source ;;
    wine/engine/wine/build/dlls/win32u) name=win32u-build-inputs ;;
    wine/engine/wine/build/include) name=wine-build-include ;;
  esac
  if [ -d "$work/$part" ]; then
    size_kib=$(du -sk "$work/$part" | cut -f1)
    if [ "$size_kib" -le 524288 ]; then
      tar -czf "$out/$name.tar.gz" -C "$work/$part" .
      shasum -a 256 "$out/$name.tar.gz" > "$out/$name.sha256"
      printf 'PRESENT %s KiB\n' "$size_kib" > "$out/$name.state.txt"
    else
      printf 'DROPPED CAP_524288_KiB measured=%s\n' "$size_kib" > "$out/$name.state.txt"
    fi
  else
    printf 'NOT_PRODUCED\n' > "$out/$name.state.txt"
  fi
done
if [ -f "$work/wine/engine/wine/build/Makefile" ]; then
  cp "$work/wine/engine/wine/build/Makefile" "$out/wine-Makefile"
  shasum -a 256 "$out/wine-Makefile" > "$out/wine-Makefile.sha256"
fi
for part in wine/install deps/prefix; do
  if [ -d "$work/$part" ]; then
    case "$part" in
      wine/install) name=wine-dist ;;
      deps/prefix) name=dependency-prefix ;;
    esac
    tar -czf "$out/$name.tar.gz" -C "$work/$part" .
    shasum -a 256 "$out/$name.tar.gz" > "$out/$name.sha256"
  fi
done
printf 'SOURCEBUILT26_RESULTS=PRESENT\n'
exit "$rc"
