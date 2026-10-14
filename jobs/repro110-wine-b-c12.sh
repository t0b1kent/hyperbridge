#!/bin/bash
# c12 Wine on GitHub macos-26 with the source-built LLVM22 compiler; the ARM64EC Q-restore option is OFF unless
# REPRO110_Q_RESTORES=1 (workflow input q_restores).
set -euo pipefail
out=${1:?fresh results directory required}
bundle=${2:?pinned llvm22-macos-results.tar.gz required}
inputs=${3:-}   # optional: the verified source set prepared by the first job (build/repro110wine/prepare_sources.py)
repo=$(cd "$(dirname "$0")/.." && pwd -P)
python=${REPRO109_PYTHON:-python3}
[ "${GITHUB_ACTIONS:-}" = true ]
[ "${GITHUB_REPOSITORY:-}" = t0b1kent/hyperbridge ]
if [ ! -f "$bundle" ] || [ -L "$bundle" ]; then printf 'compiler bundle must be a regular file: %s\n' "$bundle" >&2; exit 2; fi
[ ! -e "$out" ]
run_id=${GITHUB_RUN_ID:?cloud run identifier required}
attempt=${GITHUB_RUN_ATTEMPT:-1}
work="${RUNNER_TEMP:?disposable cloud work required}/repro110-wine-b-c12-$run_id-$attempt"
[ ! -e "$work" ]
export DEVELOPER_DIR=/Applications/Xcode_26.6.app/Contents/Developer
mkdir -p "$out"
rc=0
# macOS /bin/bash is 3.2: an empty array under `set -u` is an error unless it is expanded as ${extra[@]+"${extra[@]}"}.
extra=()
if [ "${REPRO110_Q_RESTORES:-}" = 1 ]; then extra=(--arm64ec-q-restores); fi
if [ -n "$inputs" ]; then
  # Not `[ -d x ] && [ ! -L x ]`: under set -e a false first test in an AND list does not stop the script.
  if [ ! -d "$inputs" ] || [ -L "$inputs" ]; then printf 'prepared source set must be a real directory: %s\n' "$inputs" >&2; exit 2; fi
  extra=(${extra[@]+"${extra[@]}"} --source-inputs "$inputs")
fi
"$python" -B -I "$repo/build/repro110wine/build_full.py" \
  --profile github-macos26-arm64 --compiler-bundle "$bundle" ${extra[@]+"${extra[@]}"} \
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
printf 'WINE_B_C12_RESULTS=PRESENT q_restores=%s\n' "${REPRO110_Q_RESTORES:-0}"
exit "$rc"
