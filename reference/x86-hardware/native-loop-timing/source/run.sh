#!/bin/bash
# MIT. Run only in a coordinated quiet CPU window. No downloads/installations.
set -euo pipefail
cd "$(dirname "$0")"
case "$(uname -s)/$(uname -m)" in Linux/x86_64) ;; *) echo 'Requires native Linux x86-64' >&2; exit 1;; esac
out=${1:-.}
mkdir -p "$out"
label=$(awk -F ': ' '/^model name/{print $2;exit}' /proc/cpuinfo | sed -E 's/[^[:alnum:]]+/-/g;s/^-//;s/-$//')
if [[ -z "$label" ]]; then label=x86-64-unknown; fi
for suffix in '' '-run2'; do
    for prefix in RESULTS RAW RUN; do
        ext=tsv; [[ "$prefix" = RUN ]] && ext=txt
        [[ ! -e "$out/$prefix-$label$suffix.$ext" ]] || { echo "Existing output: choose a new output directory" >&2; exit 1; }
    done
done
python3 verify-original-bodies.py > "$out/ORIGINAL-BODIES-VERIFIED.txt"
{ gcc --version | head -n1; objdump --version | head -n1; printf '%s\n' 'gcc -std=gnu11 -O2 -Wall -Wextra -mno-red-zone -fno-ipa-cp-clone -fno-inline xbench-linux.c -o xbench-linux'; } > "$out/BUILD.txt"
gcc -std=gnu11 -O2 -Wall -Wextra -mno-red-zone -fno-ipa-cp-clone -fno-inline xbench-linux.c -o "$out/xbench-linux" 2> "$out/BUILD-stderr.txt"
objdump -d -Mintel "$out/xbench-linux" > "$out/DISASM-$label.txt"
diff -u --label input/xbench.c ../input/xbench.c --label submission/xbench-linux.c xbench-linux.c > "$out/LINUX-PORT.diff" || [[ $? = 1 ]]
for pass in 1 2; do
    suffix=''; [[ "$pass" = 2 ]] && suffix='-run2'
    "$out/xbench-linux" "$out/RESULTS-$label$suffix.tsv" "$out/RAW-$label$suffix.tsv" "$pass" > "$out/RUN-$label$suffix.txt" 2> "$out/RUN-$label$suffix-stderr.txt"
done
python3 analyze-results.py "$out" > "$out/VALIDATION.txt"
printf 'Completed two runs: %s/RESULTS-%s{,-run2}.tsv\n' "$out" "$label"
