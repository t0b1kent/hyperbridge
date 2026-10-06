#!/usr/bin/env bash
# Original MIT code.
set -euo pipefail
cd -- "$(dirname -- "$0")"
bash run-core.sh
bash bmi_run.sh
python3 bmi_verify.py
set +e
bash legacy_probe.sh > build/legacy.current.txt 2>&1
probe=$?
set -e
cat build/legacy.current.txt
if [[ $probe == 77 ]];then
 cp build/legacy.current.txt legacy_CHECKS.txt
 echo 'probe_script_exit=77' >> legacy_CHECKS.txt
elif [[ $probe == 0 ]];then
 echo 'Native i386 became available: class 11 full decimal generator is not included; previous environment could not execute i386. New measurement work is required.' >&2
else
 echo "Legacy probe failed: status $probe; see build/legacy.current.txt" >&2
 exit "$probe"
fi
python3 analyze_core.py
python3 verify_data.py
python3 summarize.py
