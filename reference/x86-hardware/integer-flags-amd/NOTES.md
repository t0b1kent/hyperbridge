# Measurement notes

No packages were installed and no external source was downloaded. All programs execute native instructions on the exposed AMD EPYC 9V74 CPU. The environment presents a hypervisor CPUID flag; these measurements characterize that exposed processor, not every AMD or Intel CPU.

The permitted 32-bit attempt uses `gcc -m32 -nostdlib -static -no-pie`. Compilation succeeds, but the OS rejects executing the ELF32 image with errno 8. This is recorded as unavailable, not silently emulated or classified as complete instruction coverage.

An independent code/output review identified and corrected a signed-128 addition boundary hazard in the input constructor before final generation. The constructor now casts the in-range product to unsigned before adding the offset. A UBSan-instrumented native executable then produced exactly the same bytes as the ordinary executable for every core class, with no diagnostics. No measured row was edited to repair the issue: affected classes were generated anew from native execution.

A separate review verified immediate flags capture, ucontext-based #DE register capture, undefined-field exclusions in the C model, exact field widths, both initial flag patterns, and canonical whole-value 128-bit CMPXCHG16B patterns. `verify_data.py` independently checks exact per-configuration counts and hashes. `bmi_verify.py` independently checks class 9.

To repeat the optional sanitizer audit after `bash run.sh`:

```
gcc -O1 -std=gnu11 -fsanitize=undefined -fno-sanitize-recover=all -fno-strict-aliasing core.c build/core.S -o build/core-ubsan
for cls in shifts rotates double multiply divide bitscan bittest logic misc; do
  ./build/core-ubsan "$cls" > "build/sanitized-$cls.txt"
  sha256sum "build/sanitized-$cls.txt"
  # Compare the resulting digest with out-$cls.sha256 (the named raw-stream hash).
done
```

The legacy #DE-specific tests remain unexecuted because the 32-bit compatibility probe never reaches `_start`. The actual 100,856 DIV/IDIV trap rows in the core corpus were captured in 64-bit execution mode, across 8/16/32/64-bit operand sizes.
