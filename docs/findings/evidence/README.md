# Original probe sources and selected captures

Only original source and text are included. All these probes and accompanying notes are MIT licensed. No signed application, provisioning profile, compiled module or proprietary listing is included. MANIFEST.json records SHA-256 for every supplied file.

## Apple compatibility probes

`apple-compat/probe.cpp` supplies the native PF/AF control and compatibility matrix; `signal.cpp` includes it and tests signal return. `fp-merge.cpp` tests scalar arithmetic, aliases, NaNs and conversion forms. The CSV files are unchanged captured text. `signal.csv` contains sampled rows and aggregate counters, not all 120,000 intermediate observations.

Build each program on an ARM64 Mac with the same compiler shape used for the measurements:

```sh
cd apple-compat
clang++ -std=c++20 -O2 -Wno-format -include initializer_list -march=armv8.5-a probe.cpp -o probe
clang++ -std=c++20 -O2 -Wno-format -include initializer_list -march=armv8.5-a signal.cpp -o signal
clang++ -std=c++20 -O2 -Wno-format -include initializer_list -march=armv8.5-a fp-merge.cpp -o fp-merge
```

Execution of compatibility arms requires a process legitimately admitted to the restricted compatibility API. A symbol being present or a numeric mode label is not admission proof. An ordinary unsigned process may fail the API; that result does not refute behavior of the admitted process. Consult each main function for the available arms. The publication supplies no signing identity or profile.

## Memory probe

`macos-memory/madv_probe.c` is the standalone native anonymous-memory/MAP_JIT experiment. `result-unsigned.txt` is its complete retained text output. On an ARM64 macOS host: `cc -O2 madv_probe.c -o madv_probe && ./madv_probe`. Mapping/protection failure is an observed result, not a reason to discard the run.

## Hardware-TSO loops

`tso/tsomode-ec.c` and `tsomode2-ec.c` are original ARM64EC native instruction-loop probes. Rebuild with an ARM64EC-capable Windows toolchain and run inside a controlled, positively checked compatibility-mode Wine thread. They use five samples per form. They are not x86 instruction-emulation loops; the recorded conclusions are limited to the machines/mode controls described in the [note](../m1-hardware-tso-wide-loads.md).

This package was prepared without executing any probe, Wine, game or translator build. The source signal-probe report explicitly recorded `install skipped`.
