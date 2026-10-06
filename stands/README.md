# HyperBridge testing stands

Hardware correctness gates: [hardware](hardware/README.md) runs native FEXCore
against the authored flags/SIMD tables (quick on push, full by dispatch/schedule).
[Vendor flags](vendor-flags/README.md) captures the same integer probes on Windows
x64 Intel/AMD hosts and produces a per-cell agreement table. CPU quick gates and
the deliberately broken translator control passed on macOS ARM64 in
[run 37398907615](https://github.com/t0b1kent/hyperbridge/actions/runs/37398907615).
They run on every push affecting the patch series or gate sources. Full tables
matched the local two-part fingerprints in
[run 37402886253](https://github.com/t0b1kent/hyperbridge/actions/runs/37402886253),
which re-reduced the original evidence after correcting the aggregate hash format.
Vendor coverage requires actual CPUID evidence for both vendors. No game inputs
are included.

[Synthetic instruction cost](instruction-cost/README.md) adds 26 authored forms
to candidate builds, recording static ARM/guest instruction counts and code size.
Its native frontend built and compiled all 26 forms in the first cloud attempt;
repeated-arm qualification is pending after an empty-subblock parser correction.
VM compilation timing is a
reference only; this compile-only check does not measure game or loop execution.

Published October 2, 2026. The CPU and 32-bit stands contain our MIT-licensed source, data formats and own synthetic examples. FEX, Unicorn and Capstone are external dependencies; no dependency source or binaries are bundled.

| Stand | Purpose | Start here |
| --- | --- | --- |
| CPU | x64 block comparison, independent VEX and MXCSR rules, mutation controls | [CPU README](cpu/README.md) |
| 32-bit | x86 state/memory comparison at two guest bases, independent integer x87 rules | [32-bit README](x86-32/README.md) |
| Synthetic CPU | 408 generated x86-64 cells run in a native FEXCore build of `fex/patches` and compared with Unicorn; runs in CI on every patch change | [Synthetic README](synthetic/README.md) |
| Exceptions | what a Windows x86-64 program observes when the processor raises an exception: codes, addresses, handler context, x87/SSE state; built and run on Windows x64 machines in CI | [Exceptions README](exceptions/README.md) |

Run the reference examples from each stand's directory. Native replay needs a separately prepared compatible FEX build. A synthetic example does not qualify the private multi-title gates. Read the limits before interpreting a PASS: ABI integration, full games and product FPS are outside these stands.

The graphics recording/replay stand is a change to [the DXMT fork](https://github.com/t0b1kent/dxmt), under LGPL-2.1-or-later. Its recorder/player source is published there on the branch `macrunner-trace-stand` ([documentation](https://github.com/t0b1kent/dxmt/tree/macrunner-trace-stand/docs/trace-stand)), on top of the MacRunner DXMT source snapshot (branch `macrunner-base`). This directory contains a link and description only; no DXMT source or patch is included here. Selected Direct3D 11 replay frames do not establish whole-game compatibility, DirectX 12, Vulkan or ray tracing.

No game recordings, memory, game code, frames, prefixes, run logs, signing material or compiled files are included. Use your own program to record a corpus; see the stand-specific data formats and instructions.
