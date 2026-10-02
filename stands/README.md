# HyperBridge testing stands

Published October 2, 2026. The CPU and 32-bit stands contain our MIT-licensed source, data formats and own synthetic examples. FEX, Unicorn and Capstone are external dependencies; no dependency source or binaries are bundled.

| Stand | Purpose | Start here |
| --- | --- | --- |
| CPU | x64 block comparison, independent VEX and MXCSR rules, mutation controls | [CPU README](cpu/README.md) |
| 32-bit | x86 state/memory comparison at two guest bases, independent integer x87 rules | [32-bit README](x86-32/README.md) |

Run the reference examples from each stand's directory. Native replay needs a separately prepared compatible FEX build. A synthetic example does not qualify the private multi-title gates. Read the limits before interpreting a PASS: ABI integration, full games and product FPS are outside these stands.

The graphics recording/replay stand is a change to [the DXMT fork](https://github.com/t0b1kent/dxmt), under LGPL-2.1-or-later. Its recorder/player source is published there on the branch `macrunner-trace-stand` ([documentation](https://github.com/t0b1kent/dxmt/tree/macrunner-trace-stand/docs/trace-stand)), on top of the MacRunner DXMT source snapshot (branch `macrunner-base`). This directory contains a link and description only; no DXMT source or patch is included here. Selected Direct3D 11 replay frames do not establish whole-game compatibility, DirectX 12, Vulkan or ray tracing.

No game recordings, memory, game code, frames, prefixes, run logs, signing material or compiled files are included. Use your own program to record a corpus; see the stand-specific data formats and instructions.
