## HyperBridge 1.1.0

For a separate module download, use `HyperBridge-1.1.0-arm64-r1.zip`: it adds the separate FEX-Emu license and copyright notice to the initial packaging. The executable modules are unchanged. The full MacRunner application already includes this notice.

This version includes experimental paths for block headers keyed by PC, comparisons, returns without polling, RIP literals and in-block QPC. HEADER_BY_PC, RET_NOPOLL, CMP_ZC, RIP_LITERAL and QPC_INLINE are disabled by default. The table below reports defaults and the experimental M configuration separately; “on par with Rosetta” refers to M.

### Translator measurements on M1 Pro

xbench, November 3, 2026: cycles per step, median of three rounds; lower is better. Rosetta and HyperBridge/FEX execute the same x86-64 code; ARM64 is a separate native reference. Calibration: ARM64 addchain = 1 cycle.

| Path | Call/return | Indirect call | Byte compare | Mixed loop | Arithmetic |
|---|---:|---:|---:|---:|---:|
| ARM64 | 3.00 | 3.00 | 2.00 | 4.00 | 4.21 |
| Rosetta | 4.01 | 5.54 | 2.95 | 5.01 | 4.21 |
| HyperBridge/FEX, new switches disabled (k0) | 5.02 | 6.02 | 3.65 | 6.04 | 4.21 |
| HyperBridge/FEX, experimental M configuration | 4.01 | 4.53 | 3.01 | 5.02 | 4.21 |

In configuration M, indirect-call time is 18.2% lower than Rosetta; call/return is equal, while byte comparison and the mixed loop are close. M enables CMP_ZC, RIP_LITERAL, RET_NOPOLL, HEADER_BY_PC, QPC_INLINE=5 and PAUSE=isb. These are experimental settings; the new FEX switches are disabled by default in 1.1.0. These hot microloops on one machine do not establish average application performance. Priority is identical within the series; the background launcher added nice 5 and xbench added another nice 10. Source: FEXXFER series, sections 10–11, DLL 71a43f7e.

### DirectX 12 without Rosetta

Elden Ring (DirectX 12) runs on Apple Silicon without Rosetta — our own x86 translator (HyperBridge) and our own DX12 → Metal layer. As far as we know, this is a first: CrossOver Preview (FEX, no Rosetta) does not start Elden Ring. This was checked by the owner; its FEX bottles include only D3D10/11.

### First launch in MacRunner

On a game's first launch, the app prepares its bottle for several minutes. Shader compilation during the game's first few minutes can cause stuttering. On the second launch, preparation is complete and cached shaders allow smoother play. New scenes may require compilation. MacRunner 1.1.0 does not include shader-cache migration after an engine update. For the best frame rates, close demanding background apps and disconnect your second monitor; both remained active in the owner's recordings.
