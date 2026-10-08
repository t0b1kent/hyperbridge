# Public plane interpolation discriminator 009

WARP is Microsoft software D3D12, not physical hardware. This package contains
only synthetic vertices, colors, shaders and a bounded readback host. It tests
whether a candidate interpolation rule generalizes beyond the original quad.

`geometry.json` declares eight groups: baseline, skew, offset viewport,
subpixel viewport/vertices, uniform W=2, nonuniform W=(1,2,4,1), constant COLOR,
and negative COLOR assignment. Both windings give 16 cases and 128 draws.
All four baseline/observed RGBA8/float arms must be uploaded, including every
raw ledger entry. Output layouts are unchanged from 008. Coefficients are not
part of the WARP shader: it uses normal D3D12 perspective interpolation.

Run from an x64 Native Tools Command Prompt:
`pwsh -NoLogo -NoProfile -File stands/quad-warp/run-windows.ps1 -Out build/plane009`
Initialize MSVC before PowerShell. No downloads or compiler fallback occur.
The workflow pins the same checkout/upload actions as 008. Each child has a
55-second timeout. `check-fixed.py --test` checks corruption controls;
`--run <directory>` verifies exact vertices, guards, coverage, constant color,
observer neutrality and recorded-input/output/target equality. Finite float
values outside [0,1] are inventoried, never clamped in float readback. Reversed
order byte differences are reported, not silently treated as equivalent.

This is DIAGNOSTIC_ONLY/NOT_GOLDEN. Windows runs do not measure GPU speed.
The historical 007 qualifier failure and 008 correction remain preserved.
