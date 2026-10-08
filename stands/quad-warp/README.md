# Public interpolation holdout 011

Only synthetic positions, colors, viewports and HLSL; no game or Apple inputs.
All eight geometry groups are new versus 010. They exercise both leftmost
anchor locations, subpixel offsets, W=3 and nonuniform non-power-of-two W,
nonuniform COLOR, constant COLOR under perspective, and COLOR permutation.
The 16 cases, four readback arms, 128 draws, timeouts, DXIL flags, host and
qualifier are unchanged from successful 010. No coefficients are embedded:
Windows uses ordinary D3D12 WARP interpolation. WARP is software, not hardware.

The Mac candidate was frozen before any output of this corpus: post-VS
runtime plane setup chooses minimum screen X, ties by maximum screen Y,
and negative determinant. Geometry and runtime rule must not be retuned
after reference bytes arrive; mismatches are reported exactly.

From an initialized x64 Native Tools Command Prompt:
`pwsh -NoLogo -NoProfile -File stands/quad-warp/run-windows.ps1 -Out build/holdout011`
MSVC setup remains a separate cmd workflow step. Upload all four raw arms
and every ledger entry even if qualification fails. Readback rules preserve
finite alpha/range excursions and require exact observer/target equality.
No GPU timing conclusion; DIAGNOSTIC_ONLY/NOT_GOLDEN.
