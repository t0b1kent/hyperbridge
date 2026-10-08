# Fixed triangle order / interpolation discriminator

Public synthetic D3D12 probe, WARP only (software, not hardware). Package007 supersedes the tessellation draw in this directory with a fixed triangle list. Earlier raw references stay immutable.

The common `src/fixed-fixture.h` defines exact float32 words for the four public `quad-cross.hlsl` outputs at UV=(0,1),(0,0),(1,0),(1,1). Indices (1,2,0),(0,2,3) preserve the validated minimal quad. No HS/DS is compiled or executed; VS passes these constants directly.

Matrix: three cyclic rotations × two reversals × two COLOR mappings = 12 cases. Identity moves position and color together; negative rotates only color to the next local vertex. Two cull modes × RGBA8_UNORM/RGBA32_FLOAT × baseline/fragment observer = 96 draws. Default viewport128×128, one sample, no clipping (z=0,w=1); no bias or tolerance.

Each draw saves exact target bytes, cumulative VS records (vertex ID, position index, color index, tag, position, color), and fragment input/output/SV_Position/count. Guard bytes remain intact. The observer writes its input unchanged. `check-fixed.py` validates all six permutations, every VS value, winding/coverage, observer equality, negative controls and guards; it reports order-dependent bytes rather than accepting them as equal.

Run from an initialized x64 Native Tools prompt:
`pwsh -NoLogo -NoProfile -File stands\quad-warp\run-windows.ps1 -Out build\quad-fixed-new`.
Four sequential build steps (host+VS+PS+observerPS); four bounded ≤55s processes,24 draws each. Output directory must be new. The pinned workflow initializes MSVC using cmd/call before PowerShell and uploads all four raw branches, receipts and source hashes, including failure output.

Local checker self-test: `python stands/quad-warp/check-fixed.py --test`.
Qualification: `python stands/quad-warp/check-fixed.py --run build/quad-fixed-new`.
The checker compares exact bytes; qualification does not claim WARP/Metal equality. Backend comparison is performed locally after delivery of all raw files.

All inputs here are synthetic/public. No game data, Apple library, compiled binaries or credentials are included. Legacy HLSL and `check-output.py` remain for explicit provenance and shared fragment-record validation; they are not used to compile tessellation stages in package007.
