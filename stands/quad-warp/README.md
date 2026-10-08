# Independent quad tessellation reference

Public synthetic HLSL and a D3D12 host using only `IDXGIFactory4::EnumWarpAdapter`.
The reference is **WARP, not hardware**. It measures pixels and domain coordinates,
not GPU performance. There are no game inputs, precompiled shaders, SDK binaries,
or translator implementation details in this package.

Run PowerShell 7 on Windows with installed MSVC x64 C++ tools, Windows SDK DXC,
and Python 3: `./stands/quad-warp/run-windows.ps1 -Out build/quad-warp`.
Use `-Dxc <installed-dxc.exe>` if discovery is unsuitable. The script downloads
nothing and fails if DXC is missing. All five stages use shader model 6.0 DXIL;
there is no DXBC fallback. The output directory must not exist. Builds are serial.
The WARP child is bounded at 55 seconds; each fence wait is bounded at 5 seconds.
The workflow runs Windows 2022 and 2025 serially and preserves failure artifacts.

`cases.csv` is the exact bitwise input contract. Six cases cover both hull output
windings for uniform odd1, uniform odd3, and the disputed fractional-odd fixup:
outer = `0x3f800000` four times, inner = `0x3f800080,0x3f800000`.
The unchanged public DS outputs position `(-0.875+1.75u,-0.875+1.75v,0,1)`
and color `(u*v,u*u,0.25,1)`. The red cross term distinguishes the two diagonals.
The VS and HS produce one control point; PS passes color through.

State: 128 by 128 RGBA8 UNORM, one sample, viewport origin (0,0), full scissor,
clear (0,0,0,0), no blending, no depth/stencil, depth clipping enabled.
FrontCounterClockwise is FALSE. Each case draws once with no culling and once
with back culling. Root parameters are CBV b0 and UAV u0, space 0, all stages.
The recorder capacity is 65536 with 256 guard bytes; counts accumulate across
the two draws. Float factors are uploaded as raw uint32 words without conversion.

`raw/<case>/own.pixels.bin` is tightly packed, top-to-bottom RGBA without row
padding; `front.pixels.bin` is the back-cull pass. Each is 65536 bytes.
`params.bin` contains eight little-endian words (six factors, tag, capacity).
`recorder-uncull.bin` and `recorder.bin` contain a 16-byte header
(count, overflow, two reserved zero words), then (u bits,v bits,zero,tag)
records and untouched 0xa5 bytes. Invocation order/count is implementation
dependent: compare unique UV sets, not record order. Preserve all raw bytes.

`check-output.py` qualifies bounds, tags, guards, coverage, odd1/odd3 sensitivity,
and paired winding/culling. It does not decide the disputed diagonal.
`QUALIFICATION.json` records that boundary explicitly. Compare the returned
readbacks against both previously saved candidates without silently flipping
rows or allowing tolerances. If rasterization differs, report byte differences
and color/coverage separately before making a topology claim.

The script records source/tool/build hashes, installed DLL inventory, runtime
exit and timeout state, and raw SHA256. DLL inventory is not loaded-module proof.
Build receipts and runtime receipts are separate. The upload contains raw data
and receipts only; executable/object/DXIL binaries stay out of the repository
and out of uploaded artifacts. A successful build is not a Windows execution
result. Independent equality remains unmeasured until the returned raw data is
compared locally. No shader timing or frame-time claim follows from this probe.
