# Independent quad tessellation reference

Public synthetic HLSL and a D3D12 host using only `IDXGIFactory4::EnumWarpAdapter`.
The reference is **WARP, not hardware**. It measures pixels and domain coordinates,
not GPU performance. There are no game inputs, precompiled shaders, SDK binaries,
or translator implementation details in this package.

Use an **x64 Native Tools Command Prompt for Visual Studio** with installed
Windows SDK DXC, PowerShell 7 and Python 3. From the repository root run
`pwsh -NoLogo -NoProfile -File stands\quad-warp\run-windows.ps1 -Out build\quad-warp`.
The workflow discovers the installed Visual Studio with `vswhere`, calls
`VsDevCmd.bat -arch=x64 -host_arch=x64` in a `cmd` step, and starts PowerShell
in that same step. PowerShell inherits the compiler environment; it does not
invoke `cmd /c` or parse an environment dump. Missing `cl.exe` fails explicitly.
Use `-Dxc <installed-dxc.exe>` if discovery is unsuitable. The script downloads
nothing and fails if DXC is missing. All five stages use shader model 6.0 DXIL;
there is no DXBC fallback. The output directory must not exist. Builds are serial.
Each of the four serial WARP children is bounded at 55 seconds; each fence wait is bounded at 5 seconds.
The workflow runs Windows 2022 and 2025 serially and preserves failure artifacts.

`cases.csv` is the exact bitwise input contract. Six cases cover both hull output
windings for uniform odd1, uniform odd3, and the disputed fractional-odd fixup:
outer = `0x3f800000` four times, inner = `0x3f800080,0x3f800000`.
The unchanged public DS outputs position `(-0.875+1.75u,-0.875+1.75v,0,1)`
and color `(u*v,u*u,0.25,1)`. The red cross term distinguishes the two diagonals.
The VS and HS produce one control point; PS passes color through.

Two targets: 128 by 128 RGBA8 UNORM and RGBA32 FLOAT, one sample, viewport origin (0,0), full scissor,
clear (0,0,0,0), no blending, no depth/stencil, depth clipping enabled.
FrontCounterClockwise is FALSE. Each case draws once with no culling and once
with back culling. Root parameters are CBV b0 and UAVs u0/u1, space 0, all stages.
The DS recorder capacity is 65536 with 256 guard bytes; counts accumulate across
the two draws. Float factors are uploaded as raw uint32 words without conversion.

`raw/<case>/own.pixels.bin` is tightly packed, top-to-bottom RGBA without row
padding; `front.pixels.bin` is the back-cull pass. Each is 65536 bytes.
`raw-float/<case>/` repeats the same inputs and shader binaries with the float
target: each pixel file is 262144 bytes, little-endian RGBA float32, no padding.
Both arms preserve their own device receipt and recorder buffers. The float arm
separates interpolation from UNORM conversion; neither arm adds bias or tolerance.
`params.bin` contains eight little-endian words (six factors, tag, capacity).
`recorder-uncull.bin` and `recorder.bin` contain a 16-byte header
(count, overflow, two reserved zero words), then 48-byte records containing
(u bits,v bits,zero,tag), position4 and color4, followed by untouched 0xa5 bytes.
Invocation order/count is implementation
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

Producer readback revision004 keeps the six cases, shader arithmetic and paired
RGBA8/RGBA32Float targets. Each DS invocation now records48 bytes: UV/tag,
SV_Position and COLOR, each16 bytes. The host allocates the corresponding bounded
buffer; the qualifier checks its full stride, padding, duplicate UV consistency,
finite/range outputs and guards. The observer adds stores, so first compare both
targets to revision003 exactly. Any target drift prevents attributing previous
differences to the newly observed producer values. The values must then be
compared by UV to the preserved Metal DS output buffers to distinguish producer
arithmetic from interpolation; no raster precision conclusion is assumed.
## Fragment boundary observation (revision 005)

Run the same six cases in four bounded child processes: baseline RGBA8,
baseline RGBA32Float, observed RGBA8, and observed RGBA32Float. Each child
retains the 55 second timeout. Seven build steps include the additional
`ps_observe` entry point. The original `ps_main`, DS, HS, and cases are unchanged.

The root signature adds a raw UAV at u1. The observed PS records its incoming
COLOR, outgoing value, and SV_Position without additional color arithmetic.
`fragment[-uncull].bin` contains a 16-byte overflow header, 16384 pixel records
of 64 bytes (counter/reserved16, input16, output16, position16), and 256 guard
bytes. Counts reset for each draw; repeated invocations are a qualification
failure, not silently merged. Empty records and reserved words retain A5.
Baseline arms bind the same buffer and root signature but never write it.

Qualification requires all 24 baseline/observed targets to be byte-identical,
counts/coverage/guards to agree, and fragment input/output/target conversion
to match exactly. A previous revision's baseline should also be compared
before attributing a historical pixel difference to these observations.
This is a WARP software reference, not hardware performance or a general
proof of equivalence. There is no color bias, tolerance, or image normalization.
