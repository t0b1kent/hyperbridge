# DXIL/DXBC fixtures compiled on Windows

Small HLSL fixtures written for HyperBridge's D3D12 layer tests (MIT). macOS has no packaged DirectX Shader Compiler, so the
workflow `dxc-fixtures.yml` compiles each fixture on a GitHub Windows runner with `dxc.exe` (SM 6.x, DXIL) and `fxc.exe`
(SM 5.0, DXBC) from the Windows SDK, following the fixture's `dxc-commands.txt`, and uploads the containers as an artifact.
Each fixture states its expected render result in `EXPECTED.md`.
