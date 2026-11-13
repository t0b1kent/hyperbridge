# d3d9-fpu stand: what Direct3D 9 does to the x87 control word

Direct3D 9 documents that `CreateDevice` without `D3DCREATE_FPU_PRESERVE` "defaults to single-precision round-to-nearest mode".
Both open re-implementations (Wine's `dlls/d3d9/device.c setup_fpu`, DXVK's `D3D9DeviceEx::SetupFPU`) implement that as
`cw = (cw & 0xF0C0) | 0x003F` on the calling thread, in device creation only. A translator that targets Direct3D 9 games has to
match this: with 24-bit precision a game's x87 arithmetic rounds differently, so getting it wrong changes what the game computes.

`d3d9-fpu.c` is a 32-bit probe that measures the real `d3d9.dll` on real Windows. For every case it sets the control word to a
known value, makes the call, and reads the word back — on the calling thread and on a second thread that waits on an event:

- `CreateDevice` from `0x027f`, `0x0f7f` (64-bit precision, round toward zero) and `0x083f` (bit 6 clear, round up);
- `CreateDevice` with `D3DCREATE_FPU_PRESERVE` and with `D3DCREATE_MULTITHREADED`;
- `CreateDeviceEx` with and without `D3DCREATE_FPU_PRESERVE`;
- `Reset`, `ResetEx` and `Present` after creation;
- MXCSR around each call, and the precision actually used, as the bits of `1.0 / 3.0` computed by `fdiv`.

Device types are tried in the order HAL, REF, NULLREF, and each line says which one answered: a machine with no 3D device still
reports for the types it has. The probe shows no window (an off-screen tool window), changes no display mode and writes nothing
outside its output file.

```
.\run-windows.ps1 -OutputDirectory .\results     # x86 Native Tools / Developer PowerShell
```

The workflow `d3d9-fpu-windows` runs it on GitHub-hosted Windows Server 2022 and 2025 machines and keeps the raw output
(`d3d9fpu-out-<pid>.txt`, `run.json`, `machine.txt`, `compiler.txt`) as the job's artifact.
