# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
# Builds the getctx_poison probe with a given llvm-mingw toolchain and runs every cell (0..31) in its own process (30 s limit each). Output goes only to -Out.
param(
  [Parameter(Mandatory = $true)][string]$Toolchain,
  [Parameter(Mandatory = $true)][string]$Out
)
$ErrorActionPreference = 'Stop'
$src = Join-Path $PSScriptRoot 'src'
$cc = Join-Path $Toolchain 'bin\x86_64-w64-mingw32-clang.exe'
if (-not (Test-Path $cc)) { throw "compiler not found: $cc" }
New-Item -ItemType Directory -Force $Out | Out-Null
$bin = Join-Path $Out 'bin'
New-Item -ItemType Directory -Force $bin | Out-Null
$exe = Join-Path $bin 'getctx_poison.exe'
& $cc '-O1' '-g0' '-fms-extensions' '-fno-stack-protector' '-Wl,--no-insert-timestamp' (Join-Path $src 'getctx_poison.c') -o $exe
if ($LASTEXITCODE -ne 0) { throw 'build failed: getctx_poison' }
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
@(
  "os=" + [System.Environment]::OSVersion.VersionString,
  "cpu=" + $cpu.Name,
  "cpu_id=" + $cpu.ProcessorId,
  "logical=" + $env:NUMBER_OF_PROCESSORS,
  "exe_sha256=" + (Get-FileHash -Algorithm SHA256 $exe).Hash.ToLower()
) | Set-Content -Encoding ascii (Join-Path $Out 'machine.txt')
function RunLimited($arguments, $outFile, $errFile, $limit) {
  $p = Start-Process -FilePath $exe -ArgumentList $arguments -RedirectStandardOutput $outFile -RedirectStandardError $errFile -PassThru -NoNewWindow
  $null = $p.Handle
  if (-not $p.WaitForExit($limit * 1000)) { try { $p.Kill() } catch {}; $p.WaitForExit(); return 'TIMEOUT' }
  return [string]$p.ExitCode
}
$cells = Join-Path $Out 'cells'
New-Item -ItemType Directory -Force $cells | Out-Null
for ($i = 0; $i -lt 32; $i++) {
  $name = 'c{0:D2}' -f $i
  $rc = RunLimited "cell $i" (Join-Path $cells "$name.txt") (Join-Path $cells "$name.err.txt") 30
  Set-Content -Encoding ascii (Join-Path $cells "$name.rc.txt") $rc
}

# getctx_tail: values of the CONTEXT tail fields after a debug-register request (one run, 30 s limit)
$exe2 = Join-Path $bin 'getctx_tail.exe'
& $cc '-O1' '-g0' '-fno-stack-protector' '-Wl,--no-insert-timestamp' (Join-Path $src 'getctx_tail.c') -o $exe2
if ($LASTEXITCODE -ne 0) { throw 'build failed: getctx_tail' }
$p = Start-Process -FilePath $exe2 -RedirectStandardOutput (Join-Path $Out 'tail.txt') -RedirectStandardError (Join-Path $Out 'tail.err.txt') -PassThru -NoNewWindow
$null = $p.Handle
if (-not $p.WaitForExit(30000)) { try { $p.Kill() } catch {}; $p.WaitForExit(); $rc = 'TIMEOUT' } else { $rc = [string]$p.ExitCode }
Set-Content -Encoding ascii (Join-Path $Out 'tail.rc.txt') $rc
