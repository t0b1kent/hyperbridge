# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
# Builds the selfctx probe with a given llvm-mingw toolchain, runs `list`, runs `all` once (60 s limit) and every cell in its own process (30 s limit each). Output goes only to -Out.
param(
  [Parameter(Mandatory = $true)][string]$Toolchain,
  [Parameter(Mandatory = $true)][string]$Out
)
$ErrorActionPreference = 'Stop'
$src = Join-Path $PSScriptRoot 'src'
$cc = Join-Path $Toolchain 'bin\x86_64-w64-mingw32-gcc.exe'
if (-not (Test-Path $cc)) { throw "compiler not found: $cc" }
New-Item -ItemType Directory -Force $Out | Out-Null
$bin = Join-Path $Out 'bin'
New-Item -ItemType Directory -Force $bin | Out-Null
$exe = Join-Path $bin 'selfctx.exe'
& $cc '-O1' '-g0' '-fms-extensions' '-fno-stack-protector' '-Wno-format' '-Wl,--no-insert-timestamp' (Join-Path $src 'selfctx.c') -o $exe
if ($LASTEXITCODE -ne 0) { throw 'build failed: selfctx' }

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
  if (-not $p.WaitForExit($limit * 1000)) {
    try { $p.Kill() } catch {}
    $p.WaitForExit()
    return 'TIMEOUT'
  }
  return [string]$p.ExitCode
}

$all = Join-Path $Out 'all'
New-Item -ItemType Directory -Force $all | Out-Null
$rc = RunLimited 'list' (Join-Path $all 'list.txt') (Join-Path $all 'list.err.txt') 30
Set-Content -Encoding ascii (Join-Path $all 'list.rc.txt') $rc
$rc = RunLimited 'info' (Join-Path $all 'info.txt') (Join-Path $all 'info.err.txt') 30
$rc = RunLimited 'all' (Join-Path $all 'all-1.txt') (Join-Path $all 'all-1.err.txt') 120
Set-Content -Encoding ascii (Join-Path $all 'all-1.rc.txt') $rc

$cells = Join-Path $Out 'cells'
New-Item -ItemType Directory -Force $cells | Out-Null
foreach ($line in (Get-Content (Join-Path $all 'list.txt'))) {
  $parts = $line -split "`t"
  if ($parts.Count -lt 2) { continue }
  $name = $parts[0]
  $rc = RunLimited $parts[1] (Join-Path $cells "$name.txt") (Join-Path $cells "$name.err.txt") 30
  Set-Content -Encoding ascii (Join-Path $cells "$name.rc.txt") $rc
}
