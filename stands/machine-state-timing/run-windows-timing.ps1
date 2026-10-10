# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
# Builds windows_probe_timing_fix.c with a given llvm-mingw toolchain and runs only the timing mode, twice. Output goes only to -Out.
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
$exe = Join-Path $bin 'windows_probe_timing_fix.exe'
& $cc '-O1' '-std=c11' '-Wall' '-Wextra' (Join-Path $src 'windows_probe_timing_fix.c') -o $exe 2> (Join-Path $Out 'build-warnings.txt')
if ($LASTEXITCODE -ne 0) { throw 'build failed: windows_probe_timing_fix' }

$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
@(
  "os=" + [System.Environment]::OSVersion.VersionString,
  "cpu=" + $cpu.Name,
  "logical=" + $env:NUMBER_OF_PROCESSORS,
  "exe_sha256=" + (Get-FileHash -Algorithm SHA256 $exe).Hash.ToLower()
) | Set-Content -Encoding ascii (Join-Path $Out 'machine.txt')

function RunLimited($arguments, $name, $limit) {
  $o = Join-Path $Out "$name.txt"; $e = Join-Path $Out "$name.err.txt"
  $p = Start-Process -FilePath $exe -ArgumentList $arguments -RedirectStandardOutput $o -RedirectStandardError $e -PassThru -NoNewWindow
  $null = $p.Handle
  if (-not $p.WaitForExit($limit * 1000)) { try { $p.Kill() } catch {}; $p.WaitForExit(); $rc = 'TIMEOUT' } else { $rc = [string]$p.ExitCode }
  Set-Content -Encoding ascii (Join-Path $Out "$name.rc.txt") $rc
}

$env:T86_ENVIRONMENT = 'github-hosted-runner'
foreach ($n in 1, 2) {
  $json = Join-Path $Out "timing-fix-run$n.json"
  RunLimited ("timing `"" + $json + "`"") "timing-fix-run$n" 900
}
