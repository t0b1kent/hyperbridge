# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
# Builds windows_probe.c with a given llvm-mingw toolchain and runs it by classes of cells (each range in its own process with a time limit):
# list, the non-CPUID classes, then CPUID in four chunks, then the timing mode twice. Output goes only to -Out.
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
$exe = Join-Path $bin 'windows_probe.exe'
& $cc '-O1' '-std=c11' '-Wall' '-Wextra' (Join-Path $src 'windows_probe.c') -o $exe 2> (Join-Path $Out 'build-warnings.txt')
if ($LASTEXITCODE -ne 0) { throw 'build failed: windows_probe' }

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

RunLimited 'list' 'list' 120
$ranges = [ordered]@{
  'b1-xgetbv-features' = '12484 12535'; 'b1-features-extra' = '13233 13239'; 'b2' = '12536 12601'; 'b3' = '12602 12671';
  'b4-int'   = '12672 12930'; 'b4-rest' = '12931 13029'; 'b4-prefix' = '13030 13189';
  'b5' = '13190 13210'; 'b6' = '13211 13223'; 'd-context' = '13231 13232'
}
foreach ($k in $ranges.Keys) { RunLimited ("range " + $ranges[$k]) ("range-" + $k) 1800 }
$cpuid = @('0 3120', '3121 6241', '6242 9362', '9363 12483')
for ($i = 0; $i -lt $cpuid.Count; $i++) { RunLimited ("range " + $cpuid[$i]) ("range-cpuid-" + ($i + 1)) 1800 }
$env:T86_ENVIRONMENT = 'github-hosted-runner'
foreach ($n in 1, 2) {
  $json = Join-Path $Out "timing-run$n.json"
  RunLimited ("timing `"" + $json + "`"") "timing-run$n" 600
}
