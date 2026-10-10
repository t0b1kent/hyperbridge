# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
# Builds the excdump probe with a given llvm-mingw toolchain, runs `list`, runs `all` twice (whole matrix in one process, 60 s limit each)
# and runs every cell in its own process (30 s limit each). Output goes only to -Out.
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
$exe = Join-Path $bin 'excdump.exe'
& $cc '-O1' '-g0' '-static' '-fno-stack-protector' '-Wl,--no-insert-timestamp' (Join-Path $src 'excdump.c') -o $exe
if ($LASTEXITCODE -ne 0) { throw 'build failed: excdump' }
$exe2 = Join-Path $bin 'excdump2.exe'
& $cc '-O1' '-g0' '-static' '-fno-stack-protector' '-Wl,--no-insert-timestamp' (Join-Path $src 'excdump2.c') -o $exe2
if ($LASTEXITCODE -ne 0) { throw 'build failed: excdump2' }
$exe3 = Join-Path $bin 'excdump3.exe'
& $cc '-O1' '-g0' '-static' '-fno-stack-protector' '-Wl,--no-insert-timestamp' (Join-Path $src 'excdump3.c') -o $exe3
if ($LASTEXITCODE -ne 0) { throw 'build failed: excdump3' }

# machine description
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
@(
  "os=" + [System.Environment]::OSVersion.VersionString,
  "cpu=" + $cpu.Name,
  "cpu_id=" + $cpu.ProcessorId,
  "logical=" + $env:NUMBER_OF_PROCESSORS,
  "exe_sha256=" + (Get-FileHash -Algorithm SHA256 $exe).Hash.ToLower(),
  "exe2_sha256=" + (Get-FileHash -Algorithm SHA256 $exe2).Hash.ToLower(),
  "exe3_sha256=" + (Get-FileHash -Algorithm SHA256 $exe3).Hash.ToLower()
) | Set-Content -Encoding ascii (Join-Path $Out 'machine.txt')

function RunLimited($arguments, $outFile, $errFile, $limit, $program = $exe) {
  $p = Start-Process -FilePath $program -ArgumentList $arguments -RedirectStandardOutput $outFile -RedirectStandardError $errFile -PassThru -NoNewWindow
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
foreach ($n in 1, 2) {
  $rc = RunLimited 'all' (Join-Path $all "all-$n.txt") (Join-Path $all "all-$n.err.txt") 60
  Set-Content -Encoding ascii (Join-Path $all "all-$n.rc.txt") $rc
}

$cells = Join-Path $Out 'cells'
New-Item -ItemType Directory -Force $cells | Out-Null
$tsv = & $exe 'tsv'
foreach ($line in $tsv) {
  $parts = $line -split "`t"
  if ($parts.Count -lt 2) { continue }
  $name = $parts[0]
  $rc = RunLimited $parts[1] (Join-Path $cells "$name.txt") (Join-Path $cells "$name.err.txt") 30
  Set-Content -Encoding ascii (Join-Path $cells "$name.rc.txt") $rc
}

# excdump2: the same cells plus floating-point state through the handler (cells 77-86)
$all2 = Join-Path $Out 'all2'
New-Item -ItemType Directory -Force $all2 | Out-Null
foreach ($n in 1, 2) {
  $rc = RunLimited 'all' (Join-Path $all2 "all-$n.txt") (Join-Path $all2 "all-$n.err.txt") 90 $exe2
  Set-Content -Encoding ascii (Join-Path $all2 "all-$n.rc.txt") $rc
}
$cells2 = Join-Path $Out 'cells2'
New-Item -ItemType Directory -Force $cells2 | Out-Null
$tsv2 = & $exe2 'tsv'
foreach ($line in $tsv2) {
  $parts = $line -split "`t"
  if ($parts.Count -lt 2) { continue }
  $name = $parts[0]
  $rc = RunLimited $parts[1] (Join-Path $cells2 "$name.txt") (Join-Path $cells2 "$name.err.txt") 30 $exe2
  Set-Content -Encoding ascii (Join-Path $cells2 "$name.rc.txt") $rc
}

# excdump3: excdump2 with the direction flag cleared before returning to C code (the combined run no longer stops after cell 68)
$all3 = Join-Path $Out 'all3'
New-Item -ItemType Directory -Force $all3 | Out-Null
foreach ($n in 1, 2) {
  $rc = RunLimited 'all' (Join-Path $all3 "all-$n.txt") (Join-Path $all3 "all-$n.err.txt") 90 $exe3
  Set-Content -Encoding ascii (Join-Path $all3 "all-$n.rc.txt") $rc
}
$cells3 = Join-Path $Out 'cells3'
New-Item -ItemType Directory -Force $cells3 | Out-Null
$tsv3 = & $exe3 'tsv'
foreach ($line in $tsv3) {
  $parts = $line -split "`t"
  if ($parts.Count -lt 2) { continue }
  $name = $parts[0]
  $rc = RunLimited $parts[1] (Join-Path $cells3 "$name.txt") (Join-Path $cells3 "$name.err.txt") 30 $exe3
  Set-Content -Encoding ascii (Join-Path $cells3 "$name.rc.txt") $rc
}
