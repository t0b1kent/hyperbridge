# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
# Builds longjmp_probe.c with a given llvm-mingw toolchain (and with MSVC when available) and runs: list, the observation
# cells in ten ranges, stress, timing. Every invocation is a separate process with its own time limit. Output goes only to -Out.
param(
  [Parameter(Mandatory = $true)][string]$Toolchain,
  [Parameter(Mandatory = $true)][string]$Out
)
$ErrorActionPreference = 'Stop'
$src = Join-Path $PSScriptRoot 'src\longjmp_probe.c'
New-Item -ItemType Directory -Force $Out | Out-Null
$bin = Join-Path $Out 'bin'
New-Item -ItemType Directory -Force $bin | Out-Null

$builds = [ordered]@{}
$cc = Join-Path $Toolchain 'bin\x86_64-w64-mingw32-gcc.exe'
if (-not (Test-Path $cc)) { throw "compiler not found: $cc" }
$exeMingw = Join-Path $bin 'longjmp_probe_mingw.exe'
& $cc '-std=c11' '-O2' '-Wall' '-Wextra' $src -o $exeMingw 2> (Join-Path $Out 'build-mingw.txt')
if ($LASTEXITCODE -ne 0) { throw 'build failed: mingw' }
$builds['mingw'] = $exeMingw

# MSVC is optional: record why it is absent instead of failing the run.
$exeMsvc = Join-Path $bin 'longjmp_probe_msvc.exe'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$msvcNote = Join-Path $Out 'build-msvc.txt'
if (Test-Path $vswhere) {
  $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
  $vcvars = if ($vs) { Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat' } else { $null }
  if ($vcvars -and (Test-Path $vcvars)) {
    $obj = Join-Path $bin 'longjmp_probe_msvc.obj'
    cmd /c "`"$vcvars`" >nul && cl /nologo /W4 /O2 /TC `"$src`" /Fo:`"$obj`" /Fe:`"$exeMsvc`"" > $msvcNote 2>&1
    if ($LASTEXITCODE -eq 0 -and (Test-Path $exeMsvc)) { $builds['msvc'] = $exeMsvc } else { Add-Content $msvcNote "MSVC build failed, exit code $LASTEXITCODE" }
  } else { Set-Content -Encoding ascii $msvcNote 'vcvars64.bat not found' }
} else { Set-Content -Encoding ascii $msvcNote 'vswhere.exe not found' }

$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$machine = @(
  "os=" + [System.Environment]::OSVersion.VersionString,
  "cpu=" + $cpu.Name,
  "logical=" + $env:NUMBER_OF_PROCESSORS
)
foreach ($k in $builds.Keys) { $machine += ("exe_" + $k + "_sha256=" + (Get-FileHash -Algorithm SHA256 $builds[$k]).Hash.ToLower()) }
$machine | Set-Content -Encoding ascii (Join-Path $Out 'machine.txt')

function RunLimited($program, $arguments, $dir, $name, $limit) {
  $o = Join-Path $dir "$name.txt"; $e = Join-Path $dir "$name.err.txt"
  $p = Start-Process -FilePath $program -ArgumentList $arguments -RedirectStandardOutput $o -RedirectStandardError $e -PassThru -NoNewWindow
  $null = $p.Handle
  if (-not $p.WaitForExit($limit * 1000)) { try { $p.Kill() } catch {}; $p.WaitForExit(); $rc = 'TIMEOUT' } else { $rc = [string]$p.ExitCode }
  Set-Content -Encoding ascii (Join-Path $dir "$name.rc.txt") $rc
}

foreach ($k in $builds.Keys) {
  $exe = $builds[$k]
  $dir = Join-Path $Out $k
  New-Item -ItemType Directory -Force $dir | Out-Null
  RunLimited $exe 'list' $dir 'list' 120
  # observation cells: ten transition flavours, 108 cells each
  for ($f = 0; $f -lt 10; $f++) {
    $first = 950000 + $f * 108; $last = $first + 107
    RunLimited $exe "range $first $last --timeout-ms 30000" $dir ("range-f{0}" -f $f) 1500
  }
  RunLimited $exe 'stress --timeout-ms 600000' $dir 'stress' 3600
  RunLimited $exe 'timing --iterations 100000 --timeout-ms 600000' $dir 'timing' 1800
}
