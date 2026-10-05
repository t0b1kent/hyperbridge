# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
# Builds the exception probes with a given llvm-mingw toolchain and runs every cell in its own process with a time limit.
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

$common = @('-O1', '-g0', '-static', '-fno-stack-protector')
$probe = $common + @('-fms-extensions', '-fno-vectorize', '-fno-slp-vectorize')
function Build($name, $flags, $libs) {
  $exe = Join-Path $bin "$name.exe"
  & $cc @flags (Join-Path $src "$name.c") (Join-Path $src "$name.S") -o $exe @libs
  if ($LASTEXITCODE -ne 0) { throw "build failed: $name" }
  return $exe
}
$v1 = Build 'exception_context64-v1' $probe @('-lntdll')
$v3 = Build 'exception_context64-v3' $probe @('-lntdll')
$v4 = Build 'exception_context64-v4' $probe @('-lntdll')
$hb = Build 'eflags_highbits64' $common @()

$m = Join-Path $Out 'machine.txt'
(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name) | Set-Content $m
('cores=' + (Get-CimInstance Win32_Processor | Measure-Object -Property NumberOfCores -Sum).Sum) | Add-Content $m
('arch=' + $env:PROCESSOR_ARCHITECTURE + ' id=' + $env:PROCESSOR_IDENTIFIER) | Add-Content $m
$w = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
('windows=' + $w.ProductName + ' ' + $w.DisplayVersion + ' build ' + $w.CurrentBuild + '.' + $w.UBR) | Add-Content $m
('powershell=' + $PSVersionTable.PSVersion.ToString()) | Add-Content $m
Get-ChildItem $bin -Filter *.exe | ForEach-Object { (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower() + '  ' + $_.Name } | Set-Content (Join-Path $Out 'binaries-sha256.txt')

$ErrorActionPreference = 'Continue'
function RunOne($exe, $dir, $name, $argList, $limitMs) {
  $o = Join-Path $dir "$name.txt"; $e = Join-Path $dir "$name.err.txt"; $rc = Join-Path $dir 'outcomes.txt'
  if ($argList) { $p = Start-Process -FilePath $exe -ArgumentList $argList -NoNewWindow -PassThru -RedirectStandardOutput $o -RedirectStandardError $e }
  else { $p = Start-Process -FilePath $exe -NoNewWindow -PassThru -RedirectStandardOutput $o -RedirectStandardError $e }
  $null = $p.Handle
  if (-not $p.WaitForExit($limitMs)) { try { $p.Kill(); $null = $p.WaitForExit(5000) } catch {}; Add-Content $rc "$name TIMEOUT" }
  else { Add-Content $rc ("$name rc=" + $p.ExitCode) }
}
function NewDir($name) { $d = Join-Path $Out $name; New-Item -ItemType Directory -Force $d | Out-Null; return $d }

$d1 = NewDir 'v1'
foreach ($mode in 'flagbits', 'exceptions', 'exceptions-seh', 'capture', 'race', 'smoke') { RunOne $v1 $d1 "mode-$mode" $mode 90000 }
foreach ($k in 0..27) {
  if ($k -eq 6) { continue }
  RunOne $v1 $d1 ("cell-{0:d2}-veh" -f $k) "cell $k 15 0" 30000
  RunOne $v1 $d1 ("cell-{0:d2}-seh" -f $k) "cell $k 15 1" 30000
}
RunOne $hb $d1 'highbits' $null 30000

$d3 = NewDir 'v3'
foreach ($k in 0..64) {
  if ($k -eq 6) { continue }
  RunOne $v3 $d3 ("cell-{0:d2}-veh" -f $k) "cell $k 15 0" 25000
  RunOne $v3 $d3 ("cell-{0:d2}-seh" -f $k) "cell $k 15 1" 25000
}
foreach ($mode in 'x87', 'capture', 'flagbits', 'fastfail') { RunOne $v3 $d3 "mode-$mode" $mode 60000 }

$d4 = NewDir 'v4'
foreach ($k in 62, 63, 64) {
  RunOne $v4 $d4 ("cell-{0:d2}-veh" -f $k) "cell $k 15 0" 25000
  RunOne $v4 $d4 ("cell-{0:d2}-seh" -f $k) "cell $k 15 1" 25000
}

Get-Content $m
foreach ($d in $d1, $d3, $d4) { $f = Join-Path $d 'outcomes.txt'; ('--- ' + $d + ': ' + (Get-Content $f | Measure-Object).Count + ' runs, timeouts ' + (Select-String -Path $f -Pattern 'TIMEOUT' | Measure-Object).Count) }
exit 0
