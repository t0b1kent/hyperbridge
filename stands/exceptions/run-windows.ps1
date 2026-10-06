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
function BuildC($name, $flags) {
  $exe = Join-Path $bin "$name.exe"
  & $cc @flags (Join-Path $src "$name.c") -o $exe
  if ($LASTEXITCODE -ne 0) { throw "build failed: $name" }
  return $exe
}
$p5 = BuildC 'windows_process64-v5c' $probe
$sc = Build 'stack-context64' $probe @('-lntdll')
$ts = Join-Path $bin 'thread_priority_starvation64.exe'
& $cc -O1 -g0 -static -fno-stack-protector (Join-Path $src 'thread_priority_starvation64.c') -o $ts -lsynchronization
if ($LASTEXITCODE -ne 0) { throw 'build failed: thread_priority_starvation64' }

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

$d5 = NewDir 'process-v5c'
(Get-FileHash -Algorithm SHA256 (Join-Path $src 'windows_process64-v5c.c')).Hash.ToLower() | Set-Content (Join-Path $d5 'source-sha256.txt')
RunOne $p5 $d5 'list' '--list' 25000
foreach ($k in 0..82) { RunOne $p5 $d5 ("cell-{0:d2}" -f $k) "cell $k" 25000 }

$d6 = NewDir 'thread-priority'
foreach ($rep in 1..3) { foreach ($k in 0..4) { RunOne $ts $d6 ("cell-$k-rep$rep") "$k 60" 90000 } }

$d7 = NewDir 'stack-context'
foreach ($n in 'stack-context64.c', 'stack-context64.S') { (Get-FileHash -Algorithm SHA256 (Join-Path $src $n)).Hash.ToLower() + '  ' + $n | Add-Content (Join-Path $d7 'source-sha256.txt') }
foreach ($rep in 1..2) { RunOne $sc $d7 "all-rep$rep" $null 60000 }

Get-Content $m
foreach ($d in $d1, $d3, $d4, $d5, $d6, $d7) { $f = Join-Path $d 'outcomes.txt'; ('--- ' + $d + ': ' + (Get-Content $f | Measure-Object).Count + ' runs, timeouts ' + (Select-String -Path $f -Pattern 'TIMEOUT' | Measure-Object).Count) }
exit 0
