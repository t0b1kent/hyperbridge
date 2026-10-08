# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
# Builds the exception probes with a given llvm-mingw toolchain and runs every cell in its own process with a time limit.
param(
  [Parameter(Mandatory = $true)][string]$Toolchain,
  [Parameter(Mandatory = $true)][string]$Out,
  [Parameter(Mandatory = $true)][string]$OldStackExe,
  [Parameter(Mandatory = $true)][string]$NewStackExe
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
$pi = Build 'windows_process64-pinned209' ($probe + @('-Wl,--no-insert-timestamp')) @()
$mx = BuildC 'mxcsr_restore64' $probe
$om = BuildC 'object_family193' $common
$ma = Join-Path $bin 'object_marshal254.exe'
& $cc @common (Join-Path $src 'object_marshal254.c') '-Wl,--no-insert-timestamp' -o $ma -ladvapi32
if ($LASTEXITCODE -ne 0) { throw 'build failed: object_marshal254' }
$ct = Join-Path $bin 'windows_process64-continue268.exe'
& $cc @probe (Join-Path $src 'windows_process64-continue268.c') (Join-Path $src 'windows_process64-continue268.S') '-Wl,--no-insert-timestamp' -o $ct
if ($LASTEXITCODE -ne 0) { throw 'build failed: windows_process64-continue268' }
# PF354 and NV341 use the exact ordered flags from their local build receipts.
$winctxFlags = @('-O1','-g0','-static','-fms-extensions','-fno-stack-protector',
                 '-fno-vectorize','-fno-slp-vectorize','-Wl,--no-insert-timestamp')
$pf354 = Build 'pf-stack354' $winctxFlags @('-lntdll')
$nv341 = Build 'windows_process64-nv341' $winctxFlags @()
$pf375 = Join-Path $bin 'pf-stack375.exe'
& $cc @winctxFlags (Join-Path $src 'pf-stack375.c') (Join-Path $src 'pf-stack375.S') (Join-Path $src 'pf-meta375.c') -o $pf375 '-lntdll'
if ($LASTEXITCODE -ne 0) { throw 'build failed: pf-stack375' }


$sc = Build 'stack-context64' $probe @('-lntdll')
$sr = Build 'stack-returns64' $probe @('-lntdll')
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

$d8 = NewDir 'stack-returns'
foreach ($n in 'stack-returns64.c', 'stack-returns64.S') { (Get-FileHash -Algorithm SHA256 (Join-Path $src $n)).Hash.ToLower() + '  ' + $n | Add-Content (Join-Path $d8 'source-sha256.txt') }
foreach ($rep in 1..2) { RunOne $sr $d8 "all-rep$rep" $null 60000 }

$d9 = NewDir 'mxcsr-restore'
(Get-FileHash -Algorithm SHA256 (Join-Path $src 'mxcsr_restore64.c')).Hash.ToLower() | Set-Content (Join-Path $d9 'source-sha256.txt')
RunOne $mx $d9 'reserved' 'reserved' 30000
RunOne $mx $d9 'request-bv' 'request-bv' 30000

$d10 = NewDir 'object-family193'
(Get-FileHash -Algorithm SHA256 (Join-Path $src 'object_family193.c')).Hash.ToLower() | Set-Content (Join-Path $d10 'source-sha256.txt')
foreach ($rep in 1..2) { RunOne $om $d10 "all-rep$rep" $null 30000 }


$d11 = NewDir 'process-pinned209'
foreach ($n in 'windows_process64-pinned209.c', 'windows_process64-pinned209.S') {
  (Get-FileHash -Algorithm SHA256 (Join-Path $src $n)).Hash.ToLower() + '  ' + $n |
    Add-Content (Join-Path $d11 'source-sha256.txt')
}
(Get-FileHash -Algorithm SHA256 $pi).Hash.ToLower() |
  Set-Content (Join-Path $d11 'binary-sha256.txt')
$pinnedQualification = @()
foreach ($rep in 1..2) {
  foreach ($k in 2, 3, 7, 77) {
    $name = 'r{0}-cell{1:d3}' -f $rep, $k
    RunOne $pi $d11 $name @('cell', [string]$k) 30000
    $rawPath = Join-Path $d11 ($name + '.txt')
    $raw = if (Test-Path -LiteralPath $rawPath) { Get-Content -Raw -LiteralPath $rawPath } else { '' }
    $outcome = @(Get-Content -LiteralPath (Join-Path $d11 'outcomes.txt') |
      Where-Object { $_ -match ('^' + [regex]::Escape($name) + ' ') })
    $complete = $raw.Contains(('WINENV_PROBE COMPLETE cell={0:d3}' -f $k))
    $version = $raw.Contains(('WINENV_PROBE version=pinned209 base=5c cell={0:d3}' -f $k))
    $entry = $raw -match 'field=API\.ENTRY209 bytes=80 hex=[0-9a-fA-F]{160}'
    $rc0 = $outcome.Count -eq 1 -and $outcome[0] -eq ($name + ' rc=0')
    $pinnedQualification += [pscustomobject]@{
      name=$name; cell=$k; repeat=$rep; rc0=$rc0; complete=$complete
      version=$version; entry=$entry
      stdout_sha256=if (Test-Path -LiteralPath $rawPath) {
        (Get-FileHash -Algorithm SHA256 -LiteralPath $rawPath).Hash.ToLower()
      } else { $null }
    }
    $pinnedQualification | ConvertTo-Json -Depth 4 |
      Set-Content (Join-Path $d11 'qualification.json')
  }
}
$pinnedFailed = $pinnedQualification.Count -ne 8 -or
  @($pinnedQualification | Where-Object { -not ($_.rc0 -and $_.complete -and $_.version -and $_.entry) }).Count -ne 0
if (-not $pinnedFailed) {
  'COMPLETE8; Windows API reference only; games0' | Set-Content (Join-Path $d11 'COMPLETE')
}

$d12 = NewDir 'object-marshal254'
(Get-FileHash -Algorithm SHA256 (Join-Path $src 'object_marshal254.c')).Hash.ToLower() |
  Set-Content (Join-Path $d12 'source-sha256.txt')
(Get-FileHash -Algorithm SHA256 $ma).Hash.ToLower() |
  Set-Content (Join-Path $d12 'binary-sha256.txt')
$marshalQualification = @()
foreach ($rep in 1..2) {
  $name = "all-rep$rep"
  RunOne $ma $d12 $name $null 30000
  $rawPath = Join-Path $d12 ($name + '.txt')
  $raw = if (Test-Path -LiteralPath $rawPath) { Get-Content -Raw -LiteralPath $rawPath } else { '' }
  $outcome = @(Get-Content -LiteralPath (Join-Path $d12 'outcomes.txt') |
    Where-Object { $_ -match ('^' + [regex]::Escape($name) + ' ') })
  $rc0 = $outcome.Count -eq 1 -and $outcome[0] -eq ($name + ' rc=0')
  $complete = $raw.Contains('OBJECT254_COMPLETE snapshots=6 failures=0')
  $info = [regex]::Matches($raw, '(?m)^OBJECT254_INFO ').Count -eq 6
  $names = [regex]::Matches($raw, '(?m)^OBJECT254_NAME .*state=PRESENT ').Count -eq 6
  $sd = [regex]::Matches($raw, '(?m)^OBJECT254_SD .*state=PRESENT ').Count -eq 6
  $after = [regex]::Matches($raw, '(?m)^OBJECT254_AFTER ').Count -eq 6
  $marshalQualification += [pscustomobject]@{
    name=$name; repeat=$rep; rc0=$rc0; complete=$complete
    info=$info; names=$names; sd=$sd; after=$after
    stdout_sha256=if (Test-Path -LiteralPath $rawPath) {
      (Get-FileHash -Algorithm SHA256 -LiteralPath $rawPath).Hash.ToLower()
    } else { $null }
  }
  $marshalQualification | ConvertTo-Json -Depth 4 |
    Set-Content (Join-Path $d12 'qualification.json')
}
$marshalFailed = $marshalQualification.Count -ne 2 -or
  @($marshalQualification | Where-Object { -not ($_.rc0 -and $_.complete -and $_.info -and $_.names -and $_.sd -and $_.after) }).Count -ne 0
if (-not $marshalFailed) { 'COMPLETE2; synthetic object metadata only; games0' | Set-Content (Join-Path $d12 'COMPLETE') }

$d13 = NewDir 'process-continue268'
foreach ($source in @('windows_process64-continue268.c','windows_process64-continue268.S')) {
  $hash = (Get-FileHash -Algorithm SHA256 (Join-Path $src $source)).Hash.ToLower()
  "$hash  $source" | Add-Content (Join-Path $d13 'source-sha256.txt')
}
(Get-FileHash -Algorithm SHA256 $ct).Hash.ToLower() | Set-Content (Join-Path $d13 'binary-sha256.txt')
$continueQualification = @()
foreach ($rep in 1..2) {
  foreach ($cell in @(2,3)) {
    foreach ($mode in 0..7) {
      $name = ('r{0}-cell{1:000}-m{2}' -f $rep,$cell,$mode)
      RunOne $ct $d13 $name @('cell',"$cell","$mode") 30000
      $rawPath = Join-Path $d13 ($name + '.txt')
      $raw = if (Test-Path -LiteralPath $rawPath) { Get-Content -Raw -LiteralPath $rawPath } else { '' }
      $outcome = @(Get-Content -LiteralPath (Join-Path $d13 'outcomes.txt') |
        Where-Object { $_ -match ('^' + [regex]::Escape($name) + ' ') })
      $rc0 = $outcome.Count -eq 1 -and $outcome[0] -eq ($name + ' rc=0')
      $complete = $raw.Contains(('WINENV_PROBE COMPLETE cell={0:000}' -f $cell))
      $entry = $raw.Contains('field=API.ENTRY268 ')
      $after = $raw.Contains('field=API.AFTER268 ')
      $continueQualification += [pscustomobject]@{
        name=$name; repeat=$rep; cell=$cell; mode=$mode
        rc0=$rc0; complete=$complete; entry=$entry; after=$after
        stdout_sha256=if (Test-Path -LiteralPath $rawPath) {
          (Get-FileHash -Algorithm SHA256 -LiteralPath $rawPath).Hash.ToLower()
        } else { $null }
      }
      $continueQualification | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $d13 'qualification.json')
    }
  }
}
$continueFailed = $continueQualification.Count -ne 32 -or
  @($continueQualification | Where-Object { -not ($_.rc0 -and $_.complete -and $_.entry -and $_.after) }).Count -ne 0
if (-not $continueFailed) { 'COMPLETE32; synthetic continuation family only; games0' | Set-Content (Join-Path $d13 'COMPLETE') }

# Raw evidence only: values are compared to local execution after collection.
$d14 = NewDir 'pf-count-0-3-354'
foreach ($source in @('pf-stack354.c','pf-stack354.S')) {
  $hash = (Get-FileHash -Algorithm SHA256 (Join-Path $src $source)).Hash.ToLower()
  "$hash  $source" | Add-Content (Join-Path $d14 'source-sha256.txt')
}
(Get-FileHash -Algorithm SHA256 $pf354).Hash.ToLower() | Set-Content (Join-Path $d14 'binary-sha256.txt')
@{ flags=$winctxFlags; libraries=@('-lntdll'); compiler_sha256=(Get-FileHash -Algorithm SHA256 $cc).Hash.ToLower() } |
  ConvertTo-Json -Depth 4 | Set-Content (Join-Path $d14 'compiler-flags.json')
$pfQualification = @()
foreach ($rep in 1..2) {
  $name = 'all-rep{0}' -f $rep
  RunOne $pf354 $d14 $name @() 30000
  $rawPath = Join-Path $d14 ($name + '.txt')
  $raw = if (Test-Path -LiteralPath $rawPath) { Get-Content -Raw -LiteralPath $rawPath } else { '' }
  $outcome = @(Get-Content -LiteralPath (Join-Path $d14 'outcomes.txt') |
    Where-Object { $_ -match ('^' + [regex]::Escape($name) + ' ') })
  $rc0 = $outcome.Count -eq 1 -and $outcome[0] -eq ($name + ' rc=0')
  $contexts = [regex]::Matches($raw, '(?m)^STACK_CONTEXT path=').Count
  $returns = [regex]::Matches($raw, '(?m)^STACK_RETURN path=').Count
  $contextComplete = [regex]::Matches($raw, '(?m)^PF354_CONTEXT_COMPLETE rows=96 failures=0\r?$').Count -eq 1
  $returnComplete = [regex]::Matches($raw, '(?m)^PF354_RETURN_COMPLETE rows=128 failures=0\r?$').Count -eq 1
  $pfQualification += [pscustomobject]@{
    name=$name; repeat=$rep; rc0=$rc0; contexts=$contexts; returns=$returns
    complete=($contextComplete -and $returnComplete)
    stdout_sha256=if (Test-Path -LiteralPath $rawPath) { (Get-FileHash -Algorithm SHA256 -LiteralPath $rawPath).Hash.ToLower() } else { $null }
  }
  $pfQualification | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $d14 'qualification.json')
}
$pfFailed = $pfQualification.Count -ne 2 -or
  @($pfQualification | Where-Object { -not ($_.rc0 -and $_.complete -and $_.contexts -eq 96 -and $_.returns -eq 128) }).Count -ne 0
if (-not $pfFailed) { 'COMPLETE2; PF argument/stack reference only; games0' | Set-Content (Join-Path $d14 'COMPLETE') }

$d15 = NewDir 'process-nv341'
foreach ($source in @('windows_process64-nv341.c','windows_process64-nv341.S')) {
  $hash = (Get-FileHash -Algorithm SHA256 (Join-Path $src $source)).Hash.ToLower()
  "$hash  $source" | Add-Content (Join-Path $d15 'source-sha256.txt')
}
(Get-FileHash -Algorithm SHA256 $nv341).Hash.ToLower() | Set-Content (Join-Path $d15 'binary-sha256.txt')
@{ flags=$winctxFlags; libraries=@(); compiler_sha256=(Get-FileHash -Algorithm SHA256 $cc).Hash.ToLower() } |
  ConvertTo-Json -Depth 4 | Set-Content (Join-Path $d15 'compiler-flags.json')
$nvQualification = @()
foreach ($rep in 1..2) {
  foreach ($cell in @(2,3)) {
    foreach ($mode in 8..18) {
      $name = 'r{0}-cell{1:000}-m{2}' -f $rep,$cell,$mode
      RunOne $nv341 $d15 $name @('cell',"$cell","$mode") 15000
      $rawPath = Join-Path $d15 ($name + '.txt')
      $raw = if (Test-Path -LiteralPath $rawPath) { Get-Content -Raw -LiteralPath $rawPath } else { '' }
      $outcome = @(Get-Content -LiteralPath (Join-Path $d15 'outcomes.txt') |
        Where-Object { $_ -match ('^' + [regex]::Escape($name) + ' ') })
      $rc0 = $outcome.Count -eq 1 -and $outcome[0] -eq ($name + ' rc=0')
      $complete = $raw.Contains(('WINENV_PROBE COMPLETE cell={0:000}' -f $cell))
      $prefix = '(?m)^WINENV cell=' + ('{0:000}' -f $cell) + ' field='
      $entry = [regex]::Matches($raw, ($prefix + 'API\.ENTRY268 bytes=120 hex=[0-9a-f]{240}\r?$')).Count -eq 1
      $after = [regex]::Matches($raw, ($prefix + 'API\.AFTER341 bytes=256 hex=[0-9a-f]{512}\r?$')).Count -eq 1
      $requestedMode = [regex]::Matches($raw, ($prefix + 'Continue\.Mode value=' + ('{0:x16}' -f $mode) + '\r?$')).Count -eq 1
      $nvQualification += [pscustomobject]@{
        name=$name; repeat=$rep; cell=$cell; mode=$mode
        rc0=$rc0; complete=$complete; entry=$entry; after=$after; requested_mode=$requestedMode
        stdout_sha256=if (Test-Path -LiteralPath $rawPath) { (Get-FileHash -Algorithm SHA256 -LiteralPath $rawPath).Hash.ToLower() } else { $null }
      }
      $nvQualification | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $d15 'qualification.json')
    }
  }
}
$nvFailed = $nvQualification.Count -ne 44 -or
  @($nvQualification | Where-Object { -not ($_.rc0 -and $_.complete -and $_.entry -and $_.after -and $_.requested_mode) }).Count -ne 0
if (-not $nvFailed) { 'COMPLETE44; nested INTEGER selection reference only; games0' | Set-Content (Join-Path $d15 'COMPLETE') }

# Saved references run unchanged; these binaries are job inputs, not source payload.
$ErrorActionPreference = 'Stop'
$d16 = NewDir 'pf-metadata-375'
$d17 = NewDir 'stack-context-byteexact-375'
$referenceHashes = @{
  '20348' = @{
    old='a4820ee62b7d0ab70b2e2cbfa40462a369dd65dc41e288aaf4995870aa0d3f81'
    new='b906b4f833baf303a38439a20d8c60010007cec1aea89e0a9d4f83663762d99d'
  }
  '26100' = @{
    old='f15533e53b12c4ee67644b3ead927c716f109da11c804e74d6f9884f17ac86f0'
    new='c23849c12b9a14b4533f047ffe2e46f885a7682d24a3d8677c70690782d3ed9b'
  }
}
$referenceBuild = [string]$w.CurrentBuild
if (-not $referenceHashes.ContainsKey($referenceBuild)) { throw "unqualified reference OS build: $referenceBuild" }
$references = @(
  @{ label='old'; exe=$OldStackExe; run_id='37425633239' },
  @{ label='new'; exe=$NewStackExe; run_id='37790391364' }
)
$referencePins = @()
foreach ($reference in $references) {
  $item = Get-Item -LiteralPath $reference.exe
  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $reference.exe).Hash.ToLower()
  if ($item.Length -ne 92160 -or $hash -ne $referenceHashes[$referenceBuild][$reference.label]) {
    throw ("reference bytes/SHA mismatch: " + $reference.label)
  }
  $referencePins += [pscustomobject]@{
    label=$reference.label; origin_run_id=$reference.run_id; bytes=$item.Length; sha256=$hash
  }
}
$referencePins | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $d17 'input-pins.json')
$stackControlQualification = @()
foreach ($rep in 1..2) {
  foreach ($reference in $references) {
    $name = '{0}-rep{1}' -f $reference.label,$rep
    RunOne $reference.exe $d17 $name @() 30000
    $rawPath = Join-Path $d17 ($name + '.txt')
    $raw = if (Test-Path -LiteralPath $rawPath) { Get-Content -Raw -LiteralPath $rawPath } else { '' }
    $outcome = @(Get-Content -LiteralPath (Join-Path $d17 'outcomes.txt') |
      Where-Object { $_ -match ('^' + [regex]::Escape($name) + ' ') })
    $rc0 = $outcome.Count -eq 1 -and $outcome[0] -eq ($name + ' rc=0')
    $contexts = [regex]::Matches($raw, '(?m)^STACK_CONTEXT path=').Count
    $complete = [regex]::Matches($raw, '(?m)^STACK_CONTEXT_COMPLETE rows=64 failures=0\r?$').Count -eq 1
    $hashAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath $reference.exe).Hash.ToLower()
    $stderrBytes = (Get-Item -LiteralPath (Join-Path $d17 ($name + '.err.txt'))).Length
    $stackControlQualification += [pscustomobject]@{
      name=$name; repeat=$rep; origin_run_id=$reference.run_id; rc0=$rc0
      contexts=$contexts; complete=$complete
      byte_exact=($hashAfter -eq $referenceHashes[$referenceBuild][$reference.label])
      stderr_bytes=$stderrBytes; exe_sha256_after=$hashAfter
      stdout_sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $rawPath).Hash.ToLower()
    }
    $stackControlQualification | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $d17 'qualification.json')
  }
}
$stackControlFailed = $stackControlQualification.Count -ne 4 -or
  @($stackControlQualification | Where-Object {
    -not ($_.rc0 -and $_.complete -and $_.contexts -eq 64 -and $_.byte_exact -and $_.stderr_bytes -eq 0)
  }).Count -ne 0
if (-not $stackControlFailed) { 'COMPLETE4; old/new original bytes; games0' | Set-Content (Join-Path $d17 'COMPLETE') }

foreach ($source in @('pf-stack375.c','pf-stack375.S','pf-meta375.c')) {
  $hash = (Get-FileHash -Algorithm SHA256 (Join-Path $src $source)).Hash.ToLower()
  "$hash  $source" | Add-Content (Join-Path $d16 'source-sha256.txt')
}
(Get-FileHash -Algorithm SHA256 $pf375).Hash.ToLower() | Set-Content (Join-Path $d16 'binary-sha256.txt')
@{ flags=$winctxFlags; libraries=@('-lntdll'); compiler_sha256=(Get-FileHash -Algorithm SHA256 $cc).Hash.ToLower() } |
  ConvertTo-Json -Depth 4 | Set-Content (Join-Path $d16 'compiler-flags.json')
@{ current_build=$w.CurrentBuild; ubr=$w.UBR; architecture=$env:PROCESSOR_ARCHITECTURE } |
  ConvertTo-Json | Set-Content (Join-Path $d16 'OS375.json')
$pfMetadataQualification = @()
foreach ($rep in 1..2) {
  $name = 'all-rep{0}' -f $rep
  RunOne $pf375 $d16 $name @() 30000
  $rawPath = Join-Path $d16 ($name + '.txt')
  $raw = if (Test-Path -LiteralPath $rawPath) { Get-Content -Raw -LiteralPath $rawPath } else { '' }
  $outcome = @(Get-Content -LiteralPath (Join-Path $d16 'outcomes.txt') |
    Where-Object { $_ -match ('^' + [regex]::Escape($name) + ' ') })
  $rc0 = $outcome.Count -eq 1 -and $outcome[0] -eq ($name + ' rc=0')
  $contexts = [regex]::Matches($raw, '(?m)^STACK_CONTEXT path=').Count
  $returns = [regex]::Matches($raw, '(?m)^STACK_RETURN path=').Count
  $contextComplete = [regex]::Matches($raw, '(?m)^PF354_CONTEXT_COMPLETE rows=96 failures=0\r?$').Count -eq 1
  $returnComplete = [regex]::Matches($raw, '(?m)^PF354_RETURN_COMPLETE rows=128 failures=0\r?$').Count -eq 1
  $metadataComplete = [regex]::Matches($raw, '(?m)^PF375_METADATA_COMPLETE modules=3 length_rows=8\r?$').Count -eq 1
  $moduleLines = [regex]::Matches($raw, '(?m)^PF375_MODULE ').Count
  $modules = @()
  foreach ($match in [regex]::Matches($raw, '(?m)^PF375_MODULE name=(\S+) state=PRESENT path_hex=([0-9a-f]+)\r?$')) {
    $hex = $match.Groups[2].Value
    if ($hex.Length % 2 -ne 0) { throw 'odd module path hex length' }
    $bytes = New-Object byte[] ($hex.Length / 2)
    for ($i=0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring(2*$i,2),16) }
    $modulePath = [Text.Encoding]::Default.GetString($bytes)
    $item = Get-Item -LiteralPath $modulePath
    $modules += [pscustomobject]@{
      name=$match.Groups[1].Value; state='PRESENT'; bytes=$item.Length
      file_version=$item.VersionInfo.FileVersion; product_version=$item.VersionInfo.ProductVersion
      sha256=(Get-FileHash -LiteralPath $modulePath -Algorithm SHA256).Hash.ToLower()
    }
  }
  $modules | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $d16 ($name + '-loaded-modules.json'))
  $moduleNames = @($modules | ForEach-Object { $_.name } | Sort-Object -Unique)
  $modulesPresent = $moduleLines -eq 3 -and $modules.Count -eq 3 -and
    ($moduleNames -join ',') -eq 'kernel32.dll,kernelbase.dll,ntdll.dll'
  $lengthRows = [regex]::Matches($raw, '(?m)^PF375_LENGTH api=\S+ state=PRESENT ').Count
  $xstate = [regex]::Matches($raw, '(?m)^PF375_XSTATE state=PRESENT enabled=[0-9a-f]{16}\r?$').Count -eq 1
  $cpuRows = [regex]::Matches($raw, '(?m)^PF375_CPU ').Count
  $stderrBytes = (Get-Item -LiteralPath (Join-Path $d16 ($name + '.err.txt'))).Length
  $pfMetadataQualification += [pscustomobject]@{
    name=$name; repeat=$rep; rc0=$rc0; contexts=$contexts; returns=$returns
    complete=($contextComplete -and $returnComplete -and $metadataComplete)
    modules_present=$modulesPresent; length_rows=$lengthRows; xstate_present=$xstate
    cpu_rows=$cpuRows; stderr_bytes=$stderrBytes
    stdout_sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $rawPath).Hash.ToLower()
  }
  $pfMetadataQualification | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $d16 'qualification.json')
}
$pfMetadataFailed = $pfMetadataQualification.Count -ne 2 -or
  @($pfMetadataQualification | Where-Object {
    -not ($_.rc0 -and $_.complete -and $_.contexts -eq 96 -and $_.returns -eq 128 -and
          $_.modules_present -and $_.length_rows -eq 8 -and $_.xstate_present -and
          $_.cpu_rows -eq 3 -and $_.stderr_bytes -eq 0)
  }).Count -ne 0
if (-not $pfMetadataFailed) { 'COMPLETE2; DLL/XSTATE/PF reference only; games0' | Set-Content (Join-Path $d16 'COMPLETE') }
$ErrorActionPreference = 'Continue'

Get-Content $m
foreach ($d in $d1, $d3, $d4, $d5, $d6, $d7, $d8, $d9, $d10, $d11, $d12, $d13, $d14, $d15, $d16, $d17) { $f = Join-Path $d 'outcomes.txt'; ('--- ' + $d + ': ' + (Get-Content $f | Measure-Object).Count + ' runs, timeouts ' + (Select-String -Path $f -Pattern 'TIMEOUT' | Measure-Object).Count) }
if ($pinnedFailed -or $marshalFailed -or $continueFailed -or $pfFailed -or $nvFailed -or $pfMetadataFailed -or $stackControlFailed) { exit 1 }
exit 0
