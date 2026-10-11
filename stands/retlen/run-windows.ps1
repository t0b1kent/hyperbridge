# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
# Builds retlen.c with a given llvm-mingw toolchain as a 64-bit and a 32-bit program and runs each once (60 s limit).
# Output goes only to -Out.
param(
  [Parameter(Mandatory = $true)][string]$Toolchain,
  [Parameter(Mandatory = $true)][string]$Out
)
$ErrorActionPreference = 'Stop'
$src = Join-Path $PSScriptRoot 'src\retlen.c'
New-Item -ItemType Directory -Force $Out | Out-Null
@("os=" + [System.Environment]::OSVersion.VersionString) | Set-Content -Encoding ascii (Join-Path $Out 'machine.txt')
foreach ($arch in @(@{ tag = '64'; cc = 'x86_64-w64-mingw32-gcc.exe' }, @{ tag = '32'; cc = 'i686-w64-mingw32-gcc.exe' })) {
  $cc = Join-Path $Toolchain ('bin\' + $arch.cc)
  if (-not (Test-Path $cc)) { throw "compiler not found: $cc" }
  $name = 'retlen' + $arch.tag
  $exe = Join-Path $Out ($name + '.exe')
  & $cc '-O1' '-Wall' '-Wextra' $src '-lntdll' -o $exe 2> (Join-Path $Out ($name + '.build.txt'))
  if ($LASTEXITCODE -ne 0) { throw "build failed: $name" }
  $p = Start-Process -FilePath $exe -RedirectStandardOutput (Join-Path $Out ($name + '.txt')) -RedirectStandardError (Join-Path $Out ($name + '.err.txt')) -PassThru -NoNewWindow
  $null = $p.Handle
  if (-not $p.WaitForExit(60000)) { try { $p.Kill() } catch {}; $p.WaitForExit(); $rc = 'TIMEOUT' } else { $rc = [string]$p.ExitCode }
  Set-Content -Encoding ascii (Join-Path $Out ($name + '.rc.txt')) $rc
  Remove-Item -Force $exe
}
