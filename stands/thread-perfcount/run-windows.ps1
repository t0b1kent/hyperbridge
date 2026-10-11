# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
# Builds thread_performance_count.c with a given llvm-mingw toolchain as a 64-bit and a 32-bit program and runs every
# case of each in its own process through run-cases.ps1. Output goes only to -Out.
param(
  [Parameter(Mandatory = $true)][string]$Toolchain,
  [Parameter(Mandatory = $true)][string]$Out
)
$ErrorActionPreference = 'Stop'
$src = Join-Path $PSScriptRoot 'src\thread_performance_count.c'
$runner = Join-Path $PSScriptRoot 'run-cases.ps1'
New-Item -ItemType Directory -Force $Out | Out-Null
@("os=" + [System.Environment]::OSVersion.VersionString) | Set-Content -Encoding ascii (Join-Path $Out 'machine.txt')
foreach ($arch in @(@{ tag = 'x64'; cc = 'x86_64-w64-mingw32-gcc.exe' }, @{ tag = 'x86'; cc = 'i686-w64-mingw32-gcc.exe' })) {
  $cc = Join-Path $Toolchain ('bin\' + $arch.cc)
  if (-not (Test-Path $cc)) { throw "compiler not found: $cc" }
  $exe = Join-Path $Out ('thread-performance-count-' + $arch.tag + '.exe')
  & $cc '-O1' '-Wall' '-Wextra' $src -o $exe 2> (Join-Path $Out ($arch.tag + '.build.txt'))
  if ($LASTEXITCODE -ne 0) { throw "build failed: $($arch.tag)" }
  & $runner -Exe $exe -OutDir (Join-Path $Out $arch.tag)
  Remove-Item -Force $exe
}
