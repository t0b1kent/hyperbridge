# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
# Builds thread_performance_count.c with a given llvm-mingw toolchain as a 64-bit and a 32-bit program and runs every
# case of each in its own process through run-cases.ps1. Output goes only to -Out. The source fingerprint and the build
# target are passed to the program through a generated header, so every output record names the source it came from.
param(
  [Parameter(Mandatory = $true)][string]$Toolchain,
  [Parameter(Mandatory = $true)][string]$Out
)
$ErrorActionPreference = 'Stop'
$src = Join-Path $PSScriptRoot 'src\thread_performance_count.c'
$runner = Join-Path $PSScriptRoot 'run-cases.ps1'
New-Item -ItemType Directory -Force $Out | Out-Null
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $src).Hash.ToLowerInvariant()
$osLine = 'os=' + [System.Environment]::OSVersion.VersionString
$hashLine = 'source_sha256=' + $hash
Set-Content -Encoding ascii (Join-Path $Out 'machine.txt') -Value @($osLine, $hashLine)
foreach ($arch in @(@{ tag = 'x64'; target = 'x86_64-w64-mingw32' }, @{ tag = 'x86'; target = 'i686-w64-mingw32' })) {
  $cc = Join-Path $Toolchain ('bin\' + $arch.target + '-clang.exe')
  if (-not (Test-Path $cc)) { throw "compiler not found: $cc" }
  $defs = Join-Path $Out ('probe-defs-' + $arch.tag + '.h')
  $defLine1 = '#define PROBE_SOURCE_SHA256 "' + $hash + '"'
  $defLine2 = '#define PROBE_BUILD_TARGET "' + $arch.target + '"'
  Set-Content -Encoding ascii $defs -Value @($defLine1, $defLine2)
  $exe = Join-Path $Out ('thread-performance-count-' + $arch.tag + '.exe')
  & $cc '-std=c11' '-O1' '-Wall' '-Wextra' '-Werror' '-Wl,--no-insert-timestamp' '-include' $defs $src -o $exe 2> (Join-Path $Out ($arch.tag + '.build.txt'))
  if ($LASTEXITCODE -ne 0) { throw "build failed: $($arch.tag)" }
  & $runner -Exe $exe -OutDir (Join-Path $Out $arch.tag)
  # Schema 3: retain this Windows-built EXE in -Out for independent artifact hashing.
}
