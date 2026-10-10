# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
# Builds protflags.c with a given llvm-mingw toolchain and runs it once (60 s limit). Output goes only to -Out.
param(
  [Parameter(Mandatory = $true)][string]$Toolchain,
  [Parameter(Mandatory = $true)][string]$Out
)
$ErrorActionPreference = 'Stop'
$src = Join-Path $PSScriptRoot 'src\protflags.c'
$cc = Join-Path $Toolchain 'bin\x86_64-w64-mingw32-gcc.exe'
if (-not (Test-Path $cc)) { throw "compiler not found: $cc" }
New-Item -ItemType Directory -Force $Out | Out-Null
$exe = Join-Path $Out 'protflags.exe'
& $cc '-O1' '-Wall' '-Wextra' $src -o $exe 2> (Join-Path $Out 'build.txt')
if ($LASTEXITCODE -ne 0) { throw 'build failed: protflags' }
@("os=" + [System.Environment]::OSVersion.VersionString) | Set-Content -Encoding ascii (Join-Path $Out 'machine.txt')
$p = Start-Process -FilePath $exe -RedirectStandardOutput (Join-Path $Out 'protflags.txt') -RedirectStandardError (Join-Path $Out 'protflags.err.txt') -PassThru -NoNewWindow
$null = $p.Handle
if (-not $p.WaitForExit(60000)) { try { $p.Kill() } catch {}; $p.WaitForExit(); $rc = 'TIMEOUT' } else { $rc = [string]$p.ExitCode }
Set-Content -Encoding ascii (Join-Path $Out 'protflags.rc.txt') $rc
