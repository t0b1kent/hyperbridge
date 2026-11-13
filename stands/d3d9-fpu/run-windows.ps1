# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
# Builds and runs the d3d9-fpu probe (32-bit).  Run in an x86 Native Tools / Developer PowerShell (cl.exe on the path).
# Nothing is installed, no display mode is changed, no window is shown (the probe's window is off screen).
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [int]$TimeoutSeconds = 120
)
$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot 'd3d9-fpu.c'
$compiler = Get-Command cl.exe -ErrorAction Stop
$out = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $out) { throw 'OutputDirectory must be new; existing evidence will not be overwritten.' }
$null = New-Item -ItemType Directory -Path $out
$build = Join-Path $out 'build'
$null = New-Item -ItemType Directory -Path $build
Copy-Item -LiteralPath $source -Destination (Join-Path $build 'd3d9-fpu.c')
$sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
Push-Location $build
try {
    & $compiler.Path /nologo /O1 /W3 d3d9-fpu.c d3d9.lib user32.lib /link /subsystem:windows 2>&1 | Tee-Object -FilePath (Join-Path $out 'compiler.txt')
    $compilerExit = $LASTEXITCODE
} finally { Pop-Location }
$exe = Join-Path $build 'd3d9-fpu.exe'
$record = [ordered]@{ schema = 1; probe = 'd3d9-fpu-v1'; source_sha256 = $sourceHash; compiler = $compiler.Path
                      compiler_exit = $compilerExit; launched = $false; timeout = $false; exit_code = $null }
if ($compilerExit -eq 0 -and (Test-Path -LiteralPath $exe)) {
    $p = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden
    $record.launched = $true
    if (-not $p.WaitForExit($TimeoutSeconds * 1000)) { $record.timeout = $true; try { $p.Kill() } catch { } ; $p.WaitForExit(10000) | Out-Null }
    $record.exit_code = $p.ExitCode
    Get-ChildItem -LiteralPath $build -Filter 'd3d9fpu-out-*.txt' | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $out $_.Name) }
}
$cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
$os = (Get-CimInstance Win32_OperatingSystem).Version
"$cpu`n$os" | Out-File -Encoding utf8 (Join-Path $out 'machine.txt')
$record | ConvertTo-Json -Depth 4 | Out-File -Encoding utf8 (Join-Path $out 'run.json')
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $build
Get-ChildItem -LiteralPath $out | Select-Object -ExpandProperty Name
