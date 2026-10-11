param(
    [Parameter(Mandatory=$true)][string]$Toolchain,
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\named-object-stage1b-build')
)
$ErrorActionPreference = 'Stop'
# Existing official llvm-mingw only. This script does not download or install tools.
New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
$Source = Join-Path $PSScriptRoot 'source\named_object_stage1b.c'
foreach ($Target in @('x86_64', 'i686')) {
    $Compiler = Join-Path $Toolchain "bin\$Target-w64-mingw32-clang.exe"
    if (-not (Test-Path $Compiler)) { throw "Compiler is absent: $Compiler" }
    $Output = Join-Path $BuildDir "named-object-stage1b-$Target.exe"
    & $Compiler -std=c11 -O1 -Wall -Wextra -Werror -municode $Source -ladvapi32 -o $Output
    if ($LASTEXITCODE -ne 0) { throw "Compile failed for $Target ($LASTEXITCODE)." }
    Write-Host "Built $Output"
}
