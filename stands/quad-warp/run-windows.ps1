# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
param(
  [Parameter(Mandatory = $true)][string]$Out,
  [string]$Dxc = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (Test-Path -LiteralPath $Out) { throw 'Out must be new; preserve failed runs' }
$outDir = (New-Item -ItemType Directory -Path $Out).FullName
$src = Join-Path $PSScriptRoot 'src'
$status = @{ schema=1; status='FAILED'; backend='WARP, not hardware'; runtime='NOT_ENABLED'; timeout=$false }
$build = @{ schema=1; status='NOT_ENABLED'; workers=1; minimum_steps=6; steps=@() }
function Digest($path) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Native($exe, $argList) {
  & $exe @argList >> (Join-Path $outDir 'build.txt') 2>&1
  $rc = $LASTEXITCODE
  $build.steps += @{ tool=[IO.Path]::GetFileName($exe); rc=$rc;
    argv=@($argList | ForEach-Object { $_.Replace($src,'src') }) }
  $build.status = if ($rc -eq 0) { 'PREPARING' } else { 'FAILED' }
  $build | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $outDir 'BUILD.json') -Encoding utf8
  if ($rc -ne 0) { throw "build failed: $([IO.Path]::GetFileName($exe)), rc=$rc" }
}
try {
  # The caller initializes MSVC once, before starting PowerShell.
  # The workflow uses a cmd step so VsDevCmd's environment is inherited directly.
  if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    throw 'MSVC cl.exe is not in PATH; initialize VsDevCmd.bat -arch=x64 -host_arch=x64 before starting PowerShell'
  }
  if (-not $Dxc) {
    $found = Get-Command dxc.exe -ErrorAction SilentlyContinue
    if ($found) { $Dxc = $found.Source }
    else {
      $sdkBin = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
      $choices = @(Get-ChildItem -Path $sdkBin -Filter dxc.exe -Recurse |
        Where-Object { $_.Directory.Name -eq 'x64' } | Sort-Object FullName -Descending)
      if ($choices.Count) { $Dxc = $choices[0].FullName }
    }
  }
  if (-not $Dxc -or -not (Test-Path -LiteralPath $Dxc)) { throw 'Installed DXC required; pass -Dxc explicitly; no DXBC fallback' }
  $compiler = (Get-Command cl.exe).Source
  $python = (Get-Command python.exe).Source
  New-Item -ItemType Directory (Join-Path $outDir 'bin'),(Join-Path $outDir 'shaders') | Out-Null
  Copy-Item (Join-Path $PSScriptRoot 'cases.csv') (Join-Path $outDir 'cases.csv')
  $sourceHashes = @(Get-ChildItem -LiteralPath $PSScriptRoot -Recurse -File | Sort-Object FullName | ForEach-Object {
    @{ path=[IO.Path]::GetRelativePath($PSScriptRoot,$_.FullName).Replace('\','/'); bytes=$_.Length; sha256=(Digest $_.FullName) }
  })
  $sourceHashes | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $outDir 'sources.json') -Encoding utf8
  $tools = @($compiler,$Dxc) | ForEach-Object {
    @{ name=[IO.Path]::GetFileName($_); version=(Get-Item $_).VersionInfo.FileVersion; sha256=(Digest $_) }
  }
  $tools | ConvertTo-Json | Set-Content (Join-Path $outDir 'tools.json') -Encoding utf8
  & $Dxc --version > (Join-Path $outDir 'dxc-version.txt') 2>&1
  $sdkDlls = @('d3d12.dll','d3d12core.dll','d3d12warp.dll','dxgi.dll') | ForEach-Object {
    $dll = Join-Path $env:SystemRoot "System32\$_"
    if (Test-Path $dll) { @{ name=$_; version=(Get-Item $dll).VersionInfo.FileVersion; sha256=(Digest $dll); status='PRESENT' } }
    else { @{ name=$_; status='NOT_PRESENT_AT_SYSTEM32' } }
  }
  @{ os=[Environment]::OSVersion.Version.ToString(); arch=$env:PROCESSOR_ARCHITECTURE;
     powershell=$PSVersionTable.PSVersion.ToString(); system_dlls=$sdkDlls;
     dll_scope='System32 inventory, not proof of loaded paths' } |
    ConvertTo-Json -Depth 5 | Set-Content (Join-Path $outDir 'machine.json') -Encoding utf8
  Push-Location $outDir
  try {
    Native $compiler @('/nologo','/std:c++17','/O2','/EHsc','/MT','/W4','/WX',
      (Join-Path $src 'quad-warp.cpp'),'/Febin\quad-warp.exe','/Fobin\quad-warp.obj',
      '/link','d3d12.lib','dxgi.lib','d3dcompiler.lib')
    foreach ($stage in @('vs','ps')) {
      Native $Dxc @('-T',"${stage}_6_0",'-E',"${stage}_main",(Join-Path $src 'triquad-endpoints.hlsl'),'-Fo',"shaders\$stage.dxil")
    }
    Native $Dxc @('-T','ds_6_0','-E','ds_main',(Join-Path $src 'quad-cross.hlsl'),'-Fo','shaders\ds.dxil')
    foreach ($winding in @('cw','ccw')) {
      Native $Dxc @('-T','hs_6_0','-E','hs_main',(Join-Path $src "hs-$winding.hlsl"),'-Fo',"shaders\hs-$winding.dxil")
    }
    $build.status = 'PRESENT'
    $build | ConvertTo-Json -Depth 6 | Set-Content 'BUILD.json' -Encoding utf8
    $built = @(Get-ChildItem bin,shaders -File | Sort-Object FullName | ForEach-Object {
      @{ path=[IO.Path]::GetRelativePath($outDir,$_.FullName).Replace('\','/'); bytes=$_.Length; sha256=(Digest $_.FullName) }
    })
    $built | ConvertTo-Json | Set-Content 'built-sha256.json' -Encoding utf8
    $status.runtime = 'STARTED'
    $proc = Start-Process -FilePath (Join-Path $outDir 'bin\quad-warp.exe') -ArgumentList @('shaders','cases.csv','raw') `
      -WorkingDirectory $outDir -NoNewWindow -PassThru -RedirectStandardOutput 'stdout.txt' -RedirectStandardError 'stderr.txt'
    $null = $proc.Handle
    if (-not $proc.WaitForExit(55000)) {
      $status.timeout = $true; $status.runtime = 'TIMEOUT'
      $proc.Kill($true); $null = $proc.WaitForExit(5000)
      throw 'WARP process exceeded 55 seconds'
    }
    $status.runtime = 'EXITED'; $status.exit_code = $proc.ExitCode
    if ($proc.ExitCode -ne 0) { throw "WARP failed rc=$($proc.ExitCode)" }
    & $python (Join-Path $PSScriptRoot 'check-output.py') --run . > 'qualification.txt' 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'readback qualification failed' }
    $status.status = 'PRESENT'
  } finally { Pop-Location }
} catch {
  $status.reason = $_.Exception.Message
  Write-Host ('FAILED: ' + $status.reason)
} finally {
  $build | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $outDir 'BUILD.json') -Encoding utf8
  $rawDir = Join-Path $outDir 'raw'
  if (Test-Path $rawDir) {
    @(Get-ChildItem -LiteralPath $rawDir -Recurse -File | Sort-Object FullName | ForEach-Object {
      @{ path=[IO.Path]::GetRelativePath($outDir,$_.FullName).Replace('\','/'); bytes=$_.Length; sha256=(Digest $_.FullName) }
    }) | ConvertTo-Json | Set-Content (Join-Path $outDir 'raw-sha256.json') -Encoding utf8
  }
  $status | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $outDir 'RUN.json') -Encoding utf8
}
if ($status.status -ne 'PRESENT') { exit 1 }
Write-Host 'PRESENT: 6 cases, 12 RGBA readbacks, WARP not hardware'
exit 0
