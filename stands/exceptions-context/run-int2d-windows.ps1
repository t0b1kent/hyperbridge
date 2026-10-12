# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
[CmdletBinding()]
param(
    [string]$OutputDirectory = "",
    [ValidateRange(10, 300)][int]$TimeoutSeconds = 150
)
$ErrorActionPreference = "Stop"
if (-not [Environment]::Is64BitProcess -or $env:PROCESSOR_ARCHITECTURE -ne "AMD64") {
    throw "The primary reference requires a native AMD64 Windows PowerShell process."
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path ([IO.Path]::GetTempPath()) ("int2d-matrix-" + [Guid]::NewGuid().ToString("N"))
}
$sourceDirectory = $PSScriptRoot
$output = [IO.Path]::GetFullPath($OutputDirectory)
if ($output.StartsWith($sourceDirectory.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -or $output -eq $sourceDirectory) {
    throw "Build and result files must stay outside the source directory."
}
if (Test-Path $output) { throw "Use a new output directory; preserve previous results." }
New-Item -ItemType Directory -Path $output | Out-Null

# Use the installed Visual Studio SDK and Clang. No downloads or toolchain fallback.
$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "Visual Studio SDK discovery is unavailable." }
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or -not $installation) { throw "An installed x64 Visual Studio toolchain is required." }
& (Join-Path $installation "Common7\Tools\Launch-VsDevShell.ps1") -Arch amd64 -HostArch amd64 -SkipAutomaticLocation
$cl = (Get-Command clang-cl.exe -ErrorAction Stop).Source
$assembler = Join-Path (Split-Path $cl) "clang.exe"
if (-not (Test-Path $assembler)) { throw "The matching Clang assembly driver is unavailable." }
$c = Join-Path $sourceDirectory "int2d-matrix.c"
$assembly = Join-Path $sourceDirectory "int2d-matrix.S"
$cObject = Join-Path $output "context.obj"
$asmObject = Join-Path $output "assembly.obj"
$exe = Join-Path $output "int2d-matrix.exe"
$oldLocation = Get-Location
try {
    Set-Location $output
    & $cl /nologo /c /TC /Od /Z7 /GS- /MT ("/Fo" + $cObject) $c 2>&1 | Out-File -Encoding utf8 (Join-Path $output "compile-c.raw.txt")
    if ($LASTEXITCODE -ne 0) { throw "C compilation failed; preserve compile-c.raw.txt." }
    & $assembler --target=x86_64-pc-windows-msvc -c $assembly -o $asmObject 2>&1 | Out-File -Encoding utf8 (Join-Path $output "compile-assembly.raw.txt")
    if ($LASTEXITCODE -ne 0) { throw "Assembly compilation failed; preserve compile-assembly.raw.txt." }
    & $cl /nologo $cObject $asmObject ("/Fe" + $exe) /link /SUBSYSTEM:CONSOLE kernel32.lib 2>&1 | Out-File -Encoding utf8 (Join-Path $output "link.raw.txt")
    if ($LASTEXITCODE -ne 0) { throw "Link failed; preserve link.raw.txt." }
} finally {
    Set-Location $oldLocation
}

$identity = [ordered]@{
    utc = [DateTime]::UtcNow.ToString("o")
    os = [Environment]::OSVersion.VersionString
    architecture = $env:PROCESSOR_ARCHITECTURE
    compiler = $cl
    compiler_version = (& $cl --version | Out-String).Trim()
    timeout_seconds = $TimeoutSeconds
    source_hashes = @{}
}
foreach ($file in @($c, $assembly, (Join-Path $sourceDirectory "run-int2d-windows.ps1"))) {
    $identity.source_hashes[(Split-Path $file -Leaf)] = (Get-FileHash -Algorithm SHA256 $file).Hash.ToLowerInvariant()
}
$identity.exe_sha256 = (Get-FileHash -Algorithm SHA256 $exe).Hash.ToLowerInvariant()
$identity | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 (Join-Path $output "identity.json")

$stdout = Join-Path $output "int2d-matrix.stdout.txt"
$stderr = Join-Path $output "int2d-matrix.stderr.txt"
$started = [DateTime]::UtcNow.ToString("o")
$watch = [Diagnostics.Stopwatch]::StartNew()
$process = Start-Process -FilePath $exe -ArgumentList "int2d-matrix" -WorkingDirectory $output -NoNewWindow -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
$finished = $process.WaitForExit($TimeoutSeconds * 1000)
if (-not $finished) {
    if (-not $process.HasExited) { $process.Kill() }
    $process.WaitForExit()
}
$watch.Stop()
$process.Refresh()
$complete = @(Select-String -LiteralPath $stdout -Pattern '^CONTEXT_PROBE COMPLETE mode=int2d-matrix cases=000001a4 ' | ForEach-Object { $_.Line })
$state = if (-not $finished) { "FAILED_TIMEOUT" } elseif ($complete.Count -ne 1) { "FAILED_INCOMPLETE" } else { "PRESENT" }
$result = [ordered]@{
    state = $state
    started_utc = $started
    finished_utc = [DateTime]::UtcNow.ToString("o")
    elapsed_seconds = $watch.Elapsed.TotalSeconds
    pid = $process.Id
    exit_code = $process.ExitCode
    complete = $complete
    stdout_bytes = (Get-Item $stdout).Length
    stderr_bytes = (Get-Item $stderr).Length
    stdout_sha256 = (Get-FileHash -Algorithm SHA256 $stdout).Hash.ToLowerInvariant()
    stderr_sha256 = (Get-FileHash -Algorithm SHA256 $stderr).Hash.ToLowerInvariant()
}
$result | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 (Join-Path $output "result.json")
Write-Output ("RESULT_DIRECTORY=" + $output)
Write-Output ("STATE=" + $state + " EXIT_CODE=" + $process.ExitCode)
if ($state -ne "PRESENT" -or $process.ExitCode -ne 0) { exit 1 }
exit 0
