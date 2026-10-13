# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
[CmdletBinding()]
param(
    [string]$OutputDirectory = "",
    [ValidateRange(1, 9)][int]$Runs = 3,
    [ValidateRange(10, 600)][int]$TimeoutSeconds = 60
)
$ErrorActionPreference = "Stop"
if (-not [Environment]::Is64BitProcess -or $env:PROCESSOR_ARCHITECTURE -ne "AMD64") {
    throw "The primary reference requires a native AMD64 Windows PowerShell process."
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path ([IO.Path]::GetTempPath()) ("env-read-" + [Guid]::NewGuid().ToString("N"))
}
$sourceDirectory = $PSScriptRoot
$output = [IO.Path]::GetFullPath($OutputDirectory)
if ($output.StartsWith($sourceDirectory.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -or $output -eq $sourceDirectory) {
    throw "Build and result files must stay outside the source directory."
}
if (Test-Path $output) { throw "Use a new output directory; preserve previous results." }
New-Item -ItemType Directory -Path $output | Out-Null

# Use the installed Visual Studio SDK, Clang and LLD. No downloads or toolchain fallback.
$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "Visual Studio SDK discovery is unavailable." }
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or -not $installation) { throw "An installed x64 Visual Studio toolchain is required." }
& (Join-Path $installation "Common7\Tools\Launch-VsDevShell.ps1") -Arch amd64 -HostArch amd64 -SkipAutomaticLocation
$cl = (Get-Command clang-cl.exe -ErrorAction Stop).Source
$c = Join-Path $sourceDirectory "envread.c"
$exe = Join-Path $output "envread.exe"
$oldLocation = Get-Location
try {
    Set-Location $output
    # The program has no C runtime and includes no headers: only kernel32.lib is linked, the entry point is its own.
    & $cl /nologo /TC /O1 /GS- /Gs1048576 /Zl /W3 /clang:-ffreestanding /clang:-fno-builtin /clang:-mno-stack-arg-probe /clang:-masm=att `
        -fuse-ld=lld ("/Fe" + $exe) $c /link /NODEFAULTLIB /ENTRY:envread_entry /SUBSYSTEM:CONSOLE kernel32.lib 2>&1 |
        Out-File -Encoding utf8 (Join-Path $output "compile.raw.txt")
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $exe)) { throw "Compilation failed; preserve compile.raw.txt." }
} finally {
    Set-Location $oldLocation
}

$identity = [ordered]@{
    utc = [DateTime]::UtcNow.ToString("o")
    os = [Environment]::OSVersion.VersionString
    architecture = $env:PROCESSOR_ARCHITECTURE
    compiler = $cl
    compiler_version = (& $cl --version | Out-String).Trim()
    runs = $Runs
    timeout_seconds = $TimeoutSeconds
    source_hashes = @{}
}
foreach ($file in @($c, (Join-Path $sourceDirectory "run-windows.ps1"))) {
    $identity.source_hashes[(Split-Path $file -Leaf)] = (Get-FileHash -Algorithm SHA256 $file).Hash.ToLowerInvariant()
}
$identity.exe_sha256 = (Get-FileHash -Algorithm SHA256 $exe).Hash.ToLowerInvariant()
$identity | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 (Join-Path $output "identity.json")

# The same program several times: a cell whose value changes between runs of one machine is not a property of the system.
$records = @()
$allPresent = $true
for ($n = 1; $n -le $Runs; $n++) {
    $stdout = Join-Path $output ("envread.run$n.stdout.txt")
    $stderr = Join-Path $output ("envread.run$n.stderr.txt")
    $started = [DateTime]::UtcNow.ToString("o")
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath $exe -WorkingDirectory $output -NoNewWindow -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $finished = $process.WaitForExit($TimeoutSeconds * 1000)
    if (-not $finished) {
        if (-not $process.HasExited) { $process.Kill() }
        $process.WaitForExit()
    }
    $watch.Stop()
    $process.Refresh()
    $lines = @(Get-Content -LiteralPath $stdout)
    $done = @($lines | Where-Object { $_ -match '^\{"c":"meta\.done","v":"0x([0-9a-f]+)"\}$' })
    $complete = $false
    if ($done.Count -eq 1 -and $done[0] -match '"v":"0x([0-9a-f]+)"') {
        $complete = ([Convert]::ToInt32($Matches[1], 16) -eq $lines.Count)
    }
    $state = if (-not $finished) { "FAILED_TIMEOUT" } elseif (-not $complete) { "FAILED_INCOMPLETE" } elseif ($process.ExitCode -ne 0) { "FAILED_EXIT_CODE" } else { "PRESENT" }
    if ($state -ne "PRESENT") { $allPresent = $false }
    $records += [ordered]@{
        run = $n
        state = $state
        started_utc = $started
        elapsed_seconds = $watch.Elapsed.TotalSeconds
        exit_code = $process.ExitCode
        cells = $lines.Count
        stdout_bytes = (Get-Item $stdout).Length
        stderr_bytes = (Get-Item $stderr).Length
        stdout_sha256 = (Get-FileHash -Algorithm SHA256 $stdout).Hash.ToLowerInvariant()
    }
}
$result = [ordered]@{
    state = if ($allPresent) { "PRESENT" } else { "FAILED" }
    finished_utc = [DateTime]::UtcNow.ToString("o")
    runs = $records
}
$result | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 (Join-Path $output "result.json")
Write-Output ("RESULT_DIRECTORY=" + $output)
Write-Output ("STATE=" + $result.state)
foreach ($r in $records) { Write-Output ("RUN " + $r.run + " " + $r.state + " cells=" + $r.cells + " exit=" + $r.exit_code) }
# A short readable extract of the first run.
Get-Content -LiteralPath (Join-Path $output "envread.run1.stdout.txt") |
    Where-Object { $_ -match '"c":"(entry\.(rcx|rdx|r8|r9|eflags|cs|ss|ds|es|fs|gs)|peb\.(BeingDebugged|NtGlobalFlag|OSBuildNumber|NumberOfProcessors)|heap\.0\.(Flags|ForceFlags)|usd\.(NtBuildNumber|KdDebuggerEnabled|NativeProcessorArchitecture|ProcessorFeatures)|ret\.NtClose\.invalid\.A\.(rax|rcx|rdx|r8|r9|r10|r11|eflags)|cpu\.[a-z0-9_.]+)"' } |
    Write-Output
if (-not $allPresent) { exit 1 }
exit 0
