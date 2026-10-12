#requires -Version 7.0
<#
Build and run the source-only Windows x64 own-process exception probe.
No toolchain installation, downloads, shell command interpolation, or retries.
Use a fresh output directory. Existing results are never overwritten.
#>
[CmdletBinding()]
param(
    [string] $Clang = 'x86_64-w64-mingw32-clang',
    [string] $Python = 'python',
    [string] $OutputDirectory = (Join-Path $PSScriptRoot ('results-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff')))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function Write-JsonFile {
    param([string] $Path, [object] $Value)
    [System.IO.File]::WriteAllText($Path, (($Value | ConvertTo-Json -Depth 12) + [Environment]::NewLine), $Utf8NoBom)
}

function Format-HexCode {
    param([int] $Code)
    return ('0x{0:x}' -f ([uint32]([int64]$Code -band 0xffffffffL)))
}

function Resolve-Executable {
    param([string] $Name)
    $found = @(Get-Command -Name $Name -CommandType Application -ErrorAction Stop)
    if ($found.Count -eq 0) { throw "Application was not found: $Name" }
    $path = $found[0].Source
    if ([System.IO.Path]::GetExtension($path) -ine '.exe') {
        throw "An existing .exe application is required, not a shell script: $path"
    }
    return [System.IO.Path]::GetFullPath($path)
}

function Invoke-LoggedNative {
    param(
        [string] $Executable,
        [string[]] $Arguments,
        [string] $LogBase
    )
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.WorkingDirectory = $PSScriptRoot
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw "Could not start application: $Executable" }
        # Drain both pipes concurrently, including on nonzero process exit.
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        [System.IO.File]::WriteAllText(($LogBase + '.stdout.log'), $stdout, $Utf8NoBom)
        [System.IO.File]::WriteAllText(($LogBase + '.stderr.log'), $stderr, $Utf8NoBom)
        $result = [pscustomobject]@{ ExitCode = $process.ExitCode; Stdout = $stdout; Stderr = $stderr }
        Write-JsonFile ($LogBase + '.status.json') ([ordered]@{
            executable = $Executable
            arguments = $Arguments
            exit_code = Format-HexCode $process.ExitCode
        })
        return $result
    }
    catch {
        [System.IO.File]::WriteAllText(($LogBase + '.start-error.log'), ($_ | Out-String), $Utf8NoBom)
        throw
    }
    finally { $process.Dispose() }
}

$output = [System.IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) {
    if (-not (Test-Path -LiteralPath $output -PathType Container)) {
        throw "Output path is not a directory: $output"
    }
    if (@(Get-ChildItem -LiteralPath $output -Force).Count -ne 0) {
        throw "Output directory must be empty or absent; refusing to overwrite prior results: $output"
    }
}
else { [void](New-Item -ItemType Directory -Path $output) }
$build = Join-Path $output 'build'
[void](New-Item -ItemType Directory -Path $build)
$statusPath = Join-Path $output 'runner.status.json'

try {
    $nativeArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    $environment = [ordered]@{
        utc_start = [DateTime]::UtcNow.ToString('o')
        operating_system = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
        native_os_architecture = $nativeArchitecture
        process_architecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
        PROCESSOR_ARCHITECTURE = $env:PROCESSOR_ARCHITECTURE
        PROCESSOR_ARCHITEW6432 = $env:PROCESSOR_ARCHITEW6432
        powershell_version = $PSVersionTable.PSVersion.ToString()
        source_directory = $PSScriptRoot
        output_directory = $output
    }
    Write-JsonFile (Join-Path $output 'run_environment.json') $environment
    Write-Host "Native OS architecture: $nativeArchitecture; PROCESSOR_ARCHITECTURE=$env:PROCESSOR_ARCHITECTURE"
    if (-not $IsWindows -or $nativeArchitecture -ne 'X64' -or
        [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString() -ne 'X64' -or
        $env:PROCESSOR_ARCHITECTURE -ine 'AMD64' -or [IntPtr]::Size -ne 8) {
        throw 'Native Windows x64 and x64 PowerShell are required. ARM64, emulated x64, x86 and WOW64 are unsupported.'
    }

    $compiler = Resolve-Executable $Clang
    $pythonExe = Resolve-Executable $Python
    foreach ($file in @('exception_probe.c', 'asm_fragment.h', 'check_results.py')) {
        if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $file) -PathType Leaf)) {
            throw "Required source file is missing: $file"
        }
    }
    $versionResult = Invoke-LoggedNative $compiler @('--version') (Join-Path $build 'compiler-version')
    if ($versionResult.ExitCode -ne 0 -or $versionResult.Stdout -notmatch '(?i)clang') {
        throw 'Compiler version check failed or the selected application did not identify itself as clang.'
    }
    $targetResult = Invoke-LoggedNative $compiler @('-dumpmachine') (Join-Path $build 'compiler-target')
    $target = $targetResult.Stdout.Trim()
    if ($targetResult.ExitCode -ne 0 -or $target -notmatch '^x86_64-w64-(windows-gnu|mingw32)$') {
        throw "Unsupported compiler target '$target'. Select the x86_64 llvm-mingw compiler. No retargeting retry is attempted."
    }
    if ($versionResult.Stdout -notmatch 'clang version 22\.1\.5(?:\s|$)') {
        throw 'This package requires llvm-mingw 20260505 (clang 22.1.5). No alternative compiler retry is attempted.'
    }
    Write-JsonFile (Join-Path $build 'toolchain-identity.json') ([ordered]@{
        expected_release = 'llvm-mingw 20260505 UCRT'
        actual_clang_version = $versionResult.Stdout.Trim()
        compiler_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $compiler).Hash.ToLowerInvariant()
        release_provenance = 'User must supply the official 20260505 distribution; version check alone is not archive provenance.'
    })
    Write-Host "Compiler target: $target"
    $pythonResult = Invoke-LoggedNative $pythonExe @('-c', 'import sys; print(sys.version); sys.exit(0 if sys.version_info >= (3, 10) else 1)') (Join-Path $build 'python-version')
    if ($pythonResult.ExitCode -ne 0) { throw 'Python 3.10 or newer is required.' }

    $exe = Join-Path $build 'exception_probe.exe'
    $compileArguments = @(
        '-std=c11', '-fms-extensions', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
        '-municode', (Join-Path $PSScriptRoot 'exception_probe.c'), '-o', $exe
    )
    $compile = Invoke-LoggedNative $compiler $compileArguments (Join-Path $build 'compile')
    if ($compile.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        Write-JsonFile $statusPath ([ordered]@{
            status = 'build_blocked'
            compiler_exit_code = Format-HexCode $compile.ExitCode
            reason = 'Compilation failed; no retry, alternative implementation, or executable run was attempted.'
        })
        Write-Host "Build blocked. Read $build\compile.stdout.log and compile.stderr.log"
        exit 2
    }
    $sourceHashes = [ordered]@{}
    foreach ($name in @('exception_probe.c', 'asm_fragment.h', 'run_windows.ps1', 'check_results.py', 'DESIGN.md', 'MAPPING.md', 'README.md')) {
        $sourceHashes[$name] = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $PSScriptRoot $name)).Hash.ToLowerInvariant()
    }
    Write-JsonFile (Join-Path $output 'input-and-binary-sha256.json') ([ordered]@{
        source_sha256 = $sourceHashes
        executable_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash.ToLowerInvariant()
    })
}
catch {
    Write-JsonFile $statusPath ([ordered]@{ status = 'setup_or_build_blocked'; reason = $_.Exception.Message })
    [System.IO.File]::WriteAllText((Join-Path $build 'runner-error.log'), ($_ | Out-String), $Utf8NoBom)
    Write-Host "Setup/build blocked: $($_.Exception.Message)"
    exit 2
}

# The probe owns all group children and bounds each child wait itself.
$probeExit = -1
$probeStartError = $null
try {
    $probeResult = Invoke-LoggedNative $exe @('--output', $output) (Join-Path $output 'probe')
    $probeExit = $probeResult.ExitCode
}
catch { $probeStartError = $_.Exception.Message }

# Always inspect partial/missing raw output after an attempted native probe run.
$checkerExit = -1
$checkerStartError = $null
$raw = Join-Path $output 'raw.jsonl'
$summary = Join-Path $output 'summary.json'
try {
    $checkResult = Invoke-LoggedNative $pythonExe @((Join-Path $PSScriptRoot 'check_results.py'), $raw, '--summary', $summary) (Join-Path $output 'checker')
    $checkerExit = $checkResult.ExitCode
    if ($checkResult.Stdout) { Write-Host $checkResult.Stdout.TrimEnd() }
    if ($checkResult.Stderr) { Write-Host $checkResult.Stderr.TrimEnd() }
}
catch { $checkerStartError = $_.Exception.Message }

$passed = $probeExit -eq 0 -and $checkerExit -eq 0 -and (Test-Path -LiteralPath $summary -PathType Leaf)
Write-JsonFile $statusPath ([ordered]@{
    status = $(if ($passed) { 'checked' } else { 'run_or_check_failed' })
    probe_exit_code = Format-HexCode $probeExit
    probe_start_error = $probeStartError
    checker_exit_code = Format-HexCode $checkerExit
    checker_start_error = $checkerStartError
    raw = $raw
    summary = $summary
    utc_end = [DateTime]::UtcNow.ToString('o')
    note = 'A successful accounting check does not imply that unsupported continuation policies were measured.'
})
Write-Host "Results: $output"
Write-Host "Probe exit: $(Format-HexCode $probeExit); checker exit: $(Format-HexCode $checkerExit)"
if (-not $passed) { exit 1 }
exit 0
