# SPDX-License-Identifier: MIT
# Run in an x64 Native Tools/Developer PowerShell environment with MSVC installed.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [switch]$CompileOnly
)
$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot 'probe.c'
$compiler = Get-Command cl.exe -ErrorAction Stop
$out = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $out) { throw 'OutputDirectory must be new; existing evidence will not be overwritten.' }
$null = New-Item -ItemType Directory -Path $out
$build = Join-Path $out 'build'
$null = New-Item -ItemType Directory -Path $build
$compiledSource = Join-Path $build 'probe.c'
Copy-Item -LiteralPath $source -Destination $compiledSource
$utf8 = New-Object Text.UTF8Encoding($false)
$sourceHash = (Get-FileHash -LiteralPath $compiledSource -Algorithm SHA256).Hash.ToLowerInvariant()
$record = [ordered]@{
    schema=1; probe='0064-ordinary-api-v1'; source_sha256=$sourceHash
    requested_mode=$(if ($CompileOnly) { 'compile_only' } else { 'compile_and_run' })
    compiler_exit=$null; launched=$false; timeout=$false; kill_requested=$false
    kill_confirmed=$false; kill_error_type=$null; launcher_error_type=$null; exit_code=$null
    stdout_drain=$null; stderr_drain=$null
    native_results='NOT_RUN'; raw_jsonl_sha256=$null; raw_stderr_sha256=$null
}
function Finish-Copy {
    param($Task, $InputStream)
    # No unbounded Wait/GetResult. Partial bytes are already in the output file.
    try { $finished = $Task.Wait(5000) } catch { $finished = $Task.IsCompleted }
    if (-not $finished) {
        try { $InputStream.Close() } catch { }
        try { $finished = $Task.Wait(1000) } catch { $finished = $Task.IsCompleted }
    }
    if (-not $finished) { return 'timeout_partial' }
    if ($Task.IsFaulted -or $Task.IsCanceled) { return 'faulted_partial' }
    return 'completed'
}
try {
    Push-Location -LiteralPath $build
    try {
        $savedPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $buildText = (& $compiler.Source /nologo /std:c11 /O2 /W4 /D_CRT_SECURE_NO_WARNINGS /Fe:probe.exe /Fo:probe.obj probe.c 2>&1 | Out-String)
        $compileExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedPreference
        Pop-Location
    }
    $record.compiler_exit = $compileExit
    [IO.File]::WriteAllText((Join-Path $out 'compiler.txt'), $buildText, $utf8)
    if ($compileExit -ne 0) { throw "Compiler exited with code $compileExit; see compiler.txt." }
    if (-not $CompileOnly) {
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = Join-Path $build 'probe.exe'
        $info.WorkingDirectory = $build
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $process = New-Object Diagnostics.Process
        $process.StartInfo = $info
        $rawPath = Join-Path $out 'raw.jsonl'
        $errPath = Join-Path $out 'raw.stderr.txt'
        $raw = [IO.File]::Open($rawPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        $err = [IO.File]::Open($errPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try {
            if (-not $process.Start()) { throw 'Probe process did not start.' }
            $record.launched = $true
            $record.native_results = 'LAUNCHED_INCOMPLETE_CAPTURE'
            # Copy bytes incrementally, without decoding or regenerating JSON lines.
            $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($raw)
            $stderrTask = $process.StandardError.BaseStream.CopyToAsync($err)
            $exited = $process.WaitForExit(60000)
            if (-not $exited) {
                $record.timeout = $true
                $record.kill_requested = $true
                try { $process.Kill() } catch { $record.kill_error_type = $_.Exception.GetType().Name }
                $exited = $process.WaitForExit(5000)
                $record.kill_confirmed = $exited
            }
            if ($exited) { $record.exit_code = $process.ExitCode }
            $record.stdout_drain = Finish-Copy $stdoutTask $process.StandardOutput.BaseStream
            $record.stderr_drain = Finish-Copy $stderrTask $process.StandardError.BaseStream
            $record.native_results = if ($record.timeout) { 'TIMEOUT_PARTIAL_RAW' }
                elseif ($record.stdout_drain -ne 'completed' -or $record.stderr_drain -ne 'completed') { 'DRAIN_FAILURE_PARTIAL_RAW' }
                elseif ($record.exit_code -eq 0) { 'CAPTURED_REQUIRES_ANALYSIS' }
                else { 'NONZERO_EXIT_PARTIAL_RAW' }
        } catch {
            $record.native_results = 'LAUNCHER_FAILURE_PARTIAL_RAW'
            $record.launcher_error_type = $_.Exception.GetType().Name
            throw
        } finally {
            # Disposing output streams preserves already-written bytes even on failure.
            $raw.Dispose()
            $err.Dispose()
            $process.Dispose()
        }
        $record.raw_jsonl_sha256 = (Get-FileHash -LiteralPath $rawPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $record.raw_stderr_sha256 = (Get-FileHash -LiteralPath $errPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
} finally {
    foreach ($pair in @(@('raw.jsonl','raw_jsonl_sha256'),@('raw.stderr.txt','raw_stderr_sha256'))) {
        $path = Join-Path $out $pair[0]
        if (Test-Path -LiteralPath $path) {
            try { $record[$pair[1]] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() } catch { }
        }
    }
    [IO.File]::WriteAllText((Join-Path $out 'run.json'), ($record | ConvertTo-Json -Depth 5), $utf8)
}
Write-Output "Evidence saved in the requested new directory. Runtime status: $($record.native_results)"
if ($record.launched -and $record.native_results -ne 'CAPTURED_REQUIRES_ANALYSIS') { exit 2 }
