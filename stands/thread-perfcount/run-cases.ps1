param(
    [Parameter(Mandatory=$true)][string]$Exe,
    [Parameter(Mandatory=$true)][string]$OutDir
)
$ErrorActionPreference = 'Stop'
$exePath = (Resolve-Path -LiteralPath $Exe).Path
if (Test-Path -LiteralPath $OutDir) { throw 'Use a new output directory to preserve prior raw runs.' }
New-Item -ItemType Directory -Path $OutDir | Out-Null
$outPath = (Resolve-Path -LiteralPath $OutDir).Path
$names = @(& $exePath --list)
if ($LASTEXITCODE -ne 0 -or $names.Count -eq 0) { throw 'Cannot list probe cases.' }
Get-FileHash -Algorithm SHA256 -LiteralPath $exePath |
    Select-Object Algorithm, Hash | ConvertTo-Json | Set-Content -Encoding UTF8 "$outPath\binary-sha256.json"
$summary = @()

function Stop-ProbeProcess($Process) {
    try { $Process.Kill() }
    catch {
        # It may have exited naturally between the timeout and Kill().
        if (-not $Process.HasExited) { throw }
    }
}

foreach ($name in $names) {
    if ($name -notmatch '^[a-z0-9_]+$') { throw "Invalid case name: $name" }
    $stdout = Join-Path $outPath "$name.jsonl"
    $stderr = Join-Path $outPath "$name.stderr.txt"
    $started = [DateTime]::UtcNow.ToString('o')
    # Start directly so this Process retains the native handle and exit code,
    # including for very short-lived/crashing cases on Windows PowerShell.
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo.FileName = $exePath
    $process.StartInfo.Arguments = "--case $name"
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    $stdoutStream = $null
    $stderrStream = $null
    $processStarted = $false
    try {
        $stdoutStream = [System.IO.File]::Open($stdout, [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        $stderrStream = [System.IO.File]::Open($stderr, [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        if (-not $process.Start()) { throw "Could not start case: $name" }
        $processStarted = $true
        # Drain both pipes concurrently and preserve the bytes without text
        # decoding, newline rewriting, or stdout/stderr deadlocks.
        $stdoutCopy = $process.StandardOutput.BaseStream.CopyToAsync($stdoutStream)
        $stderrCopy = $process.StandardError.BaseStream.CopyToAsync($stderrStream)
        $exited = $process.WaitForExit(15000)
        if (-not $exited) { Stop-ProbeProcess $process }
        $process.WaitForExit()
        $stdoutCopy.GetAwaiter().GetResult()
        $stderrCopy.GetAwaiter().GetResult()
        $exitCode = $process.ExitCode
    }
    finally {
        if ($processStarted -and -not $process.HasExited) {
            Stop-ProbeProcess $process
            $process.WaitForExit()
        }
        if ($null -ne $stdoutStream) { $stdoutStream.Dispose() }
        if ($null -ne $stderrStream) { $stderrStream.Dispose() }
        $process.Dispose()
    }
    $unsignedExitCode = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$exitCode), 0)
    $summary += [pscustomobject]@{
        case = $name; started_utc = $started; finished_utc = [DateTime]::UtcNow.ToString('o')
        timed_out = (-not $exited); exit_code = $exitCode
        exit_code_hex = ('0x{0:x8}' -f $unsignedExitCode)
        stdout = "$name.jsonl"; stderr = "$name.stderr.txt"
    }
    ConvertTo-Json -InputObject @($summary) -Depth 4 |
        Set-Content -Encoding UTF8 "$outPath\process-results.json"
}
Write-Host "Saved $($names.Count) isolated cases in $outPath"
