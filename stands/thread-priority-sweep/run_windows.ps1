# Native Windows only. Run sequentially on each dedicated 4-logical-CPU host.
[CmdletBinding()]
param(
    [string]$Compiler = 'clang.exe',
    [string]$Python = 'python.exe',
    [string]$OutputDirectory = '',
    [ValidateRange(0,15)][int]$Base = 0,
    [switch]$AllPairs,
    [ValidateRange(1000,30000)][int]$ShortMs = 3000,
    [ValidateRange(1000,120000)][int]$BusyMs = 20000,
    [ValidateRange(100,5000)][int]$WarmupMs = 500,
    [ValidateRange(2,8)][int]$ExpectedCpus = 4,
    [ValidateRange(-1,63)][int]$WorkerCpu = -1
)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This runner requires native Windows.' }
if ($AllPairs -and $Base) { throw 'Use either -AllPairs or -Base.' }
$root = $PSScriptRoot
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $root ('results-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Output directory already exists; choose a fresh directory.' }
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
$out = (Resolve-Path -LiteralPath $OutputDirectory).Path
$exe = Join-Path $out 'priority_probe.exe'
$source = Join-Path $root 'priority_probe.c'
$compilerPath = (Get-Command $Compiler -ErrorAction Stop).Source
$pythonPath = (Get-Command $Python -ErrorAction Stop).Source
& $compilerPath --version 2>&1 | Out-File -Encoding utf8 (Join-Path $out 'compiler.txt')
$buildArgs = @('-std=c11', '-O1', '-Wall', '-Wextra', '-Werror', $source, '-o', $exe)
& $compilerPath @buildArgs 2>&1 | Out-File -Encoding utf8 (Join-Path $out 'build.log')
$buildExit = $LASTEXITCODE
if ($buildExit -ne 0 -or -not (Test-Path -LiteralPath $exe)) { throw "Build failed ($buildExit); inspect build.log." }
$probeArgs = @('--short-ms', "$ShortMs", '--busy-ms', "$BusyMs", '--warmup-ms', "$WarmupMs", '--expected-cpus', "$ExpectedCpus")
if ($Base) { $probeArgs += @('--base', "$Base") }
if ($AllPairs) { $probeArgs += '--all-pairs' }
if ($WorkerCpu -ge 0) { $probeArgs += @('--worker-cpu', "$WorkerCpu") }
$os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture
$cpu = @(Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors)
$meta = [ordered]@{
    utc_started = [DateTime]::UtcNow.ToString('o')
    runner_os = $env:RUNNER_OS
    runner_arch = $env:RUNNER_ARCH
    runner_image_os = $env:ImageOS
    runner_image_version = $env:ImageVersion
    os = $os
    cpu = $cpu
    arguments = $probeArgs
    build_arguments = $buildArgs
    source_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash.ToLowerInvariant()
    exe_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash.ToLowerInvariant()
}
$meta | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 (Join-Path $out 'host.json')
Write-Host 'Running owned worker/helpers sequentially. Default sweep takes roughly 9 minutes. Do not run other benchmarks in parallel.'
$process = Start-Process -FilePath $exe -ArgumentList $probeArgs -NoNewWindow -PassThru -Wait -RedirectStandardOutput (Join-Path $out 'raw.jsonl') -RedirectStandardError (Join-Path $out 'stderr.txt')
$probeExit = $process.ExitCode
& $pythonPath (Join-Path $root 'check_results.py') (Join-Path $out 'raw.jsonl') --out (Join-Path $out 'summary.json') | Out-File -Encoding utf8 (Join-Path $out 'checker.stdout.json')
$checkerExit = $LASTEXITCODE
[ordered]@{ utc_finished = [DateTime]::UtcNow.ToString('o'); build_exit = $buildExit; probe_exit = $probeExit; checker_exit = $checkerExit } |
    ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $out 'run_status.json')
Get-ChildItem -LiteralPath $out -File | Where-Object Name -ne 'SHA256SUMS.txt' | Sort-Object Name |
    ForEach-Object { '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant(), $_.Name } |
    Set-Content -Encoding ascii (Join-Path $out 'SHA256SUMS.txt')
Write-Host "Results and locally built EXE: $out"
if ($probeExit -ne 0 -or $checkerExit -ne 0) { throw "Probe/checker failed: probe=$probeExit checker=$checkerExit. Return the complete output directory, including partial logs." }
