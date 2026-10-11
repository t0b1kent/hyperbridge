param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][string]$Label,
    [string]$OutputDir = '.'
)
$ErrorActionPreference = 'Stop'
if ($Label -notmatch '^[A-Za-z0-9_.-]+$') { throw 'Use a simple filename label, for example win2022-x64.' }
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$Program = (Resolve-Path $Executable).Path
$Results = @()
foreach ($Pattern in @('A', 'B')) {
    $Output = Join-Path $OutputDir "$Label-$Pattern.jsonl"
    if ((Test-Path $Output) -or (Test-Path "$Output.stderr.txt")) { throw "An output exists already: $Output" }
    & $Program --output $Output --pattern $Pattern
    $Code = $LASTEXITCODE
    $Results += [pscustomobject]@{ Pattern=$Pattern; ExitCode=$Code; Log=$Output; Diagnostics="$Output.stderr.txt" }
    if ($Code -ne 0 -and $Code -ne 1) {
        $Results | Format-List
        throw "The parent could not run the fixture (exit $Code). Resolve the setup failure before another run."
    }
    # Exit 1 preserves abnormal observations; continue to the independent B run.
    # An unresolved child requires human cleanup; do not launch the second run.
    if (-not (Test-Path -LiteralPath $Output)) { throw 'No output log; child cleanup is unverified. Stop here.' }
    $Rows = @()
    foreach ($Line in (Get-Content -LiteralPath $Output -Encoding UTF8)) {
        if ([string]::IsNullOrWhiteSpace($Line)) { throw 'Empty JSONL record; stop before another run.' }
        $Rows += ($Line | ConvertFrom-Json -ErrorAction Stop)
    }
    $Terminals = @($Rows | Where-Object { $_.record -eq 'run_complete' })
    if ($Terminals.Count -ne 1) { throw 'Exactly one terminal parent record is required before another run.' }
    $Terminal = $Terminals[0]
    # Inspect the explicit parent record, even if an unresolved child appended after it.
    if ($Terminal.run_outcome -eq 'aborted_unresolved_child') {
        $Results | Format-List
        throw 'A fixture child did not terminate. Stop here and resolve that process before running again.'
    }
    $ExpectedKeys = @('record', 'planned_groups', 'planned_cases', 'started_groups', 'abnormal_groups', 'run_outcome')
    $ActualKeys = @($Terminal.PSObject.Properties.Name)
    if (@(Compare-Object ($ExpectedKeys | Sort-Object) ($ActualKeys | Sort-Object)).Count -ne 0) {
        throw 'Terminal parent record has unexpected or missing fields.'
    }
    foreach ($Key in @('planned_groups', 'planned_cases', 'started_groups', 'abnormal_groups')) {
        if ($Terminal.$Key -isnot [int] -and $Terminal.$Key -isnot [long]) { throw 'Invalid terminal accounting type.' }
        if ($Terminal.$Key -lt 0) { throw 'Invalid terminal accounting value.' }
    }
    if ($Rows.Count -eq 0 -or $Rows[-1].record -ne 'run_complete') { throw 'Records follow the terminal parent record; stop before another run.' }
    if ($Terminal.planned_groups -le 0 -or $Terminal.planned_cases -le 0 -or
        $Terminal.started_groups -ne $Terminal.planned_groups -or
        $Terminal.abnormal_groups -gt $Terminal.started_groups) { throw 'Incomplete terminal accounting; cleanup is not established.' }
    if ($Terminal.run_outcome -eq 'complete') {
        if ($Code -ne 0 -or $Terminal.abnormal_groups -ne 0) { throw 'Exit code and complete accounting disagree.' }
    } elseif ($Terminal.run_outcome -eq 'completed_with_failures') {
        if ($Code -ne 1 -or $Terminal.abnormal_groups -le 0) { throw 'Exit code and failure accounting disagree.' }
    } else { throw 'Unknown terminal run outcome; stop before another run.' }

}
$Results | Format-List
