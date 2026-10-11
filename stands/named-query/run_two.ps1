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
    if (Test-Path $Output) {
        $Last = Get-Content -LiteralPath $Output -Tail 1 | ConvertFrom-Json
        if ($Last.run_outcome -eq 'aborted_unresolved_child') {
            $Results | Format-List
            throw 'A fixture child did not terminate. Stop here and resolve that process before running again.'
        }
    }
}
$Results | Format-List
