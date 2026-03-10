#Requires -Version 5.1
<#
.SYNOPSIS
    Generates function-to-test mapping checklist for MDEValidator public functions.

.DESCRIPTION
    Scans MDEValidator/Public for function files and Tests/Public for test files,
    then produces Tests/Mapping/function-test-map.json showing coverage status.

    Run this script after adding new test files to update the mapping.
    The JSON output is used for TEST-01 compliance verification.

.OUTPUTS
    Tests/Mapping/function-test-map.json

.EXAMPLE
    # From the repository root:
    pwsh -NoProfile -File './Tests/Mapping/generate-mapping.ps1'
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------
# Resolve paths relative to the repository root (two levels up from
# Tests/Mapping where this script lives)
# ------------------------------------------------------------------
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')

$publicFunctionsPath = Join-Path $repoRoot 'MDEValidator' 'Public' '*.ps1'
$publicTestsPath     = Join-Path $repoRoot 'Tests' 'Public' '*.Tests.ps1'
$outputPath          = Join-Path $PSScriptRoot 'function-test-map.json'

# ------------------------------------------------------------------
# Collect function and test file names
# ------------------------------------------------------------------
$publicFunctions = @(Get-ChildItem $publicFunctionsPath -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty BaseName |
    Sort-Object)

$testFiles = @(Get-ChildItem $publicTestsPath -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty BaseName |
    ForEach-Object { $_ -replace '\.Tests$', '' } |
    Sort-Object)

if (-not $publicFunctions) {
    Write-Warning "No public function files found at: $publicFunctionsPath"
}

# ------------------------------------------------------------------
# Build mapping ordered dictionary
# ------------------------------------------------------------------
$functions = [ordered]@{}
foreach ($func in $publicFunctions) {
    $hasTest = $func -in $testFiles
    $functions[$func] = [ordered]@{
        test_file = "$func.Tests.ps1"
        has_test  = $hasTest
    }
}

$covered = @($functions.Values | Where-Object { $_.has_test }).Count
$total   = @($publicFunctions).Count
$pct     = if ($total -gt 0) { [math]::Round(($covered / $total) * 100, 2) } else { 0 }

$mapping = [ordered]@{
    generated_at         = (Get-Date -Format 'o')
    public_function_count = $total
    test_file_count       = $testFiles.Count
    coverage              = [ordered]@{
        covered    = $covered
        total      = $total
        percentage = $pct
    }
    functions = $functions
}

# ------------------------------------------------------------------
# Write JSON output
# ------------------------------------------------------------------
$mapping | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputPath -Encoding utf8 -Force

# ------------------------------------------------------------------
# Console summary
# ------------------------------------------------------------------
Write-Host "Mapping generated: $covered / $total public functions have tests ($pct%)"

if ($covered -lt $total) {
    Write-Host "`nFunctions missing tests:" -ForegroundColor Yellow
    $functions.GetEnumerator() | Where-Object { -not $_.Value.has_test } | ForEach-Object {
        Write-Host "  - $($_.Key)" -ForegroundColor Yellow
    }
}

exit 0
