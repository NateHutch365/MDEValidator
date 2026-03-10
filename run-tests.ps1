#!/usr/bin/env pwsh
#Requires -Version 5.1

param()

$ErrorActionPreference = 'Stop'

Write-Host "`n========== PESTER TEST EXECUTION ==========" -ForegroundColor Cyan

# Ensure Tests/Artifacts directory exists for output files
$artifactsDir = Join-Path $PSScriptRoot 'Tests' 'Artifacts'
if (-not (Test-Path $artifactsDir)) {
    New-Item -ItemType Directory -Path $artifactsDir -Force | Out-Null
}

# Build Pester 5 configuration object
$config = New-PesterConfiguration

# Run all test files under Tests/
$config.Run.Path    = './Tests'
$config.Run.PassThru = $true

# Code coverage (TEST-05): JaCoCo output for CI integration
$config.CodeCoverage.Enabled      = $true
$config.CodeCoverage.OutputFormat = 'JaCoCo'
$config.CodeCoverage.OutputPath   = './Tests/Artifacts/coverage.xml'
$config.CodeCoverage.Path         = @(
    './MDEValidator/Public/*.ps1',
    './MDEValidator/Private/*.ps1'
)

# Test result output: NUnitXml for CI integration
$config.TestResult.Enabled      = $true
$config.TestResult.OutputFormat = 'NUnitXml'
$config.TestResult.OutputPath   = './Tests/Artifacts/test-results.xml'

# Detailed output for interactive runs
$config.Output.Verbosity = 'Detailed'

Write-Host "Running Pester tests from ./Tests ...`n" -ForegroundColor Yellow

$result = Invoke-Pester -Configuration $config

Write-Host "`n========== TEST SUMMARY ==========" -ForegroundColor Cyan
Write-Host "Passed:  $($result.PassedCount)" -ForegroundColor Green
Write-Host "Failed:  $($result.FailedCount)" -ForegroundColor $(if ($result.FailedCount -gt 0) { 'Red' } else { 'Green' })
Write-Host "Skipped: $($result.SkippedCount)" -ForegroundColor Yellow
Write-Host "Total:   $($result.TotalCount)`n" -ForegroundColor Cyan

if ($result.FailedCount -gt 0) {
    Write-Host "FAILED TESTS:" -ForegroundColor Red
    foreach ($fail in $result.Failed) {
        Write-Host "  x $($fail.ExpandedName)" -ForegroundColor Red
        Write-Host "    $($fail.ErrorRecord)" -ForegroundColor Yellow
    }
}

exit $result.FailedCount
