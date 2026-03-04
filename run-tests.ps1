#!/usr/bin/env pwsh
#Requires -Version 5.1 -Modules Pester

$ErrorActionPreference = 'Continue'

Write-Host "`n========== PESTER TEST EXECUTION ==========" -ForegroundColor Cyan

Remove-Module MDEValidator -ErrorAction SilentlyContinue

# Run Pester tests
Write-Host "Running Pester tests from Tests/MDEValidator.Tests.ps1...`n" -ForegroundColor Yellow

try {
    $result = Invoke-Pester -Path './Tests/MDEValidator.Tests.ps1' -Output Detailed -PassThru
    
    Write-Host "`n========== TEST SUMMARY ==========" -ForegroundColor Cyan
    Write-Host "Passed:  $($result.PassedCount)" -ForegroundColor Green
    Write-Host "Failed:  $($result.FailedCount)" -ForegroundColor $(if ($result.FailedCount -gt 0) { 'Red' } else { 'Green' })
    Write-Host "Skipped: $($result.SkippedCount)" -ForegroundColor Yellow
    Write-Host "Total:   $($result.TotalCount)`n" -ForegroundColor Cyan
    
    if ($result.FailedCount -gt 0) {
        Write-Host "FAILED TESTS:" -ForegroundColor Red
        foreach ($fail in $result.Failed) {
            Write-Host "  ✗ $($fail.Name)" -ForegroundColor Red
            Write-Host "    $($fail.FailureMessage)" -ForegroundColor Yellow
        }
    }
    
    exit $result.FailedCount
    
} catch {
    Write-Error "Error running tests: $_"
    exit 1
}
