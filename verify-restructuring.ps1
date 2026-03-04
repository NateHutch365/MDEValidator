#!/usr/bin/env pwsh
#Requires -Version 5.1
<#
.SYNOPSIS
    Comprehensive verification of restructured MDEValidator module against baseline.
.DESCRIPTION
    Verifies:
    1. All 45 functions export correctly
    2. All function names match baseline
    3. All parameters match baseline
    4. 4 private helpers are NOT exported
    5. .psd1 FunctionsToExport matches actual exports
#>

$ErrorActionPreference = 'Continue'
$results = @{
    Checks = @()
    Passed = 0
    Failed = 0
    Details = @()
}

# ============================================================================
# SETUP: Load baseline
# ============================================================================

$baselineJsonPath = '.planning/phases/01-module-restructuring/audit-baseline.json'
if (-not (Test-Path $baselineJsonPath)) {
    Write-Error "Baseline file not found: $baselineJsonPath"
    exit 1
}

$baseline = Get-Content $baselineJsonPath | ConvertFrom-Json
$baselineExports = $baseline.exportedFunctions
$baselinePrivates = $baseline.privateFunctions

Write-Host "`n========== VERIFICATION SCRIPT ==========" -ForegroundColor Cyan
Write-Host "Baseline: $($baseline.totalPublic) public, $($baseline.totalPrivate) private functions`n"

# ============================================================================
# TEST 1: Import restructured module
# ============================================================================

Write-Host "TEST 1: Import restructured module..." -ForegroundColor Yellow
Remove-Module MDEValidator -ErrorAction SilentlyContinue
try {
    Import-Module './MDEValidator/MDEValidator.psm1' -Force -ErrorAction Stop
    Write-Host "  ✓ Module imported successfully`n" -ForegroundColor Green
    $results.Checks += @{ Name = 'Module Import'; Status = 'PASS' }
    $results.Passed++
} catch {
    Write-Error "  ✗ FAILED to import module: $_"
    $results.Checks += @{ Name = 'Module Import'; Status = 'FAIL'; Error = $_ }
    $results.Failed++
    exit 1
}

# ============================================================================
# TEST 2: Verify export count
# ============================================================================

Write-Host "TEST 2: Verify export count..." -ForegroundColor Yellow
$exportedCommands = @(Get-Command -Module MDEValidator)
$actualCount = $exportedCommands.Count

if ($actualCount -eq 45) {
    Write-Host "  ✓ Export count: $actualCount (expected 45)`n" -ForegroundColor Green
    $results.Checks += @{ Name = 'Export Count'; Status = 'PASS'; Value = $actualCount }
    $results.Passed++
} else {
    Write-Host "  ✗ Export count mismatch: $actualCount (expected 45)`n" -ForegroundColor Red
    $results.Checks += @{ Name = 'Export Count'; Status = 'FAIL'; Value = $actualCount }
    $results.Failed++
}

# ============================================================================
# TEST 3: Verify all function names match baseline
# ============================================================================

Write-Host "TEST 3: Verify function names match baseline..." -ForegroundColor Yellow
$actualNames = @($exportedCommands | Select-Object -ExpandProperty Name | Sort-Object)
$baselineNames = @($baselineExports | Select-Object -ExpandProperty name | Sort-Object)

$missingFromActual = @($baselineNames | Where-Object { $_ -notin $actualNames })
$extraInActual = @($actualNames | Where-Object { $_ -notin $baselineNames })

if ($missingFromActual.Count -eq 0 -and $extraInActual.Count -eq 0) {
    Write-Host "  ✓ All function names match baseline`n" -ForegroundColor Green
    $results.Checks += @{ Name = 'Function Names'; Status = 'PASS' }
    $results.Passed++
} else {
    Write-Host "  ✗ Function name mismatches detected`n" -ForegroundColor Red
    if ($missingFromActual.Count -gt 0) {
        Write-Host "    Missing from actual: $($missingFromActual -join ', ')" -ForegroundColor Red
        $results.Details += "Missing functions: $($missingFromActual -join ', ')"
    }
    if ($extraInActual.Count -gt 0) {
        Write-Host "    Extra in actual: $($extraInActual -join ', ')" -ForegroundColor Red
        $results.Details += "Extra functions: $($extraInActual -join ', ')"
    }
    $results.Checks += @{ Name = 'Function Names'; Status = 'FAIL'; Missing = $missingFromActual; Extra = $extraInActual }
    $results.Failed++
}

# ============================================================================
# TEST 4: Verify parameters match baseline
# ============================================================================

Write-Host "TEST 4: Verify parameters match baseline..." -ForegroundColor Yellow
$paramMismatches = @()

foreach ($baselineFunc in $baselineExports) {
    $funcName = $baselineFunc.name
    $commonParams = @('Debug', 'ErrorAction', 'ErrorVariable', 'InformationAction', 'InformationVariable', 'OutBuffer', 'OutVariable', 'PipelineVariable', 'ProgressAction', 'Verbose', 'WarningAction', 'WarningVariable')
    $baselineParams = @($baselineFunc.parameters | Sort-Object) | Where-Object { $_ -notin $commonParams }
    
    $actualCmd = Get-Command -Name $funcName -Module MDEValidator -ErrorAction SilentlyContinue
    if ($null -eq $actualCmd) {
        Write-Host "    ✗ Function not found: $funcName" -ForegroundColor Red
        $paramMismatches += @{ Function = $funcName; Issue = 'Not found' }
        continue
    }
    
    $actualParams = @($actualCmd.Parameters.Keys | Sort-Object) | Where-Object { $_ -notin $commonParams }
    
    # Compare user-defined parameters only
    $missingParams = @($baselineParams | Where-Object { $_ -notin $actualParams })
    $extraParams = @($actualParams | Where-Object { $_ -notin $baselineParams })
    
    if ($missingParams.Count -gt 0 -or $extraParams.Count -gt 0) {
        $paramMismatches += @{
            Function = $funcName
            Missing = $missingParams
            Extra = $extraParams
        }
    }
}

if ($paramMismatches.Count -eq 0) {
    Write-Host "  ✓ All parameters match baseline`n" -ForegroundColor Green
    $results.Checks += @{ Name = 'Parameters'; Status = 'PASS' }
    $results.Passed++
} else {
    Write-Host "  ✗ Parameter mismatches detected ($($paramMismatches.Count) functions)`n" -ForegroundColor Red
    foreach ($mismatch in $paramMismatches) {
        Write-Host "    Function: $($mismatch.Function)" -ForegroundColor Yellow
        if ($mismatch.Missing.Count -gt 0) {
            Write-Host "      Missing: $($mismatch.Missing -join ', ')" -ForegroundColor Red
        }
        if ($mismatch.Extra.Count -gt 0) {
            Write-Host "      Extra: $($mismatch.Extra -join ', ')" -ForegroundColor Red
        }
    }
    $results.Details += "Parameter mismatches: $($paramMismatches | ConvertTo-Json -Compress)"
    $results.Checks += @{ Name = 'Parameters'; Status = 'FAIL'; Mismatches = $paramMismatches }
    $results.Failed++
}

# ============================================================================
# TEST 5: Verify private helpers NOT exported
# ============================================================================

Write-Host "TEST 5: Verify private helpers NOT exported..." -ForegroundColor Yellow
$privateLeaked = @()

foreach ($privateName in $baselinePrivates) {
    $cmd = Get-Command -Name $privateName -Module MDEValidator -ErrorAction SilentlyContinue
    if ($null -ne $cmd) {
        $privateLeaked += $privateName
    }
}

if ($privateLeaked.Count -eq 0) {
    Write-Host "  ✓ All private helpers correctly excluded from exports`n" -ForegroundColor Green
    $results.Checks += @{ Name = 'Private Helpers Excluded'; Status = 'PASS' }
    $results.Passed++
} else {
    Write-Host "  ✗ Private helpers exported (should NOT be): $($privateLeaked -join ', ')`n" -ForegroundColor Red
    $results.Details += "Leaked private functions: $($privateLeaked -join ', ')"
    $results.Checks += @{ Name = 'Private Helpers Excluded'; Status = 'FAIL'; Leaked = $privateLeaked }
    $results.Failed++
}

# ============================================================================
# TEST 6: Verify .psd1 FunctionsToExport matches actual exports
# ============================================================================

Write-Host "TEST 6: Verify .psd1 FunctionsToExport matches actual exports..." -ForegroundColor Yellow
$manifestPath = './MDEValidator/MDEValidator.psd1'
$manifestData = Import-PowerShellDataFile $manifestPath

$manifestFunctions = @($manifestData.FunctionsToExport | Sort-Object)
$actualExports = @($exportedCommands | Select-Object -ExpandProperty Name | Sort-Object)

$missingFromManifest = @($actualExports | Where-Object { $_ -notin $manifestFunctions })
$extraInManifest = @($manifestFunctions | Where-Object { $_ -notin $actualExports })

if ($missingFromManifest.Count -eq 0 -and $extraInManifest.Count -eq 0) {
    Write-Host "  ✓ .psd1 FunctionsToExport matches actual exports ($($manifestFunctions.Count))`n" -ForegroundColor Green
    $results.Checks += @{ Name = 'Manifest Sync'; Status = 'PASS'; Count = $manifestFunctions.Count }
    $results.Passed++
} else {
    Write-Host "  ✗ .psd1 FunctionsToExport mismatch`n" -ForegroundColor Red
    if ($missingFromManifest.Count -gt 0) {
        Write-Host "    Missing from manifest: $($missingFromManifest -join ', ')" -ForegroundColor Red
    }
    if ($extraInManifest.Count -gt 0) {
        Write-Host "    Extra in manifest: $($extraInManifest -join ', ')" -ForegroundColor Red
    }
    $results.Details += "Manifest sync issues: Missing=$($missingFromManifest -join ','), Extra=$($extraInManifest -join ',')"
    $results.Checks += @{ Name = 'Manifest Sync'; Status = 'FAIL'; Missing = $missingFromManifest; Extra = $extraInManifest }
    $results.Failed++
}

# ============================================================================
# SUMMARY
# ============================================================================

Write-Host "`n========== VERIFICATION SUMMARY ==========" -ForegroundColor Cyan
Write-Host "Passed: $($results.Passed)/6" -ForegroundColor Green
Write-Host "Failed: $($results.Failed)/6`n" -ForegroundColor $(if ($results.Failed -eq 0) { 'Green' } else { 'Red' })

foreach ($check in $results.Checks) {
    $statusColor = if ($check.Status -eq 'PASS') { 'Green' } else { 'Red' }
    Write-Host "  [$($check.Status)] $($check.Name)" -ForegroundColor $statusColor
}

if ($results.Details.Count -gt 0) {
    Write-Host "`n--- DETAILS ---" -ForegroundColor Yellow
    foreach ($detail in $results.Details) {
        Write-Host $detail -ForegroundColor Yellow
    }
}

Write-Host "`n========== END VERIFICATION ==========" -ForegroundColor Cyan

exit $results.Failed
