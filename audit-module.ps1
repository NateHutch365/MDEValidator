#!/usr/bin/env pwsh
#Requires -Version 5.1

param(
    [string]$ModuleRoot = (Join-Path $PSScriptRoot 'MDEValidator'),
    [string]$OutputPath = '.\.planning\phases\01-module-restructuring\audit-baseline.json'
)

$ErrorActionPreference = 'Stop'
Write-Host "Auditing MDEValidator module..." -ForegroundColor Cyan

$psmPath = Join-Path $ModuleRoot 'MDEValidator.psm1'
$psdPath = Join-Path $ModuleRoot 'MDEValidator.psd1'

if (-not (Test-Path $psmPath)) { throw "Module file not found: $psmPath" }
if (-not (Test-Path $psdPath)) { throw "Manifest file not found: $psdPath" }

# --- TASK 1: Extract all function declarations ---
Write-Host "`nTask 1: Extracting function declarations..." -ForegroundColor Yellow
$psm1Content = Get-Content $psmPath -Raw
$allFunctions = @()
$funcPattern = '^\s*function\s+(\S+)\s*\{'
$matches = [regex]::Matches($psm1Content, $funcPattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)
foreach ($m in $matches) {
    $funcName = $m.Groups[1].Value
    # Filter out JavaScript functions (e.g., toggleDetails(expanderId))
    if (-not ($funcName -match '\(.*\)')) {
        $allFunctions += $funcName
    }
}
Write-Host "  Found $($allFunctions.Count) total function definitions"

# --- TASK 2: Identify private vs public functions ---
Write-Host "`nTask 2: Identifying private vs public functions..." -ForegroundColor Yellow
$privateExpected = @('ConvertTo-HtmlEncodedString', 'Write-ValidationResult', 'Test-IsElevated', 'Test-IsWindowsServer')

# Parse Export-ModuleMember block
$exportedFromPsm1 = @()
$lines = $psm1Content -split [System.Environment]::NewLine
$inExport = $false
foreach ($line in $lines) {
    if ($line -match 'Export-ModuleMember') {
        $inExport = $true
    }
    if ($inExport -and $line -match "^\s*'([^']+)'") {
        $exportedFromPsm1 += $matches[1]
    }
    if ($inExport -and $line -match '^\s*\)') {
        break
    }
}
Write-Host "  Found $($exportedFromPsm1.Count) functions in Export-ModuleMember"

$privateActual = $allFunctions | Where-Object { $_ -notin $exportedFromPsm1 }
Write-Host "  Identified $($privateActual.Count) private functions"

# --- TASK 3: Verify zero module-scope state ---
Write-Host "`nTask 3: Checking for module-scope state..." -ForegroundColor Yellow
$dollarScriptPattern = [regex]::Escape('$script:')
$scriptMatches = [regex]::Matches($psm1Content, $dollarScriptPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
Write-Host "  Found $($scriptMatches.Count) module-scope variable references"

# --- TASK 4: Import module and capture baseline ---
Write-Host "`nTask 4: Importing module and capturing parameters..." -ForegroundColor Yellow
if (Get-Module MDEValidator -ErrorAction Ignore) { Remove-Module MDEValidator -Force }
Import-Module $psmPath -Force -ErrorAction Stop

$exportedFunctions = @()
foreach ($fnName in $exportedFromPsm1) {
    try {
        $cmd = Get-Command -Name $fnName -Module MDEValidator -ErrorAction Stop
        $parameterNames = $cmd.Parameters.Keys | Sort-Object
        $exportedFunctions += @{
            name = $fnName
            parameters = @($parameterNames)
        }
    }
    catch { }
}
Write-Host "  Captured parameters for $($exportedFunctions.Count) functions"

# --- TASK 5: Parse .psd1 FunctionsToExport ---
Write-Host "`nTask 5: Parsing .psd1 FunctionsToExport..." -ForegroundColor Yellow
$psd1Content = Get-Content $psdPath -Raw
$exportedFromPsd1 = @()
$psd1Lines = $psd1Content -split [System.Environment]::NewLine
$inFuncExport = $false
foreach ($line in $psd1Lines) {
    if ($line -match 'FunctionsToExport\s*=') {
        $inFuncExport = $true
    }
    if ($inFuncExport -and $line -match "^\s*'([^']+)'") {
        $exportedFromPsd1 += $matches[1]
    }
    if ($inFuncExport -and $line -match '^\s*\)') {
        break
    }
}
Write-Host "  Found $($exportedFromPsd1.Count) functions in .psd1 FunctionsToExport"

# --- TASK 6: Compare export lists ---
Write-Host "`nTask 6: Comparing export lists..." -ForegroundColor Yellow
$exportListsMatch = $true
$discrepancies = @()

$onlyInPsd1 = $exportedFromPsd1 | Where-Object { $_ -notin $exportedFromPsm1 }
$onlyInPsm1 = $exportedFromPsm1 | Where-Object { $_ -notin $exportedFromPsd1 }

if ($onlyInPsd1) {
    $exportListsMatch = $false
    $discrepancies += "In .psd1 but not .psm1: $($onlyInPsd1 -join ', ')"
}
if ($onlyInPsm1) {
    $exportListsMatch = $false
    $discrepancies += "In .psm1 but not .psd1: $($onlyInPsm1 -join ', ')"
}

if ($exportListsMatch) {
    Write-Host "  Export lists match perfectly"
} else {
    Write-Host "  Export lists DO NOT match" -ForegroundColor Red
}

# --- TASK 7: Build and save baseline JSON ---
Write-Host "`nTask 7: Building baseline JSON..." -ForegroundColor Yellow

$baseline = @{
    exportedFunctions = $exportedFunctions
    privateFunctions = @($privateActual | Sort-Object)
    totalPublic = $exportedFromPsm1.Count
    totalPrivate = $privateActual.Count
    exportListsMatch = $exportListsMatch
    discrepancies = if ($discrepancies) { $discrepancies } else { @() }
    modulePathRoot = $ModuleRoot
    auditDate = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    auditedVersion = '1.0.0'
}

$outputDir = Split-Path -Parent $OutputPath
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$baselineJson = $baseline | ConvertTo-Json -Depth 10
Set-Content -Path $OutputPath -Value $baselineJson -Encoding UTF8
Write-Host "  Baseline JSON created"

# --- SUMMARY ---
Write-Host "`n===================================================" -ForegroundColor Cyan
Write-Host "AUDIT SUMMARY" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "Total functions:        $($allFunctions.Count) (Expected: 49)" -ForegroundColor Green
Write-Host "  - Public functions:   $($exportedFromPsm1.Count) (Expected: 45)" -ForegroundColor Green
Write-Host "  - Private functions:  $($privateActual.Count) (Expected: 4)" -ForegroundColor Green
Write-Host "Module-scope state:     $($scriptMatches.Count) script-scope vars (Expected: 0)" -ForegroundColor Green
$matchColor = if ($exportListsMatch) { 'Green' } else { 'Red' }
Write-Host "Export lists match:     $exportListsMatch" -ForegroundColor $matchColor
Write-Host "===================================================" -ForegroundColor Cyan

$success = ($allFunctions.Count -eq 49) -and
           ($exportedFromPsm1.Count -eq 45) -and
           ($privateActual.Count -eq 4) -and
           ($scriptMatches.Count -eq 0) -and
           ($exportListsMatch -eq $true)

if ($success) {
    Write-Host "`nALL AUDIT CHECKS PASSED" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`nSOME AUDIT CHECKS FAILED" -ForegroundColor Red
    exit 1
}
