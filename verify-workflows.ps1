# Task 1 proof check script — verify both workflow files
Set-Location $PSScriptRoot

# CHECK 1
$files = @('.github/workflows/ci.yml', '.github/workflows/publish.yml')
foreach ($f in $files) {
    if (-not (Test-Path $f)) { throw "MISSING: $f" }
    Write-Host "EXISTS: $f" -ForegroundColor Green
}

# CHECK 2 - ci.yml patterns
$ci = Get-Content '.github/workflows/ci.yml' -Raw
$ciPatterns = @{
    'branches: [main]'          = 'branches: \[main\]'
    'pull_request trigger'      = 'pull_request'
    'windows-latest'            = 'windows-latest'
    'Pester install'            = 'Install-Module.*Pester'
    'PSSA install'              = 'Install-Module.*PSScriptAnalyzer'
    'run-tests.ps1'             = 'run-tests\.ps1'
    'test-results.xml artifact' = 'test-results\.xml'
    'coverage.xml artifact'     = 'coverage\.xml'
    'madrapps/jacoco-report'    = 'madrapps/jacoco-report'
    'PR-only jacoco gate'       = 'github\.event_name.*pull_request'
    'Invoke-ScriptAnalyzer'     = 'Invoke-ScriptAnalyzer'
    'throw on violations'       = 'throw'
    'if: always()'              = 'if: always\(\)'
    'pull-requests: write'      = 'pull-requests: write'
    'GITHUB_TOKEN'              = 'GITHUB_TOKEN'
}
$failed = @()
foreach ($name in $ciPatterns.Keys) {
    $pattern = $ciPatterns[$name]
    if ($ci -notmatch $pattern) { $failed += $name }
    else { Write-Host "  OK: $name" -ForegroundColor Green }
}
if ($failed.Count -gt 0) { throw "ci.yml missing: $($failed -join ', ')" }
Write-Host "ci.yml: ALL CHECKS PASSED" -ForegroundColor Cyan

# CHECK 3 - publish.yml patterns
$pub = Get-Content '.github/workflows/publish.yml' -Raw
$pubPatterns = @{
    'release trigger'    = 'release'
    'types: [published]' = 'types: \[published\]'
    'windows-latest'     = 'windows-latest'
    'NUGET_API_KEY'      = 'NUGET_API_KEY'
    'Publish-Module'     = 'Publish-Module'
    'MDEValidator path'  = 'MDEValidator'
}
$failed2 = @()
foreach ($name in $pubPatterns.Keys) {
    $pattern = $pubPatterns[$name]
    if ($pub -notmatch $pattern) { $failed2 += $name }
    else { Write-Host "  OK: $name" -ForegroundColor Green }
}
if ($failed2.Count -gt 0) { throw "publish.yml missing: $($failed2 -join ', ')" }
Write-Host "publish.yml: ALL CHECKS PASSED" -ForegroundColor Cyan

Write-Host "`nAll Task 1 proof checks PASSED" -ForegroundColor Green
