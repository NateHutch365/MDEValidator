# Testing Patterns

**Analysis Date:** 2026-03-04

## Test Framework

**Runner:**
- Pester (PowerShell test framework; version not pinned in repository files).
- Config: `Not detected` (no `PesterConfiguration.psd1` or equivalent config file found).

**Assertion Library:**
- Pester built-in assertions (`Should`) in `Tests/MDEValidator.Tests.ps1`.

**Run Commands:**
```bash
Invoke-Pester -Path .\Tests\MDEValidator.Tests.ps1   # Run all module tests
Invoke-Pester -Path .\Tests                           # Run test folder
Invoke-Pester -Path .\Tests -CodeCoverage .\MDEValidator\MDEValidator.psm1  # Coverage report (manual)
```

The first command is explicitly documented in `README.md`.

## Test File Organization

**Location:**
- Tests are in a dedicated root-level test directory: `Tests/MDEValidator.Tests.ps1`.

**Naming:**
- Test file naming follows `<ModuleName>.Tests.ps1`: `Tests/MDEValidator.Tests.ps1`.

**Structure:**
```
Tests/
└── MDEValidator.Tests.ps1
```

## Test Structure

**Suite Organization:**
```powershell
BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..' 'MDEValidator' 'MDEValidator.psm1'
    Import-Module $modulePath -Force
}

Describe 'MDEValidator Module' {
    Context 'Module Import' {
        It 'Should import the module without errors' {
            { Import-Module (Join-Path $PSScriptRoot '..' 'MDEValidator' 'MDEValidator.psm1') -Force } | Should -Not -Throw
        }
    }
}
```

Pattern used in `Tests/MDEValidator.Tests.ps1`.

**Patterns:**
- Setup pattern: single `BeforeAll` import bootstrap in `Tests/MDEValidator.Tests.ps1`.
- Teardown pattern: local `try/finally` cleanup for file-system side effects (HTML report temp file removal) in `Tests/MDEValidator.Tests.ps1`.
- Assertion pattern: property/type/status checks with `Should -Be`, `Should -BeIn`, `Should -Match`, `Should -Not -BeNullOrEmpty` in `Tests/MDEValidator.Tests.ps1`.

## Mocking

**Framework:**
- Pester mocking features not used in current suite (`Mock`/`InModuleScope` not detected in `Tests/MDEValidator.Tests.ps1`).

**Patterns:**
```powershell
# Current suite style prefers direct execution + shape/content assertions.
$result = Test-MDEPassiveMode
$result.TestName | Should -Be 'Passive Mode / EDR Block Mode'
$result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
```

From `Tests/MDEValidator.Tests.ps1`.

**What to Mock:**
- External/environment-dependent system calls in future tests (for deterministic unit tests): `Get-MpPreference`, `Get-MpComputerStatus`, `Get-Service`, registry access wrappers in `MDEValidator/MDEValidator.psm1`.

**What NOT to Mock:**
- Contract-level object shape validation (`Write-ValidationResult` output schema) and export-surface tests (`Get-Command` export checks) in `Tests/MDEValidator.Tests.ps1`.

## Fixtures and Factories

**Test Data:**
```powershell
# Inline expected sets and strings are used as lightweight fixtures.
$result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
$testNames | Should -Contain 'Cloud-Delivered Protection'
```

Pattern used across `Tests/MDEValidator.Tests.ps1`.

**Location:**
- No separate fixtures/factories directories detected.
- Temporary filesystem fixture is created inline in `Context 'Get-MDEValidationReport'` within `Tests/MDEValidator.Tests.ps1`.

## Coverage

**Requirements:** Not enforced
- No coverage threshold or CI gating config detected in repository files.

**View Coverage:**
```bash
Invoke-Pester -Path .\Tests -CodeCoverage .\MDEValidator\MDEValidator.psm1
```

## Test Types

**Unit Tests:**
- Primary test type.
- Focus on function contracts: exported command presence, return object properties, status domains, expected test-name inclusion in aggregate runs.
- Files: `Tests/MDEValidator.Tests.ps1` against module functions in `MDEValidator/MDEValidator.psm1`.

**Integration Tests:**
- Lightweight environment-integrated checks are present because tests execute real system-interaction functions (Defender cmdlets, service/registry reads) without mocks.
- This means outcomes may vary by host configuration.

**E2E Tests:**
- Not used (no separate E2E framework or scenario harness detected).

## Common Patterns

**Async Testing:**
```powershell
Not applicable - no async patterns detected in PowerShell module tests.
```

**Error Testing:**
```powershell
{ Import-Module (Join-Path $PSScriptRoot '..' 'MDEValidator' 'MDEValidator.psm1') -Force } |
    Should -Not -Throw

$result.Message | Should -Match '(Unable to query|Windows Server|NotApplicable)'
```

Patterns from `Tests/MDEValidator.Tests.ps1`.

---

*Testing analysis: 2026-03-04*
