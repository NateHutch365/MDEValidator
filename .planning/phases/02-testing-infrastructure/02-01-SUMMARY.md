---
phase: 02-testing-infrastructure
plan: "01"
subsystem: test-infrastructure
tags: [pester5, mocking, jacoco, coverage, test-structure]
dependency_graph:
  requires: [Phase 1 complete (01-03)]
  provides: [Test folder structure, Shared helpers, Pester 5 runner, Mapping checklist]
  affects: [run-tests.ps1, Tests/]
tech_stack:
  added: [Pester 5 New-PesterConfiguration, JaCoCo coverage output, NUnitXml test results]
  patterns: [file-per-function test layout, MockBuilders pattern, TestBootstrap pattern]
key_files:
  created:
    - Tests/Public/.gitkeep
    - Tests/Private/.gitkeep
    - Tests/Helpers/TestBootstrap.ps1
    - Tests/Helpers/MockBuilders.ps1
    - Tests/Artifacts/.gitkeep
    - Tests/Mapping/.gitkeep
    - Tests/Public/Template.Tests.ps1.example
    - Tests/Mapping/generate-mapping.ps1
    - Tests/Mapping/function-test-map.json
  modified:
    - run-tests.ps1
decisions:
  - One .gitkeep per empty directory (Public, Private, Artifacts, Mapping) to preserve structure in git
  - MockBuilders use named bool/int params (not switches) for cleaner override syntax in test files
  - generate-mapping.ps1 paths resolved relative to script location for portability
metrics:
  duration: ~10 minutes
  completed: "2026-03-10"
  tasks_completed: 3
  files_created: 9
  files_modified: 1
---

# Phase 2 Plan 1: Test Infrastructure Baseline Summary

**One-liner:** Pester 5 test folder scaffold with TestBootstrap/MockBuilders helpers, JaCoCo-configured runner, and 45-function mapping checklist at 0% baseline coverage.

## What Was Built

### Folder Structure
```
Tests/
├── Public/            ← one test file per public function (45 expected)
│   └── Template.Tests.ps1.example
├── Private/           ← one test file per private helper (4 expected)
├── Helpers/
│   ├── TestBootstrap.ps1   ← Initialize-MDEValidatorTest (module import)
│   └── MockBuilders.ps1    ← New-MpPreferenceMock, New-MpComputerStatusMock,
│                              New-ServiceMock, New-ItemPropertyMock
├── Artifacts/         ← coverage.xml and test-results.xml written here
└── Mapping/
    ├── generate-mapping.ps1
    └── function-test-map.json
```

### TestBootstrap.ps1
Exports `Initialize-MDEValidatorTest`. Resolves the module manifest path relative to the bootstrap file and calls `Import-Module $manifestPath -Force`. All test files call this inside `BeforeAll`.

### MockBuilders.ps1
Exports four factory functions for the four external dependencies:
- `New-MpPreferenceMock` — `[PSCustomObject]` with all common `Get-MpPreference` properties, bool/int overrides
- `New-MpComputerStatusMock` — `[PSCustomObject]` with `AMServiceEnabled`, `RealTimeProtectionEnabled`, `OnboardingState`, etc.
- `New-ServiceMock` — `[PSCustomObject]` with `Name`, `Status`, `StartType`, `DisplayName`
- `New-ItemPropertyMock` — `[PSCustomObject]` from a `[hashtable]` of registry property names

### run-tests.ps1 (updated)
Replaced `Invoke-Pester -Path ... -Output Detailed -PassThru` with `New-PesterConfiguration` object:
- `$config.Run.Path = './Tests'` — discovers all `*.Tests.ps1` under Tests/
- `$config.CodeCoverage.Enabled = $true` with `OutputFormat = 'JaCoCo'` to `Tests/Artifacts/coverage.xml`
- `$config.CodeCoverage.Path` scoped to `MDEValidator/Public/*.ps1` and `Private/*.ps1`
- `$config.TestResult` writes `NUnitXml` to `Tests/Artifacts/test-results.xml`

### Template.Tests.ps1.example
Demonstrates the standard test pattern:
- `BeforeAll` dot-sources `TestBootstrap.ps1` and `MockBuilders.ps1`, then calls `Initialize-MDEValidatorTest`
- `Context 'Pass path'` and `Context 'Fail path'` blocks (TEST-03)
- `Mock Get-Service -ModuleName MDEValidator { ... }` pattern (TEST-02)
- `Should -Invoke` assertions to verify external calls

### generate-mapping.ps1 + function-test-map.json
Scans `MDEValidator/Public/*.ps1` vs `Tests/Public/*.Tests.ps1` and produces:
```json
{
  "public_function_count": 45,
  "test_file_count": 0,
  "coverage": { "covered": 0, "total": 45, "percentage": 0.0 },
  "functions": { "<FunctionName>": { "test_file": "...", "has_test": false }, ... }
}
```
Baseline: 45/45 functions mapped, 0 tests, 0% coverage — ready for Plan 02-02 to add tests.

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| 1 | b6c3ebe | Create test folder structure and shared helpers |
| 2 | 59b02d2 | Update run-tests.ps1 with Pester 5 config and JaCoCo coverage |
| 3 | f0aca8f | Add test template and function-test mapping checklist |

## Deviations from Plan

None - plan executed exactly as written.

## Next Step

Plan 02-02: Create test files for all 45 public functions using the template pattern established here.

## Self-Check: PASSED

- [x] Tests/Public exists: `Test-Path Tests/Public` → True
- [x] Tests/Private exists: `Test-Path Tests/Private` → True
- [x] Tests/Helpers/TestBootstrap.ps1 exists with `Initialize-MDEValidatorTest`
- [x] Tests/Helpers/MockBuilders.ps1 exists with all four mock builders
- [x] Tests/Artifacts exists: `Test-Path Tests/Artifacts` → True
- [x] Tests/Mapping/generate-mapping.ps1 runs without error
- [x] Tests/Mapping/function-test-map.json: 45 functions, 0 tests, 0% coverage
- [x] run-tests.ps1 contains `New-PesterConfiguration`, `JaCoCo`, `coverage.xml`, `MDEValidator/Public`
- [x] Template.Tests.ps1.example contains `BeforeAll`, `Pass path`, `Fail path`, `Mock`, `-ModuleName`, `Should -Invoke`
- [x] All 3 commits exist in git log
