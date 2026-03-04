# Feature Landscape

**Domain:** PowerShell module restructuring + desktop UI
**Researched:** 2026-03-04

## Table Stakes

Features users expect. Missing = product feels incomplete or unprofessional.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Function-per-file module layout | Standard for any published PowerShell module with >10 functions | Medium | ~45 files to extract, must preserve API surface |
| Mock-based unit tests | Required for CI and maintainability | Medium | ~45 test files matching public functions |
| PSScriptAnalyzer compliance | Expected for published modules, catches real bugs | Low | Configure rules, fix violations |
| Module manifest completeness | PSGallery requires it, users expect metadata | Low | LicenseUri, ProjectUri, ReleaseNotes missing |
| CI pipeline (tests + lint) | Standard for any published module | Low | GitHub Actions with windows-latest |
| PSGallery availability | How PowerShell users install modules | Low | `Install-Module MDEValidator` |
| Code coverage reporting | Expected for tested modules | Low | Pester built-in JaCoCo output |

## Differentiators

Features that set MDEValidator apart. Not expected, but valued.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Desktop UI (WPF) | Visual validation for non-terminal users; instant at-a-glance status | High | XAML design, data binding, event handling |
| Color-coded status grid | Green/red/yellow indicators matching console semantics in GUI | Medium | WPF DataTriggers on Status property |
| One-click HTML report export from UI | Combines visual review + shareable output | Low | Reuses existing `Get-MDEValidationReport -OutputFormat HTML` |
| Real-time re-validation button | Re-run checks without restarting app | Low | Button click → re-run `Test-MDEConfiguration` → rebind grid |
| Filter/search validation results | Large result sets need filtering by status or category | Medium | WPF CollectionViewSource with filter predicates |

## Anti-Features

Features to explicitly NOT build.

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Web dashboard | Wrong medium for local endpoint validation tool. Adds Node.js/web server dependency. | WPF desktop app — native, zero dependencies |
| Remote endpoint scanning | Fundamentally different architecture (WinRM, credentials, network). Out of scope per PROJECT.md. | Keep local-only; fleet tools can invoke module remotely themselves |
| Auto-remediation | Validator should report, not change system state. Mixing both creates trust/safety issues. | Report findings with clear recommendations (already done) |
| Cross-platform support | MDE validation is Windows-only by nature. Supporting macOS/Linux adds complexity for zero value. | Windows-only requirement is a feature, not a limitation |
| Plugin/extension system | ~45 checks is a manageable, curated set. Plugin systems add complexity for unlikely use case. | Add new checks directly as new function files |
| Configuration file for checks | Over-engineering. Users either run all checks or call individual functions. | Keep current pattern: `Test-MDEConfiguration` (all) or individual `Test-MDE*` functions |

## Feature Dependencies

```
Module Restructuring → Mock-Based Testing (can't easily mock functions in monolith)
Mock-Based Testing → CI Pipeline (tests must exist to run in CI)
Module Restructuring → Desktop UI (UI imports restructured module)
Mock-Based Testing → Desktop UI (validated logic before building UI on top)
CI Pipeline → PSGallery Publishing (must pass CI before publish)
Desktop UI → (independent of publishing, but should be included in published module)
```

## MVP Recommendation

Prioritize:
1. Module restructuring (enables everything else)
2. Mock-based tests for top 10 most critical validators (service status, onboarding, real-time protection, cloud protection)
3. PSScriptAnalyzer compliance
4. GitHub Actions CI pipeline
5. PSGallery publishing with complete manifest

Defer:
- Desktop UI: Build after foundation is solid. Module is fully usable without it.
- platyPS documentation: Nice-to-have for PSGallery, not blocking.
- Code coverage targets: Measure first, set targets later.
