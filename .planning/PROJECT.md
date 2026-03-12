# MDEValidator

## Current State — v1 Shipped (2026-03-12)

MDEValidator v1 is complete. The module has been transformed from a monolithic .psm1 into a maintainable, tested, CI-gated codebase:

- **49 function files** (45 Public + 4 Private) replacing the 2000-line monolith
- **303 Pester tests** covering all functions with mocked external dependencies
- **Zero PSScriptAnalyzer violations** with committed settings file
- **GitHub Actions CI/CD** — tests + lint + coverage on push/PR; PSGallery publish on GitHub Release

**Pending human checkpoint:** Push to GitHub remote to confirm live CI run. NUGET_API_KEY secret must be added to repo Settings before first release.

## What This Is

A PowerShell module that validates Microsoft Defender for Endpoint configurations on Windows endpoints, serving both IT admins checking individual machines and security teams auditing fleet compliance. The module is now fully restructured, tested, and CI-gated — ready for PSGallery publishing and desktop UI development.

## Core Value

Reliably validate that MDE is configured correctly on any Windows endpoint and surface the results clearly — whether in a terminal, HTML report, or desktop application.

## Requirements

### Validated

- ✓ Service status validation (WinDefend/Sense) — existing
- ✓ Passive mode detection — existing
- ✓ Real-time protection validation — existing
- ✓ Cloud-delivered protection (MAPS) checks — existing
- ✓ Cloud block level and extended timeout validation — existing
- ✓ Automatic sample submission checks — existing
- ✓ Behavior monitoring validation — existing
- ✓ MDE onboarding status verification — existing
- ✓ MDE device tag listing — existing
- ✓ Network protection checks (desktop + server) — existing
- ✓ Datagram processing validation (server) — existing
- ✓ Auto exclusions for servers — existing
- ✓ Attack Surface Reduction (ASR) rules validation — existing
- ✓ Threat default actions checks — existing
- ✓ Tamper protection status — existing
- ✓ Tamper protection for exclusions — existing
- ✓ Exclusion visibility settings — existing
- ✓ Edge SmartScreen policy validation — existing
- ✓ Catchup quick scan validation — existing
- ✓ Real-time scan direction checks — existing
- ✓ Signature update settings validation — existing
- ✓ Disable local admin merge checks — existing
- ✓ File hash computation validation — existing
- ✓ Policy registry verification (Intune/GPO/SCCM/SSM) — existing
- ✓ Management type detection — existing
- ✓ Console output with color-coded results — existing
- ✓ HTML report generation — existing
- ✓ PowerShell object output — existing
- ✓ Function-per-file module layout (45 Public + 4 Private) — v1
- ✓ Mock-based Pester 5.x tests for all 49 functions (303 tests, JaCoCo coverage) — v1
- ✓ Zero PSScriptAnalyzer violations with committed settings file — v1
- ✓ Publish-ready module manifest (LicenseUri, ProjectUri, Tags, ReleaseNotes) — v1
- ✓ GitHub Actions CI (tests + lint + coverage on push/PR to main) — v1
- ✓ Automated PSGallery publish workflow (triggered on GitHub Release) — v1

### Active

- [ ] Publish to PowerShell Gallery (workflow ready; live push + NUGET_API_KEY secret pending)
- [ ] Build desktop UI for viewing validation results (WPF DataGrid with color-coded results)

### Out of Scope

- Web-based dashboard — desktop app is the UI target
- Fleet/remote endpoint scanning — this validates the local machine
- Remediation/auto-fix capabilities — this is a validator, not a configuration tool
- Cross-platform support — MDE validation is Windows-only by nature

## Context

- Module restructured: 49 function files (45 Public + 4 Private), dot-source loader .psm1
- Test coverage: 303 tests, JaCoCo coverage.xml (107KB), runs without Defender or admin
- Static analysis: 0 PSSA errors/warnings (.PSScriptAnalyzerSettings.psd1 committed)
- CI/CD: ci.yml (push/PR gate) + publish.yml (release trigger) in .github/workflows/
- Module requires PowerShell 5.1+ on Windows 10/11 or Server 2016+
- Admin privileges recommended for full policy/registry access
- Users are IT admins and security teams managing Windows endpoints

## Constraints

- **Platform**: Windows-only — Defender APIs and registry paths are Windows-specific
- **PowerShell**: Must support 5.1+ (Windows PowerShell) for broadest enterprise compatibility
- **Backward compatibility**: Restructuring must preserve existing public API surface (function names, parameters, output shapes)
- **Admin access**: Full validation requires elevated privileges — graceful degradation when not elevated

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Split module into function-per-file structure | Navigability is the primary pain; function-per-file is cleanest for a module this size | ✓ 49 files; clear navigation |
| AST parser for function extraction | Regex-based attempt had brace-parsing issues | ✓ 100% extraction accuracy |
| Belt-and-suspenders exports (Export-ModuleMember + FunctionsToExport) | Ensures nothing slips through; both mechanisms agree | ✓ 45/45 synchronized |
| Mock external dependencies in tests | Enables testing without live Defender instance; CI-friendly | ✓ 303 tests pass in CI |
| PSSA Severity: Error+Warning only | PSSA 1.24.0 Information severity exposes 744 unscoped violations | ✓ 0 violations in quality gate |
| Release trigger for publish.yml (not tag push) | Requires deliberate human action; prevents accidental PSGallery uploads | ✓ Configured |
| No test step in publish.yml | CI gate on main already ensures quality; duplicate run is overhead | ✓ Accepted |
| Foundation first, UI later | Restructuring and testing are prerequisites for a maintainable UI layer | ✓ v1 foundation complete |
| Desktop app for UI (not web) | Target audience runs this on Windows endpoints already; desktop is native fit | — v2 Active |
| Publish to PSGallery | Makes installation easy for the IT admin/security team audience | — v2 Active |

---
*Last updated: 2026-03-12 after v1 milestone*
