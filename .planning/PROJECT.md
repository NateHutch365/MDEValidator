# MDEValidator

## What This Is

A PowerShell module that validates Microsoft Defender for Endpoint configurations on Windows endpoints, serving both IT admins checking individual machines and security teams auditing fleet compliance. Currently a working monolithic module being restructured into a maintainable, testable, publishable product with a desktop UI.

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

### Active

- [ ] Restructure monolithic .psm1 into separate function files
- [ ] Add mock-based testing for external dependencies (Defender cmdlets, registry, services)
- [ ] Build desktop UI for viewing validation results
- [ ] Publish to PowerShell Gallery
- [ ] CI/CD pipeline for automated testing and publishing

### Out of Scope

- Web-based dashboard — desktop app is the UI target
- Fleet/remote endpoint scanning — this validates the local machine
- Remediation/auto-fix capabilities — this is a validator, not a configuration tool
- Cross-platform support — MDE validation is Windows-only by nature

## Context

- Existing monolithic module (~2000+ lines in single .psm1) with ~45 exported functions
- Current tests verify export surface and return shapes but don't mock external dependencies
- Module requires PowerShell 5.1+ on Windows 10/11 or Server 2016+
- Admin privileges recommended for full policy/registry access
- No CI/CD pipeline currently exists
- Users are IT admins and security teams managing Windows endpoints
- Codebase already mapped (architecture, conventions, stack documented in .planning/codebase/)

## Constraints

- **Platform**: Windows-only — Defender APIs and registry paths are Windows-specific
- **PowerShell**: Must support 5.1+ (Windows PowerShell) for broadest enterprise compatibility
- **Backward compatibility**: Restructuring must preserve existing public API surface (function names, parameters, output shapes)
- **Admin access**: Full validation requires elevated privileges — graceful degradation when not elevated

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Split module into function-per-file structure | Navigability is the primary pain; function-per-file is cleanest for a module this size | — Pending |
| Foundation first, UI later | Restructuring and testing are prerequisites for a maintainable UI layer | — Pending |
| Desktop app for UI (not web) | Target audience runs this on Windows endpoints already; desktop is native fit | — Pending |
| Publish to PSGallery | Makes installation easy for the IT admin/security team audience | — Pending |
| Mock external dependencies in tests | Enables testing without live Defender instance; CI-friendly | — Pending |

---
*Last updated: 2026-03-04 after initialization*
