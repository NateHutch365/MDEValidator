# Requirements: MDEValidator

**Defined:** 2026-03-04
**Core Value:** Reliably validate that MDE is configured correctly on any Windows endpoint and surface the results clearly.

## v1 Requirements

Requirements for the restructured, tested, published module. Each maps to roadmap phases.

### Module Structure

- [ ] **STRUCT-01**: Module uses function-per-file layout with Public/ and Private/ folders
- [ ] **STRUCT-02**: Root .psm1 uses dot-source loader to import all function files
- [ ] **STRUCT-03**: All 45 existing exported functions preserve their names, parameters, and output shapes
- [ ] **STRUCT-04**: Private helper functions (Write-ValidationResult, ConvertTo-HtmlEncodedString, etc.) are in Private/ folder and not exported
- [ ] **STRUCT-05**: Export-ModuleMember and .psd1 FunctionsToExport remain synchronized

### Testing

- [ ] **TEST-01**: Each public validation function has a corresponding Pester 5.x test file
- [ ] **TEST-02**: Tests mock all external dependencies (Get-MpPreference, Get-MpComputerStatus, Get-Service, Get-ItemProperty)
- [ ] **TEST-03**: Tests validate both pass and fail scenarios for each check
- [ ] **TEST-04**: Tests can run without admin privileges and without Defender installed
- [ ] **TEST-05**: Pester generates JaCoCo code coverage output
- [ ] **TEST-06**: Private helper functions have test coverage via module-scoped mocking

### Quality

- [ ] **QUAL-01**: Module passes PSScriptAnalyzer with standard rules (no errors or warnings)
- [ ] **QUAL-02**: Module manifest includes LicenseUri, ProjectUri, Tags, and ReleaseNotes
- [ ] **QUAL-03**: PSScriptAnalyzer settings file (.PSScriptAnalyzerSettings.psd1) is committed to repo

### CI/CD

- [ ] **CICD-01**: GitHub Actions workflow runs Pester tests on push and PR to main
- [ ] **CICD-02**: GitHub Actions workflow runs PSScriptAnalyzer lint on push and PR to main
- [ ] **CICD-03**: CI runs on windows-latest runner
- [ ] **CICD-04**: Automated PSGallery publish triggered on GitHub release/tag
- [ ] **CICD-05**: CI reports code coverage results

### Publishing

- [ ] **PUBL-01**: Module is installable via `Install-Module MDEValidator` from PSGallery
- [ ] **PUBL-02**: Module version follows SemVer (major.minor.patch)
- [ ] **PUBL-03**: Published module includes all function files and manifest

## v2 Requirements

Deferred to future release. Tracked but not in current roadmap.

### Desktop UI

- **UI-01**: WPF desktop application displays validation results in a DataGrid
- **UI-02**: Status indicators are color-coded (green=Pass, red=Fail, yellow=Warning)
- **UI-03**: User can filter results by status (Pass/Fail/Warning) or search by test name
- **UI-04**: User can export HTML report from the UI
- **UI-05**: User can re-run all validation checks via button click
- **UI-06**: Application loads without admin privileges (with graceful degradation for restricted checks)

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature | Reason |
|---------|--------|
| Web dashboard | Desktop app is the UI target; web adds server dependency for a local tool |
| Remote endpoint scanning | Different architecture (WinRM, credentials); out of scope |
| Auto-remediation | Validator should report, not change system state |
| Cross-platform support | MDE validation is Windows-only by nature |
| Plugin/extension system | 45 checks is manageable; add new checks as function files |
| Configuration file for checks | Over-engineering; current Test-MDEConfiguration / individual function pattern works |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| STRUCT-01 | — | Pending |
| STRUCT-02 | — | Pending |
| STRUCT-03 | — | Pending |
| STRUCT-04 | — | Pending |
| STRUCT-05 | — | Pending |
| TEST-01 | — | Pending |
| TEST-02 | — | Pending |
| TEST-03 | — | Pending |
| TEST-04 | — | Pending |
| TEST-05 | — | Pending |
| TEST-06 | — | Pending |
| QUAL-01 | — | Pending |
| QUAL-02 | — | Pending |
| QUAL-03 | — | Pending |
| CICD-01 | — | Pending |
| CICD-02 | — | Pending |
| CICD-03 | — | Pending |
| CICD-04 | — | Pending |
| CICD-05 | — | Pending |
| PUBL-01 | — | Pending |
| PUBL-02 | — | Pending |
| PUBL-03 | — | Pending |

**Coverage:**
- v1 requirements: 22 total
- Mapped to phases: 0
- Unmapped: 22 ⚠️

---
*Requirements defined: 2026-03-04*
*Last updated: 2026-03-04 after initialization*
