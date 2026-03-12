# Requirements: MDEValidator

**Defined:** 2026-03-04
**Core Value:** Reliably validate that MDE is configured correctly on any Windows endpoint and surface the results clearly.

## v1 Requirements

Requirements for the restructured, tested, published module. Each maps to roadmap phases.

### Module Structure

- [x] **STRUCT-01**: Module uses function-per-file layout with Public/ and Private/ folders
- [x] **STRUCT-02**: Root .psm1 uses dot-source loader to import all function files
- [x] **STRUCT-03**: All 45 existing exported functions preserve their names, parameters, and output shapes
- [x] **STRUCT-04**: Private helper functions (Write-ValidationResult, ConvertTo-HtmlEncodedString, etc.) are in Private/ folder and not exported
- [x] **STRUCT-05**: Export-ModuleMember and .psd1 FunctionsToExport remain synchronized

### Testing

- [x] **TEST-01**: Each public validation function has a corresponding Pester 5.x test file
- [x] **TEST-02**: Tests mock all external dependencies (Get-MpPreference, Get-MpComputerStatus, Get-Service, Get-ItemProperty)
- [x] **TEST-03**: Tests validate both pass and fail scenarios for each check
- [x] **TEST-04**: Tests can run without admin privileges and without Defender installed
- [x] **TEST-05**: Pester generates JaCoCo code coverage output
- [x] **TEST-06**: Private helper functions have test coverage via module-scoped mocking

### Quality

- [x] **QUAL-01**: Module passes PSScriptAnalyzer with standard rules (no errors or warnings)
- [x] **QUAL-02**: Module manifest includes LicenseUri, ProjectUri, Tags, and ReleaseNotes
- [x] **QUAL-03**: PSScriptAnalyzer settings file (.PSScriptAnalyzerSettings.psd1) is committed to repo

### CI/CD

- [x] **CICD-01**: GitHub Actions workflow runs Pester tests on push and PR to main
- [x] **CICD-02**: GitHub Actions workflow runs PSScriptAnalyzer lint on push and PR to main
- [x] **CICD-03**: CI runs on windows-latest runner
- [x] **CICD-04**: Automated PSGallery publish triggered on GitHub release/tag
- [x] **CICD-05**: CI reports code coverage results

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
| STRUCT-01 | Phase 1 | Complete |
| STRUCT-02 | Phase 1 | Complete |
| STRUCT-03 | Phase 1 | Complete |
| STRUCT-04 | Phase 1 | Complete |
| STRUCT-05 | Phase 1 | Complete |
| TEST-01 | Phase 2 | Complete |
| TEST-02 | Phase 2 | Complete |
| TEST-03 | Phase 2 | Complete |
| TEST-04 | Phase 2 | Complete |
| TEST-05 | Phase 2 | Complete |
| TEST-06 | Phase 2 | Complete |
| QUAL-01 | Phase 3 | Complete |
| QUAL-02 | Phase 3 | Complete |
| QUAL-03 | Phase 3 | Complete |
| CICD-01 | Phase 4 | Complete |
| CICD-02 | Phase 4 | Complete |
| CICD-03 | Phase 4 | Complete |
| CICD-04 | Phase 4 | Complete |
| CICD-05 | Phase 4 | Complete |
| PUBL-01 | Phase 5 | Pending |
| PUBL-02 | Phase 5 | Pending |
| PUBL-03 | Phase 5 | Pending |

**Coverage:**
- v1 requirements: 22 total
- Mapped to phases: 22 ✓
- Unmapped: 0

---
*Requirements defined: 2026-03-04*
*Last updated: 2026-03-04 — traceability updated with phase mappings*
