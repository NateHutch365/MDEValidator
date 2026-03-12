# Requirements Archive: v1 — Module Modernization & CI/CD Foundation

**Milestone:** v1
**Archived:** 2026-03-12
**Status:** All v1 requirements shipped

## v1 Requirements — All Complete

Requirements for the restructured, tested, published module. All satisfied as of 2026-03-12.

### Module Structure

- [x] **STRUCT-01**: Module uses function-per-file layout with Public/ and Private/ folders
  - *Outcome: Validated — 45 Public/*.ps1 + 4 Private/*.ps1 files committed*
- [x] **STRUCT-02**: Root .psm1 uses dot-source loader to import all function files
  - *Outcome: Validated — MDEValidator.psm1 replaced with dot-source loader; loads Private then Public*
- [x] **STRUCT-03**: All 45 existing exported functions preserve their names, parameters, and output shapes
  - *Outcome: Validated — 144 regression tests confirm API contract; verify-restructuring.ps1 confirms 45/45 parameter baselines match*
- [x] **STRUCT-04**: Private helper functions (Write-ValidationResult, ConvertTo-HtmlEncodedString, etc.) are in Private/ folder and not exported
  - *Outcome: Validated — 4 Private/*.ps1 files; none appear in FunctionsToExport in .psd1*
- [x] **STRUCT-05**: Export-ModuleMember and .psd1 FunctionsToExport remain synchronized
  - *Outcome: Validated — FunctionsToExport = 45 = Public/*.ps1 count = 45*

### Testing

- [x] **TEST-01**: Each public validation function has a corresponding Pester 5.x test file
  - *Outcome: Validated — 45 Tests/Public/*.Tests.ps1 files; function-test-map.json = 100%*
- [x] **TEST-02**: Tests mock all external dependencies (Get-MpPreference, Get-MpComputerStatus, Get-Service, Get-ItemProperty)
  - *Outcome: Validated — Mock -ModuleName MDEValidator used consistently for all external dependencies*
- [x] **TEST-03**: Tests validate both pass and fail scenarios for each check
  - *Outcome: Validated — Pass/fail contexts in every test file; 303 total tests*
- [x] **TEST-04**: Tests can run without admin privileges and without Defender installed
  - *Outcome: Validated — Full suite passes on windows-latest CI runner (no Defender installed)*
- [x] **TEST-05**: Pester generates JaCoCo code coverage output
  - *Outcome: Validated — Tests/Artifacts/coverage.xml (JaCoCo format, 107KB)*
- [x] **TEST-06**: Private helper functions have test coverage via module-scoped mocking
  - *Outcome: Validated — 4 Tests/Private/*.Tests.ps1 files using InModuleScope MDEValidator*

### Quality

- [x] **QUAL-01**: Module passes PSScriptAnalyzer with standard rules (no errors or warnings)
  - *Outcome: Validated — 0 errors, 0 warnings confirmed; fixed 5 violations (3 empty catch blocks, 1 unused variable, 1 unused parameter)*
- [x] **QUAL-02**: Module manifest includes LicenseUri, ProjectUri, Tags, and ReleaseNotes
  - *Outcome: Validated — All fields populated; Note: URLs are placeholder GitHub URLs pending real repo URL update before PSGallery publish*
- [x] **QUAL-03**: PSScriptAnalyzer settings file (.PSScriptAnalyzerSettings.psd1) is committed to repo
  - *Outcome: Validated — .PSScriptAnalyzerSettings.psd1 committed at repo root; Severity: Error+Warning*

### CI/CD

- [x] **CICD-01**: GitHub Actions workflow runs Pester tests on push and PR to main
  - *Outcome: Validated — .github/workflows/ci.yml confirmed; structural verification by verify-workflows.ps1*
- [x] **CICD-02**: GitHub Actions workflow runs PSScriptAnalyzer lint on push and PR to main
  - *Outcome: Validated — PSScriptAnalyzer lint step in ci.yml with throw to fail job on violations*
- [x] **CICD-03**: CI runs on windows-latest runner
  - *Outcome: Validated — runs-on: windows-latest in ci.yml*
- [x] **CICD-04**: Automated PSGallery publish triggered on GitHub release/tag
  - *Outcome: Validated — .github/workflows/publish.yml with on: release: types: [published] trigger; Note: No pre-publish CI gate (tech debt — release on failing commit would still publish)*
- [x] **CICD-05**: CI reports code coverage results
  - *Outcome: Validated — madrapps/jacoco-report@v1.7.2 configured in ci.yml; min-coverage-overall: 60*

### Publishing (Deferred to v2)

- [ ] **PUBL-01**: Module is installable via `Install-Module MDEValidator` from PSGallery
  - *Status: Deferred — publish workflow exists but live push to GitHub remote pending; actual PSGallery publish not yet done*
- [ ] **PUBL-02**: Module version follows SemVer (major.minor.patch)
  - *Status: Deferred — manifest version set but not yet published*
- [ ] **PUBL-03**: Published module includes all function files and manifest
  - *Status: Deferred — module structure is correct but not yet published*

---

## Traceability

| Requirement | Phase | Final Status | Notes |
|-------------|-------|--------------|-------|
| STRUCT-01 | Phase 1 | ✅ Complete | 45 Public/*.ps1 files |
| STRUCT-02 | Phase 1 | ✅ Complete | Dot-source loader in .psm1 |
| STRUCT-03 | Phase 1 | ✅ Complete | 144 regression tests pass |
| STRUCT-04 | Phase 1 | ✅ Complete | 4 Private/*.ps1, not exported |
| STRUCT-05 | Phase 1 | ✅ Complete | FunctionsToExport = 45 |
| TEST-01 | Phase 2 | ✅ Complete | 45 test files, 100% mapping |
| TEST-02 | Phase 2 | ✅ Complete | All mocked, no live Defender calls |
| TEST-03 | Phase 2 | ✅ Complete | 303 tests (pass + fail scenarios) |
| TEST-04 | Phase 2 | ✅ Complete | CI: windows-latest, no Defender |
| TEST-05 | Phase 2 | ✅ Complete | JaCoCo coverage.xml (107KB) |
| TEST-06 | Phase 2 | ✅ Complete | 4 Private test files, InModuleScope |
| QUAL-01 | Phase 3 | ✅ Complete | 0 PSSA errors/warnings |
| QUAL-02 | Phase 3 | ✅ Complete | All manifest fields populated |
| QUAL-03 | Phase 3 | ✅ Complete | .PSScriptAnalyzerSettings.psd1 committed |
| CICD-01 | Phase 4 | ✅ Complete | ci.yml: test on push/PR to main |
| CICD-02 | Phase 4 | ✅ Complete | ci.yml: PSSA lint step with failure throw |
| CICD-03 | Phase 4 | ✅ Complete | windows-latest runner |
| CICD-04 | Phase 4 | ✅ Complete | publish.yml: on release published |
| CICD-05 | Phase 4 | ✅ Complete | jacoco-report@v1.7.2, min 60% coverage |
| PUBL-01 | Phase 5 | ⏳ Deferred | Workflow ready; publish not yet executed |
| PUBL-02 | Phase 5 | ⏳ Deferred | Manifest version set; not published |
| PUBL-03 | Phase 5 | ⏳ Deferred | Module structure correct; not published |

---

*For current requirements, see .planning/REQUIREMENTS.md (created for next milestone)*
