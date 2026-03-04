# Roadmap: MDEValidator

## Overview

Transform MDEValidator from a working monolithic ~2000-line .psm1 into a maintainable, tested, CI-gated, PSGallery-published module. Five phases move from restructuring the codebase, through testing and quality gates, to automated publishing — each delivering a verifiable capability that unblocks the next.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Module Restructuring** - Split monolithic .psm1 into function-per-file layout preserving all 45 exports
- [ ] **Phase 2: Testing Infrastructure** - Mock-based Pester tests for every function, runnable without Defender or admin
- [ ] **Phase 3: Code Quality** - PSScriptAnalyzer compliance and publish-ready manifest metadata
- [ ] **Phase 4: CI/CD Pipeline** - GitHub Actions for automated testing, linting, coverage, and publish triggers
- [ ] **Phase 5: PSGallery Publishing** - Module installable via Install-Module from PowerShell Gallery

## Phase Details

### Phase 1: Module Restructuring
**Goal**: Module uses function-per-file layout while preserving the existing 45-function public API
**Depends on**: Nothing (first phase)
**Requirements**: STRUCT-01, STRUCT-02, STRUCT-03, STRUCT-04, STRUCT-05
**Success Criteria** (what must be TRUE):
  1. Every exported function lives in its own .ps1 file under a Public/ folder
  2. Private helper functions (Write-ValidationResult, ConvertTo-HtmlEncodedString, etc.) live in separate .ps1 files under Private/ and are not exported
  3. Running `Import-Module MDEValidator` loads all functions via dot-source loader without errors
  4. All 45 exported function names, parameters, and output shapes are identical to the monolithic version
  5. FunctionsToExport in .psd1 matches the actual exported function set exactly
**Plans**: Planned 2026-03-04

Plans:
- [x] 01-01: Audit function inventory, confirm public/private classification, capture parameter baselines
- [x] 01-02: Extract 49 functions to Public/ and Private/ files, replace .psm1 with dot-source loader
- [ ] 01-03: Verify exports match baseline, private helpers not exported, Pester tests pass

### Phase 2: Testing Infrastructure
**Goal**: Every validation function has mock-based Pester tests that run without Defender or admin privileges
**Depends on**: Phase 1
**Requirements**: TEST-01, TEST-02, TEST-03, TEST-04, TEST-05, TEST-06
**Success Criteria** (what must be TRUE):
  1. Every public function and private helper has corresponding Pester 5.x test coverage
  2. Tests mock all external dependencies (Get-MpPreference, Get-MpComputerStatus, Get-Service, Get-ItemProperty) — no live calls
  3. Each test validates both passing and failing validation scenarios
  4. Full test suite passes on a machine without Defender installed and without admin privileges
  5. Pester run produces JaCoCo XML coverage report
**Plans**: TBD

Plans:
- [ ] 02-01: TBD
- [ ] 02-02: TBD
- [ ] 02-03: TBD

### Phase 3: Code Quality
**Goal**: Module passes static analysis and has complete, publish-ready manifest metadata
**Depends on**: Phase 1
**Requirements**: QUAL-01, QUAL-02, QUAL-03
**Success Criteria** (what must be TRUE):
  1. PSScriptAnalyzer reports zero errors and zero warnings against the full module
  2. Module manifest (.psd1) includes LicenseUri, ProjectUri, Tags, and ReleaseNotes
  3. PSScriptAnalyzer settings file (.PSScriptAnalyzerSettings.psd1) is committed to the repo root
**Plans**: TBD

Plans:
- [ ] 03-01: TBD
- [ ] 03-02: TBD

### Phase 4: CI/CD Pipeline
**Goal**: Every push and PR to main is automatically tested, linted, and coverage-reported via GitHub Actions
**Depends on**: Phase 2, Phase 3
**Requirements**: CICD-01, CICD-02, CICD-03, CICD-04, CICD-05
**Success Criteria** (what must be TRUE):
  1. GitHub Actions workflow runs the full Pester test suite on every push and PR to main
  2. GitHub Actions workflow runs PSScriptAnalyzer and fails the build on any violation
  3. CI executes on a windows-latest runner
  4. CI publishes code coverage results from JaCoCo output
  5. A GitHub release/tag triggers automated PSGallery module publishing
**Plans**: TBD

Plans:
- [ ] 04-01: TBD
- [ ] 04-02: TBD
- [ ] 04-03: TBD

### Phase 5: PSGallery Publishing
**Goal**: Module is installable by anyone via `Install-Module MDEValidator` from PowerShell Gallery
**Depends on**: Phase 4
**Requirements**: PUBL-01, PUBL-02, PUBL-03
**Success Criteria** (what must be TRUE):
  1. Running `Install-Module MDEValidator` from PSGallery succeeds and the module imports correctly
  2. Published module version follows SemVer (major.minor.patch)
  3. Published module package includes all function files, manifest, and required assets
**Plans**: TBD

Plans:
- [ ] 05-01: TBD
- [ ] 05-02: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Module Restructuring | 1/3 | In Progress | 01-01 ✓ |
| 2. Testing Infrastructure | 0/3 | Not started | — |
| 3. Code Quality | 0/2 | Not started | — |
| 4. CI/CD Pipeline | 0/3 | Not started | — |
| 5. PSGallery Publishing | 0/2 | Not started | — |

---
*Roadmap created: 2026-03-04*
*Last updated: 2026-03-04*
