---
phase: 04-cicd
plan: 01
subsystem: cicd
tags: [github-actions, ci, pester, pssa, jacoco, coverage, powershell]

# Dependency graph
requires:
  - phase: 02-testing-infrastructure
    provides: run-tests.ps1 + Tests/Artifacts/coverage.xml + test-results.xml
  - phase: 03-code-quality
    provides: .PSScriptAnalyzerSettings.psd1 committed at repo root
provides:
  - .github/workflows/ci.yml — CI workflow for test + lint + coverage on every push/PR to main
affects: [ci-pipeline, code-quality-gate, coverage-reporting]

# Tech tracking
tech-stack:
  added: [GitHub Actions, Pester 5.7.1, PSScriptAnalyzer, madrapps/jacoco-report@v1.7.2, actions/upload-artifact@v4]
  patterns: [Artifact upload with if:always() guard, PSScriptAnalyzer lint-last ordering, PR-gated JaCoCo comment]

key-files:
  created: [.github/workflows/ci.yml]
  modified: []

key-decisions:
  - "PSScriptAnalyzer runs LAST — artifact uploads have if:always() guards so coverage.xml is preserved even when lint fails"
  - "JaCoCo step gated on github.event_name == 'pull_request' — avoids posting duplicate comments on push-to-main runs"
  - "throw used in PSSA step (not Write-Error alone) — terminates pwsh step with non-zero exit code to fail the job"
  - "min-coverage-overall: 60 — fails CI if overall JaCoCo coverage drops below 60%"
  - "update-comment: true on JaCoCo — edits existing PR comment on re-runs instead of creating duplicates"

patterns-established:
  - "Lint-last pattern: run tests + upload artifacts before lint so coverage is always preserved"
  - "if:always() on artifact upload steps — required when preceding steps can fail"

requirements-completed: [CICD-01, CICD-02, CICD-03, CICD-05]

# Metrics
duration: 3min
completed: 2026-03-11
---

# Phase 4 Plan 01: CI Workflow Summary

**GitHub Actions CI pipeline — runs Pester tests, uploads JaCoCo/NUnit artifacts, posts PR coverage comment, fails build on any PSScriptAnalyzer violation**

## Performance

- **Duration:** ~3 min
- **Completed:** 2026-03-11
- **Tasks:** 2 completed
- **Files modified:** 1

## Accomplishments
- Created `.github/workflows/ci.yml` — full CI pipeline for the MDEValidator PowerShell module
- Runs on `windows-latest` runner on every push and PR to `main`
- Installs Pester 5.7.1+ and PSScriptAnalyzer from PSGallery before running
- Executes `.\run-tests.ps1` (exits non-zero on test failure → fails job)
- Uploads `test-results.xml` and `coverage.xml` as artifacts with `if: always()` guard
- Posts JaCoCo coverage comment on PRs (gated on `github.event_name == 'pull_request'`)
- Runs PSScriptAnalyzer last with `throw` on violations — preserves artifact uploads even when lint fails

## Task Commits

Each task was committed atomically:

1. **Task 1: Create .github/workflows/ci.yml** - `3149053` (feat)

## Files Created/Modified
- `.github/workflows/ci.yml` — CI workflow: checkout, install Pester 5.7.1+, install PSScriptAnalyzer, run-tests.ps1, upload artifacts (if:always()), JaCoCo PR comment (PR-only), PSScriptAnalyzer lint with throw on violations

## Decisions Made
- **Lint-last ordering:** PSScriptAnalyzer step placed after artifact uploads so `coverage.xml` and `test-results.xml` are always preserved regardless of lint outcome. The `if: always()` guards on upload steps are the safety net.
- **throw vs Write-Error:** Using `throw` ensures the pwsh step exits non-zero and fails the job. `Write-Error` alone does not reliably fail a GitHub Actions step.
- **PR-only JaCoCo:** The `if: github.event_name == 'pull_request'` condition prevents the JaCoCo action from failing push-to-main runs (which have no PR context to comment on).
- **pull-requests: write permission:** Required for the JaCoCo action to post and update PR comments.

## Self-Check: PASSED

- `FOUND: .github/workflows/ci.yml` — created and committed (3149053)
- `FOUND: 04-01-SUMMARY.md` — created at `.planning/phases/04-cicd/04-01-SUMMARY.md`
- All required patterns verified: windows-latest, madrapps/jacoco-report@v1.7.2, PSScriptAnalyzerSettings, run-tests.ps1, upload-artifact@v4, pull-requests: write
