---
phase: 4
slug: cicd
status: approved
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-11
---

# Phase 4 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Pester 5.7.1 (local) + GitHub Actions (integration) |
| **Config file** | `run-tests.ps1` — calls `New-PesterConfiguration` |
| **Quick run command** | `pwsh -NoProfile -File ./run-tests.ps1` |
| **Full suite command** | `pwsh -NoProfile -File ./run-tests.ps1` |
| **Estimated runtime** | ~60 seconds (local) |

---

## Sampling Rate

- **After every task commit:** Run `pwsh -NoProfile -File ./run-tests.ps1` (verifies existing tests still pass)
- **After every plan wave:** Run full suite + YAML syntax check
- **Before `/gsd:verify-work`:** Full suite must be green; workflow YAML files must be parseable
- **Max feedback latency:** 90 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 04-01-01 | 01 | 1 | CICD-01, CICD-02, CICD-03, CICD-05 | structure | `pwsh -NoProfile -Command "Test-Path .github/workflows/ci.yml"` | ❌ W0 | ⬜ pending |
| 04-01-02 | 01 | 1 | CICD-01 | smoke | `pwsh -NoProfile -File ./run-tests.ps1` | ✅ existing | ⬜ pending |
| 04-01-03 | 01 | 1 | CICD-02 | smoke | `pwsh -NoProfile -Command "Invoke-ScriptAnalyzer -Path .\MDEValidator -Recurse -Settings .\.PSScriptAnalyzerSettings.psd1 -Severity @('Error','Warning') | Select-Object -First 1"` | ✅ existing | ⬜ pending |
| 04-02-01 | 02 | 1 | CICD-04 | structure | `pwsh -NoProfile -Command "Test-Path .github/workflows/publish.yml"` | ❌ W0 | ⬜ pending |
| 04-02-02 | 02 | 1 | CICD-04 | content | `pwsh -NoProfile -Command "Select-String -Path .github/workflows/publish.yml -Pattern 'NUGET_API_KEY'"` | ❌ W0 | ⬜ pending |
| 04-03-01 | 03 | 2 | CICD-01, CICD-02, CICD-03, CICD-04, CICD-05 | integration | Push/PR triggers actual GHA run | ❌ Requires push | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠ flaky*

---

## Wave 0 Requirements

- [ ] `.github/workflows/` directory created
- [ ] `.github/workflows/ci.yml` — CI workflow for CICD-01, CICD-02, CICD-03, CICD-05
- [ ] `.github/workflows/publish.yml` — Publish workflow for CICD-04

*These are the primary deliverables of this phase — both files must exist before integration verification can be run.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| GHA actually runs on push to main | CICD-01 | Requires live GitHub repo + push | Create a PR or push to main, confirm Actions tab shows green run |
| GHA actually runs on PR to main | CICD-01 | Requires live GitHub repo + PR | Open a test PR, confirm CI job completes successfully |
| PSGallery publish succeeds on Release | CICD-04 | Requires `NUGET_API_KEY` secret + real GitHub repo URLs in manifest | Set secret, create GitHub Release, confirm module appears in PSGallery |
| JaCoCo PR comment appears | CICD-05 | Requires PR event on live repo | Open a PR against main, confirm coverage comment posted by `github-actions[bot]` |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 90s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
