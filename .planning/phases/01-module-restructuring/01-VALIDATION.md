---
phase: 1
slug: module-restructuring
status: approved
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-04
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Pester (via `#Requires -Modules Pester`) |
| **Config file** | None — direct invocation |
| **Quick run command** | `Import-Module ./MDEValidator/MDEValidator.psm1 -Force; (Get-Command -Module MDEValidator).Count` |
| **Full suite command** | `Invoke-Pester -Path ./Tests/MDEValidator.Tests.ps1 -Output Detailed` |
| **Estimated runtime** | ~5 seconds |

---

## Sampling Rate

- **After every task commit:** Run `Import-Module ./MDEValidator/MDEValidator.psm1 -Force; (Get-Command -Module MDEValidator).Count`
- **After every plan wave:** Run `Invoke-Pester -Path ./Tests/MDEValidator.Tests.ps1 -Output Detailed`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 5 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 01-01 | 01 | 1 | STRUCT-03, STRUCT-04 | smoke | `Test-Path audit-baseline.json; ConvertFrom-Json count check` | ❌ W0 (created by task) | ⬜ pending |
| 01-02 | 01 | 1 | STRUCT-05 | smoke | `ConvertFrom-Json exportListsMatch check` | ❌ W0 (created by task) | ⬜ pending |
| 02-01 | 02 | 2 | STRUCT-01, STRUCT-04 | smoke | `Get-ChildItem Public/*.ps1 count = 45; Private/*.ps1 count = 4` | ❌ W0 (created by task) | ⬜ pending |
| 02-02 | 02 | 2 | STRUCT-02 | smoke | `Import-Module + Get-Command count = 45` | ✅ Existing test covers import | ⬜ pending |
| 03-01 | 03 | 3 | STRUCT-03, STRUCT-05 | unit | `Import-Module + export count + private leak + param comparison` | ✅ Existing tests + inline checks | ⬜ pending |
| 03-02 | 03 | 3 | STRUCT-03 | integration | `Invoke-Pester -PassThru` | ✅ Tests/MDEValidator.Tests.ps1 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements.

- Pester is already installed (`#Requires -Modules Pester` in test file)
- Existing test suite covers module import and export surface validation
- audit-baseline.json is created by Plan 01 tasks (not a prerequisite)

---

## Manual-Only Verifications

All phase behaviors have automated verification.

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 5s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-03-04
