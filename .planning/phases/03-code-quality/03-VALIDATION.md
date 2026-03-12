---
phase: 3
slug: code-quality
status: approved
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-12
---

# Phase 3 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> *Created retroactively 2026-03-12 as part of milestone gap closure (v1-v1-GAP-PLAN.md Task 4b). Phase was executed 2026-03-11 and verified in 03-VERIFICATION.md (status: passed).*

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | PSScriptAnalyzer (direct) + Pester 5.7.1 (regression guard) |
| **Config file** | `.PSScriptAnalyzerSettings.psd1` |
| **Quick run command** | `Invoke-ScriptAnalyzer -Path .\MDEValidator -Recurse -Settings .\.PSScriptAnalyzerSettings.psd1` |
| **Full suite command** | `pwsh -NoProfile -File ./run-tests.ps1` |
| **Estimated runtime** | ~5 seconds (PSSA) + ~60 seconds (Pester) |

---

## Sampling Rate

- **After every task commit:** Run `Invoke-ScriptAnalyzer -Path .\MDEValidator -Recurse -Settings .\.PSScriptAnalyzerSettings.psd1`
- **After every plan wave:** Run Pester full suite to confirm no regressions
- **Before `/gsd:verify-work`:** PSSA must return 0 violations; full Pester suite must be green
- **Max feedback latency:** 10 seconds (PSSA)

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 03-01-01 | 01 | 1 | QUAL-03 | structure | `Test-Path .PSScriptAnalyzerSettings.psd1` | ❌ W0 | ✅ green |
| 03-01-02 | 01 | 1 | QUAL-01 | smoke | `Invoke-ScriptAnalyzer -Path .\MDEValidator -Recurse -Settings .\.PSScriptAnalyzerSettings.psd1` | ✅ existing | ✅ green |
| 03-02-01 | 02 | 2 | QUAL-02 | smoke | `(Test-ModuleManifest MDEValidator/MDEValidator.psd1).PrivateData.PSData.LicenseUri` | ✅ existing | ✅ green |
| 03-02-02 | 02 | 2 | QUAL-01, QUAL-02 | integration | `Invoke-ScriptAnalyzer + Test-ModuleManifest` | ✅ existing | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠ flaky*

---

## Wave 0 Requirements

All Wave 0 items resolved during phase execution.

- [x] `.PSScriptAnalyzerSettings.psd1` created at repo root (03-01 Task 1)
- [x] Zero PSSA violations against MDEValidator module (03-01 Task 2 — 5 violations fixed)
- [x] MDEValidator.psd1 LicenseUri, ProjectUri, Tags, ReleaseNotes populated (03-02)

---

## Manual-Only Verifications

All phase behaviors have automated verification. No manual-only checks required.

---

## Validation Sign-Off

- [x] All tasks have automated verify
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 10s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-03-12 (retroactive — phase verified in 03-VERIFICATION.md)
