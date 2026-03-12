---
phase: 2
slug: testing-infrastructure
status: approved
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-07
---

# Phase 2 - Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Pester 5.x |
| **Config file** | none - configured via `run-tests.ps1` in Wave 0 |
| **Quick run command** | `pwsh -NoProfile -File ./run-tests.ps1` |
| **Full suite command** | `pwsh -NoProfile -Command "$c=New-PesterConfiguration; $c.Run.Path='./Tests'; $c.CodeCoverage.Enabled=$true; $c.CodeCoverage.OutputFormat='JaCoCo'; $c.CodeCoverage.OutputPath='./Tests/Artifacts/coverage.xml'; Invoke-Pester -Configuration $c"` |
| **Estimated runtime** | ~60 seconds |

---

## Sampling Rate

- **After every task commit:** Run `pwsh -NoProfile -File ./run-tests.ps1`
- **After every plan wave:** Run full suite with JaCoCo coverage enabled
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 90 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 02-01-01 | 01 | 1 | TEST-01 | unit/structure | `pwsh -NoProfile -Command "(Get-ChildItem ./MDEValidator/Public/*.ps1).BaseName | ForEach-Object { Test-Path \"./Tests/Public/$_.Tests.ps1\" } | Where-Object { -not $_ } | Measure-Object | Select-Object -ExpandProperty Count"` | ❌ W0 | ⬜ pending |
| 02-01-02 | 01 | 1 | TEST-02 | unit | `pwsh -NoProfile -Command "Invoke-Pester -Path ./Tests/Public -Output None"` | ❌ W0 | ⬜ pending |
| 02-01-03 | 01 | 1 | TEST-03 | unit | `pwsh -NoProfile -Command "Invoke-Pester -Path ./Tests/Public -Output None"` | ❌ W0 | ⬜ pending |
| 02-01-04 | 01 | 1 | TEST-04 | integration/smoke | `pwsh -NoProfile -Command "$env:MDE_TEST_NO_DEFENDER='1'; Invoke-Pester -Path ./Tests -Output Detailed"` | ❌ W0 | ⬜ pending |
| 02-02-01 | 02 | 2 | TEST-05 | integration | `pwsh -NoProfile -Command "$c=New-PesterConfiguration; $c.Run.Path='./Tests'; $c.CodeCoverage.Enabled=$true; $c.CodeCoverage.OutputFormat='JaCoCo'; $c.CodeCoverage.OutputPath='./Tests/Artifacts/coverage.xml'; Invoke-Pester -Configuration $c"` | ❌ W0 | ⬜ pending |
| 02-03-01 | 03 | 3 | TEST-06 | unit | `pwsh -NoProfile -Command "Invoke-Pester -Path ./Tests/Private -Output None"` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠ flaky*

---

## Wave 0 Requirements

- [ ] `Tests/Public/*.Tests.ps1` - stubs aligned to all public function files for TEST-01
- [ ] `Tests/Private/*.Tests.ps1` - private helper tests for TEST-06
- [ ] `Tests/Helpers/TestBootstrap.ps1` - shared import/setup helpers
- [ ] `Tests/Helpers/MockBuilders.ps1` - standardized mocks for external dependencies
- [ ] `Tests/Mapping/function-test-map.json` (generated) - function-to-test checklist
- [ ] `Tests/Artifacts/` - output location for coverage/test artifacts
- [ ] Update `run-tests.ps1` to use `New-PesterConfiguration` and JaCoCo output

---

## Manual-Only Verifications

All phase behaviors have automated verification.

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all missing references
- [x] No watch-mode flags
- [x] Feedback latency < 90s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
