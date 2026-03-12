---
milestone: 1
type: gap-closure
audit_ref: v1-v1-MILESTONE-AUDIT.md
status: complete
created: 2026-03-12
completed: 2026-03-12
tasks_total: 4
tasks_completed: 4
closes:
  requirements: [STRUCT-01, STRUCT-02, STRUCT-03, STRUCT-04, STRUCT-05, TEST-01, TEST-02, TEST-03, TEST-04, TEST-05, TEST-06, CICD-01, CICD-02, CICD-03, CICD-04, CICD-05]
  phase_blockers: [01-module-restructuring, 04-cicd]
  tech_debt_items: 8
---

# Milestone v1 — Gap Closure Plan

**Audit source:** `v1-v1-MILESTONE-AUDIT.md`
**Gap type:** Documentation-only — all implementation is complete; no code changes required
**Goal:** Move milestone audit status from `gaps_found` → `passed`

---

## Gap Summary

| # | Gap | Impact | Effort |
|---|-----|--------|--------|
| 1 | Phase 1 missing `VERIFICATION.md` | STRUCT-01–05 classified unsatisfied; Phase 1 unverified | Low |
| 2 | Phase 4 missing `VERIFICATION.md` | CICD-01–05 classified partial; Phase 4 unverified | Low |
| 3 | REQUIREMENTS.md checkboxes all `[ ]` for STRUCT-*, TEST-*, CICD-* | Primary requirements doc shows all v1 work as pending | Low |
| 4 | VALIDATION.md tech debt across Phases 2, 3, 4 | Nyquist compliance misleadingly partial/missing | Low |

All gaps are **documentation gaps**. No code changes, no test changes required.

---

## Task 1: Create Phase 1 VERIFICATION.md

**Closes:** STRUCT-01, STRUCT-02, STRUCT-03, STRUCT-04, STRUCT-05 (unsatisfied → satisfied); Phase 1 phase-blocker
**Effort:** Low — all evidence confirmed by audit codebase checks and 01-03-SUMMARY.md
**File:** `.planning/phases/01-module-restructuring/01-VERIFICATION.md`

**Content to document:**
- STRUCT-01: 45 files in MDEValidator/Public/ (confirmed via `(Get-ChildItem MDEValidator/Public/*.ps1).Count`)
- STRUCT-02: MDEValidator.psm1 uses dot-source loader pattern (confirmed by file content)
- STRUCT-03: All 45 functions preserve names, parameters, output shapes (confirmed by verify-restructuring.ps1 — 45/45 parameter baseline match)
- STRUCT-04: 4 private helpers in MDEValidator/Private/; none appear in psd1 FunctionsToExport (confirmed)
- STRUCT-05: psd1 FunctionsToExport = 45 = Public/*.ps1 count = Get-Command output count (confirmed)

**Verification commands to embed:**
```powershell
# STRUCT-01: 45 public function files
(Get-ChildItem MDEValidator/Public/*.ps1).Count  # expect 45

# STRUCT-02: dot-source loader
Select-String -Path MDEValidator/MDEValidator.psm1 -Pattern 'Get-ChildItem'  # loader pattern

# STRUCT-03: parameter baseline match (all 45)
.\verify-restructuring.ps1  # all 45 parameters match; script exits 0

# STRUCT-04: private helpers not exported
(Get-ChildItem MDEValidator/Private/*.ps1).Count  # expect 4
(Test-ModuleManifest MDEValidator/MDEValidator.psd1).ExportedFunctions.Keys -contains 'Write-ValidationResult'  # expect False

# STRUCT-05: export sync
(Test-ModuleManifest MDEValidator/MDEValidator.psd1).ExportedFunctions.Count  # expect 45
```

---

## Task 2: Create Phase 4 VERIFICATION.md

**Closes:** CICD-01, CICD-02, CICD-03, CICD-04, CICD-05 (partial → satisfied); Phase 4 phase-blocker
**Effort:** Low — workflow files locally verified by verify-workflows.ps1 (21/21 pattern checks pass)
**File:** `.planning/phases/04-cicd/04-VERIFICATION.md`
**Note:** Live GitHub Actions run is a pending human checkpoint (documented in 04-03-PLAN.md); VERIFICATION.md notes this as deferred verification

**Content to document:**
- CICD-01: ci.yml triggers on push + pull_request to main (confirmed by Select-String pattern check)
- CICD-02: ci.yml runs PSScriptAnalyzer with .PSScriptAnalyzerSettings.psd1; throws on violations (confirmed)
- CICD-03: ci.yml uses windows-latest runner (confirmed)
- CICD-04: publish.yml triggers on release:published; uses NUGET_API_KEY secret (confirmed)
- CICD-05: ci.yml uploads coverage.xml + test-results.xml; includes JaCoCo PR comment step (confirmed)

**Verification commands to embed:**
```powershell
# CICD-01: CI trigger patterns
Select-String -Path .github/workflows/ci.yml -Pattern 'push|pull_request|branches.*main'

# CICD-02: PSScriptAnalyzer step with throw
Select-String -Path .github/workflows/ci.yml -Pattern 'PSScriptAnalyzerSettings|throw'

# CICD-03: windows-latest
Select-String -Path .github/workflows/ci.yml -Pattern 'windows-latest'

# CICD-04: publish workflow
Select-String -Path .github/workflows/publish.yml -Pattern 'release.*published|NUGET_API_KEY|Publish-Module'

# CICD-05: coverage upload
Select-String -Path .github/workflows/ci.yml -Pattern 'coverage.xml|upload-artifact|jacoco'

# Full verify-workflows.ps1 (21/21 pattern checks)
.\verify-workflows.ps1
```

**Human checkpoint (deferred):** Live GitHub Actions run requires a push to the GitHub remote. This was documented in 04-03-PLAN.md and deferred as a human checkpoint. The VERIFICATION.md should note this outstanding item.

---

## Task 3: Update REQUIREMENTS.md

**Closes:** 16 requirements (partial/unsatisfied → satisfied); traceability table Pending → Complete
**Effort:** Low — mechanical checkbox updates
**File:** `.planning/REQUIREMENTS.md`

**Changes:**
1. Check `[x]` for STRUCT-01, STRUCT-02, STRUCT-03, STRUCT-04, STRUCT-05 (Phase 1 — confirmed by codebase)
2. Check `[x]` for TEST-01, TEST-02, TEST-03, TEST-04, TEST-05, TEST-06 (Phase 2 — VERIFICATION.md passed)
3. Check `[x]` for CICD-01, CICD-02, CICD-03, CICD-04, CICD-05 (Phase 4 — locally verified; live GHA pending)
4. Update Traceability table: change `Pending` → `Complete` for all 16 requirements

**Do not change:** QUAL-01, QUAL-02, QUAL-03 (already `[x]` and `Complete`); PUBL-* (Phase 5, not started)

---

## Task 4: Fix VALIDATION.md Tech Debt

**Closes:** 3 Nyquist compliance gaps (partial/missing → compliant)
**Effort:** Low — update frontmatter values and create one missing file

### 4a: Update 02-VALIDATION.md

**File:** `.planning/phases/02-testing-infrastructure/02-VALIDATION.md`
**Change:** Set `wave_0_complete: true` (was: `false` — left in draft state; 02-VERIFICATION.md confirms phase complete)

### 4b: Create 03-VALIDATION.md

**File:** `.planning/phases/03-code-quality/03-VALIDATION.md`
**Reason:** No VALIDATION.md was created for Phase 3 (discovered by audit as MISSING)
**Content:** Create from Phase 3 VERIFICATION.md evidence; set `nyquist_compliant: true`, `wave_0_complete: true`
**Phase 3 context:** Phase 3 had 2 plans (03-01, 03-02); both SUMMARY files exist; VERIFICATION.md exists with status:passed; no wave-0 gaps remained at execution time

### 4c: Update 04-VALIDATION.md

**File:** `.planning/phases/04-cicd/04-VALIDATION.md`
**Changes:**
- Set `nyquist_compliant: true` (was: `false` — left in initial draft state)
- Set `wave_0_complete: true` (was: `false` — ci.yml and publish.yml both exist, resolving all Wave 0 items)
- Update per-task status column: all tasks → ✅ green
- Update Wave 0 checkboxes: all 3 items → checked

---

## Execution Order

Tasks are independent — no sequencing constraint. Suggested order:

1. **Task 1** — Phase 1 VERIFICATION.md (highest impact: unblocks 5 requirements from "unsatisfied")
2. **Task 2** — Phase 4 VERIFICATION.md (unblocks 5 requirements from "partial")
3. **Task 3** — REQUIREMENTS.md update (completes 3-source cross-reference for all 16 requirements)
4. **Task 4** — VALIDATION.md tech debt (fixes Nyquist compliance reporting)

---

## Post-Completion Checklist

After all 4 tasks complete, re-run milestone audit to confirm gaps_found → passed:

- [ ] `.planning/phases/01-module-restructuring/01-VERIFICATION.md` exists with `status: passed`
- [ ] `.planning/phases/04-cicd/04-VERIFICATION.md` exists with `status: passed`
- [ ] REQUIREMENTS.md: STRUCT-01–05, TEST-01–06, CICD-01–05 all checked `[x]`
- [ ] REQUIREMENTS.md traceability table: STRUCT-*, TEST-*, CICD-* all show `Complete`
- [ ] `02-VALIDATION.md`: `wave_0_complete: true`
- [ ] `03-VALIDATION.md` exists with `nyquist_compliant: true`
- [ ] `04-VALIDATION.md`: `nyquist_compliant: true` and `wave_0_complete: true`
- [ ] Human checkpoint: Push to GitHub remote and observe passing Actions run (resolves live CI deferred item)

---

## Out of Scope

The following tech debt items from the audit are intentionally deferred — they require non-trivial effort and do not block milestone closure:

| Item | Reason deferred |
|------|----------------|
| Add `requirements-completed` to Phase 1–3 SUMMARY frontmatter | Medium effort; SUMMARY files are historical records and don't affect 3-source cross-reference (VERIFICATION.md is the authoritative source) |
| Add pre-publish CI gate to publish.yml (`needs:` dependency) | Requires workflow change; separate enhancement |

_Gap plan created: 2026-03-12_
