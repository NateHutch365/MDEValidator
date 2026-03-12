# Debug Session: ci-pipeline-test-failures

**Status:** ACTIVE — FIX APPLIED  
**Slug:** ci-pipeline-test-failures  
**Created:** 2026-03-12  
**Last Updated:** 2026-03-12

---

## Issue Summary

CI pipeline tests are failing on GitHub Actions. This is the **second CI failure** — the first was fixed (PSScriptRoot bug, commit `2bd1f59`) but CI is failing again after that push. User is providing updated logs.

---

## Symptoms

- **Expected:** 303/303 tests pass on `windows-latest` GitHub Actions runner
- **Actual:** CI pipeline failing again after push `2bd1f59` (second failure)
- **Timeline:** First CI run failed with 159/303 failures. Root cause diagnosed as `$PSScriptRoot` unreliable in Pester 5 BeforeAll on Windows Server 2025. Fix applied and pushed. Second CI run also failing — logs not yet analyzed.
- **Reproduction:** Push to `main` branch triggers `.github/workflows/ci.yml`

---

## Fix History

### Fix #1 (APPLIED — `2bd1f59`)
**Root cause:** `$PSScriptRoot` unreliable in Pester 5 BeforeAll on Windows Server 2025 CI runner  
**Symptom:** All 48 per-function test files failed with `time="0"` — BeforeAll crash before any test ran  
**Error in NUnit XML:** "This test should run but it did not. Most likely a setup in some parent block failed."  
**Fix:** `Tests/Helpers/TestBootstrap.ps1::Initialize-MDEValidatorTest` changed to use `$MyInvocation.MyCommand.ScriptBlock.File` instead of `$PSScriptRoot`  
**Local verification:** 303/0 ✅  
**CI result:** STILL FAILING (second failure — logs pending analysis)

---

## Key Files

| File | Purpose |
|------|---------|
| `Tests/Helpers/TestBootstrap.ps1` | Shared module import — dot-sourced by all per-function test files in BeforeAll |
| `run-tests.ps1` | Pester 5 runner; produces JaCoCo + NUnit artifacts |
| `.github/workflows/ci.yml` | CI pipeline trigger (push/PR to main, windows-latest) |
| `MDEValidator/MDEValidator.psd1` | Module manifest imported during tests |
| `Tests/MDEValidator.Tests.ps1` | Main test file (144 tests) — imports via `.psm1` directly, NOT via TestBootstrap |

---

## Architecture Context

- **Test framework:** Pester 5.7.1+, NUnit XML output, JaCoCo coverage
- **CI runner:** `windows-latest` = Windows Server 2025
- **Module structure:** 45 public + 4 private functions, dot-sourced via `MDEValidator.psm1`
- **TestBootstrap pattern:** Every per-function test file dot-sources `TestBootstrap.ps1` then calls `Initialize-MDEValidatorTest` inside `BeforeAll {}`. The `MDEValidator.Tests.ps1` file does NOT use TestBootstrap — it imports `.psm1` directly.
- **Pester config (run-tests.ps1):** `PassThru = $true`, NUnit XML to `Tests/Artifacts/test-results.xml`, JaCoCo to `Tests/Artifacts/coverage.xml`

---

## Current State of TestBootstrap.ps1

```powershell
function Initialize-MDEValidatorTest {
    param()
    # Uses function source file location (NOT $PSScriptRoot) — reliable in Pester 5 BeforeAll
    $bootstrapDir = Split-Path $MyInvocation.MyCommand.ScriptBlock.File -Parent
    $manifestPath = Resolve-Path (Join-Path $bootstrapDir '..\..\MDEValidator\MDEValidator.psd1')
    Import-Module $manifestPath -Force -ErrorAction Stop
    Get-Module MDEValidator
}
```

---

## Relevant Commits

```
2bd1f59  fix(tests): resolve PSScriptRoot unreliability in Pester BeforeAll context
a81789c  docs(04-03): complete plan — workflow proof checks passed; checkpoint pending
84145d6  fix(tests): correct 8 test expectation mismatches
e09ae6e  docs(04-01): complete ci.yml plan
0ad259a  docs(04-cicd-02): complete publish.yml plan
3149053  feat(04-01): create GitHub Actions CI workflow
6e207d2  feat(04-cicd-02): create PSGallery publish workflow
```

---

## CI Workflow Snippet (relevant)

```yaml
- name: Install Pester
  shell: pwsh
  run: Install-Module -Name Pester -MinimumVersion 5.7.1 -Force -Scope CurrentUser

- name: Run Pester Tests
  shell: pwsh
  run: .\run-tests.ps1
```

---

## Pending Action

**Fix #2 applied — awaiting CI verification.** Push commit and check CI results.

---

## Investigation Log

### 2026-03-12 — Fix #2
- Analyzed second CI failure NUnit XML: 149/303 failures (down from 159)
- Fix #1 recovered 10 tests in 2 files (Get-MDEPolicyRegistryPath, Get-MDEPolicySettingConfig)
- KEY INSIGHT: The 2 passing per-function files don't use Mock/InModuleScope; all 46 failing files do
- Root cause: file-scope `$PSScriptRoot` in TestBootstrap.ps1 also unreliable on CI
- `.(Join-Path $PSScriptRoot 'MockBuilders.ps1')` fails → MockBuilders not loaded → BeforeAll crashes
- Fix: replaced single `$PSScriptRoot` with 5-method fallback chain
- Local verification: 303/0 in both script mode and interactive mode

### 2026-03-12 — Session Start
- Phase 4 CI/CD pipeline complete, CI failed first time (159/303)
- Root cause: `$PSScriptRoot` empty in Pester 5 BeforeAll on Server 2025
- Fix applied and verified locally (303/0)
- Pushed `2bd1f59` — CI still failing (149/303)

