---
phase: 01-module-restructuring
plan: 03
type: execute
wave: 3
depends_on: ["01-02"]
files_modified:
  - Tests/MDEValidator.Tests.ps1
autonomous: true
requirements: [STRUCT-03, STRUCT-05]

must_haves:
  truths:
    - "All 45 exported function names are identical to the monolithic version"
    - "All exported function parameter sets are identical to the baseline"
    - "Private helpers (Write-ValidationResult, ConvertTo-HtmlEncodedString, Test-IsElevated, Test-IsWindowsServer) are NOT exported"
    - ".psd1 FunctionsToExport matches actual module exports exactly"
    - "Existing Pester test suite passes without regressions"
  artifacts:
    - path: "Tests/MDEValidator.Tests.ps1"
      provides: "Existing test file (may have minimal fixes if restructuring broke anything)"
  key_links:
    - from: "MDEValidator/MDEValidator.psd1"
      to: "Get-Command -Module MDEValidator"
      via: "FunctionsToExport list matches actual runtime exports"
      pattern: "FunctionsToExport"
    - from: ".planning/phases/01-module-restructuring/audit-baseline.json"
      to: "Get-Command -Module MDEValidator"
      via: "parameter comparison — pre vs post restructuring"
---

<objective>
Verify that the restructured module is functionally identical to the monolithic version: all 45 functions export correctly, parameter sets match the pre-restructuring baseline, private helpers are not exported, and existing Pester tests pass.

Purpose: Gate check that restructuring preserved the public API contract with zero regressions.
Output: Verification results and green Pester test suite.
</objective>

<execution_context>
@./.claude/get-shit-done/workflows/execute-plan.md
@./.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/STATE.md
@.planning/phases/01-module-restructuring/01-RESEARCH.md
@.planning/phases/01-module-restructuring/01-02-SUMMARY.md
@.planning/phases/01-module-restructuring/audit-baseline.json
@MDEValidator/MDEValidator.psm1
@MDEValidator/MDEValidator.psd1
@Tests/MDEValidator.Tests.ps1
</context>

<tasks>

<task type="auto">
  <name>Task 1: Verify exports, parameters, and private helper exclusion</name>
  <files></files>
  <action>
Run a comprehensive verification script that compares the restructured module against the Plan 01 baseline:

1. **Load baseline:** Read `.planning/phases/01-module-restructuring/audit-baseline.json`.

2. **Import restructured module:**
```powershell
Remove-Module MDEValidator -ErrorAction SilentlyContinue
Import-Module ./MDEValidator/MDEValidator.psm1 -Force
```

3. **Verify export count:** `(Get-Command -Module MDEValidator).Count` must equal 45.

4. **Verify every function name:** Compare the set of `(Get-Command -Module MDEValidator).Name` against the baseline's `exportedFunctions[].name`. Every name must match — no missing, no extra.

5. **Verify parameter sets:** For each exported function, compare `(Get-Command $name -Module MDEValidator).Parameters.Keys` against the baseline parameters for that function. Flag any differences (missing params, extra params, renamed params). Ignore common parameters added by CmdletBinding (Verbose, Debug, etc.) — compare only the user-defined parameters from the baseline.

6. **Verify private helpers NOT exported:** For each of the 4 private helpers (ConvertTo-HtmlEncodedString, Write-ValidationResult, Test-IsElevated, Test-IsWindowsServer), confirm that `Get-Command -Name $name -Module MDEValidator -ErrorAction SilentlyContinue` returns $null.

7. **Verify .psd1 sync:** Import the module via manifest path (`Import-Module ./MDEValidator/MDEValidator.psd1 -Force -PassThru`). Compare `.ExportedFunctions.Keys` against the baseline function names. They must match.

Print a summary: pass/fail for each check. If any check fails, print details of what's wrong.
  </action>
  <verify>
    <automated>powershell -Command "Remove-Module MDEValidator -ErrorAction SilentlyContinue; Import-Module ./MDEValidator/MDEValidator.psm1 -Force; $count = (Get-Command -Module MDEValidator).Count; $privLeaked = @('ConvertTo-HtmlEncodedString','Write-ValidationResult','Test-IsElevated','Test-IsWindowsServer') | Where-Object { Get-Command -Name $_ -Module MDEValidator -ErrorAction SilentlyContinue }; Write-Host \"Exports: $count (expected 45), Private leaks: $($privLeaked.Count)\"; if ($count -ne 45) { throw \"Export count mismatch: $count\" }; if ($privLeaked.Count -gt 0) { throw \"Private helpers exported: $($privLeaked -join ', ')\" }"</automated>
  </verify>
  <done>45 exported functions match baseline names and parameters, 4 private helpers confirmed not exported, .psd1 FunctionsToExport matches actual exports</done>
</task>

<task type="auto">
  <name>Task 2: Run existing Pester test suite and apply minimal fixes if needed</name>
  <files>Tests/MDEValidator.Tests.ps1</files>
  <action>
Run the existing Pester test suite:

```powershell
Invoke-Pester -Path ./Tests/MDEValidator.Tests.ps1 -Output Detailed
```

**Expected outcome:** All tests pass. The test file imports via `Join-Path $PSScriptRoot '..' 'MDEValidator' 'MDEValidator.psm1'` which still works because the .psm1 is in the same location (now a dot-source loader instead of monolith).

**If tests fail due to restructuring:**
- Diagnose the failure. Root causes would be: import path change (unlikely — path unchanged), missing function export, or function behavior change (shouldn't happen — pure extraction).
- Apply MINIMAL fixes only. Per user decision: "Minimal test fixes in Phase 1 only if restructuring breaks them; full test work in Phase 2."
- Do NOT add new tests, refactor existing tests, or add mock infrastructure. That's Phase 2 scope.

**If tests fail due to Defender not being installed or requiring admin:**
- These are pre-existing failures unrelated to restructuring. Document them but do NOT fix — Phase 2 handles mock-based testing.
- The key verification is that the "Module Import" context tests all pass (these check export availability, not live Defender state).

Record which tests passed and which failed (with reasons) for the summary.
  </action>
  <verify>
    <automated>powershell -Command "Remove-Module MDEValidator -ErrorAction SilentlyContinue; $result = Invoke-Pester -Path ./Tests/MDEValidator.Tests.ps1 -Output Detailed -PassThru; Write-Host \"Passed: $($result.PassedCount) Failed: $($result.FailedCount)\"; if ($result.FailedCount -gt 0) { $result.Failed | ForEach-Object { Write-Host \"FAIL: $($_.Name)\" } }"</automated>
  </verify>
  <done>Pester test suite runs; Module Import context tests pass; any failures are documented as pre-existing (Defender/admin dependent) and not caused by restructuring</done>
</task>

</tasks>

<verification>
- `(Get-Command -Module MDEValidator).Count` = 45
- All 45 function names match pre-restructuring baseline
- Parameter sets match baseline for every function
- Private helpers (4) not exported
- .psd1 FunctionsToExport matches actual `Get-Command` output
- Pester "Module Import" context tests all pass
</verification>

<success_criteria>
- Zero regressions: all function names, parameters, and output shapes preserved
- Private helpers correctly isolated (not exported)
- Export lists (.psd1 and Export-ModuleMember) synchronized
- Existing test suite confirms module loads and exports are intact
</success_criteria>

<output>
After completion, create `.planning/phases/01-module-restructuring/01-03-SUMMARY.md`
</output>
