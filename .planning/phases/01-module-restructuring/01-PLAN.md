---
phase: 01-module-restructuring
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - .planning/phases/01-module-restructuring/audit-baseline.json
autonomous: true
requirements: [STRUCT-03, STRUCT-04, STRUCT-05]

must_haves:
  truths:
    - "49 functions confirmed in monolithic .psm1 (45 public + 4 private)"
    - "Zero module-scope state ($script: variables, init code outside functions)"
    - ".psd1 FunctionsToExport and Export-ModuleMember lists are identical (45 entries)"
    - "Baseline snapshot of all exported function names and parameters exists for post-restructuring comparison"
  artifacts:
    - path: ".planning/phases/01-module-restructuring/audit-baseline.json"
      provides: "Baseline snapshot of function names, parameters, and classifications for Plan 03 comparison"
  key_links:
    - from: "MDEValidator/MDEValidator.psd1"
      to: "MDEValidator/MDEValidator.psm1"
      via: "FunctionsToExport matches Export-ModuleMember"
      pattern: "FunctionsToExport"
---

<objective>
Audit the monolithic MDEValidator.psm1 to confirm the function inventory, public/private classification, and absence of module-scope state. Produce a baseline snapshot of exported function names and parameter sets for post-restructuring verification in Plan 03.

Purpose: Confirm research findings programmatically before extraction begins, and capture parameter baselines for regression detection.
Output: audit-baseline.json with function names, parameter sets, and classifications.
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
@MDEValidator/MDEValidator.psm1
@MDEValidator/MDEValidator.psd1
</context>

<tasks>

<task type="auto">
  <name>Task 1: Verify function inventory and module-scope state</name>
  <files>.planning/phases/01-module-restructuring/audit-baseline.json</files>
  <action>
Run PowerShell commands against MDEValidator/MDEValidator.psm1 to programmatically confirm:

1. Extract all function declarations: `Select-String -Path MDEValidator/MDEValidator.psm1 -Pattern '^\s*function\s+(\S+)' | ForEach-Object { $_.Matches.Groups[1].Value }`. Confirm exactly 49 unique function names.

2. Confirm the 4 private helpers (NOT in Export-ModuleMember): ConvertTo-HtmlEncodedString, Write-ValidationResult, Test-IsElevated, Test-IsWindowsServer.

3. Confirm zero module-scope state: `Select-String -Path MDEValidator/MDEValidator.psm1 -Pattern '\$script:'` should return zero matches.

4. Import the module and capture baseline: For each of the 45 exported functions, capture function name and parameter names via `(Get-Command -Name $fn -Module MDEValidator).Parameters.Keys`. Save as JSON to `.planning/phases/01-module-restructuring/audit-baseline.json` with structure:
```json
{
  "exportedFunctions": [
    { "name": "Test-MDEConfiguration", "parameters": ["OutputFormat", "IncludeOnboarding", ...] }
  ],
  "privateFunctions": ["ConvertTo-HtmlEncodedString", "Write-ValidationResult", "Test-IsElevated", "Test-IsWindowsServer"],
  "totalPublic": 45,
  "totalPrivate": 4
}
```
  </action>
  <verify>
    <automated>powershell -Command "Test-Path '.planning/phases/01-module-restructuring/audit-baseline.json' ; $json = Get-Content '.planning/phases/01-module-restructuring/audit-baseline.json' | ConvertFrom-Json; Write-Host \"Public: $($json.totalPublic) Private: $($json.totalPrivate)\"; if ($json.totalPublic -ne 45 -or $json.totalPrivate -ne 4) { throw 'Count mismatch' }"</automated>
  </verify>
  <done>audit-baseline.json exists with 45 public and 4 private functions, each public function has its parameter list captured</done>
</task>

<task type="auto">
  <name>Task 2: Cross-reference .psd1 and Export-ModuleMember lists</name>
  <files>.planning/phases/01-module-restructuring/audit-baseline.json</files>
  <action>
Run PowerShell to compare the two export sources:

1. Parse .psd1 FunctionsToExport: Read MDEValidator/MDEValidator.psd1, extract the FunctionsToExport array entries.

2. Parse Export-ModuleMember from .psm1: `Select-String -Path MDEValidator/MDEValidator.psm1 -Pattern "Export-ModuleMember" -Context 0,50` and extract the function list.

3. Compare: Both lists must contain exactly the same 45 function names (order-independent). Report any discrepancies.

4. Update audit-baseline.json to add a `"exportListsMatch": true` field confirming synchronization.

If any discrepancy is found, log it in the baseline file as `"exportListsMatch": false` with a `"discrepancies"` array. This would be a blocker for Plan 02.
  </action>
  <verify>
    <automated>powershell -Command "$json = Get-Content '.planning/phases/01-module-restructuring/audit-baseline.json' | ConvertFrom-Json; if (-not $json.exportListsMatch) { throw 'Export lists do not match' }; Write-Host 'Export lists synchronized: OK'"</automated>
  </verify>
  <done>.psd1 FunctionsToExport and .psm1 Export-ModuleMember contain identical 45-function sets, confirmed in audit-baseline.json</done>
</task>

</tasks>

<verification>
- audit-baseline.json exists and is valid JSON
- totalPublic = 45, totalPrivate = 4
- exportListsMatch = true
- Every exported function has a non-empty parameter list captured
</verification>

<success_criteria>
- Function inventory confirmed: 45 public + 4 private = 49 total
- Zero $script: variables found
- .psd1 and Export-ModuleMember lists identical
- Baseline snapshot ready for Plan 03 comparison
</success_criteria>

<output>
After completion, create `.planning/phases/01-module-restructuring/01-01-SUMMARY.md`
</output>
