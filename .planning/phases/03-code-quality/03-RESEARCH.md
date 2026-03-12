# Phase 3 Research: Code Quality

**Phase:** 3 — Code Quality
**Goal:** Module passes static analysis and has complete, publish-ready manifest metadata
**Requirements:** QUAL-01, QUAL-02, QUAL-03
**Researched:** 2026-03-10
**Researcher:** Direct investigation (PSScriptAnalyzer run + manifest audit)

---

## Summary

Phase 3 is straightforward and executable in 2 plans. The actual PSScriptAnalyzer violations are known (30 total across 11 files) and fall into 5 rule categories with clear fix strategies. The manifest is 80% complete — LicenseUri and ProjectUri are present but empty. No architectural surprises. Total scope: fix 30 violations, populate 2 manifest URIs, commit a PSScriptAnalyzerSettings.psd1.

**Confidence: HIGH** — violations discovered by running `Invoke-ScriptAnalyzer` against the actual module.

---

## Standard Stack

| Tool | Usage | Version |
|------|-------|---------|
| `PSScriptAnalyzer` | Static analysis | 1.24.0 installed |
| `Invoke-ScriptAnalyzer` | Run analysis | Built into PSScriptAnalyzer |
| `Test-ModuleManifest` | Validate .psd1 | Built into PowerShell 5.1+ |

**No additional installs needed.** PSScriptAnalyzer 1.24.0 is already installed.

---

## Architecture Patterns

### Pattern 1: PSScriptAnalyzerSettings.psd1

Commit one settings file at repo root. Use `ExcludeRules` for rules that are intentionally violated for valid reasons specific to this module. Keep `Severity` inclusive so all levels are checked.

```powershell
# .PSScriptAnalyzerSettings.psd1 at repo root
@{
    Severity = @('Error', 'Warning', 'Information')
    ExcludeRules = @(
        'PSAvoidUsingWriteHost',   # Intentional: console report uses host colors
        'PSUseSingularNouns'       # Intentional: function names are public API, cannot rename
    )
}
```

Invoke with settings file:
```powershell
Invoke-ScriptAnalyzer -Path .\MDEValidator -Recurse -Settings .\.PSScriptAnalyzerSettings.psd1
```

### Pattern 2: Empty Catch Block Fix

PSSA accepts a comment-only catch block. Zero code change needed — just add a comment explaining the intent:

```powershell
# Before (violation):
catch { }

# After (PSSA compliant):
catch {
    # Intentionally suppressed: registry key absence is a valid non-error state
}
```

### Pattern 3: Unused Variable Fix

For `PSUseDeclaredVarsMoreThanAssignments` — remove the variable or use `$null =` if the assignment has side-effects to discard, or rename to `$_` if inside a loop/pipeline.

### Pattern 4: Unused Parameter Fix

For `PSReviewUnusedParameter` — either remove the parameter if truly unused, or add inline suppression attribute if it must be kept for future compatibility:

```powershell
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSReviewUnusedParameter', 'ParameterName',
    Justification = 'Reserved for future use')]
```

### Pattern 5: Manifest PSData Block

The PSData block lives in PrivateData.PSData. Empty strings for URIs (`LicenseUri = ''`) will pass `Test-ModuleManifest` locally but **PSGallery rejects empty URI strings** — the field must either be absent or contain a valid URI.

```powershell
PrivateData = @{
    PSData = @{
        Tags         = @('MDE', 'Defender', 'Security', 'Endpoint', 'Validation', 'Windows', 'Microsoft')
        LicenseUri   = 'https://github.com/YOUR_ORG/MDEValidator/blob/main/LICENSE'
        ProjectUri   = 'https://github.com/YOUR_ORG/MDEValidator'
        ReleaseNotes = 'Initial release. Validates MDE configuration across 45 security checks.'
    }
}
```

---

## Phase-Specific Findings

### Actual Violations Found (Run: 2026-03-10)

**Total violations: 30** (Errors: 0, Warnings: 30)

| Rule | Count | Files | Fix Strategy |
|------|-------|-------|--------------|
| `PSAvoidUsingWriteHost` | 18 | Get-MDEValidationReport.ps1 | Exclude in settings (intentional console coloring) |
| `PSUseSingularNouns` | 7 | Test-MDEDeviceTags, Test-MDEExclusionVisibilityLocalAdmins, Test-MDEExclusionVisibilityLocalUsers, Test-MDESmartScreenAppRepExclusions, Test-MDESmartScreenDomainExclusions, Test-MDETamperProtectionForExclusions, Test-MDEThreatDefaultActions | Exclude in settings (public API, cannot rename) |
| `PSAvoidUsingEmptyCatchBlock` | 3 | Test-MDEExclusionVisibilityLocalAdmins:71, Test-MDEExclusionVisibilityLocalUsers:73, Test-MDEPassiveMode:51 | Add comment to catch block |
| `PSReviewUnusedParameter` | 1 | Test-MDEPolicyRegistryValue.ps1:47 | Per-function SuppressMessage or remove parameter |
| `PSUseDeclaredVarsMoreThanAssignments` | 1 | Test-MDEPassiveMode.ps1:70 | Remove unused variable |

### PSAvoidUsingWriteHost — Why Exclude (Not Fix)

`Get-MDEValidationReport.ps1` uses `Write-Host` for intentional color-coded console output (Pass=Green, Fail=Red, Warning=Yellow). The function has an `-OutputFormat 'Console'` branch that is the entire purpose of that execution path. Converting to `Write-Information` would break the colored output behavior.

**Decision: Exclude `PSAvoidUsingWriteHost` globally in settings file.**

Alternative (if global exclusion is undesirable): Add `[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]` on the function.

### PSUseSingularNouns — Why Exclude (Not Fix)

7 function names contain plural nouns in their domain concept (Exclusions, Tags, Actions). These are established public API names locked in Phase 1. Renaming breaks the contract.

**Decision: Exclude `PSUseSingularNouns` globally in settings file.**

### Current Manifest State

| Field | Status | Current Value |
|-------|--------|---------------|
| `ModuleVersion` | ✅ Set | `'1.0.0'` |
| `GUID` | ✅ Set | `'e8f9c7d6-...'` |
| `Author` | ✅ Set | `'MDEValidator Team'` |
| `Description` | ✅ Set | Full description present |
| `PowerShellVersion` | ✅ Set | `'5.1'` |
| `Tags` | ✅ Set | `@('Security','Defender','MDE','Endpoint','Validation','Windows')` |
| `LicenseUri` | ⚠️ Empty string | `''` — must be real URL or omitted |
| `ProjectUri` | ⚠️ Empty string | `''` — must be real URL or omitted |
| `ReleaseNotes` | ✅ Set | Present with text |
| `FunctionsToExport` | ✅ Set | 45 functions listed |

**Action needed:** Replace empty strings with actual GitHub URLs, or remove the fields entirely (PSGallery will accept absent fields but not empty-string URIs).

---

## Don't Hand-Roll

- **PSScriptAnalyzer rule list** — Do not manually enumerate all 200+ rules to include. Use `ExcludeRules` for exceptions; all others run by default.
- **Manifest validation** — Use `Test-ModuleManifest` to validate `MDEValidator.psd1` before declaring done. Do not visually inspect.
- **Violation discovery** — Do not guess violations. Use `Invoke-ScriptAnalyzer -Recurse` output. The actual violations are already known (table above).
- **PSGallery URI validation** — Do not guess URI format. PSGallery validates that URIs are reachable; use real GitHub URLs once repo is public.

---

## Common Pitfalls

1. **Empty-string URIs break PSGallery publish** — `LicenseUri = ''` passes `Test-ModuleManifest` locally but PSGallery rejects it. Either set a real URL or remove the key.

2. **PSScriptAnalyzerSettings.psd1 not found at invocation time** — The `-Settings` parameter requires a file path, not a directory. Use `-Settings .\.PSScriptAnalyzerSettings.psd1` explicitly.

3. **Empty catch block with whitespace only** — PSSA requires an actual comment, not just whitespace. `catch {   }` (whitespace) still triggers the violation. Must add a `# comment`.

4. **Test-ModuleManifest warnings on empty PSData fields** — `Test-ModuleManifest` warns but does not fail on empty LicenseUri. Do not use this as "green" — PSGallery is stricter.

5. **PSUseSingularNouns fires on function name in the file, line 1** — The violation is on the `function` declaration keyword, not on a usage. Fixing requires renaming the function (not possible here).

6. **Invoke-ScriptAnalyzer recurse includes Tests/ directory** — Run PSSA against `.\MDEValidator` (module only), not the repo root, to avoid flagging test helper patterns.

7. **`PSReviewUnusedParameter` is a Warning (not Error)** — Some teams suppress this. For this module, fix it properly since we target zero warnings.

---

## Code Examples

### Run PSSA With Settings File
```powershell
Invoke-ScriptAnalyzer `
    -Path .\MDEValidator `
    -Recurse `
    -Settings .\.PSScriptAnalyzerSettings.psd1 `
    -Severity @('Error', 'Warning') |
    Format-Table ScriptName, Line, RuleName, Message -AutoSize
```

### Verify Zero Violations (CI-style check)
```powershell
$violations = Invoke-ScriptAnalyzer `
    -Path .\MDEValidator `
    -Recurse `
    -Settings .\.PSScriptAnalyzerSettings.psd1 `
    -Severity @('Error', 'Warning')

if ($violations) {
    $violations | Format-Table ScriptName, Line, RuleName, Message -AutoSize
    throw "PSScriptAnalyzer found $($violations.Count) violation(s)"
}
Write-Host "PSScriptAnalyzer: PASS (0 violations)" -ForegroundColor Green
```

### Fix Empty Catch Block
```powershell
# In Test-MDEExclusionVisibilityLocalAdmins.ps1, Test-MDEExclusionVisibilityLocalUsers.ps1, Test-MDEPassiveMode.ps1
catch {
    # Registry key absence is handled by the outer condition; no action needed here
}
```

### Validate Manifest
```powershell
Test-ModuleManifest -Path .\MDEValidator\MDEValidator.psd1 | Select-Object Name, Version, Author, Description
```

### PSScriptAnalyzerSettings.psd1 (Complete File)
```powershell
@{
    Severity    = @('Error', 'Warning', 'Information')
    ExcludeRules = @(
        # Intentional: Get-MDEValidationReport uses Write-Host for color-coded console output
        'PSAvoidUsingWriteHost',
        # Intentional: Function names are established public API (Test-MDEDeviceTags etc.) - cannot rename
        'PSUseSingularNouns'
    )
}
```

---

## Recommended Plan Structure

Phase 3 fits cleanly into 2 plans:

**Plan 03-01: PSSA Settings + Violation Fixes**
1. Create `.PSScriptAnalyzerSettings.psd1` with ExcludeRules for `PSAvoidUsingWriteHost` and `PSUseSingularNouns`
2. Fix `PSAvoidUsingEmptyCatchBlock` in 3 files (add comments to catch blocks)
3. Fix `PSUseDeclaredVarsMoreThanAssignments` in Test-MDEPassiveMode.ps1:70 (remove unused var)
4. Fix `PSReviewUnusedParameter` in Test-MDEPolicyRegistryValue.ps1:47 (suppress or remove)
5. Verify: `Invoke-ScriptAnalyzer` with settings returns 0 violations

**Plan 03-02: Manifest Metadata**
1. Set `LicenseUri` to GitHub LICENSE URL (or remove empty string)
2. Set `ProjectUri` to GitHub repo URL (or remove empty string)
3. Verify: `Test-ModuleManifest` passes cleanly
4. Verify: All QUAL-01, QUAL-02, QUAL-03 criteria met

---

## Open Questions

1. **GitHub repo URL** — LicenseUri/ProjectUri need the actual GitHub org/username. Either: (a) use a placeholder and note it must be updated before PSGallery publish, or (b) use `https://github.com/MDEValidator/MDEValidator` as a convention placeholder.

2. **PSReviewUnusedParameter in Test-MDEPolicyRegistryValue.ps1:47** — Need to inspect whether the parameter is intentionally kept for future use (use SuppressMessage) or is a genuine dead code issue (remove parameter). Check impacted test files before removing.

3. **InformationAction scope for Write-Host** — Considered but rejected: converting Write-Host to Write-Information in Get-MDEValidationReport would require callers to use `-InformationAction Continue` to see output, which is worse UX than current behavior. Exclusion is correct.

---

## Confidence

| Domain | Confidence | Basis |
|--------|-----------|-------|
| Actual violations | HIGH | Ran `Invoke-ScriptAnalyzer` against the module directly |
| Fix strategies | HIGH | PSScriptAnalyzer 1.24.0 behavior is well-established |
| Settings file format | HIGH | Standard psd1 hashtable format, no magic |
| Manifest PSData format | HIGH | PowerShell 5.1 manifest format, stable |
| PSGallery URI validation | MEDIUM | PSGallery rejects empty strings; exact validation behavior verified by community reports |
| PSReviewUnusedParameter fix | MEDIUM | Need to inspect the specific parameter before deciding suppress vs remove |

---

*Research completed: 2026-03-10*
*Method: Direct `Invoke-ScriptAnalyzer` run + manifest file audit*
*PSScriptAnalyzer version: 1.24.0*
