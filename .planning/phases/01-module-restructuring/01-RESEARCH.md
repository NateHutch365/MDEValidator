# Phase 1: Module Restructuring - Research

**Researched:** 2026-03-04
**Domain:** PowerShell module architecture — function-per-file layout with dot-source loader
**Confidence:** HIGH

## Summary

The monolithic `MDEValidator.psm1` (4,426 lines) contains **49 functions total**: 45 exported (public) and 4 private helpers. The module has **zero module-scope state** — no `$script:` variables, no initialization code outside functions, and no code between function definitions aside from `#region`/`#endregion` markers and the final `Export-ModuleMember` block. This makes it an ideal candidate for mechanical extraction to function-per-file layout with no state-management complications.

The existing `Export-ModuleMember` list and `.psd1` `FunctionsToExport` are already **perfectly synchronized** at 45 functions. Dependencies flow in one direction (validation functions → helpers → PowerShell runtime), with no circular calls. The dot-source loader pattern is a well-established PowerShell convention that will work cleanly here.

**Primary recommendation:** Extract each function to its own `.ps1` file (named after the function), place public functions in `Public/` and private helpers in `Private/`, replace `.psm1` content with a dot-source loader, and keep the `.psd1` `FunctionsToExport` list unchanged.

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| STRUCT-01 | Module uses function-per-file layout with Public/ and Private/ folders | Complete function inventory (49 functions), public/private classification confirmed, no obstacles |
| STRUCT-02 | Root .psm1 uses dot-source loader to import all function files | Dot-source loader pattern documented below; no module-scope state means simple `Get-ChildItem | . $_` pattern works |
| STRUCT-03 | All 45 existing exported functions preserve names, parameters, and output shapes | Full function list verified; no parameter or output changes needed — pure file extraction |
| STRUCT-04 | Private helper functions in Private/ folder and not exported | 4 private helpers identified: ConvertTo-HtmlEncodedString, Write-ValidationResult, Test-IsElevated, Test-IsWindowsServer |
| STRUCT-05 | Export-ModuleMember and .psd1 FunctionsToExport remain synchronized | Both already list identical 45 functions; loader pattern preserves this |
</phase_requirements>

## Complete Function Inventory

### Public Functions (45 — exported via Export-ModuleMember + FunctionsToExport)

Located in `#region Helper Functions` (lines 15-773) but ARE exported:

| # | Function | Line | Called By |
|---|----------|------|-----------|
| 1 | Get-MDEManagedDefenderProductType | 144 | Get-MDESecuritySettingsManagementStatus, Test-MDETamperProtectionForExclusions, Test-MDEDisableLocalAdminMerge |
| 2 | Get-MDEManagementType | 260 | Test-MDEPolicyRegistryValue, Test-MDEPolicyRegistryVerification, Test-MDEDisableLocalAdminMerge |
| 3 | Get-MDEPolicyRegistryPath | 354 | Test-MDEPolicyRegistryValue |
| 4 | Get-MDEPolicySettingConfig | 391 | Test-MDEPolicyRegistryValue, Test-MDEPolicyRegistryVerification, Test-MDEDisableLocalAdminMerge |
| 5 | Test-MDEPolicyRegistryValue | 558 | Test-MDEPolicyRegistryVerification |
| 6 | Test-MDEPolicyRegistryVerification | 660 | Test-MDEConfiguration |

Located in `#region Public Functions` (lines 775-4378):

| # | Function | Line | Called By |
|---|----------|------|-----------|
| 7 | Get-MDEOperatingSystemInfo | 777 | Get-MDEValidationReport |
| 8 | Get-MDESecuritySettingsManagementStatus | 844 | Get-MDEValidationReport |
| 9 | Get-MDEOnboardingStatusString | 930 | Get-MDEValidationReport |
| 10 | Get-MDEManagementTypeFallback | 984 | Get-MDESecuritySettingsManagementStatus |
| 11 | Test-MDEPassiveMode | 1097 | Test-MDEConfiguration |
| 12 | Test-MDEServiceStatus | 1212 | Test-MDEConfiguration |
| 13 | Test-MDERealTimeProtection | 1260 | Test-MDEConfiguration |
| 14 | Test-MDECloudProtection | 1300 | Test-MDEConfiguration |
| 15 | Test-MDESampleSubmission | 1346 | Test-MDEConfiguration |
| 16 | Test-MDEBehaviorMonitoring | 1395 | Test-MDEConfiguration |
| 17 | Test-MDEOnboardingStatus | 1435 | Test-MDEConfiguration |
| 18 | Test-MDEDeviceTags | 1501 | Test-MDEConfiguration |
| 19 | Test-MDENetworkProtection | 1561 | Test-MDEConfiguration |
| 20 | Test-MDENetworkProtectionWindowsServer | 1615 | Test-MDEConfiguration |
| 21 | Test-MDEDatagramProcessingWindowsServer | 1703 | Test-MDEConfiguration |
| 22 | Test-MDEAutoExclusionsWindowsServer | 1773 | Test-MDEConfiguration |
| 23 | Test-MDEAttackSurfaceReduction | 1838 | Test-MDEConfiguration |
| 24 | Test-MDEThreatDefaultActions | 1975 | Test-MDEConfiguration |
| 25 | Test-MDETroubleshootingMode | 2111 | Test-MDEConfiguration |
| 26 | Test-MDEExclusionVisibilityLocalAdmins | 2186 | Test-MDEConfiguration |
| 27 | Test-MDEExclusionVisibilityLocalUsers | 2306 | Test-MDEConfiguration |
| 28 | Test-MDESmartScreen | 2407 | Test-MDEConfiguration |
| 29 | Test-MDESmartScreenPUA | 2509 | Test-MDEConfiguration |
| 30 | Test-MDESmartScreenPromptOverride | 2584 | Test-MDEConfiguration |
| 31 | Test-MDESmartScreenDownloadOverride | 2659 | Test-MDEConfiguration |
| 32 | Test-MDESmartScreenDomainExclusions | 2734 | Test-MDEConfiguration |
| 33 | Test-MDESmartScreenAppRepExclusions | 2813 | Test-MDEConfiguration |
| 34 | Test-MDECloudBlockLevel | 2937 | Test-MDEConfiguration |
| 35 | Test-MDETamperProtection | 3038 | Test-MDEConfiguration |
| 36 | Test-MDETamperProtectionForExclusions | 3098 | Test-MDEConfiguration |
| 37 | Test-MDECloudExtendedTimeout | 3265 | Test-MDEConfiguration |
| 38 | Test-MDEDisableCatchupQuickScan | 3337 | Test-MDEConfiguration |
| 39 | Test-MDERealTimeScanDirection | 3388 | Test-MDEConfiguration |
| 40 | Test-MDESignatureUpdateFallbackOrder | 3479 | Test-MDEConfiguration |
| 41 | Test-MDESignatureUpdateInterval | 3540 | Test-MDEConfiguration |
| 42 | Test-MDEDisableLocalAdminMerge | 3611 | Test-MDEConfiguration |
| 43 | Test-MDEFileHashComputation | 3735 | Test-MDEConfiguration |
| 44 | Test-MDEConfiguration | 3801 | Get-MDEValidationReport |
| 45 | Get-MDEValidationReport | 3989 | (end-user entry point) |

### Private Functions (4 — NOT exported)

| # | Function | Line | Used By |
|---|----------|------|---------|
| 1 | ConvertTo-HtmlEncodedString | 17 | Get-MDEValidationReport (HTML rendering, 9 call sites) |
| 2 | Write-ValidationResult | 36 | Nearly every Test-MDE* function + Test-MDEPolicyRegistryVerification (80+ call sites) |
| 3 | Test-IsElevated | 66 | Test-MDEConfiguration (line 3858) |
| 4 | Test-IsWindowsServer | 100 | Test-MDENetworkProtectionWindowsServer, Test-MDEDatagramProcessingWindowsServer, Test-MDEAutoExclusionsWindowsServer |

## Module-Scope State Analysis

**Finding: NONE.** Confidence: HIGH.

- **No `$script:` variables** — grep confirmed zero matches
- **No module-level variables** — no assignments outside functions
- **No initialization code outside functions** — only `#Requires -Version 5.1`, module comment-based help, `#region`/`#endregion` markers, and `Export-ModuleMember` at end
- **No static state shared between functions** — all state is passed via parameters or computed within each function

This means the dot-source loader pattern can be applied with zero state-management considerations.

## Function Dependency Map

```
Get-MDEValidationReport
├── Test-MDEConfiguration
│   ├── [Private] Test-IsElevated
│   ├── Test-MDEServiceStatus → [Private] Write-ValidationResult
│   ├── Test-MDEPassiveMode → [Private] Write-ValidationResult
│   ├── Test-MDERealTimeProtection → [Private] Write-ValidationResult
│   ├── Test-MDECloudProtection → [Private] Write-ValidationResult
│   ├── Test-MDECloudBlockLevel → [Private] Write-ValidationResult
│   ├── Test-MDECloudExtendedTimeout → [Private] Write-ValidationResult
│   ├── Test-MDESampleSubmission → [Private] Write-ValidationResult
│   ├── Test-MDEBehaviorMonitoring → [Private] Write-ValidationResult
│   ├── Test-MDEOnboardingStatus → [Private] Write-ValidationResult
│   ├── Test-MDEDeviceTags → [Private] Write-ValidationResult
│   ├── Test-MDENetworkProtection → [Private] Write-ValidationResult
│   ├── Test-MDENetworkProtectionWindowsServer
│   │   ├── [Private] Test-IsWindowsServer
│   │   └── [Private] Write-ValidationResult
│   ├── Test-MDEDatagramProcessingWindowsServer
│   │   ├── [Private] Test-IsWindowsServer
│   │   └── [Private] Write-ValidationResult
│   ├── Test-MDEAutoExclusionsWindowsServer
│   │   ├── [Private] Test-IsWindowsServer
│   │   └── [Private] Write-ValidationResult
│   ├── Test-MDEAttackSurfaceReduction → [Private] Write-ValidationResult
│   ├── Test-MDEThreatDefaultActions → [Private] Write-ValidationResult
│   ├── Test-MDETroubleshootingMode → [Private] Write-ValidationResult
│   ├── Test-MDETamperProtection → [Private] Write-ValidationResult
│   ├── Test-MDETamperProtectionForExclusions
│   │   ├── Get-MDEManagedDefenderProductType
│   │   └── [Private] Write-ValidationResult
│   ├── Test-MDEExclusionVisibilityLocalAdmins → [Private] Write-ValidationResult
│   ├── Test-MDEExclusionVisibilityLocalUsers → [Private] Write-ValidationResult
│   ├── Test-MDESmartScreen → [Private] Write-ValidationResult
│   ├── Test-MDESmartScreenPUA → [Private] Write-ValidationResult
│   ├── Test-MDESmartScreenPromptOverride → [Private] Write-ValidationResult
│   ├── Test-MDESmartScreenDownloadOverride → [Private] Write-ValidationResult
│   ├── Test-MDESmartScreenDomainExclusions → [Private] Write-ValidationResult
│   ├── Test-MDESmartScreenAppRepExclusions → [Private] Write-ValidationResult
│   ├── Test-MDEDisableCatchupQuickScan → [Private] Write-ValidationResult
│   ├── Test-MDERealTimeScanDirection → [Private] Write-ValidationResult
│   ├── Test-MDESignatureUpdateFallbackOrder → [Private] Write-ValidationResult
│   ├── Test-MDESignatureUpdateInterval → [Private] Write-ValidationResult
│   ├── Test-MDEDisableLocalAdminMerge
│   │   ├── Get-MDEManagementType
│   │   ├── Get-MDEPolicySettingConfig
│   │   ├── Get-MDEManagedDefenderProductType
│   │   └── [Private] Write-ValidationResult
│   ├── Test-MDEFileHashComputation → [Private] Write-ValidationResult
│   └── Test-MDEPolicyRegistryVerification (when -IncludePolicyVerification)
│       ├── Get-MDEManagementType
│       ├── Get-MDEPolicySettingConfig
│       ├── Test-MDEPolicyRegistryValue
│       │   ├── Get-MDEManagementType
│       │   ├── Get-MDEPolicyRegistryPath
│       │   └── Get-MDEPolicySettingConfig
│       └── [Private] Write-ValidationResult
├── Get-MDEOperatingSystemInfo
├── Get-MDESecuritySettingsManagementStatus
│   ├── Get-MDEManagedDefenderProductType
│   └── Get-MDEManagementTypeFallback
├── Get-MDEOnboardingStatusString
└── [Private] ConvertTo-HtmlEncodedString (HTML rendering)
```

**Key insight:** Dependencies flow strictly downward. No circular dependencies exist. Private helpers are leaf nodes called by many public functions but calling nothing else in the module.

## Architecture Patterns

### Recommended Project Structure (Post-Restructuring)

```
MDEValidator/
├── MDEValidator.psd1          # Module manifest (unchanged except RootModule stays same)
├── MDEValidator.psm1          # Dot-source loader (replaces monolithic content)
├── Public/                    # 45 exported functions, one per file
│   ├── Get-MDEManagementType.ps1
│   ├── Get-MDEManagedDefenderProductType.ps1
│   ├── Get-MDEManagementTypeFallback.ps1
│   ├── Get-MDEOnboardingStatusString.ps1
│   ├── Get-MDEOperatingSystemInfo.ps1
│   ├── Get-MDEPolicyRegistryPath.ps1
│   ├── Get-MDEPolicySettingConfig.ps1
│   ├── Get-MDESecuritySettingsManagementStatus.ps1
│   ├── Get-MDEValidationReport.ps1
│   ├── Test-MDEAttackSurfaceReduction.ps1
│   ├── Test-MDEAutoExclusionsWindowsServer.ps1
│   ├── Test-MDEBehaviorMonitoring.ps1
│   ├── Test-MDECloudBlockLevel.ps1
│   ├── Test-MDECloudExtendedTimeout.ps1
│   ├── Test-MDECloudProtection.ps1
│   ├── Test-MDEConfiguration.ps1
│   ├── Test-MDEDatagramProcessingWindowsServer.ps1
│   ├── Test-MDEDeviceTags.ps1
│   ├── Test-MDEDisableCatchupQuickScan.ps1
│   ├── Test-MDEDisableLocalAdminMerge.ps1
│   ├── Test-MDEExclusionVisibilityLocalAdmins.ps1
│   ├── Test-MDEExclusionVisibilityLocalUsers.ps1
│   ├── Test-MDEFileHashComputation.ps1
│   ├── Test-MDENetworkProtection.ps1
│   ├── Test-MDENetworkProtectionWindowsServer.ps1
│   ├── Test-MDEOnboardingStatus.ps1
│   ├── Test-MDEPassiveMode.ps1
│   ├── Test-MDEPolicyRegistryValue.ps1
│   ├── Test-MDEPolicyRegistryVerification.ps1
│   ├── Test-MDERealTimeProtection.ps1
│   ├── Test-MDERealTimeScanDirection.ps1
│   ├── Test-MDESampleSubmission.ps1
│   ├── Test-MDEServiceStatus.ps1
│   ├── Test-MDESignatureUpdateFallbackOrder.ps1
│   ├── Test-MDESignatureUpdateInterval.ps1
│   ├── Test-MDESmartScreen.ps1
│   ├── Test-MDESmartScreenAppRepExclusions.ps1
│   ├── Test-MDESmartScreenDomainExclusions.ps1
│   ├── Test-MDESmartScreenDownloadOverride.ps1
│   ├── Test-MDESmartScreenPUA.ps1
│   ├── Test-MDESmartScreenPromptOverride.ps1
│   ├── Test-MDETamperProtection.ps1
│   ├── Test-MDETamperProtectionForExclusions.ps1
│   ├── Test-MDEThreatDefaultActions.ps1
│   └── Test-MDETroubleshootingMode.ps1
└── Private/                   # 4 private helpers, one per file
    ├── ConvertTo-HtmlEncodedString.ps1
    ├── Write-ValidationResult.ps1
    ├── Test-IsElevated.ps1
    └── Test-IsWindowsServer.ps1
```

### Pattern: Dot-Source Loader

The new `MDEValidator.psm1` replaces all function definitions with a loader:

```powershell
#Requires -Version 5.1

# Dot-source all private functions
$privateFunctions = @(Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue)
foreach ($file in $privateFunctions) {
    try {
        . $file.FullName
    }
    catch {
        Write-Error "Failed to import private function '$($file.FullName)': $_"
    }
}

# Dot-source all public functions
$publicFunctions = @(Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue)
foreach ($file in $publicFunctions) {
    try {
        . $file.FullName
    }
    catch {
        Write-Error "Failed to import public function '$($file.FullName)': $_"
    }
}

# Export public functions
Export-ModuleMember -Function $publicFunctions.BaseName
```

**Critical: Private functions MUST be loaded before Public functions** because public functions call private helpers (`Write-ValidationResult`, `Test-IsElevated`, `Test-IsWindowsServer`, `ConvertTo-HtmlEncodedString`). The loader handles this by dot-sourcing `Private/` first.

### Anti-Patterns to Avoid

- **Don't use wildcard exports in .psd1:** Keep `FunctionsToExport` as an explicit list — wildcards defeat module auto-discovery and tab-completion.
- **Don't add `#Requires` to individual .ps1 function files:** The `#Requires -Version 5.1` belongs only in the root `.psm1`; adding it to each file creates unnecessary duplication and potential conflicts.
- **Don't create nested folders within Public/Private:** Flat structure is correct for 45+4 files. Subfolders add complexity without benefit.
- **Don't change the .psd1 RootModule:** It should remain `MDEValidator.psm1` — the loader is the new content of that file.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Load ordering | Custom dependency resolver | Private-first, Public-second loading | No circular deps; simple ordering suffices |
| Export list generation | Dynamic export scanning from file names | Explicit `Export-ModuleMember` list from `$publicFunctions.BaseName` | Belt-and-suspenders with .psd1 list |
| Function extraction | Manual copy-paste per function | Scripted extraction or systematic cut from known line ranges | 49 functions is mechanical; errors come from fatigue |

## Common Pitfalls

### Pitfall 1: Load Order — Private Before Public
**What goes wrong:** Public functions fail with "command not found" for `Write-ValidationResult` or other helpers if Public/ is loaded before Private/.
**Why it happens:** Dot-source loader processes folders in wrong order.
**How to avoid:** Always dot-source `Private/*.ps1` before `Public/*.ps1` in the loader.
**Warning signs:** `Import-Module` succeeds but function calls fail at runtime.

### Pitfall 2: Missing Function from Extraction
**What goes wrong:** A function is accidentally left out or its file is named differently from the function it contains.
**Why it happens:** 49 functions is a lot of mechanical work.
**How to avoid:** Verify count after extraction: `(Get-ChildItem Public/*.ps1).Count` should be 45, `(Get-ChildItem Private/*.ps1).Count` should be 4. Verify every exported command exists: `(Get-Command -Module MDEValidator).Count` should be 45.
**Warning signs:** `Import-Module` works but `Get-Command -Module MDEValidator | Measure-Object` returns less than 45.

### Pitfall 3: Comment-Based Help Truncation
**What goes wrong:** When extracting functions, the comment-based help block above the function definition gets left behind in the monolith.
**Why it happens:** Comment-based help (`<# .SYNOPSIS ... #>`) is INSIDE the function body in this codebase (after the `function` keyword, before `param`), so this is actually low-risk. But verify during extraction.
**How to avoid:** Each extracted function file starts with `function FunctionName {` and includes the full function body including comment-based help.
**Warning signs:** `Get-Help Test-MDEServiceStatus` returns no synopsis.

### Pitfall 4: .psd1 FunctionsToExport Desync
**What goes wrong:** Export-ModuleMember in .psm1 exports a different set than FunctionsToExport in .psd1.
**Why it happens:** Updating one list but not the other.
**How to avoid:** Both lists must have the same 45 entries. Verification: compare `(Import-Module ... -PassThru).ExportedFunctions.Keys.Count` with the .psd1 entry count.
**Warning signs:** `Get-Command -Module MDEValidator` returns fewer functions than expected.

### Pitfall 5: Encoding Issues in Extracted Files
**What goes wrong:** Files saved without UTF-8 BOM or with wrong line endings cause PowerShell parsing errors.
**Why it happens:** Different editors/tools use different default encodings.
**How to avoid:** Save all `.ps1` files as UTF-8 (with or without BOM — PowerShell 5.1 handles both). Keep consistent line endings (CRLF on Windows).
**Warning signs:** Unexpected parse errors on `Import-Module`.

## Existing Tests Impact Analysis

The test file `Tests/MDEValidator.Tests.ps1` (≈960 lines) will be **minimally impacted**:

**Import mechanism (BeforeAll block):**
```powershell
$modulePath = Join-Path $PSScriptRoot '..' 'MDEValidator' 'MDEValidator.psm1'
Import-Module $modulePath -Force
```
This imports the `.psm1` directly. Since the restructured `.psm1` is a dot-source loader at the same path, **this will continue to work unchanged**.

**Test structure:**
- Tests check `Get-Command -Name 'FunctionName' -Module 'MDEValidator'` — will continue to work since exports are preserved.
- Tests call functions directly and check return shapes — will continue to work since function signatures are unchanged.
- Tests do NOT mock internal helpers — they call functions live, which is why they need Defender installed to pass fully. Phase 2 addresses this.

**Verdict:** No test changes needed for Phase 1 unless an extraction error breaks import. The existing tests serve as a verification gate.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Pester (version requirement via `#Requires -Modules Pester`) |
| Config file | None — test invocation is direct |
| Quick run command | `Invoke-Pester -Path ./Tests/MDEValidator.Tests.ps1 -Output Detailed` |
| Full suite command | `Invoke-Pester -Path ./Tests/ -Output Detailed` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| STRUCT-01 | Function-per-file layout with Public/ and Private/ folders | smoke | `Test-Path MDEValidator/Public; Test-Path MDEValidator/Private` | ❌ — verify manually or add check |
| STRUCT-02 | .psm1 uses dot-source loader | smoke | `Import-Module ./MDEValidator/MDEValidator.psm1 -Force` | ✅ Existing test covers import |
| STRUCT-03 | 45 exports with same names/params/outputs | unit | `(Get-Command -Module MDEValidator).Count -eq 45` | ✅ Partial — existing tests check ~30 exports individually |
| STRUCT-04 | Private helpers not exported | unit | `Get-Command -Name 'Write-ValidationResult' -Module MDEValidator` should fail | ❌ — no existing negative test |
| STRUCT-05 | Export lists synchronized | unit | Compare .psd1 FunctionsToExport with actual exports | ❌ — no existing sync test |

### Sampling Rate
- **Per task commit:** `Import-Module ./MDEValidator/MDEValidator.psm1 -Force; (Get-Command -Module MDEValidator).Count`
- **Per wave merge:** `Invoke-Pester -Path ./Tests/MDEValidator.Tests.ps1 -Output Detailed`
- **Phase gate:** Full Pester suite green + export count = 45 + private helpers not exported

### Wave 0 Gaps
- None critical — existing test file covers import and export checks sufficiently for Phase 1 verification. Full test infrastructure is Phase 2 scope.

## Code Examples

### Dot-Source Loader (complete replacement for .psm1)

```powershell
#Requires -Version 5.1

# Dot-source all private functions first (helpers used by public functions)
$privateFunctions = @(Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue)
foreach ($file in $privateFunctions) {
    try {
        . $file.FullName
    }
    catch {
        Write-Error "Failed to import private function '$($file.FullName)': $_"
    }
}

# Dot-source all public functions
$publicFunctions = @(Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue)
foreach ($file in $publicFunctions) {
    try {
        . $file.FullName
    }
    catch {
        Write-Error "Failed to import public function '$($file.FullName)': $_"
    }
}

# Export only public functions (belt-and-suspenders with .psd1 FunctionsToExport)
Export-ModuleMember -Function $publicFunctions.BaseName
```

### Individual Function File Format (example: Public/Test-MDEServiceStatus.ps1)

```powershell
function Test-MDEServiceStatus {
    <#
    .SYNOPSIS
        Tests the Windows Defender service status.
    ...existing comment-based help...
    #>
    [CmdletBinding()]
    param()

    ...existing function body...
}
```

Each `.ps1` file contains exactly one function definition — the entire `function Name { ... }` block including comment-based help.

### Verification Script (post-extraction)

```powershell
# Remove any cached module
Remove-Module MDEValidator -ErrorAction SilentlyContinue

# Import fresh
Import-Module ./MDEValidator/MDEValidator.psm1 -Force

# Verify export count
$commands = Get-Command -Module MDEValidator
Write-Host "Exported functions: $($commands.Count) (expected: 45)"

# Verify private helpers are NOT exported
$privateHelpers = @('ConvertTo-HtmlEncodedString', 'Write-ValidationResult', 'Test-IsElevated', 'Test-IsWindowsServer')
foreach ($helper in $privateHelpers) {
    $found = Get-Command -Name $helper -Module MDEValidator -ErrorAction SilentlyContinue
    if ($found) { Write-Warning "FAIL: Private helper '$helper' is exported!" }
    else { Write-Host "OK: '$helper' is not exported" }
}

# Verify file counts
$publicCount = (Get-ChildItem ./MDEValidator/Public/*.ps1).Count
$privateCount = (Get-ChildItem ./MDEValidator/Private/*.ps1).Count
Write-Host "Public files: $publicCount (expected: 45)"
Write-Host "Private files: $privateCount (expected: 4)"
```

## Open Questions

1. **Edge case: `Get-MDEPolicySettingConfig` contains a large hashtable**
   - What we know: The function at line 391 contains a multi-hundred-line hashtable mapping setting keys to registry paths. This is all within the function body.
   - What's unclear: Nothing — it extracts cleanly as a self-contained function.
   - Recommendation: Extract as-is; no special handling needed.

2. **Should the 6 "helper region" functions that ARE exported be treated differently?**
   - What we know: `Get-MDEManagedDefenderProductType`, `Get-MDEManagementType`, `Get-MDEPolicyRegistryPath`, `Get-MDEPolicySettingConfig`, `Test-MDEPolicyRegistryValue`, `Test-MDEPolicyRegistryVerification` are in the `#region Helper Functions` block but are exported.
   - Recommendation: Place them in `Public/` since they are exported. The `#region` label was a documentation choice, not an access-control decision. Export status determines classification.

## Sources

### Primary (HIGH confidence)
- `MDEValidator/MDEValidator.psm1` — direct source code analysis, all 49 functions enumerated
- `MDEValidator/MDEValidator.psd1` — FunctionsToExport list verified (45 entries)
- `Tests/MDEValidator.Tests.ps1` — full test file analyzed for import patterns and coverage
- Grep searches for `$script:`, `Write-ValidationResult`, `ConvertTo-HtmlEncodedString`, `Test-IsElevated`, `Test-IsWindowsServer`, and all cross-function calls

### Secondary (HIGH confidence — well-established pattern)
- PowerShell dot-source loader pattern — standard community convention used in PoshCode, PSFramework, dbatools, and documented in PowerShell best practices

## Metadata

**Confidence breakdown:**
- Function inventory: HIGH — exhaustive grep of all 49 `^function` declarations cross-referenced with Export-ModuleMember
- Module-scope state: HIGH — zero `$script:` matches, no code outside functions
- Dependency map: HIGH — all cross-function calls traced via grep
- Dot-source loader pattern: HIGH — well-established PowerShell community pattern
- Test impact: HIGH — full test file read and analyzed

**Research date:** 2026-03-04
**Valid until:** Indefinite — this is codebase-specific structural analysis, not library version research
