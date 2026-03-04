---
phase: 01-module-restructuring
plan: 02
type: execute
wave: 2
depends_on: ["01-01"]
files_modified:
  - MDEValidator/MDEValidator.psm1
  - MDEValidator/Public/Get-MDEManagedDefenderProductType.ps1
  - MDEValidator/Public/Get-MDEManagementType.ps1
  - MDEValidator/Public/Get-MDEManagementTypeFallback.ps1
  - MDEValidator/Public/Get-MDEOnboardingStatusString.ps1
  - MDEValidator/Public/Get-MDEOperatingSystemInfo.ps1
  - MDEValidator/Public/Get-MDEPolicyRegistryPath.ps1
  - MDEValidator/Public/Get-MDEPolicySettingConfig.ps1
  - MDEValidator/Public/Get-MDESecuritySettingsManagementStatus.ps1
  - MDEValidator/Public/Get-MDEValidationReport.ps1
  - MDEValidator/Public/Test-MDEAttackSurfaceReduction.ps1
  - MDEValidator/Public/Test-MDEAutoExclusionsWindowsServer.ps1
  - MDEValidator/Public/Test-MDEBehaviorMonitoring.ps1
  - MDEValidator/Public/Test-MDECloudBlockLevel.ps1
  - MDEValidator/Public/Test-MDECloudExtendedTimeout.ps1
  - MDEValidator/Public/Test-MDECloudProtection.ps1
  - MDEValidator/Public/Test-MDEConfiguration.ps1
  - MDEValidator/Public/Test-MDEDatagramProcessingWindowsServer.ps1
  - MDEValidator/Public/Test-MDEDeviceTags.ps1
  - MDEValidator/Public/Test-MDEDisableCatchupQuickScan.ps1
  - MDEValidator/Public/Test-MDEDisableLocalAdminMerge.ps1
  - MDEValidator/Public/Test-MDEExclusionVisibilityLocalAdmins.ps1
  - MDEValidator/Public/Test-MDEExclusionVisibilityLocalUsers.ps1
  - MDEValidator/Public/Test-MDEFileHashComputation.ps1
  - MDEValidator/Public/Test-MDENetworkProtection.ps1
  - MDEValidator/Public/Test-MDENetworkProtectionWindowsServer.ps1
  - MDEValidator/Public/Test-MDEOnboardingStatus.ps1
  - MDEValidator/Public/Test-MDEPassiveMode.ps1
  - MDEValidator/Public/Test-MDEPolicyRegistryValue.ps1
  - MDEValidator/Public/Test-MDEPolicyRegistryVerification.ps1
  - MDEValidator/Public/Test-MDERealTimeProtection.ps1
  - MDEValidator/Public/Test-MDERealTimeScanDirection.ps1
  - MDEValidator/Public/Test-MDESampleSubmission.ps1
  - MDEValidator/Public/Test-MDEServiceStatus.ps1
  - MDEValidator/Public/Test-MDESignatureUpdateFallbackOrder.ps1
  - MDEValidator/Public/Test-MDESignatureUpdateInterval.ps1
  - MDEValidator/Public/Test-MDESmartScreen.ps1
  - MDEValidator/Public/Test-MDESmartScreenAppRepExclusions.ps1
  - MDEValidator/Public/Test-MDESmartScreenDomainExclusions.ps1
  - MDEValidator/Public/Test-MDESmartScreenDownloadOverride.ps1
  - MDEValidator/Public/Test-MDESmartScreenPUA.ps1
  - MDEValidator/Public/Test-MDESmartScreenPromptOverride.ps1
  - MDEValidator/Public/Test-MDETamperProtection.ps1
  - MDEValidator/Public/Test-MDETamperProtectionForExclusions.ps1
  - MDEValidator/Public/Test-MDEThreatDefaultActions.ps1
  - MDEValidator/Public/Test-MDETroubleshootingMode.ps1
  - MDEValidator/Private/ConvertTo-HtmlEncodedString.ps1
  - MDEValidator/Private/Write-ValidationResult.ps1
  - MDEValidator/Private/Test-IsElevated.ps1
  - MDEValidator/Private/Test-IsWindowsServer.ps1
autonomous: true
requirements: [STRUCT-01, STRUCT-02, STRUCT-04]

must_haves:
  truths:
    - "Every exported function lives in its own .ps1 file in MDEValidator/Public/"
    - "Every private helper lives in its own .ps1 file in MDEValidator/Private/"
    - "MDEValidator.psm1 is a dot-source loader, not a monolith"
    - "Private functions are dot-sourced before Public functions"
    - "Import-Module MDEValidator succeeds without errors"
  artifacts:
    - path: "MDEValidator/Public/"
      provides: "45 individual function files"
    - path: "MDEValidator/Private/"
      provides: "4 private helper function files"
    - path: "MDEValidator/MDEValidator.psm1"
      provides: "Dot-source loader replacing monolithic content"
      contains: "Get-ChildItem.*Private.*Public"
  key_links:
    - from: "MDEValidator/MDEValidator.psm1"
      to: "MDEValidator/Private/*.ps1"
      via: "dot-source loader loads Private/ first"
      pattern: 'Get-ChildItem.*Private.*\.ps1'
    - from: "MDEValidator/MDEValidator.psm1"
      to: "MDEValidator/Public/*.ps1"
      via: "dot-source loader loads Public/ second"
      pattern: 'Get-ChildItem.*Public.*\.ps1'
    - from: "MDEValidator/MDEValidator.psm1"
      to: "Export-ModuleMember"
      via: "exports only Public/ function basenames"
      pattern: 'Export-ModuleMember.*publicFunctions'
---

<objective>
Extract all 49 functions from the monolithic MDEValidator.psm1 into individual .ps1 files (one per function), organized into Public/ (45 files) and Private/ (4 files) folders. Replace the .psm1 content with a dot-source loader that imports Private/ first, then Public/, and exports only public functions.

Purpose: This is the core restructuring — transforms the monolith into a maintainable function-per-file layout.
Output: 49 individual .ps1 files + rewritten MDEValidator.psm1 dot-source loader.
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
@.planning/phases/01-module-restructuring/01-01-SUMMARY.md
@MDEValidator/MDEValidator.psm1
@MDEValidator/MDEValidator.psd1

<interfaces>
<!-- Audit baseline from Plan 01 provides function inventory -->
<!-- Read .planning/phases/01-module-restructuring/audit-baseline.json for confirmed function list -->

From MDEValidator/MDEValidator.psd1 (FunctionsToExport — 45 functions):
  Test-MDEConfiguration, Get-MDEValidationReport, Get-MDEOperatingSystemInfo,
  Get-MDESecuritySettingsManagementStatus, Get-MDEOnboardingStatusString,
  Get-MDEManagementType, Get-MDEManagedDefenderProductType, Get-MDEManagementTypeFallback,
  Get-MDEPolicyRegistryPath, Get-MDEPolicySettingConfig, Test-MDEPolicyRegistryValue,
  Test-MDEPolicyRegistryVerification, Test-MDEServiceStatus, Test-MDEPassiveMode,
  Test-MDERealTimeProtection, Test-MDECloudProtection, Test-MDECloudBlockLevel,
  Test-MDECloudExtendedTimeout, Test-MDESampleSubmission, Test-MDEBehaviorMonitoring,
  Test-MDEOnboardingStatus, Test-MDEDeviceTags, Test-MDENetworkProtection,
  Test-MDENetworkProtectionWindowsServer, Test-MDEDatagramProcessingWindowsServer,
  Test-MDEAutoExclusionsWindowsServer, Test-MDEAttackSurfaceReduction,
  Test-MDEThreatDefaultActions, Test-MDETroubleshootingMode, Test-MDETamperProtection,
  Test-MDETamperProtectionForExclusions, Test-MDEExclusionVisibilityLocalAdmins,
  Test-MDEExclusionVisibilityLocalUsers, Test-MDESmartScreen, Test-MDESmartScreenPUA,
  Test-MDESmartScreenPromptOverride, Test-MDESmartScreenDownloadOverride,
  Test-MDESmartScreenDomainExclusions, Test-MDESmartScreenAppRepExclusions,
  Test-MDEDisableCatchupQuickScan, Test-MDERealTimeScanDirection,
  Test-MDESignatureUpdateFallbackOrder, Test-MDESignatureUpdateInterval,
  Test-MDEDisableLocalAdminMerge, Test-MDEFileHashComputation

Private helpers (4 — NOT exported):
  ConvertTo-HtmlEncodedString, Write-ValidationResult, Test-IsElevated, Test-IsWindowsServer
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Extract all 49 functions into individual .ps1 files</name>
  <files>MDEValidator/Public/*.ps1, MDEValidator/Private/*.ps1</files>
  <action>
Create `MDEValidator/Public/` and `MDEValidator/Private/` directories.

Read MDEValidator/MDEValidator.psm1 and extract each function into its own .ps1 file. Each file is named exactly after the function (e.g., `Test-MDEServiceStatus.ps1`) and contains the complete `function FunctionName { ... }` block including all comment-based help inside the function body.

**45 Public functions** → `MDEValidator/Public/{FunctionName}.ps1`:
All functions listed in FunctionsToExport (see interfaces block above).

**4 Private functions** → `MDEValidator/Private/{FunctionName}.ps1`:
- ConvertTo-HtmlEncodedString
- Write-ValidationResult
- Test-IsElevated
- Test-IsWindowsServer

**Extraction rules:**
- Each .ps1 file contains exactly ONE `function FunctionName { ... }` block — nothing else.
- Do NOT add `#Requires` directives to individual files (only the root .psm1 has `#Requires`).
- Do NOT add `Export-ModuleMember` to individual files.
- Preserve the exact function body — no modifications to logic, parameters, or formatting.
- Do NOT include `#region`/`#endregion` markers in individual files.
- The 6 functions that are in the `#region Helper Functions` section of .psm1 but ARE exported (Get-MDEManagedDefenderProductType, Get-MDEManagementType, Get-MDEPolicyRegistryPath, Get-MDEPolicySettingConfig, Test-MDEPolicyRegistryValue, Test-MDEPolicyRegistryVerification) go in `Public/` because they are exported. Export status determines classification, not region labels.

After extraction, verify file counts:
```powershell
(Get-ChildItem MDEValidator/Public/*.ps1).Count   # must be 45
(Get-ChildItem MDEValidator/Private/*.ps1).Count   # must be 4
```
  </action>
  <verify>
    <automated>powershell -Command "$pub = (Get-ChildItem MDEValidator/Public/*.ps1).Count; $priv = (Get-ChildItem MDEValidator/Private/*.ps1).Count; Write-Host \"Public: $pub Private: $priv\"; if ($pub -ne 45 -or $priv -ne 4) { throw \"Expected 45+4, got $pub+$priv\" }"</automated>
  </verify>
  <done>45 .ps1 files exist in MDEValidator/Public/, 4 .ps1 files exist in MDEValidator/Private/, each containing exactly one function definition</done>
</task>

<task type="auto">
  <name>Task 2: Replace .psm1 with dot-source loader</name>
  <files>MDEValidator/MDEValidator.psm1</files>
  <action>
Replace the entire content of MDEValidator/MDEValidator.psm1 with a dot-source loader. Use this exact pattern:

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

**Critical:** Private functions MUST be loaded before Public functions because public functions call Write-ValidationResult (80+ call sites), Test-IsElevated, Test-IsWindowsServer, and ConvertTo-HtmlEncodedString.

**Do NOT modify MDEValidator.psd1** — it already has the correct FunctionsToExport list and RootModule = 'MDEValidator.psm1'.

After writing the loader, do a quick smoke test:
```powershell
Remove-Module MDEValidator -ErrorAction SilentlyContinue
Import-Module ./MDEValidator/MDEValidator.psm1 -Force
(Get-Command -Module MDEValidator).Count  # should be 45
```
  </action>
  <verify>
    <automated>powershell -Command "Remove-Module MDEValidator -ErrorAction SilentlyContinue; Import-Module ./MDEValidator/MDEValidator.psm1 -Force; $count = (Get-Command -Module MDEValidator).Count; Write-Host \"Exported: $count\"; if ($count -ne 45) { throw \"Expected 45 exports, got $count\" }"</automated>
  </verify>
  <done>MDEValidator.psm1 is a dot-source loader (~25 lines), Import-Module succeeds, 45 functions exported</done>
</task>

</tasks>

<verification>
- `(Get-ChildItem MDEValidator/Public/*.ps1).Count` = 45
- `(Get-ChildItem MDEValidator/Private/*.ps1).Count` = 4
- `Import-Module ./MDEValidator/MDEValidator.psm1 -Force` succeeds without errors
- `(Get-Command -Module MDEValidator).Count` = 45
- MDEValidator.psm1 contains `Get-ChildItem` loader pattern, NOT function definitions
</verification>

<success_criteria>
- 45 public function files in Public/, 4 private helper files in Private/
- MDEValidator.psm1 replaced with dot-source loader
- Module imports successfully with 45 exported functions
- No modifications to function logic, parameters, or formatting
</success_criteria>

<output>
After completion, create `.planning/phases/01-module-restructuring/01-02-SUMMARY.md`
</output>
