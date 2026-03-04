---
phase: 01-module-restructuring
plan: 02
subsystem: Module Restructuring
tags:
  - restructuring
  - function-extraction
  - module-loader
  - function-per-file
dependency_graph:
  requires:
    - 01-01 (audit baseline)
  provides:
    - 45 public .ps1 files
    - 4 private .ps1 files
    - dot-source loader .psm1
  affects:
    - 01-03 (Plan 03 uses restructured module for validation)
tech_stack:
  patterns:
    - Function-per-file layout
    - Dot-source loader pattern
    - Private/Public directory separation
  tools:
    - PowerShell 5.1+
    - AST parser for function extraction
key_files:
  created:
    - MDEValidator/Public/*.ps1 (45 files)
    - MDEValidator/Private/*.ps1 (4 files)
  modified:
    - MDEValidator/MDEValidator.psm1 (replaced with loader)
decisions:
  - decision: "Use AST parser for function extraction to ensure 100% complete function bodies"
    rationale: "Previous regex-based attempt had parsing issues; AST parser handles all brace complexities"
    accepted: true
  - decision: "Load Private functions before Public functions in loader"
    rationale: "Private helpers like Write-ValidationResult are used by 80+ public function call sites"
    accepted: true
  - decision: "Use Export-ModuleMember with BaseName property for automatic export list"
    rationale: "Ensures all public functions are exported without manual list maintenance"
    accepted: true
metrics:
  duration: ~8 minutes
  completed: 2026-03-04 22:08:00Z
  commits: 2 (atomic per task)
---

# Phase 01 Plan 02: Extract Functions to Individual Files and Create Dot-Source Loader

**Objective**: Extract all 49 functions from the monolithic MDEValidator.psm1 into individual .ps1 files (45 public in Public/, 4 private in Private/), replacing the monolithic .psm1 with a dot-source loader pattern.

## Summary

Module restructuring completed successfully. The monolithic ~2000-line .psm1 has been transformed into a maintainable function-per-file layout with a minimal dot-source loader.

### Task 1: Extract 49 Functions (da92f46)

**Status: ✓ COMPLETE**

- ✓ Created `MDEValidator/Public/` directory
- ✓ Created `MDEValidator/Private/` directory
- ✓ Extracted 45 public functions to individual .ps1 files (one per function)
- ✓ Extracted 4 private helpers to individual .ps1 files
- ✓ All function files named exactly after the function (e.g., `Test-MDEServiceStatus.ps1`)
- ✓ Preserved all function bodies including help, parameters, and logic (no modifications)
- ✓ No `Export-ModuleMember` or `#Requires` directives added to individual files

**Extraction Method**: PowerShell AST (Abstract Syntax Tree) parser for 100% complete function extraction

**Private functions extracted:**
  - ConvertTo-HtmlEncodedString.ps1
  - Write-ValidationResult.ps1
  - Test-IsElevated.ps1
  - Test-IsWindowsServer.ps1

**Public functions extracted (45 total):**
  - Get-MDEManagedDefenderProductType.ps1
  - Get-MDEManagementType.ps1
  - Get-MDEPolicyRegistryPath.ps1
  - Get-MDEPolicySettingConfig.ps1
  - Test-MDEPolicyRegistryValue.ps1
  - Test-MDEPolicyRegistryVerification.ps1
  - Get-MDEOperatingSystemInfo.ps1
  - Get-MDESecuritySettingsManagementStatus.ps1
  - Get-MDEOnboardingStatusString.ps1
  - Get-MDEManagementTypeFallback.ps1
  - Test-MDEPassiveMode.ps1
  - Test-MDEServiceStatus.ps1
  - Test-MDERealTimeProtection.ps1
  - Test-MDECloudProtection.ps1
  - Test-MDESampleSubmission.ps1
  - Test-MDEBehaviorMonitoring.ps1
  - Test-MDEOnboardingStatus.ps1
  - Test-MDEDeviceTags.ps1
  - Test-MDENetworkProtection.ps1
  - Test-MDENetworkProtectionWindowsServer.ps1
  - Test-MDEDatagramProcessingWindowsServer.ps1
  - Test-MDEAutoExclusionsWindowsServer.ps1
  - Test-MDEAttackSurfaceReduction.ps1
  - Test-MDEThreatDefaultActions.ps1
  - Test-MDETroubleshootingMode.ps1
  - Test-MDEExclusionVisibilityLocalAdmins.ps1
  - Test-MDEExclusionVisibilityLocalUsers.ps1
  - Test-MDESmartScreen.ps1
  - Test-MDESmartScreenPUA.ps1
  - Test-MDESmartScreenPromptOverride.ps1
  - Test-MDESmartScreenDownloadOverride.ps1
  - Test-MDESmartScreenDomainExclusions.ps1
  - Test-MDESmartScreenAppRepExclusions.ps1
  - Test-MDECloudBlockLevel.ps1
  - Test-MDETamperProtection.ps1
  - Test-MDETamperProtectionForExclusions.ps1
  - Test-MDECloudExtendedTimeout.ps1
  - Test-MDEDisableCatchupQuickScan.ps1
  - Test-MDERealTimeScanDirection.ps1
  - Test-MDESignatureUpdateFallbackOrder.ps1
  - Test-MDESignatureUpdateInterval.ps1
  - Test-MDEDisableLocalAdminMerge.ps1
  - Test-MDEFileHashComputation.ps1
  - Test-MDEConfiguration.ps1
  - Get-MDEValidationReport.ps1

### Task 2: Replace .psm1 with Dot-Source Loader (163eb7d)

**Status: ✓ COMPLETE**

- ✓ Replaced entire content of MDEValidator.psm1 with dot-source loader (~25 lines)
- ✓ Loader pattern loads Private/*.ps1 functions first (dependencies)
- ✓ Loader pattern loads Public/*.ps1 functions second
- ✓ Export-ModuleMember uses `$publicFunctions.BaseName` for dynamic export list
- ✓ Import-Module MDEValidator succeeds without errors
- ✓ All 45 public functions exported correctly
- ✓ Private functions loaded but not exported

**Loader Pattern Verification:**

```text
Pattern: Get-ChildItem → dot-source (.) → for each file
Sequence: Private first (helpers), then Public (users of helpers)
Export: Export-ModuleMember -Function $publicFunctions.BaseName
```

## Verification Results

| Criterion | Expected | Actual | Status |
|-----------|----------|--------|--------|
| Public function files | 45 | 45 | ✓ PASS |
| Private function files | 4 | 4 | ✓ PASS |
| .psm1 is loader (Get-ChildItem pattern) | true | true | ✓ PASS |
| Import-Module succeeds | true | true | ✓ PASS |
| Exported functions | 45 | 45 | ✓ PASS |
| Module-scope state | 0 | 0 | ✓ PASS |
| Function definitions in .psm1 | 0 | 0 | ✓ PASS |

## Deviations from Plan

None — plan executed exactly as written.

## Technical Notes

**AST Extraction**: The PowerShell AST parser (`System.Management.Automation.Language.Parser`) was used for final function extraction to ensure complete function bodies, particularly for functions with complex nested structures (hashtables, script blocks, etc.).

**Load Order**: Private functions are loaded before public functions because:
  - `Write-ValidationResult` is called by 80+ public function call sites
  - `Test-IsElevated`, `Test-IsWindowsServer`, `ConvertTo-HtmlEncodedString` are used by multiple public functions
  - Explicit ordering ensures no "function not yet defined" errors during import

**No Modifications**: Function bodies were extracted as-is with no changes to logic, parameters, help comments, or formatting.

## Next Steps

Plan 01-03 will verify that the restructured module:
1. Maintains all 45 exported functions with identical parameter signatures
2. Ensures private helper functions are not exported
3. Validates that Pester tests pass with the new structure
