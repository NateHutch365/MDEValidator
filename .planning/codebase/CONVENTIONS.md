# Coding Conventions

**Analysis Date:** 2026-03-04

## Naming Patterns

**Files:**
- PowerShell module files use PascalCase module naming: `MDEValidator/MDEValidator.psm1`, `MDEValidator/MDEValidator.psd1`.
- Test files use `*.Tests.ps1` naming under a dedicated test directory: `Tests/MDEValidator.Tests.ps1`.
- Utility JavaScript hook files under `.claude/hooks` use kebab-case: `.claude/hooks/gsd-statusline.js`, `.claude/hooks/gsd-context-monitor.js`.

**Functions:**
- Public PowerShell functions follow approved verb-noun style with a domain prefix: `Test-MDE*`, `Get-MDE*` in `MDEValidator/MDEValidator.psm1`.
- Internal helper functions are also verb-noun, but use generic helper names where scoped privately by export list: `ConvertTo-HtmlEncodedString`, `Write-ValidationResult`, `Test-IsElevated` in `MDEValidator/MDEValidator.psm1`.

**Variables:**
- Local PowerShell variables use camelCase with `$` prefix: `$managementType`, `$outputDirectory`, `$regResult` in `MDEValidator/MDEValidator.psm1`.
- Boolean flag parameters use descriptive switch names: `-IncludeOnboarding`, `-IncludePolicyVerification` in `MDEValidator/MDEValidator.psm1`.

**Types:**
- Custom return shapes are built with `[PSCustomObject]` and stable property sets, for example in `Write-ValidationResult` and `Test-MDEPolicyRegistryValue` in `MDEValidator/MDEValidator.psm1`.
- Input constraints are declared with PowerShell attributes, especially `[ValidateSet(...)]` and typed parameters (`[string]`, `[switch]`) in `MDEValidator/MDEValidator.psm1`.

## Code Style

**Formatting:**
- No dedicated formatter configuration file is detected (`.prettierrc`, `eslint.config.*`, `.editorconfig` not present at repository root).
- Style is manually consistent in PowerShell: 4-space indentation, multi-line `param(...)` blocks, aligned hashtable literals, and generous blank-line separation between logical blocks in `MDEValidator/MDEValidator.psm1` and `Tests/MDEValidator.Tests.ps1`.
- Comment-based help (`<# ... #>`) is used for module and function documentation in `MDEValidator/MDEValidator.psm1`.

**Linting:**
- No active repository lint config for module/test code is detected (no PSScriptAnalyzer config or lint script in root).
- Convention enforcement appears code-review-driven and test-driven via `Tests/MDEValidator.Tests.ps1`.

## Import Organization

**Order:**
1. PowerShell scripts place `#Requires` directives first (`#Requires -Version 5.1` and `#Requires -Modules Pester`) in `MDEValidator/MDEValidator.psm1` and `Tests/MDEValidator.Tests.ps1`.
2. Module import is done in `BeforeAll` for tests (`Import-Module $modulePath -Force`) in `Tests/MDEValidator.Tests.ps1`.
3. Exports are centralized at file end with one `Export-ModuleMember -Function @(...)` block in `MDEValidator/MDEValidator.psm1`.

**Path Aliases:**
- Not applicable for PowerShell module code. Relative path composition is done with `Join-Path` in tests (`Tests/MDEValidator.Tests.ps1`).

## Error Handling

**Patterns:**
- `try/catch` is used per function and around risky platform calls (registry/service access, file output) in `MDEValidator/MDEValidator.psm1`.
- Cmdlet-level error behavior is explicit with `-ErrorAction Stop` for hard-fail operations and `-ErrorAction SilentlyContinue` for probe/check operations in `MDEValidator/MDEValidator.psm1`.
- Instead of throwing for validation failures, functions return structured status objects using `Write-ValidationResult` with status values such as `Pass`, `Fail`, `Warning`, `Info`, `NotApplicable` in `MDEValidator/MDEValidator.psm1`.

## Logging

**Framework:** console / PowerShell host output.

**Patterns:**
- Progress/informational diagnostics use `Write-Verbose` and `Write-Warning` in orchestration functions like `Test-MDEConfiguration` in `MDEValidator/MDEValidator.psm1`.
- User-facing reports use `Write-Host` with colors and symbols for console rendering in `Get-MDEValidationReport` in `MDEValidator/MDEValidator.psm1`.
- Hard output errors for report generation use `Write-Error` when directory creation fails in `Get-MDEValidationReport` in `MDEValidator/MDEValidator.psm1`.

## Comments

**When to Comment:**
- Use comment-based help for every exported function (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, `.OUTPUTS`) as the primary documentation style in `MDEValidator/MDEValidator.psm1`.
- Use short inline comments for non-obvious control flow and platform caveats (for example, SSM applicability checks and SmartScreen scope notes) in `MDEValidator/MDEValidator.psm1`.

**JSDoc/TSDoc:**
- Not used for module code.
- Node hook scripts use concise line comments, not JSDoc blocks, in `.claude/hooks/gsd-statusline.js` and `.claude/hooks/gsd-context-monitor.js`.

## Function Design

**Size:**
- Core check functions are medium-sized single-responsibility validators (`Test-MDERealTimeProtection`, `Test-MDECloudProtection`), while orchestration/report functions are large (`Test-MDEConfiguration`, `Get-MDEValidationReport`) in `MDEValidator/MDEValidator.psm1`.

**Parameters:**
- Parameter definitions are strongly declarative with attribute blocks and defaults, for example:

```powershell
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Console', 'HTML', 'Object')]
    [string]$OutputFormat = 'Console',

    [Parameter()]
    [switch]$IncludePolicyVerification
)
```

Pattern appears in `Get-MDEValidationReport` and other functions in `MDEValidator/MDEValidator.psm1`.

**Return Values:**
- Validation functions return normalized `[PSCustomObject]` records with `TestName`, `Status`, `Message`, `Recommendation`, `Timestamp` via `Write-ValidationResult` in `MDEValidator/MDEValidator.psm1`.
- Aggregators return arrays of those objects (`Test-MDEConfiguration`) or emit formatted output and optional file paths (`Get-MDEValidationReport`) in `MDEValidator/MDEValidator.psm1`.

## Module Design

**Exports:**
- Export strategy is explicit and centralized through `Export-ModuleMember -Function @(...)` at the end of `MDEValidator/MDEValidator.psm1`, mirrored by `FunctionsToExport` in `MDEValidator/MDEValidator.psd1`.
- Use this explicit export list pattern for new public functions; do not rely on wildcard exports.

**Barrel Files:**
- Not applicable. PowerShell module uses a single script module (`MDEValidator/MDEValidator.psm1`) plus manifest (`MDEValidator/MDEValidator.psd1`) instead of multi-file barrel exports.

---

*Convention analysis: 2026-03-04*
