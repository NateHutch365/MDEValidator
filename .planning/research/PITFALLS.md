# Domain Pitfalls

**Domain:** PowerShell module restructuring + testing + desktop UI + publishing
**Researched:** 2026-03-04

## Critical Pitfalls

Mistakes that cause rewrites or major issues.

### Pitfall 1: Breaking Export Surface During Restructuring
**What goes wrong:** Splitting the monolith into files but missing a function, misspelling a filename, or losing an export — causing `Get-Command -Module MDEValidator` to return fewer functions than before.
**Why it happens:** 45+ functions manually extracted. Easy to miss one or have a typo in `FunctionsToExport`.
**Consequences:** Existing users' scripts break silently (function not found errors). Published module is broken.
**Prevention:**
1. Snapshot existing exports BEFORE restructuring: `Get-Command -Module MDEValidator | Select Name | Sort Name > exports-baseline.txt`
2. After restructuring, compare: test that `(Get-Command -Module MDEValidator).Count` equals baseline count
3. Keep existing `MDEValidator.Module.Tests.ps1` (export surface tests) running throughout
**Detection:** Export count test fails. Functions missing from `Get-Command` output.

### Pitfall 2: Pester Mock Scoping Bugs
**What goes wrong:** Mocks defined in wrong scope silently don't apply. Tests pass when they should fail (false green).
**Why it happens:** Pester 5 changed scoping rules. Mocks in `BeforeAll` apply to `It` blocks in the same `Describe`/`Context`. Mocks in `It` only apply to that `It`. `-ModuleName` parameter is REQUIRED when mocking calls inside a module's functions.
**Consequences:** Tests pass in CI but validation logic is actually broken. False confidence.
**Prevention:**
1. **Always** use `-ModuleName MDEValidator` when mocking cmdlets called inside module functions
2. Place mocks in `BeforeAll` or `BeforeEach`, not floating in `Describe` body
3. Write "negative tests" that verify mocks are actually being hit (e.g., mock returns failure → assert result is Fail)
**Detection:** A test passes even when you intentionally break the function under test.

### Pitfall 3: WPF Threading — Blocking the UI Thread
**What goes wrong:** Running `Test-MDEConfiguration` on the UI thread freezes the window during validation (~seconds of unresponsive UI).
**Why it happens:** WPF requires UI work on the dispatcher thread, but long-running operations must run on background threads. PowerShell's single-threaded nature makes this tricky.
**Consequences:** App appears frozen/crashed. Poor user experience.
**Prevention:**
1. Use PowerShell runspaces or `Start-Job` for background validation
2. Or accept the brief freeze with a "Running..." status indicator and `[System.Windows.Forms.Application]::DoEvents()` calls (simpler but less clean)
3. For a PowerShell-native approach: run validation in a runspace, update UI via `$window.Dispatcher.Invoke()`
**Detection:** UI becomes unresponsive during validation run.

## Moderate Pitfalls

### Pitfall 4: `Get-ItemProperty` Mock Ambiguity
**What goes wrong:** Mocking `Get-ItemProperty` without `-ParameterFilter` affects ALL registry reads including ones you didn't intend to mock.
**Prevention:** Always use `-ParameterFilter` with path matching:
```powershell
Mock Get-ItemProperty {
    [PSCustomObject]@{ EnableNetworkProtection = 1 }
} -ParameterFilter { $Path -like '*Windows Defender*' } -ModuleName MDEValidator
```

### Pitfall 5: Module Reload State During Development
**What goes wrong:** `Import-Module -Force` during development doesn't clear all state from the previous load, especially if you have module-scoped variables.
**Prevention:** Use `Remove-Module MDEValidator -Force -ErrorAction SilentlyContinue` before `Import-Module`. In Pester, the `BeforeAll { Import-Module ... -Force }` pattern handles this.

### Pitfall 6: PowerShell 5.1 vs 7.x Differences in WPF
**What goes wrong:** WPF works natively in PowerShell 5.1 (Windows PowerShell) but requires explicit assembly loading in PowerShell 7.x (Core). Some XAML features differ.
**Prevention:** Target PowerShell 5.1 for the UI entry point. If supporting PS7, add conditional assembly loading:
```powershell
if ($PSVersionTable.PSEdition -eq 'Core') {
    Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
}
```
Test UI on both editions.

### Pitfall 7: PSGallery Publish Without Testing Locally
**What goes wrong:** `Publish-Module` pushes a broken version that can't be unpublished (PSGallery doesn't allow deleting, only unlisting).
**Prevention:**
1. Run `Test-ModuleManifest` before every publish
2. Test install from local path: `Install-Module -Name ./MDEValidator -Scope CurrentUser`
3. Use CI pipeline — never publish manually from local machine

### Pitfall 8: FunctionsToExport Wildcard in Manifest
**What goes wrong:** Using `FunctionsToExport = '*'` in .psd1 exports EVERYTHING including private helpers.
**Prevention:** Keep the explicit export list in .psd1 (already done correctly). After restructuring, the .psm1's `Export-ModuleMember -Function $Public.BaseName` is a safety net, but .psd1 is the authoritative gate.

## Minor Pitfalls

### Pitfall 9: XAML Namespace Confusion
**What goes wrong:** XAML loaded via `[System.Xml.XmlNodeReader]` fails with cryptic errors if namespaces or `x:Class` attributes reference compiled types.
**Prevention:** Remove `x:Class` from XAML root element. Use `x:Name` for element access via `$window.FindName('ElementName')`.

### Pitfall 10: InvokeBuild Task Dependency Cycles
**What goes wrong:** Circular task dependencies cause infinite loops or confusing errors.
**Prevention:** Keep task graph simple and linear: Clean → Build → Analyze → Test → Publish. No cross-dependencies.

### Pitfall 11: Git Diff Noise During Restructuring
**What goes wrong:** Moving 2000+ lines from one file to 50+ files makes git history hard to follow. PR becomes unreviewable.
**Prevention:** Do restructuring in stages. Stage 1: extract Private helpers. Stage 2: extract Public validators in batches. Each PR is reviewable. Use `git log --follow` to track function history.

### Pitfall 12: Code Coverage Misinterpretation
**What goes wrong:** High code coverage (>80%) gives false confidence. Coverage measures lines executed, not correctness of assertions.
**Prevention:** Focus on assertion quality (test failure cases, edge cases, not just happy path). Use coverage as a gap-finder, not a quality metric.

## Phase-Specific Warnings

| Phase Topic | Likely Pitfall | Mitigation |
|-------------|---------------|------------|
| Module restructuring | Breaking exports (Pitfall 1) | Export count test as gatekeeper |
| Module restructuring | Git diff noise (Pitfall 11) | Stage extraction in batches |
| Mock-based testing | Mock scoping (Pitfall 2) | Always use `-ModuleName`, write negative tests |
| Mock-based testing | Registry mock ambiguity (Pitfall 4) | Always use `-ParameterFilter` |
| Desktop UI | UI thread blocking (Pitfall 3) | Runspace or status indicator |
| Desktop UI | PS 5.1 vs 7.x WPF (Pitfall 6) | Target 5.1 primarily, test both |
| PSGallery publishing | Broken publish (Pitfall 7) | CI-only publishing, `Test-ModuleManifest` |
| PSGallery publishing | Wildcard exports (Pitfall 8) | Keep explicit export list |
