# Architecture Patterns

**Domain:** PowerShell module restructuring + desktop UI
**Researched:** 2026-03-04

## Recommended Architecture

### Post-Restructuring Module Layout

```
MDEValidator/
├── Public/                        # Exported functions (1 per file)
│   ├── Test-MDEServiceStatus.ps1
│   ├── Test-MDERealTimeProtection.ps1
│   ├── Test-MDEConfiguration.ps1      # Orchestrator
│   ├── Get-MDEValidationReport.ps1    # Presenter
│   ├── Show-MDEValidatorUI.ps1        # UI entry point (Phase 4)
│   └── ... (~38 more validators + getters)
├── Private/                       # Internal helpers (not exported)
│   ├── Write-ValidationResult.ps1
│   ├── ConvertTo-HtmlEncodedString.ps1
│   ├── Test-IsElevated.ps1
│   ├── Test-IsWindowsServer.ps1
│   └── ... (~5-8 more)
├── UI/                           # WPF resources (Phase 4)
│   ├── MainWindow.xaml
│   ├── Styles.xaml
│   └── Resources/
│       └── icon.ico
├── MDEValidator.psm1             # Dot-source loader (simple)
├── MDEValidator.psd1             # Manifest (unchanged exports)
└── MDEValidator.Format.ps1xml    # Optional: custom formatting
Tests/
├── Unit/
│   ├── Public/                   # One test file per public function
│   │   ├── Test-MDEServiceStatus.Tests.ps1
│   │   └── ...
│   └── Private/                  # Test files for key helpers
│       ├── Write-ValidationResult.Tests.ps1
│       └── ...
├── MDEValidator.Module.Tests.ps1  # Export surface tests (existing)
└── .pester.config.psd1           # Test configuration
```

### Component Boundaries

| Component | Responsibility | Communicates With |
|-----------|---------------|-------------------|
| Public validators (`Test-MDE*`) | Execute individual checks, return result objects | Private helpers, Windows APIs (mockable) |
| Private helpers | Result formatting, OS detection, HTML encoding | PowerShell runtime only |
| Orchestrator (`Test-MDEConfiguration`) | Calls all validators, aggregates results | All public validators |
| Presenter (`Get-MDEValidationReport`) | Formats output (Object/Console/HTML) | Orchestrator for results |
| UI (`Show-MDEValidatorUI`) | WPF window, DataGrid display | Orchestrator for results, Presenter for export |
| Dot-source loader (`MDEValidator.psm1`) | Loads all function files at import time | File system (Public/*.ps1, Private/*.ps1) |

### Data Flow

**Validation (unchanged from current):**
```
User calls Test-MDEConfiguration or individual Test-MDE* function
  → Function calls Windows APIs (Get-MpPreference, Get-Service, registry)
  → Function calls Write-ValidationResult to create result object
  → Result object returned (PSCustomObject with TestName, Status, Message, etc.)
```

**UI flow (new):**
```
User calls Show-MDEValidatorUI
  → Load XAML, create WPF Window
  → User clicks "Run Validation"
  → Call Test-MDEConfiguration (same as CLI path)
  → Bind result array to DataGrid.ItemsSource
  → User can filter, export HTML via Get-MDEValidationReport
```

## Patterns to Follow

### Pattern 1: One Function Per File
**What:** Each function lives in its own .ps1 file named identically to the function.
**When:** Always, for all public and private functions.
**Why:** Enables git blame per function, simplifies code review, makes test file mapping obvious.

### Pattern 2: Mock at the Seam
**What:** Mock the Windows API calls (`Get-MpPreference`, `Get-Service`, `Get-ItemProperty`), not the validator functions themselves.
**When:** Unit testing any validator function.
**Why:** Tests the actual validation logic. Mocking the validator itself only tests the orchestrator's aggregation, not the logic.

```powershell
Describe 'Test-MDEServiceStatus' {
    BeforeAll {
        # Mock at the Windows API seam
        Mock Get-Service {
            [PSCustomObject]@{ Status = 'Running'; Name = 'WinDefend' }
        } -ModuleName MDEValidator
    }
    It 'Should return Pass when WinDefend is running' {
        $result = Test-MDEServiceStatus
        $result.Status | Should -Be 'Pass'
    }
}
```

### Pattern 3: XAML in Files, Logic in PowerShell
**What:** WPF layout defined in .xaml files, loaded at runtime. No inline XAML strings.
**When:** All UI work.
**Why:** XAML files get IDE support (VS Code XAML extension), are diffable, and separate concerns cleanly.

### Pattern 4: Export via Manifest, Not Module File
**What:** After restructuring, `FunctionsToExport` in .psd1 is the authoritative export list. The .psm1 `Export-ModuleMember` uses `$Public.BaseName` as a convenience but .psd1 is the contract.
**When:** Always.
**Why:** PowerShell uses .psd1 exports for module auto-discovery and command completion. Missing from .psd1 = invisible to `Get-Command` before import.

## Anti-Patterns to Avoid

### Anti-Pattern 1: Monolith Dot-Source with Logic
**What:** Putting logic (conditionals, initialization, variable setup) in the .psm1 loader beyond simple dot-sourcing.
**Why bad:** Makes module load order-dependent. Debugging import failures becomes hard.
**Instead:** .psm1 should only dot-source files. All logic lives in function files.

### Anti-Pattern 2: Testing Through the Orchestrator
**What:** Only testing `Test-MDEConfiguration` (which calls all validators) instead of testing each validator individually.
**Why bad:** When a test fails, you don't know which validator broke. Mock setup becomes enormous. Test files become unmanageable.
**Instead:** Test each validator function individually with focused mocks. Test the orchestrator separately with mocked validators.

### Anti-Pattern 3: Inline C# for WPF
**What:** Using `Add-Type` with inline C# code to create WPF controls or converters.
**Why bad:** No IDE support for the C# portion, hard to debug, mix of languages in one file.
**Instead:** Use pure XAML for layout. Use PowerShell for event handlers. If a value converter is truly needed, write it in a separate .cs file compiled to a DLL.

### Anti-Pattern 4: Global State for UI-Module Communication
**What:** Using `$script:` or `$global:` variables to pass data between UI and validation functions.
**Why bad:** Hidden coupling, makes testing impossible, breaks when module is reloaded.
**Instead:** Call validation functions directly from UI event handlers, pass results as data binding source.

## Scalability Considerations

Not applicable in the traditional sense (this is a local validation tool, not a service). Relevant scaling dimensions:

| Concern | Current (~45 checks) | At ~100 checks | At ~200 checks |
|---------|----------------------|----------------|----------------|
| Module load time | Negligible | Dot-source ~100 files: <1s | Consider compiled module (.dll) if >2s load time |
| Test suite runtime | ~seconds | ~30s with mocks | Split test runs by category |
| UI result display | Single DataGrid | GroupBy category in DataGrid | Tabbed/category view |
| Build complexity | Simple dot-source | Same pattern scales | Same pattern scales |
