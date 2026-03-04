# Stack Research

**Domain:** PowerShell module restructuring + mock-based testing + desktop UI + PSGallery publishing + CI/CD
**Researched:** 2026-03-04
**Overall Confidence:** HIGH

## Recommended Stack

### Core Technologies

| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| PowerShell 5.1+ | 5.1 minimum | Runtime target | Already required; broadest enterprise Windows coverage. Core edition optional but not primary. |
| Pester | 5.6+ | Test framework | Standard PowerShell testing. Already in use with v5 syntax (`BeforeAll`, `Should`). Mock support is built-in and handles cmdlet/function mocking natively. |
| PSScriptAnalyzer | 1.22+ | Static analysis / linting | Only real PowerShell linter. Catches style issues, security anti-patterns, compatibility problems. Integrates with VS Code and CI. |
| WPF (PresentationFramework) | .NET Framework 4.x (ships with Windows) | Desktop UI | Native to Windows PowerShell 5.1 via `Add-Type -AssemblyName PresentationFramework`. XAML-based layout separates UI from logic. Rich DataGrid control is ideal for tabular validation results. No external dependency — ships with every Windows 10/11/Server 2016+ install. |
| GitHub Actions | N/A | CI/CD pipeline | Project is on GitHub. `windows-latest` runner provides full Windows environment for Defender-free mock testing. Free for public repos. |

### Supporting Libraries

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| InvokeBuild | 5.11+ | Build automation | Use during restructuring to automate: dot-source stitching, manifest updates, test runs, PSGallery publishing. Cleaner than raw build.ps1 for multi-step builds. |
| platyPS | 2.0+ | Documentation generation | Use when preparing PSGallery release. Generates MAML help from markdown. Standard for published modules. |
| PSResourceGet | 1.0+ | Modern PSGallery publishing | Successor to PowerShellGet. Use `Publish-PSResource` instead of `Publish-Module` for publishing. Falls back to PowerShellGet 2.x if enterprise environments haven't upgraded. |
| Pester TestDrive / TestRegistry | Built into Pester 5.x | Isolated test fixtures | Use for registry-based tests. TestRegistry provides a sandboxed `HKCU:\` hive that auto-cleans. For `HKLM:` reads, use `Mock Get-ItemProperty` instead. |

### Development Tools

| Tool | Purpose | Notes |
|------|---------|-------|
| VS Code + PowerShell Extension | IDE | Standard PowerShell development environment. Integrated PSScriptAnalyzer, debugging, Pester test runner. |
| `.PSScriptAnalyzerSettings.psd1` | Lint configuration | Project-level rule configuration. Exclude rules that conflict with chosen conventions. |
| `build.ps1` (InvokeBuild entry point) | Build orchestration | Single entry point: `Invoke-Build Test`, `Invoke-Build Build`, `Invoke-Build Publish`. |
| `*.build.ps1` | InvokeBuild task definitions | Defines tasks: Clean, Build (dot-source stitch + manifest update), Test, Analyze, Publish. |

## Module Restructuring Stack

### Directory Layout (Function-Per-File)

```
MDEValidator/
├── Public/                          # Exported functions (1 file per function)
│   ├── Test-MDEServiceStatus.ps1
│   ├── Test-MDERealTimeProtection.ps1
│   ├── Test-MDECloudProtection.ps1
│   ├── Test-MDEConfiguration.ps1
│   ├── Get-MDEValidationReport.ps1
│   ├── Get-MDEManagementType.ps1
│   └── ... (~38 more)
├── Private/                         # Internal helper functions
│   ├── Write-ValidationResult.ps1
│   ├── ConvertTo-HtmlEncodedString.ps1
│   ├── Test-IsElevated.ps1
│   ├── Test-IsWindowsServer.ps1
│   └── ... (~5-8 more)
├── MDEValidator.psm1               # Dot-sources all .ps1 files
├── MDEValidator.psd1               # Module manifest (unchanged API)
└── MDEValidator.Format.ps1xml      # Optional: custom formatting
```

### Module Loader Pattern (`MDEValidator.psm1`)

```powershell
# Dot-source all function files
$Private = @(Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue)
$Public  = @(Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue)

foreach ($import in @($Private + $Public)) {
    try {
        . $import.FullName
    } catch {
        Write-Error "Failed to import function $($import.FullName): $_"
    }
}

Export-ModuleMember -Function $Public.BaseName
```

**Confidence: HIGH** — This is the de facto standard for PowerShell modules with >10 functions. Used by PoshBot, PSFramework, dbatools, and virtually every serious community module.

## Testing Stack

### Pester 5.x Mock Strategy

| External Dependency | Mock Target | Mock Approach |
|---------------------|-------------|---------------|
| `Get-MpPreference` | Defender cmdlet | `Mock Get-MpPreference { [PSCustomObject]@{ RealTimeProtectionEnabled = $true; ... } }` |
| `Get-MpComputerStatus` | Defender cmdlet | `Mock Get-MpComputerStatus { [PSCustomObject]@{ AMRunningMode = 'Normal'; ... } }` |
| `Get-Service` | Windows services | `Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; Name = 'WinDefend' } }` |
| `Get-ItemProperty` | Registry reads | `Mock Get-ItemProperty { [PSCustomObject]@{ PropertyName = 'value' } } -ParameterFilter { $Path -like '*Windows Defender*' }` |
| `Test-Path` | Registry/file existence | `Mock Test-Path { $true } -ParameterFilter { $Path -like 'HKLM:*' }` |
| `Test-IsElevated` | Admin check | `Mock Test-IsElevated { $true }` (internal function, easily mockable) |
| `Test-IsWindowsServer` | OS detection | `Mock Test-IsWindowsServer { $false }` |

### Test File Layout

```
Tests/
├── Unit/
│   ├── Public/
│   │   ├── Test-MDEServiceStatus.Tests.ps1
│   │   ├── Test-MDERealTimeProtection.Tests.ps1
│   │   └── ...
│   └── Private/
│       ├── Write-ValidationResult.Tests.ps1
│       └── ...
├── Integration/
│   └── MDEValidator.Integration.Tests.ps1   # Optional: runs on real endpoint
├── MDEValidator.Module.Tests.ps1            # Export surface tests (existing)
└── .pester.config.psd1                      # Pester configuration
```

### Pester Configuration (`.pester.config.psd1`)

```powershell
@{
    Run = @{
        Path = './Tests'
        Exit = $true
    }
    CodeCoverage = @{
        Enabled = $true
        Path = './MDEValidator/Public/*.ps1', './MDEValidator/Private/*.ps1'
        OutputFormat = 'JaCoCo'
        OutputPath = './TestResults/coverage.xml'
    }
    TestResult = @{
        Enabled = $true
        OutputFormat = 'NUnitXml'
        OutputPath = './TestResults/testResults.xml'
    }
    Output = @{
        Verbosity = 'Detailed'
    }
}
```

**Confidence: HIGH** — Pester 5.x `Mock` is the only real option for PowerShell function mocking. The parameter filter pattern handles the specific challenge of mocking `Get-ItemProperty` for different registry paths.

## Desktop UI Stack

### WPF Architecture for MDEValidator

| Component | Technology | Purpose |
|-----------|------------|---------|
| Window layout | XAML loaded at runtime | Define DataGrid, status indicators, report views |
| Data binding | WPF DataGrid + ItemsSource | Bind validation result objects directly to grid rows |
| Status indicators | WPF Ellipse/Rectangle with color triggers | Green/red/yellow indicators matching console output semantics |
| Report export | Existing `Get-MDEValidationReport -OutputFormat HTML` | Reuse existing HTML generation, add "Save Report" button |
| Entry point | `Show-MDEValidatorUI` function (new exported function) | Single function launches the desktop app |

### WPF Integration Pattern

```powershell
# Load XAML at runtime — no compilation needed
Add-Type -AssemblyName PresentationFramework
[xml]$xaml = Get-Content "$PSScriptRoot\UI\MainWindow.xaml"
$reader = [System.Xml.XmlNodeReader]::new($xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

# Bind validation results to DataGrid
$results = Test-MDEConfiguration
$dataGrid = $window.FindName('ResultsGrid')
$dataGrid.ItemsSource = $results

$window.ShowDialog()
```

### UI File Layout

```
MDEValidator/
├── UI/
│   ├── MainWindow.xaml              # Main window layout
│   ├── Styles.xaml                  # Shared styles/colors
│   └── Resources/
│       └── icon.ico                 # App icon
```

**Confidence: HIGH** — WPF with runtime XAML loading is the proven pattern for PowerShell desktop UIs. Used by dozens of IT admin tools. No compilation step, no external dependencies, ships with Windows.

### Why NOT Other UI Options

See "What NOT to Use" section below.

## CI/CD Stack

### GitHub Actions Pipeline

| Workflow | Trigger | What It Does |
|----------|---------|--------------|
| `ci.yml` | Push to `main`, PRs | PSScriptAnalyzer lint → Pester tests → Code coverage upload |
| `publish.yml` | Git tag `v*` | Build → Test → Publish to PSGallery |

### Key Actions

| Action/Step | Purpose |
|-------------|---------|
| `actions/checkout@v4` | Clone repo |
| `windows-latest` runner | Windows environment for PowerShell 5.1 compatibility |
| `Install-Module Pester -Force` | Install test framework |
| `Install-Module PSScriptAnalyzer -Force` | Install linter |
| `Invoke-Pester -Configuration (Import-PowerShellDataFile .pester.config.psd1)` | Run tests with coverage |
| `Invoke-ScriptAnalyzer -Path ./MDEValidator -Recurse -Settings ./.PSScriptAnalyzerSettings.psd1` | Lint |
| `Publish-Module -Path ./MDEValidator -NuGetApiKey ${{ secrets.PSGALLERY_API_KEY }}` | Publish to PSGallery |

**Confidence: HIGH** — GitHub Actions with `windows-latest` is standard for PowerShell CI. Mock-based tests run without Defender installed on the runner.

## PSGallery Publishing Stack

### Manifest Requirements (Already Partially Met)

| Field | Current Status | Action Needed |
|-------|----------------|---------------|
| `ModuleVersion` | `1.0.0` ✓ | Increment per release |
| `Description` | Set ✓ | None |
| `Author` | Set ✓ | None |
| `GUID` | Set ✓ | None |
| `Tags` | Set ✓ | None |
| `LicenseUri` | Empty ❌ | Add license (MIT recommended) + set URI |
| `ProjectUri` | Empty ❌ | Set to GitHub repo URL |
| `ReleaseNotes` | Missing ❌ | Add per-version release notes |
| `RequiredModules` | Not set ✓ | Correct — no runtime dependencies |
| `HelpInfoURI` | Missing | Optional: add if using platyPS-generated help |

### Publishing Command

```powershell
# Validate before publishing
Test-ModuleManifest -Path ./MDEValidator/MDEValidator.psd1
# Publish
Publish-Module -Path ./MDEValidator -NuGetApiKey $env:PSGALLERY_API_KEY -Repository PSGallery
```

**Confidence: HIGH** — PSGallery requirements are well-documented and stable. The manifest is already 80% ready.

## Alternatives Considered

| Recommended | Alternative | When to Use Alternative |
|-------------|-------------|-------------------------|
| Pester 5.6+ | Pester 4.x | Never — project already uses v5 syntax. v4 has incompatible `Should` and scoping. |
| WPF (XAML) | WinForms | If team has no XAML experience and needs simplest possible UI. WinForms is simpler but lacks DataGrid richness and data binding elegance. |
| WPF (XAML) | Avalonia UI | Only if cross-platform UI is ever needed (currently out of scope). Requires compiled C# project, not PowerShell-native. |
| InvokeBuild | PSake | If team already knows PSake. InvokeBuild is more modern with better task dependency handling. |
| InvokeBuild | Plain `build.ps1` | If build process stays simple (< 5 tasks). No module dependency needed. |
| GitHub Actions | Azure DevOps Pipelines | If organization uses Azure DevOps. Equivalent capability for PowerShell CI. |
| PSScriptAnalyzer | Manual review | Never for CI — PSScriptAnalyzer catches real bugs (uninitialized variables, compatibility issues). |
| PowerShellGet 2.x `Publish-Module` | PSResourceGet `Publish-PSResource` | PowerShellGet 2.x is safer for now — more enterprise environments have it. PSResourceGet is the future but adoption is still growing. |

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| Electron / web UI | Massive dependency (Node.js + Chromium). Overkill for a desktop tool. Doesn't integrate with PowerShell naturally. | WPF — zero external dependencies, native PowerShell integration. |
| .NET MAUI | Requires compiled C# project, separate build toolchain, .NET 8+ SDK. Poor PowerShell script integration. Cross-platform focus is irrelevant for Windows-only tool. | WPF — proven PowerShell-native UI path. |
| Pester 4.x | Incompatible `Should` syntax, deprecated scoping model. Project already uses Pester 5 patterns. | Pester 5.6+ — already adopted. |
| ScriptBlock-based UI (no XAML) | Building WPF in pure PowerShell code (no XAML) creates unreadable, unmaintainable UI code. | XAML files loaded at runtime — clean separation of layout and logic. |
| Selenium / UI automation for testing | Wrong tool — this isn't a web app. WPF UI testing (if ever needed) would use UI Automation framework. | Pester unit tests for logic; manual testing for UI initially. |
| `Add-Type` with inline C# for UI | Mixing C# source in PowerShell scripts is fragile, hard to debug, no IDE support for the C# portion. | XAML for layout, PowerShell for logic. Only use `Add-Type` for the assembly loading, not inline code. |
| Module-scoped `$script:` state for UI | Creates hidden coupling between UI and validation logic. | Pass results as parameters / data binding. Keep validation functions stateless (as they already are). |
| Custom test framework | No ecosystem, no CI integration, no community support. | Pester — it's the only real option for PowerShell testing. |

## Installation Commands

```powershell
# Development dependencies
Install-Module -Name Pester -MinimumVersion 5.6.0 -Force -Scope CurrentUser
Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser
Install-Module -Name InvokeBuild -Force -Scope CurrentUser

# Documentation (when preparing PSGallery release)
Install-Module -Name platyPS -Force -Scope CurrentUser

# Publishing (if using modern PSResourceGet)
Install-Module -Name Microsoft.PowerShell.PSResourceGet -Force -Scope CurrentUser
```

## Version Confidence

| Technology | Stated Version | Confidence | Notes |
|------------|----------------|------------|-------|
| Pester | 5.6+ | HIGH | v5.6.x was latest stable as of early 2025. Patch versions may have advanced but major API is stable. |
| PSScriptAnalyzer | 1.22+ | HIGH | Stable, infrequent major releases. API hasn't changed significantly in years. |
| InvokeBuild | 5.11+ | HIGH | Mature, stable module. Minor version bumps only. |
| WPF | .NET Framework 4.x | HIGH | Ships with Windows. No version to manage — it's part of the OS. |
| GitHub Actions | N/A (service) | HIGH | `windows-latest`, `actions/checkout@v4` are stable. |
| platyPS | 2.0+ | MEDIUM | v2 was in preview in early 2025. May have reached GA by now. Fall back to v0.14.2 (stable legacy) if v2 has issues. |
| PSResourceGet | 1.0+ | MEDIUM | v1.0 was released but enterprise adoption varies. PowerShellGet 2.x remains safe fallback. |

## Sources

- PowerShell module development best practices (Microsoft Learn documentation)
- Pester documentation (pester.dev) — v5 migration guide, Mock documentation
- PSScriptAnalyzer GitHub repository (PowerShell/PSScriptAnalyzer)
- InvokeBuild GitHub repository (nightroman/Invoke-Build)
- PowerShell Gallery publishing requirements (Microsoft Learn)
- WPF in PowerShell patterns (established community practice, Microsoft PowerShell documentation)
- GitHub Actions documentation for PowerShell workflows

---
*Stack research: 2026-03-04*
