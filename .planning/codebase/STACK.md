# Technology Stack

**Analysis Date:** 2026-03-04

## Languages

**Primary:**
- PowerShell 5.1+ - Core module implementation in `MDEValidator/MDEValidator.psm1` and manifest in `MDEValidator/MDEValidator.psd1`.

**Secondary:**
- Markdown - User/developer documentation in `README.md` and `.github/prompts/*.prompt.md`.
- JSON - Agent/tooling configuration in `.claude/get-shit-done/templates/config.json` and `.claude/package.json`.

## Runtime

**Environment:**
- Windows PowerShell / PowerShell Core (Desktop and Core editions) with minimum `PowerShellVersion = '5.1'` declared in `MDEValidator/MDEValidator.psd1`.
- Windows OS target (Windows 10/11 and Windows Server 2016+) documented in `README.md`.

**Package Manager:**
- PowerShell module loading/import (`Import-Module`) for runtime module usage from `README.md`.
- PowerShell Gallery (`Install-Module`) used for test dependency installation (`Pester`) in `README.md`.
- npm metadata present for local `.claude` tooling only in `.claude/package.json`.
- Lockfile: missing.

## Frameworks

**Core:**
- PowerShell Script Module pattern (`.psm1` + `.psd1`) - Main implementation and exported API surface in `MDEValidator/MDEValidator.psm1` and `MDEValidator/MDEValidator.psd1`.
- Windows Defender PowerShell cmdlets (`Get-MpPreference`, `Get-MpComputerStatus`) - Defender state interrogation in `MDEValidator/MDEValidator.psm1`.

**Testing:**
- Pester (version not pinned in repo) - Module tests in `Tests/MDEValidator.Tests.ps1` and install/run guidance in `README.md`.

**Build/Dev:**
- Not detected for compiled build systems (no `.sln`, `.csproj`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `package.json` at repository root).

## Key Dependencies

**Critical:**
- Built-in Defender cmdlet surface (`Get-MpPreference`, `Get-MpComputerStatus`) - Required for most validation checks in `MDEValidator/MDEValidator.psm1`.
- Windows Service APIs (`Get-Service` for `WinDefend`/`Sense`) - Service and onboarding checks in `MDEValidator/MDEValidator.psm1`.
- Windows Registry provider (`HKLM:` paths via `Get-ItemProperty`) - Policy and management detection in `MDEValidator/MDEValidator.psm1`.

**Infrastructure:**
- Pester module - Automated test runner in `Tests/MDEValidator.Tests.ps1`.
- .NET utility class `System.Net.WebUtility` - HTML encoding in `MDEValidator/MDEValidator.psm1`.

## Configuration

**Environment:**
- No `.env`-style runtime configuration detected in repository root scan.
- Configuration is host-state driven (registry, Defender cmdlets, service status) rather than env vars, implemented in `MDEValidator/MDEValidator.psm1`.

**Build:**
- Module metadata and export configuration in `MDEValidator/MDEValidator.psd1`.
- No CI workflow configuration detected under `.github/workflows/`.

## Platform Requirements

**Development:**
- Windows endpoint with Defender installed and PowerShell 5.1+ (from `README.md` and `MDEValidator/MDEValidator.psd1`).
- Administrator privileges recommended to access full policy/registry surfaces (`README.md`).

**Production:**
- Deployment target is local/enterprise Windows endpoints running Microsoft Defender for Endpoint; module executed in host PowerShell session (`README.md`, `MDEValidator/MDEValidator.psm1`).

---

*Stack analysis: 2026-03-04*
