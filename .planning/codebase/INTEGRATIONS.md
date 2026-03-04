# External Integrations

**Analysis Date:** 2026-03-04

## APIs & External Services

**Endpoint Security Platform:**
- Microsoft Defender for Endpoint / Microsoft Defender Antivirus local management plane - Module validates endpoint configuration and state through built-in Defender cmdlets and policy sources in `MDEValidator/MDEValidator.psm1` and documented behavior in `README.md`.
  - SDK/Client: Native PowerShell Defender cmdlets (`Get-MpPreference`, `Get-MpComputerStatus`) in `MDEValidator/MDEValidator.psm1`.
  - Auth: Windows host/admin context (no explicit token env var detected).

**Management Channel Detection:**
- Intune, Configuration Manager (SCCM), Security Settings Management, and GPO are inferred from registry evidence in `MDEValidator/MDEValidator.psm1`.
  - SDK/Client: Windows Registry provider (`Get-ItemProperty`, `Test-Path`) in `MDEValidator/MDEValidator.psm1`.
  - Auth: Local machine policy/registry access rights (no explicit credential provider in repo).

**Documentation/Reference URLs:**
- GitHub repository clone URL appears in installation docs in `README.md`.
- Manual SmartScreen test URL appears in module messages (`https://smartscreentestratings2.net/`) in `MDEValidator/MDEValidator.psm1`.

## Data Storage

**Databases:**
- Not detected.
  - Connection: Not applicable.
  - Client: Not applicable.

**File Storage:**
- Local filesystem only.
- Optional HTML output report is written to user-specified local path by `Get-MDEValidationReport` (`README.md`, `MDEValidator/MDEValidator.psm1`).

**Caching:**
- None detected.

## Authentication & Identity

**Auth Provider:**
- Custom/local OS identity and privilege model.
  - Implementation: Uses Windows principal elevation checks (`WindowsIdentity`/`WindowsPrincipal`) and relies on current shell permissions in `MDEValidator/MDEValidator.psm1`.

## Monitoring & Observability

**Error Tracking:**
- None detected (no external error tracking SDK/service in repo).

**Logs:**
- In-process structured result objects (`Pass`/`Fail`/`Warning`/`Info`) and optional console/HTML outputs in `MDEValidator/MDEValidator.psm1` and examples in `README.md`.

## CI/CD & Deployment

**Hosting:**
- Not applicable as a hosted service; distributed as a PowerShell module folder (`README.md`).

**CI Pipeline:**
- None detected (`.github/workflows/` not present).

## Environment Configuration

**Required env vars:**
- None detected.

**Secrets location:**
- Not applicable (no secret/token config files detected in scanned repository files).

## Webhooks & Callbacks

**Incoming:**
- None detected.

**Outgoing:**
- None detected.

---

*Integration audit: 2026-03-04*
