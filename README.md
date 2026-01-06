# MDEValidator

A PowerShell module to validate Microsoft Defender for Endpoint (MDE) configurations and security settings on Windows endpoints.

## Overview

MDEValidator provides a comprehensive set of validation checks for Microsoft Defender for Endpoint configurations, helping administrators and security teams verify that endpoints are properly configured for optimal protection.

## Features

- **Service Status Validation**: Checks if Windows Defender service is running and configured properly
- **Passive Mode Detection**: Validates Windows Defender passive mode status
- **Real-Time Protection**: Validates that real-time protection is enabled
- **Cloud-Delivered Protection**: Verifies cloud-delivered protection (MAPS) settings
- **Cloud Block Level**: Checks cloud block level configuration for immediate blocking
- **Cloud Extended Timeout**: Validates extended cloud check timeout settings
- **Automatic Sample Submission**: Checks sample submission configuration
- **Behavior Monitoring**: Validates behavior monitoring status
- **MDE Onboarding Status**: Verifies device onboarding to Microsoft Defender for Endpoint
- **Network Protection**: Checks network protection configuration
- **Network Protection (Windows Server)**: Validates network protection on Windows Server editions
- **Datagram Processing (Windows Server)**: Checks datagram processing configuration on Windows Server
- **Auto Exclusions for Servers**: Checks if DisableAutoExclusions is enabled on Windows Server (Pass if enabled, Warning if not)
- **Attack Surface Reduction (ASR) Rules**: Validates ASR rules configuration
- **Threat Default Actions**: Checks default actions for threat severity levels (Low, Moderate, High, Severe) showing both registry values and settings (e.g., 2 (Quarantine))
- **Tamper Protection**: Validates tamper protection status
- **Tamper Protection for Exclusions**: Checks if Tamper Protection for Exclusions is properly configured
- **Exclusion Visibility**: Validates settings that control whether local users and administrators can view exclusions (configurable via Group Policy or Intune)
- **Edge SmartScreen Policies**: Comprehensive validation of Microsoft Edge SmartScreen settings including:
  - SmartScreen enablement
  - Potentially Unwanted Applications (PUA) blocking
  - User override controls for prompts
  - User override controls for downloads
  - Domain exclusions
  - Application reputation exclusions
- **Catchup Quick Scan**: Validates that catchup quick scan is enabled to ensure missed scheduled scans are performed
- **Real-Time Scan Direction**: Checks scan direction settings (incoming/outgoing/both)
- **Signature Update Settings**: Validates signature update fallback order and interval
- **Disable Local Admin Merge**: Checks if local administrator exclusion merging is disabled
- **File Hash Computation**: Validates file hash computation settings
- **Policy Registry Verification**: Optional verification that Get-MpPreference settings match registry/policy entries based on management type (Intune, GPO, SCCM, SSM)
- **Multiple Output Formats**: Console, HTML, and PowerShell object output options

## Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or later
- Windows Defender Antivirus installed
- Administrator privileges (recommended for full functionality)

## Installation

### Manual Installation

1. Download or clone this repository
2. Copy the `MDEValidator` folder to one of your PowerShell module directories:
   - User: `$HOME\Documents\PowerShell\Modules\`
   - System: `$env:ProgramFiles\PowerShell\Modules\`

```powershell
# Clone the repository
git clone https://github.com/NateHutch365/MDEValidator.git

# Copy to user modules folder
Copy-Item -Path ".\MDEValidator\MDEValidator" -Destination "$HOME\Documents\PowerShell\Modules\" -Recurse
```

### Direct Import

You can also import the module directly without installing:

```powershell
Import-Module .\MDEValidator\MDEValidator.psd1
```

## Usage

### Quick Start

```powershell
# Import the module
Import-Module MDEValidator

# Run all validation tests and display console report
Get-MDEValidationReport

# Run all tests including MDE onboarding status
Get-MDEValidationReport -IncludeOnboarding
```

### Available Functions

#### Get-MDEValidationReport

Runs all validation tests and generates a formatted report.

```powershell
# Console output (default)
Get-MDEValidationReport

# HTML report
Get-MDEValidationReport -OutputFormat HTML -OutputPath "C:\Reports\MDEReport.html"

# PowerShell objects for further processing
$results = Get-MDEValidationReport -OutputFormat Object
$results | Where-Object { $_.Status -eq 'Fail' }
```

#### Test-MDEConfiguration

Runs all validation tests and returns results as PowerShell objects.

```powershell
# Run all basic tests
$results = Test-MDEConfiguration

# Include MDE onboarding status check
$results = Test-MDEConfiguration -IncludeOnboarding

# Include policy registry verification sub-tests
$results = Test-MDEConfiguration -IncludePolicyVerification

# Combine both options
$results = Test-MDEConfiguration -IncludeOnboarding -IncludePolicyVerification
```

**Note on -IncludePolicyVerification**: When `HideExclusionsFromLocalAdmins` is enabled via Intune, it restricts SYSTEM/Administrator access to the entire Intune policy registry path (`HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager`). This means policy verification sub-tests will not be able to access the registry to verify policy values when this security feature is enabled.

To identify if this limitation applies to your environment:
- Check if exclusions appear as "{N/A: Administrators are not allowed to view exclusions}" when running `Get-MpPreference`
- If you receive "Access Denied" errors when attempting to read the Intune Policy Manager registry path
- If you're managing Windows Defender via Intune with `HideExclusionsFromLocalAdmins` enabled

Note: This limitation only affects Intune-managed devices with this specific security setting enabled. GPO/SCCM/SSM-managed devices can use `-IncludePolicyVerification` without restrictions.

#### Individual Test Functions

You can run individual tests for specific validations:

```powershell
# Core Defender Status
Test-MDEServiceStatus
Test-MDEPassiveMode

# Protection Features
Test-MDERealTimeProtection
Test-MDECloudProtection
Test-MDECloudBlockLevel
Test-MDECloudExtendedTimeout
Test-MDESampleSubmission
Test-MDEBehaviorMonitoring
Test-MDENetworkProtection
Test-MDENetworkProtectionWindowsServer
Test-MDEDatagramProcessingWindowsServer
Test-MDEAutoExclusionsWindowsServer

# MDE Advanced Features
Test-MDEOnboardingStatus
Test-MDEAttackSurfaceReduction
Test-MDEThreatDefaultActions
Test-MDETamperProtection
Test-MDETamperProtectionForExclusions

# Exclusion Visibility
Test-MDEExclusionVisibilityLocalAdmins
Test-MDEExclusionVisibilityLocalUsers

# Edge SmartScreen Policies
Test-MDESmartScreen
Test-MDESmartScreenPUA
Test-MDESmartScreenPromptOverride
Test-MDESmartScreenDownloadOverride
Test-MDESmartScreenDomainExclusions
Test-MDESmartScreenAppRepExclusions

# Scan and Update Configuration
Test-MDEDisableCatchupQuickScan
Test-MDERealTimeScanDirection
Test-MDESignatureUpdateFallbackOrder
Test-MDESignatureUpdateInterval
Test-MDEFileHashComputation

# Policy Management
Test-MDEDisableLocalAdminMerge

# Policy Verification (helper functions)
Test-MDEPolicyRegistryValue
Test-MDEPolicyRegistryVerification
```

### Output Example

Console output:

```
========================================
  MDE Configuration Validation Report
  Generated: 2024-01-15 10:30:45
  Computer: WORKSTATION01
========================================

[PASS] Windows Defender Service Status
         Windows Defender service is running and set to start automatically.

[INFO] Passive Mode
         Windows Defender is in active mode (not passive).

[PASS] Real-Time Protection
         Real-time protection is enabled.

[PASS] Cloud-Delivered Protection
         Cloud-delivered protection is enabled at 'Advanced' level.

[PASS] Cloud Block Level
         Cloud block level is set to 'High' for enhanced protection.

[PASS] Cloud Extended Timeout
         Cloud extended timeout is set to 50 seconds for thorough analysis.

[WARN] Automatic Sample Submission
         Automatic sample submission is set to 'Always Prompt'.
         Recommendation: Consider enabling automatic sample submission for better threat detection.

[PASS] Behavior Monitoring
         Behavior monitoring is enabled.

[FAIL] Network Protection
         Network protection is disabled.
         Recommendation: Enable network protection via Group Policy or 'Set-MpPreference -EnableNetworkProtection Enabled'.

[WARN] Attack Surface Reduction Rules
         ASR rules configured: 10 total (0 enabled/blocked, 10 audit, 0 disabled). All configured rules are in Audit mode only.
         Recommendation: Consider enabling Block mode for ASR rules after validating Audit mode results.

[PASS] Tamper Protection
         Tamper protection is enabled.

[WARN] Tamper Protection for Exclusions
         Tamper Protection for Exclusions is not configured.
         Recommendation: Enable Tamper Protection for Exclusions on supported platforms.

[PASS] Exclusion Visibility (Local Admins)
         Exclusions are hidden from local administrators. (via Intune)

[PASS] Exclusion Visibility (Local Users)
         Exclusions are hidden from local users. (via Intune)

[PASS] Edge SmartScreen
         Microsoft Edge SmartScreen is enabled.

[PASS] Disable Local Admin Merge
         Local administrator exclusion merge is disabled (DisableLocalAdminMerge=1).

========================================
  Summary: 11/16 Passed
  Passed: 11 | Failed: 1 | Warnings: 3 | Info: 1
========================================
```

HTML report output:

![MDE HTML Report](images/html_report_screenshot.png)

## Test Status Values

| Status | Description |
|--------|-------------|
| Pass | The configuration meets recommended security standards |
| Fail | The configuration does not meet security requirements |
| Warning | The configuration is partially compliant or could be improved |
| Info | Informational message about the configuration |
| NotApplicable | The test is not applicable to this system |

## Running Tests

The module includes Pester tests for validation:

```powershell
# Install Pester if not already installed
Install-Module -Name Pester -Force -SkipPublisherCheck

# Run tests
Invoke-Pester -Path .\Tests\MDEValidator.Tests.ps1
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License. All content is free to use, modify, and distribute under the terms of the MIT License.

## Disclaimer

This tool is provided as-is for validation purposes. Always verify configurations against your organization's security policies and Microsoft's official documentation.