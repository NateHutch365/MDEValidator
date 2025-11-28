# MDEValidator

A PowerShell module to validate Microsoft Defender for Endpoint (MDE) configurations and security settings on Windows endpoints.

## Overview

MDEValidator provides a comprehensive set of validation checks for Microsoft Defender for Endpoint configurations, helping administrators and security teams verify that endpoints are properly configured for optimal protection.

## Features

- **Service Status Validation**: Checks if Windows Defender service is running and configured properly
- **Real-Time Protection**: Validates that real-time protection is enabled
- **Cloud-Delivered Protection**: Verifies cloud-delivered protection (MAPS) settings
- **Automatic Sample Submission**: Checks sample submission configuration
- **Behavior Monitoring**: Validates behavior monitoring status
- **MDE Onboarding Status**: Verifies device onboarding to Microsoft Defender for Endpoint
- **Network Protection**: Checks network protection configuration
- **Attack Surface Reduction (ASR) Rules**: Validates ASR rules configuration
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
```

#### Individual Test Functions

You can run individual tests for specific validations:

```powershell
# Test Windows Defender service status
Test-MDEServiceStatus

# Test real-time protection
Test-MDERealTimeProtection

# Test cloud-delivered protection
Test-MDECloudProtection

# Test automatic sample submission
Test-MDESampleSubmission

# Test behavior monitoring
Test-MDEBehaviorMonitoring

# Test MDE onboarding status
Test-MDEOnboardingStatus

# Test network protection
Test-MDENetworkProtection

# Test Attack Surface Reduction rules
Test-MDEAttackSurfaceReduction
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

[PASS] Real-Time Protection
         Real-time protection is enabled.

[PASS] Cloud-Delivered Protection
         Cloud-delivered protection is enabled at 'Advanced' level.

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

========================================
  Summary: 4/7 Passed
  Passed: 4 | Failed: 1 | Warnings: 2
========================================
```

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

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided as-is for validation purposes. Always verify configurations against your organization's security policies and Microsoft's official documentation.