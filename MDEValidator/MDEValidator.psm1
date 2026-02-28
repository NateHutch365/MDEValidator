#Requires -Version 5.1

<#
.SYNOPSIS
    MDEValidator - Microsoft Defender for Endpoint Configuration Validation Module

.DESCRIPTION
    This module provides functions to validate Microsoft Defender for Endpoint (MDE)
    configurations and security settings on Windows endpoints.

.NOTES
    Author: MDEValidator Team
    Version: 2.0.0
#>

# Dot-source all private (helper) functions
$privatePath = Join-Path $PSScriptRoot 'Private'
if (Test-Path $privatePath) {
    Get-ChildItem -Path $privatePath -Filter '*.ps1' -Recurse | ForEach-Object {
        . $_.FullName
    }
}

# Dot-source all public functions
$publicPath = Join-Path $PSScriptRoot 'Public'
if (Test-Path $publicPath) {
    Get-ChildItem -Path $publicPath -Filter '*.ps1' -Recurse | ForEach-Object {
        . $_.FullName
    }
}

# Export public functions
Export-ModuleMember -Function @(
    'Test-MDEConfiguration',
    'Get-MDEValidationReport',
    'Get-MDEOperatingSystemInfo',
    'Get-MDESecuritySettingsManagementStatus',
    'Get-MDEOnboardingStatusString',
    'Get-MDEManagementType',
    'Get-MDEManagedDefenderProductType',
    'Get-MDEManagementTypeFallback',
    'Get-MDEPolicyRegistryPath',
    'Get-MDEPolicySettingConfig',
    'Test-MDEPolicyRegistryValue',
    'Test-MDEPolicyRegistryVerification',
    'Test-MDEServiceStatus',
    'Test-MDEPassiveMode',
    'Test-MDERealTimeProtection',
    'Test-MDECloudProtection',
    'Test-MDECloudBlockLevel',
    'Test-MDECloudExtendedTimeout',
    'Test-MDESampleSubmission',
    'Test-MDEBehaviorMonitoring',
    'Test-MDEOnboardingStatus',
    'Test-MDEDeviceTags',
    'Test-MDENetworkProtection',
    'Test-MDENetworkProtectionWindowsServer',
    'Test-MDEDatagramProcessingWindowsServer',
    'Test-MDEAutoExclusionsWindowsServer',
    'Test-MDEAttackSurfaceReduction',
    'Test-MDEThreatDefaultActions',
    'Test-MDETroubleshootingMode',
    'Test-MDETamperProtection',
    'Test-MDETamperProtectionForExclusions',
    'Test-MDEExclusionVisibilityLocalAdmins',
    'Test-MDEExclusionVisibilityLocalUsers',
    'Test-MDESmartScreen',
    'Test-MDESmartScreenPUA',
    'Test-MDESmartScreenPromptOverride',
    'Test-MDESmartScreenDownloadOverride',
    'Test-MDESmartScreenDomainExclusions',
    'Test-MDESmartScreenAppRepExclusions',
    'Test-MDEDisableCatchupQuickScan',
    'Test-MDERealTimeScanDirection',
    'Test-MDESignatureUpdateFallbackOrder',
    'Test-MDESignatureUpdateInterval',
    'Test-MDEDisableLocalAdminMerge',
    'Test-MDEFileHashComputation',
    'Show-MDEValidatorUI'
)
