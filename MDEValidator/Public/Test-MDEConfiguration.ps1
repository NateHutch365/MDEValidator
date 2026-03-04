function Test-MDEConfiguration {
    <#
    .SYNOPSIS
        Runs all MDE configuration validation tests.
    
    .DESCRIPTION
        Executes a comprehensive validation of Microsoft Defender for Endpoint
        configuration settings and returns the results.
    
    .PARAMETER IncludeOnboarding
        Include MDE onboarding status check (requires elevated privileges).
    
    .PARAMETER IncludePolicyVerification
        Include policy registry verification sub-tests. These sub-tests verify that
        settings returned by Get-MpPreference match the corresponding registry/policy
        entries based on the device's management type (Intune vs Security Settings Management).
        
        Registry locations checked:
        - Intune: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager
        - SSM/GPO/SCCM: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender
        
        Note: Some tests (Edge SmartScreen, Exclusion Visibility) are not applicable
        for Security Settings Management as only Antivirus, ASR, EDR, and Firewall
        policies are supported.
    
    .EXAMPLE
        Test-MDEConfiguration
        
        Runs all MDE configuration validation tests.
    
    .EXAMPLE
        Test-MDEConfiguration -IncludeOnboarding
        
        Runs all tests including MDE onboarding status check.
    
    .EXAMPLE
        Test-MDEConfiguration -IncludePolicyVerification
        
        Runs all tests with policy registry verification sub-tests.
    
    .OUTPUTS
        Array of PSCustomObjects with validation results.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$IncludeOnboarding,
        
        [Parameter()]
        [switch]$IncludePolicyVerification
    )
    
    $results = @()
    
    Write-Verbose "Starting MDE configuration validation..."
    
    # Check for elevation
    $isElevated = Test-IsElevated
    if (-not $isElevated) {
        Write-Warning "Some tests may require elevated privileges. Consider running as Administrator."
    }
    
    # Run all validation tests
    $results += Test-MDEServiceStatus
    $results += Test-MDEPassiveMode
    
    $results += Test-MDERealTimeProtection
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Real-Time Protection' `
            -SettingKey 'RealTimeProtection' -IsApplicableToSSM $true
    }
    
    $results += Test-MDECloudProtection
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Cloud-Delivered Protection' `
            -SettingKey 'CloudProtection' -IsApplicableToSSM $true
    }
    
    $results += Test-MDECloudBlockLevel
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Cloud Block Level' `
            -SettingKey 'CloudBlockLevel' -IsApplicableToSSM $true
    }
    
    $results += Test-MDECloudExtendedTimeout
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Cloud Extended Timeout' `
            -SettingKey 'CloudExtendedTimeout' -IsApplicableToSSM $true
    }
    
    $results += Test-MDESampleSubmission
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Automatic Sample Submission' `
            -SettingKey 'SampleSubmission' -IsApplicableToSSM $true
    }
    
    $results += Test-MDEBehaviorMonitoring
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Behavior Monitoring' `
            -SettingKey 'BehaviorMonitoring' -IsApplicableToSSM $true
    }
    
    $results += Test-MDENetworkProtection
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Network Protection' `
            -SettingKey 'NetworkProtection' -IsApplicableToSSM $true
    }
    
    $results += Test-MDENetworkProtectionWindowsServer
    $results += Test-MDEDatagramProcessingWindowsServer
    $results += Test-MDEAutoExclusionsWindowsServer
    
    $results += Test-MDEAttackSurfaceReduction
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Attack Surface Reduction Rules' `
            -SettingKey 'AttackSurfaceReduction' -IsApplicableToSSM $true
    }
    
    $results += Test-MDEThreatDefaultActions
    $results += Test-MDETroubleshootingMode
    $results += Test-MDETamperProtection
    $results += Test-MDETamperProtectionForExclusions
    
    # Exclusion visibility tests - NOT applicable to Security Settings Management
    $results += Test-MDEExclusionVisibilityLocalAdmins
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Exclusion Visibility (Local Admins)' `
            -SettingKey 'HideExclusionsFromLocalAdmins' -IsApplicableToSSM $false
    }
    
    $results += Test-MDEExclusionVisibilityLocalUsers
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Exclusion Visibility (Local Users)' `
            -SettingKey 'HideExclusionsFromLocalUsers' -IsApplicableToSSM $false
    }
    
    # Edge SmartScreen tests - NOT applicable to Security Settings Management
    # These are Edge browser policies, not Windows Defender policies
    $results += Test-MDESmartScreen
    $results += Test-MDESmartScreenPUA
    $results += Test-MDESmartScreenPromptOverride
    $results += Test-MDESmartScreenDownloadOverride
    $results += Test-MDESmartScreenDomainExclusions
    $results += Test-MDESmartScreenAppRepExclusions
    
    $results += Test-MDEDisableCatchupQuickScan
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Catchup Quick Scan' `
            -SettingKey 'CatchupQuickScan' -IsApplicableToSSM $true
    }
    
    $results += Test-MDERealTimeScanDirection
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Real Time Scan Direction' `
            -SettingKey 'RealTimeScanDirection' -IsApplicableToSSM $true
    }
    
    $results += Test-MDESignatureUpdateFallbackOrder
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Signature Update Fallback Order' `
            -SettingKey 'SignatureFallbackOrder' -IsApplicableToSSM $true
    }
    
    $results += Test-MDESignatureUpdateInterval
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Signature Update Interval' `
            -SettingKey 'SignatureUpdateInterval' -IsApplicableToSSM $true
    }
    
    $results += Test-MDEDisableLocalAdminMerge
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Disable Local Admin Merge' `
            -SettingKey 'DisableLocalAdminMerge' -IsApplicableToSSM $true
    }
    
    $results += Test-MDEFileHashComputation
    
    if ($IncludeOnboarding) {
        $results += Test-MDEOnboardingStatus
    }
    
    $results += Test-MDEDeviceTags
    
    Write-Verbose "MDE configuration validation completed."
    
    return $results
}