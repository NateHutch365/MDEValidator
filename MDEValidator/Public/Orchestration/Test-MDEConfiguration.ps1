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
    
    # Pre-fetch shared objects once to avoid redundant WMI calls across all test functions.
    # Each Test-MDE* function accepts optional -MpPreference/-MpComputerStatus parameters.
    # When provided, the function uses the shared instance; when omitted (standalone use),
    # the function fetches its own.
    $sharedMpPreference = $null
    $sharedMpComputerStatus = $null
    
    try {
        Write-Verbose "Pre-fetching Get-MpPreference (shared instance for all tests)..."
        $sharedMpPreference = Get-MpPreference -ErrorAction Stop
        Write-Debug "Get-MpPreference pre-fetch succeeded"
    }
    catch {
        Write-Warning "Unable to pre-fetch Get-MpPreference: $_. Individual tests will attempt their own calls."
    }
    
    try {
        Write-Verbose "Pre-fetching Get-MpComputerStatus (shared instance for all tests)..."
        $sharedMpComputerStatus = Get-MpComputerStatus -ErrorAction Stop
        Write-Debug "Get-MpComputerStatus pre-fetch succeeded"
    }
    catch {
        Write-Warning "Unable to pre-fetch Get-MpComputerStatus: $_. Individual tests will attempt their own calls."
    }
    
    # Build splat hashtables for passing shared instances
    $mpPrefSplat = @{}
    if ($null -ne $sharedMpPreference) { $mpPrefSplat['MpPreference'] = $sharedMpPreference }
    
    $mpStatusSplat = @{}
    if ($null -ne $sharedMpComputerStatus) { $mpStatusSplat['MpComputerStatus'] = $sharedMpComputerStatus }
    
    $mpBothSplat = @{}
    if ($null -ne $sharedMpPreference) { $mpBothSplat['MpPreference'] = $sharedMpPreference }
    if ($null -ne $sharedMpComputerStatus) { $mpBothSplat['MpComputerStatus'] = $sharedMpComputerStatus }
    
    # Run all validation tests
    $results += Test-MDEServiceStatus
    $results += Test-MDEPassiveMode @mpStatusSplat
    
    $results += Test-MDERealTimeProtection @mpPrefSplat
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Real-Time Protection' `
            -SettingKey 'RealTimeProtection' -IsApplicableToSSM $true
    }
    
    $results += Test-MDECloudProtection @mpPrefSplat
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Cloud-Delivered Protection' `
            -SettingKey 'CloudProtection' -IsApplicableToSSM $true
    }
    
    $results += Test-MDECloudBlockLevel @mpPrefSplat
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Cloud Block Level' `
            -SettingKey 'CloudBlockLevel' -IsApplicableToSSM $true
    }
    
    $results += Test-MDECloudExtendedTimeout @mpPrefSplat
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Cloud Extended Timeout' `
            -SettingKey 'CloudExtendedTimeout' -IsApplicableToSSM $true
    }
    
    $results += Test-MDESampleSubmission @mpPrefSplat
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Automatic Sample Submission' `
            -SettingKey 'SampleSubmission' -IsApplicableToSSM $true
    }
    
    $results += Test-MDEBehaviorMonitoring @mpPrefSplat
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Behavior Monitoring' `
            -SettingKey 'BehaviorMonitoring' -IsApplicableToSSM $true
    }
    
    $results += Test-MDENetworkProtection @mpPrefSplat
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Network Protection' `
            -SettingKey 'NetworkProtection' -IsApplicableToSSM $true
    }
    
    $results += Test-MDENetworkProtectionWindowsServer
    $results += Test-MDEDatagramProcessingWindowsServer
    $results += Test-MDEAutoExclusionsWindowsServer @mpPrefSplat
    
    $results += Test-MDEAttackSurfaceReduction @mpPrefSplat
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Attack Surface Reduction Rules' `
            -SettingKey 'AttackSurfaceReduction' -IsApplicableToSSM $true
    }
    
    $results += Test-MDEThreatDefaultActions @mpBothSplat
    $results += Test-MDETroubleshootingMode @mpPrefSplat
    $results += Test-MDETamperProtection @mpStatusSplat
    $results += Test-MDETamperProtectionForExclusions @mpStatusSplat
    
    # Exclusion visibility tests - NOT applicable to Security Settings Management
    $results += Test-MDEExclusionVisibilityLocalAdmins @mpPrefSplat
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Exclusion Visibility (Local Admins)' `
            -SettingKey 'HideExclusionsFromLocalAdmins' -IsApplicableToSSM $false
    }
    
    $results += Test-MDEExclusionVisibilityLocalUsers @mpPrefSplat
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Exclusion Visibility (Local Users)' `
            -SettingKey 'HideExclusionsFromLocalUsers' -IsApplicableToSSM $false
    }
    
    # Edge SmartScreen tests - NOT applicable to Security Settings Management
    $results += Test-MDESmartScreen
    $results += Test-MDESmartScreenPUA
    $results += Test-MDESmartScreenPromptOverride
    $results += Test-MDESmartScreenDownloadOverride
    $results += Test-MDESmartScreenDomainExclusions
    $results += Test-MDESmartScreenAppRepExclusions
    
    $results += Test-MDEDisableCatchupQuickScan @mpPrefSplat
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Catchup Quick Scan' `
            -SettingKey 'CatchupQuickScan' -IsApplicableToSSM $true
    }
    
    $results += Test-MDERealTimeScanDirection @mpPrefSplat
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Real Time Scan Direction' `
            -SettingKey 'RealTimeScanDirection' -IsApplicableToSSM $true
    }
    
    $results += Test-MDESignatureUpdateFallbackOrder @mpPrefSplat
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Signature Update Fallback Order' `
            -SettingKey 'SignatureFallbackOrder' -IsApplicableToSSM $true
    }
    
    $results += Test-MDESignatureUpdateInterval @mpPrefSplat
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Signature Update Interval' `
            -SettingKey 'SignatureUpdateInterval' -IsApplicableToSSM $true
    }
    
    $results += Test-MDEDisableLocalAdminMerge
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Disable Local Admin Merge' `
            -SettingKey 'DisableLocalAdminMerge' -IsApplicableToSSM $true
    }
    
    $results += Test-MDEFileHashComputation @mpPrefSplat
    
    if ($IncludeOnboarding) {
        $results += Test-MDEOnboardingStatus
    }
    
    $results += Test-MDEDeviceTags
    
    Write-Verbose "MDE configuration validation completed. Total results: $($results.Count)"
    
    return $results
}
