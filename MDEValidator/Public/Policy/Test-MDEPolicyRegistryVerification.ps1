function Test-MDEPolicyRegistryVerification {
    <#
    .SYNOPSIS
        Performs registry verification sub-test for an MDE setting.
    
    .DESCRIPTION
        Creates a sub-test result that verifies whether a policy setting exists
        in the correct registry location based on management type.
    
    .PARAMETER ParentTestName
        The name of the parent test (e.g., 'Real-Time Protection').
    
    .PARAMETER SettingKey
        The logical setting key (e.g., 'RealTimeProtection'). When provided,
        the function automatically determines the correct path, setting name,
        and display name based on the management type.
    
    .PARAMETER SettingName
        The registry setting name to verify (deprecated, use SettingKey instead).
    
    .PARAMETER SettingDisplayName
        Human-readable name for the setting (deprecated, use SettingKey instead).
    
    .PARAMETER SubPath
        Optional subpath under the main policy path (deprecated, use SettingKey instead).
    
    .PARAMETER ExpectedValue
        The expected value for the setting (optional).
    
    .PARAMETER IsApplicableToSSM
        Whether this setting is applicable to Security Settings Management.
        Default is $true. Set to $false for settings not supported by SSM.
    
    .OUTPUTS
        PSCustomObject with validation results for the registry verification sub-test.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ParentTestName,
        
        [Parameter()]
        [string]$SettingKey,
        
        [Parameter()]
        [string]$SettingName,
        
        [Parameter()]
        [string]$SettingDisplayName,
        
        [Parameter()]
        [string]$SubPath = '',
        
        [Parameter()]
        $ExpectedValue = $null,
        
        [Parameter()]
        [bool]$IsApplicableToSSM = $true
    )
    
    Write-Verbose "Performing policy registry verification for '$ParentTestName'..."
    
    $testName = "$ParentTestName - Policy Registry Verification"
    
    $managementType = Get-MDEManagementType
    
    # Check if this test is applicable based on management type
    if ($managementType -eq 'None') {
        return Write-ValidationResult -TestName $testName -Status 'Info' `
            -Message "Policy registry verification skipped - device management type could not be determined."
    }
    
    # Check if SSM-incompatible test on SSM-managed device
    if (-not $IsApplicableToSSM -and $managementType -eq 'SecuritySettingsManagement') {
        return Write-ValidationResult -TestName $testName -Status 'NotApplicable' `
            -Message "This setting cannot be enforced via Security Settings Management. Only Antivirus, ASR, EDR, and Firewall policies are supported."
    }
    
    # Use SettingKey if provided, otherwise fall back to legacy parameters
    if (-not [string]::IsNullOrEmpty($SettingKey)) {
        $regResult = Test-MDEPolicyRegistryValue -SettingKey $SettingKey -ExpectedValue $ExpectedValue
        # Get the display name from the configuration
        $config = Get-MDEPolicySettingConfig -SettingKey $SettingKey -ManagementType $managementType
        $displayName = if ($null -ne $config) { $config.DisplayName } else { $SettingKey }
    } else {
        $regResult = Test-MDEPolicyRegistryValue -SettingName $SettingName -SubPath $SubPath -ExpectedValue $ExpectedValue
        $displayName = $SettingDisplayName
    }
    
    if ($regResult.Found) {
        $valueInfo = if ($null -ne $ExpectedValue) {
            $matchStatus = if ($regResult.Value -eq $ExpectedValue) { "matches expected" } else { "differs from expected" }
            "Value: $($regResult.Value) ($matchStatus value: $ExpectedValue)"
        } else {
            "Value: $($regResult.Value)"
        }
        
        return Write-ValidationResult -TestName $testName -Status 'Pass' `
            -Message "Policy registry entry verified. $displayName found at $($regResult.Path)\$($regResult.SettingName). $valueInfo. Management type: $($regResult.ManagementType)."
    } else {
        $recommendation = @"
The policy registry entry for $displayName was not found at $($regResult.Path)\$($regResult.SettingName).
This may indicate:
- The policy has not been deployed via $($regResult.ManagementType)
- The policy is configured locally but not via management tools
- There may be a sync issue with the management platform
Verify the policy is correctly configured in your management solution ($($regResult.ManagementType)).
"@
        
        return Write-ValidationResult -TestName $testName -Status 'Warning' `
            -Message "Policy registry entry not found. Expected $displayName at $($regResult.Path)\$($regResult.SettingName). Management type: $($regResult.ManagementType)." `
            -Recommendation $recommendation
    }
}
