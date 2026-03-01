function Get-MDEPolicySettingConfig {
    <#
    .SYNOPSIS
        Gets the registry configuration for a policy setting based on management type.
    
    .DESCRIPTION
        Returns the correct registry path and setting name for a policy setting
        based on whether the device is managed by Intune or GPO/SSM/SCCM.
        
        Intune stores settings directly in Policy Manager with different key names.
        GPO/SSM/SCCM stores settings in subfolders with traditional key names.
    
    .PARAMETER SettingKey
        The logical setting key (e.g., 'RealTimeProtection', 'CloudProtection').
    
    .PARAMETER ManagementType
        The management type: 'Intune', 'SecuritySettingsManagement', 'SCCM', 'GPO', or 'None'
    
    .OUTPUTS
        PSCustomObject with properties:
        - Path: The full registry path for the setting
        - SettingName: The registry value name
        - DisplayName: Human-readable name for the setting
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'RealTimeProtection',
            'CloudProtection',
            'CloudBlockLevel',
            'CloudExtendedTimeout',
            'SampleSubmission',
            'BehaviorMonitoring',
            'NetworkProtection',
            'AttackSurfaceReduction',
            'HideExclusionsFromLocalUsers',
            'HideExclusionsFromLocalAdmins',
            'CatchupQuickScan',
            'RealTimeScanDirection',
            'SignatureFallbackOrder',
            'SignatureUpdateInterval',
            'DisableLocalAdminMerge'
        )]
        [string]$SettingKey,
        
        [Parameter(Mandatory)]
        [ValidateSet('Intune', 'SecuritySettingsManagement', 'SCCM', 'GPO', 'None')]
        [string]$ManagementType
    )
    
    Write-Verbose "Getting policy setting config for '$SettingKey' (ManagementType: $ManagementType)..."
    
    # Define the configuration mappings
    # 
    # Registry naming conventions differ between Intune and GPO:
    # - Intune (Policy Manager): Uses "Allow" prefix (e.g., AllowRealtimeMonitoring, AllowBehaviorMonitoring)
    #   where 1 = enabled and 0 = disabled
    # - GPO/SCCM/SSM: Uses "Disable" prefix (e.g., DisableRealtimeMonitoring, DisableBehaviorMonitoring)
    #   where 0 = enabled and 1 = disabled
    # This is due to the different CSP (Configuration Service Provider) implementations.
    
    $intuneBasePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'
    $gpoBasePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    
    # Configuration: [SettingKey] = @{ Intune = @{Path, Name}; GPO = @{Path, Name}; DisplayName }
    $settingConfigs = @{
        'RealTimeProtection' = @{
            Intune = @{ Path = $intuneBasePath; Name = 'AllowRealtimeMonitoring' }
            GPO = @{ Path = "$gpoBasePath\Real-Time Protection"; Name = 'DisableRealtimeMonitoring' }
            DisplayName = 'Real-Time Protection'
        }
        'CloudProtection' = @{
            # Note: "Spynet" is the legacy registry path name for Cloud Protection/MAPS
            # (Microsoft Active Protection Service). Microsoft still uses this path internally.
            Intune = @{ Path = $intuneBasePath; Name = 'AllowCloudProtection' }
            GPO = @{ Path = "$gpoBasePath\Spynet"; Name = 'SpynetReporting' }
            DisplayName = 'Cloud Protection (MAPS)'
        }
        'CloudBlockLevel' = @{
            Intune = @{ Path = "$gpoBasePath\MpEngine"; Name = 'MpCloudBlockLevel' }
            GPO = @{ Path = "$gpoBasePath\MpEngine"; Name = 'MpCloudBlockLevel' }
            DisplayName = 'Cloud Block Level'
        }
        'CloudExtendedTimeout' = @{
            Intune = @{ Path = "$gpoBasePath\MpEngine"; Name = 'MpBafsExtendedTimeout' }
            GPO = @{ Path = "$gpoBasePath\MpEngine"; Name = 'MpBafsExtendedTimeout' }
            DisplayName = 'Cloud Extended Timeout'
        }
        'SampleSubmission' = @{
            # Note: "Spynet" is the legacy registry path name for Cloud Protection/MAPS
            Intune = @{ Path = $intuneBasePath; Name = 'SubmitSamplesConsent' }
            GPO = @{ Path = "$gpoBasePath\Spynet"; Name = 'SubmitSamplesConsent' }
            DisplayName = 'Sample Submission'
        }
        'BehaviorMonitoring' = @{
            Intune = @{ Path = $intuneBasePath; Name = 'AllowBehaviorMonitoring' }
            GPO = @{ Path = "$gpoBasePath\Real-Time Protection"; Name = 'DisableBehaviorMonitoring' }
            DisplayName = 'Behavior Monitoring'
        }
        'NetworkProtection' = @{
            Intune = @{ Path = $intuneBasePath; Name = 'EnableNetworkProtection' }
            GPO = @{ Path = "$gpoBasePath\Windows Defender Exploit Guard\Network Protection"; Name = 'EnableNetworkProtection' }
            DisplayName = 'Network Protection'
        }
        'AttackSurfaceReduction' = @{
            # ASR rules verification: Intune stores rules in a combined ASRRules key,
            # while GPO uses ExploitGuard_ASR_Rules. Both indicate ASR is configured.
            Intune = @{ Path = $intuneBasePath; Name = 'ASRRules' }
            GPO = @{ Path = "$gpoBasePath\Windows Defender Exploit Guard\ASR"; Name = 'ExploitGuard_ASR_Rules' }
            DisplayName = 'Attack Surface Reduction Rules'
        }
        'HideExclusionsFromLocalUsers' = @{
            Intune = @{ Path = $intuneBasePath; Name = 'HideExclusionsFromLocalUsers' }
            GPO = @{ Path = "$gpoBasePath\Exclusions"; Name = 'HideExclusionsFromLocalUsers' }
            DisplayName = 'Hide Exclusions From Local Users'
        }
        'HideExclusionsFromLocalAdmins' = @{
            Intune = @{ Path = $intuneBasePath; Name = 'HideExclusionsFromLocalAdmins' }
            GPO = @{ Path = "$gpoBasePath\Exclusions"; Name = 'HideExclusionsFromLocalAdmins' }
            DisplayName = 'Hide Exclusions From Local Admins'
        }
        'CatchupQuickScan' = @{
            Intune = @{ Path = $intuneBasePath; Name = 'DisableCatchupQuickScan' }
            GPO = @{ Path = "$gpoBasePath\Scan"; Name = 'DisableCatchupQuickScan' }
            DisplayName = 'Catchup Quick Scan'
        }
        'RealTimeScanDirection' = @{
            Intune = @{ Path = $intuneBasePath; Name = 'RealTimeScanDirection' }
            GPO = @{ Path = "$gpoBasePath\Real-Time Protection"; Name = 'RealTimeScanDirection' }
            DisplayName = 'Real-Time Scan Direction'
        }
        'SignatureFallbackOrder' = @{
            Intune = @{ Path = $intuneBasePath; Name = 'SignatureUpdateFallbackOrder' }
            GPO = @{ Path = "$gpoBasePath\Signature Updates"; Name = 'FallbackOrder' }
            DisplayName = 'Signature Fallback Order'
        }
        'SignatureUpdateInterval' = @{
            Intune = @{ Path = $intuneBasePath; Name = 'SignatureUpdateInterval' }
            GPO = @{ Path = "$gpoBasePath\Signature Updates"; Name = 'SignatureUpdateInterval' }
            DisplayName = 'Signature Update Interval'
        }
        'DisableLocalAdminMerge' = @{
            Intune = @{ Path = $intuneBasePath; Name = 'DisableLocalAdminMerge' }
            GPO = @{ Path = $gpoBasePath; Name = 'DisableLocalAdminMerge' }
            DisplayName = 'Disable Local Admin Merge'
        }
    }
    
    $config = $settingConfigs[$SettingKey]
    if ($null -eq $config) {
        return $null
    }
    
    # Determine which configuration to use based on management type
    $pathConfig = if ($ManagementType -eq 'Intune') {
        $config.Intune
    } else {
        # GPO, SSM, SCCM, and None all use the GPO path structure
        $config.GPO
    }
    
    Write-Debug "Resolved path: '$($pathConfig.Path)', setting name: '$($pathConfig.Name)' for SettingKey '$SettingKey'"
    
    return [PSCustomObject]@{
        Path = $pathConfig.Path
        SettingName = $pathConfig.Name
        DisplayName = $config.DisplayName
    }
}
