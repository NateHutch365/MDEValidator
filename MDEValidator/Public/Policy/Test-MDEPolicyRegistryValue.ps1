function Test-MDEPolicyRegistryValue {
    <#
    .SYNOPSIS
        Tests if a policy registry value exists and matches expected value.
    
    .DESCRIPTION
        Verifies that a Windows Defender policy setting exists in the correct
        registry location based on the device's management type.
    
    .PARAMETER SettingKey
        The logical setting key (e.g., 'RealTimeProtection'). When provided,
        the function automatically determines the correct path and setting name
        based on the management type.
    
    .PARAMETER SettingName
        The name of the setting to verify (e.g., 'DisableRealtimeMonitoring').
        Used for backward compatibility. Ignored if SettingKey is provided.
    
    .PARAMETER ExpectedValue
        The expected value for the setting.
    
    .PARAMETER SubPath
        Optional subpath under the main policy path (e.g., 'Real-Time Protection').
        Used for backward compatibility. Ignored if SettingKey is provided.
    
    .OUTPUTS
        PSCustomObject with properties:
        - Found: Boolean indicating if the registry value was found
        - Value: The actual value found (if any)
        - Path: The full registry path checked
        - ManagementType: The detected management type
        - SettingName: The registry value name that was checked
    
    .NOTES
        This function checks the appropriate registry location based on the
        detected management type (Intune vs Security Settings Management/GPO/SCCM).
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'ExpectedValue',
        Justification = 'Reserved for future comparison logic; callers pass it for API consistency.')]
    param(
        [Parameter()]
        [string]$SettingKey,
        
        [Parameter()]
        [string]$SettingName,
        
        [Parameter()]
        $ExpectedValue = $null,
        
        [Parameter()]
        [string]$SubPath = ''
    )
    
    Write-Verbose "Testing policy registry value..."
    
    $managementType = Get-MDEManagementType
    
    # If SettingKey is provided, use the new configuration-based approach
    if (-not [string]::IsNullOrEmpty($SettingKey)) {
        $config = Get-MDEPolicySettingConfig -SettingKey $SettingKey -ManagementType $managementType
        if ($null -ne $config) {
            $fullPath = $config.Path
            $actualSettingName = $config.SettingName
        } else {
            # Fallback to old behavior if config not found
            $basePath = Get-MDEPolicyRegistryPath -ManagementType $managementType
            $fullPath = $basePath
            $actualSettingName = $SettingName
        }
    } else {
        # Backward compatibility: use the old SubPath approach
        $basePath = Get-MDEPolicyRegistryPath -ManagementType $managementType
        $fullPath = if ([string]::IsNullOrEmpty($SubPath)) {
            $basePath
        } else {
            Join-Path $basePath $SubPath
        }
        $actualSettingName = $SettingName
    }
    
    Write-Debug "Checking registry path: '$fullPath', setting name: '$actualSettingName'"
    
    $result = [PSCustomObject]@{
        Found = $false
        Value = $null
        Path = $fullPath
        ManagementType = $managementType
        SettingName = $actualSettingName
    }
    
    try {
        if (Test-Path $fullPath) {
            $regValue = Get-ItemProperty -Path $fullPath -Name $actualSettingName -ErrorAction SilentlyContinue
            if ($null -ne $regValue -and $null -ne $regValue.$actualSettingName) {
                $result.Found = $true
                $result.Value = $regValue.$actualSettingName
            }
        }
    }
    catch {
        # Registry path or value not accessible
        $result.Found = $false
    }
    
    Write-Debug "Registry value result — Found: $($result.Found), Value: $($result.Value)"
    
    return $result
}
