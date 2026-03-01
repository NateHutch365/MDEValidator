function Get-MDEManagementTypeFallback {
    <#
    .SYNOPSIS
        Detects management type based on Windows Defender policy registry paths.
    
    .DESCRIPTION
        Fallback detection when SenseCM registry key is not available.
        Checks for the presence of policy entries in registry paths to determine
        if the device is managed by Intune or Security Settings Management.
        
        Additional detection logic: When HideExclusionsFromLocalAdmins is enabled via Intune,
        it restricts access (including SYSTEM) to the Policy Manager registry path. Since this
        setting cannot be enforced via Security Settings Management, if access is denied to 
        the Policy Manager path, the device is Intune managed.
    
    .OUTPUTS
        String containing the detected management type.
    
    .NOTES
        Detection logic:
        1. If access to HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager is denied -> Intune
        2. If HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager has entries -> Intune
        3. If HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender has entries -> Security Settings Management
        4. Otherwise -> Not Configured
    #>
    [CmdletBinding()]
    param()
    
    Write-Verbose "Running fallback management type detection via registry paths..."
    
    # Pattern to filter out PowerShell automatic properties from registry entries
    $psAutoPropertiesPattern = '^PS(Path|ParentPath|ChildName|Provider|Drive)$'
    
    $intunePolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'
    $ssmPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    
    # First, check if access to the Intune Policy Manager path is denied
    try {
        $null = Get-Item -Path $intunePolicyPath -ErrorAction Stop
    }
    catch {
        $isAccessDenied = $_.Exception -is [System.UnauthorizedAccessException] -or
                          $_.Exception -is [System.Security.SecurityException] -or
                          ($_.Exception.InnerException -is [System.UnauthorizedAccessException]) -or
                          ($_.Exception.InnerException -is [System.Security.SecurityException])
        
        if (-not $isAccessDenied) {
            $errorMessage = $_.Exception.Message
            $isAccessDenied = $errorMessage -imatch 'access.*(denied|not allowed)|unauthorized|permission'
        }
        
        if ($isAccessDenied) {
            Write-Verbose "Access denied to Policy Manager path - indicates Intune management"
            return "Intune"
        }
    }
    
    try {
        # Check for Intune policy entries first (more specific path)
        if (Test-Path $intunePolicyPath) {
            $intuneEntries = Get-ItemProperty -Path $intunePolicyPath -ErrorAction SilentlyContinue
            if ($null -ne $intuneEntries) {
                $valueNames = @($intuneEntries.PSObject.Properties | 
                    Where-Object { $_.Name -notmatch $psAutoPropertiesPattern } |
                    Select-Object -ExpandProperty Name)
                if ($valueNames.Count -gt 0) {
                    Write-Verbose "Intune policy entries found at $intunePolicyPath"
                    return "Intune"
                }
            }
        }
        
        # Check for Security Settings Management / GPO policy entries
        if (Test-Path $ssmPolicyPath) {
            $ssmEntries = Get-ItemProperty -Path $ssmPolicyPath -ErrorAction SilentlyContinue
            $hasSubKeys = $null -ne (Get-ChildItem -Path $ssmPolicyPath -ErrorAction SilentlyContinue | Select-Object -First 1)
            
            if ($null -ne $ssmEntries) {
                $valueNames = @($ssmEntries.PSObject.Properties | 
                    Where-Object { $_.Name -notmatch $psAutoPropertiesPattern } |
                    Select-Object -ExpandProperty Name)
                if ($valueNames.Count -gt 0 -or $hasSubKeys) {
                    Write-Verbose "SSM/GPO policy entries found at $ssmPolicyPath"
                    return "Security Settings Management"
                }
            }
            elseif ($hasSubKeys) {
                Write-Verbose "SSM/GPO subkeys found at $ssmPolicyPath"
                return "Security Settings Management"
            }
        }
        
        Write-Verbose "No policy entries found - returning 'Not Configured'"
        return "Not Configured"
    }
    catch {
        Write-Verbose "Error in fallback detection: $_"
        return "Not Configured"
    }
}
