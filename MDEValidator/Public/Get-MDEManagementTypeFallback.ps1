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
           (HideExclusionsFromLocalAdmins restricts SYSTEM access, only settable via Intune)
        2. If HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager has entries -> Intune
        3. If HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender has entries -> Security Settings Management
        4. Otherwise -> Not Configured
        
        HideExclusionsFromLocalAdmins cannot be set locally using Set-MpPreference or via 
        Security Settings Management, so access denial to the Policy Manager path reliably 
        indicates Intune management.
    #>
    [CmdletBinding()]
    param()
    
    # Pattern to filter out PowerShell automatic properties from registry entries
    $psAutoPropertiesPattern = '^PS(Path|ParentPath|ChildName|Provider|Drive)$'
    
    $intunePolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'
    $ssmPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    
    # First, check if access to the Intune Policy Manager path is denied
    # When HideExclusionsFromLocalAdmins is enabled via Intune, it restricts SYSTEM access
    # to this registry location. This setting cannot be enforced via Security Settings Management,
    # so access denial reliably indicates Intune management.
    try {
        # Attempt to access the Intune Policy Manager path with ErrorAction Stop
        # to catch access denied exceptions. Using Get-Item as we only need to test access,
        # not retrieve property values.
        $null = Get-Item -Path $intunePolicyPath -ErrorAction Stop
    }
    catch {
        # Check if the error is an access denied / unauthorized exception
        $isAccessDenied = $_.Exception -is [System.UnauthorizedAccessException] -or
                          $_.Exception -is [System.Security.SecurityException] -or
                          ($_.Exception.InnerException -is [System.UnauthorizedAccessException]) -or
                          ($_.Exception.InnerException -is [System.Security.SecurityException])
        
        # Also check the error message for access denied indicators (case-insensitive)
        if (-not $isAccessDenied) {
            $errorMessage = $_.Exception.Message
            $isAccessDenied = $errorMessage -imatch 'access.*(denied|not allowed)|unauthorized|permission'
        }
        
        if ($isAccessDenied) {
            # Access denied to Policy Manager path indicates Intune management
            # because HideExclusionsFromLocalAdmins (which causes this restriction)
            # can only be set via Intune, not via Security Settings Management or locally
            return "Intune"
        }
        # If error is not access denied (e.g., path doesn't exist), continue with normal detection
    }
    
    try {
        # Check for Intune policy entries first (more specific path)
        if (Test-Path $intunePolicyPath) {
            $intuneEntries = Get-ItemProperty -Path $intunePolicyPath -ErrorAction SilentlyContinue
            if ($null -ne $intuneEntries) {
                # Check if there are any values (excluding PSPath, PSParentPath, etc.)
                $valueNames = @($intuneEntries.PSObject.Properties | 
                    Where-Object { $_.Name -notmatch $psAutoPropertiesPattern } |
                    Select-Object -ExpandProperty Name)
                if ($valueNames.Count -gt 0) {
                    return "Intune"
                }
            }
        }
        
        # Check for Security Settings Management / GPO policy entries
        if (Test-Path $ssmPolicyPath) {
            $ssmEntries = Get-ItemProperty -Path $ssmPolicyPath -ErrorAction SilentlyContinue
            # Check if any subkeys exist - limit to first result for efficiency
            $hasSubKeys = $null -ne (Get-ChildItem -Path $ssmPolicyPath -ErrorAction SilentlyContinue | Select-Object -First 1)
            
            if ($null -ne $ssmEntries) {
                # Check if there are any values (excluding PSPath, PSParentPath, etc.)
                $valueNames = @($ssmEntries.PSObject.Properties | 
                    Where-Object { $_.Name -notmatch $psAutoPropertiesPattern } |
                    Select-Object -ExpandProperty Name)
                if ($valueNames.Count -gt 0 -or $hasSubKeys) {
                    return "Security Settings Management"
                }
            }
            elseif ($hasSubKeys) {
                return "Security Settings Management"
            }
        }
        
        return "Not Configured"
    }
    catch {
        return "Not Configured"
    }
}