function Get-MDEPolicyRegistryPath {
    <#
    .SYNOPSIS
        Gets the appropriate registry path for MDE policies based on management type.
    
    .DESCRIPTION
        Returns the registry path where MDE policy settings are stored based on how
        the device is managed.
    
    .PARAMETER ManagementType
        The management type: 'Intune', 'SecuritySettingsManagement', 'SCCM', 'GPO', or 'None'
    
    .OUTPUTS
        String containing the registry path for MDE policies.
    
    .NOTES
        Registry locations based on management type:
        - Security Settings Management, SCCM, GPO: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender
        - Intune (MDM): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Intune', 'SecuritySettingsManagement', 'SCCM', 'GPO', 'None')]
        [string]$ManagementType
    )
    
    if ($ManagementType -eq 'Intune') {
        return 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'
    }
    
    return 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
}
