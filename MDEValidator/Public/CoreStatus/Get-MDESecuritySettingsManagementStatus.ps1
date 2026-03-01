function Get-MDESecuritySettingsManagementStatus {
    <#
    .SYNOPSIS
        Gets the device management status for MDE policy settings.
    
    .DESCRIPTION
        Retrieves the device management status, checking ManagedDefenderProductType first
        (preferred method), then falling back to SenseCM EnrollmentStatus, and finally
        to policy registry path detection.
    
    .EXAMPLE
        Get-MDESecuritySettingsManagementStatus
        
        Returns a string like "Intune Only", "Configuration Manager Only", 
        "Co-managed (Intune + Configuration Manager)", or "Security Settings Management" 
        depending on the management status.
    
    .OUTPUTS
        String containing the device management status.
    
    .NOTES
        Primary Registry location (checked first): 
        - HKLM\SOFTWARE\Microsoft\Windows Defender\ManagedDefenderProductType
        
        Secondary Registry location: HKLM\SOFTWARE\Microsoft\SenseCM
        
        Fallback detection:
        - Access denied to Policy Manager path indicates Intune management
        - HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager (with entries) = Intune
        - HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender (with entries) = Security Settings Management
    #>
    [CmdletBinding()]
    param()
    
    Write-Verbose "Retrieving security settings management status..."
    
    try {
        # First, check the ManagedDefenderProductType (preferred method)
        $managedDefenderInfo = Get-MDEManagedDefenderProductType
        
        if ($null -ne $managedDefenderInfo.ManagedDefenderProductType) {
            Write-Verbose "Management status from ManagedDefenderProductType: $($managedDefenderInfo.ManagementType)"
            return $managedDefenderInfo.ManagementType
        }
        
        # Fall back to SenseCM EnrollmentStatus
        $senseCmPath = 'HKLM:\SOFTWARE\Microsoft\SenseCM'
        
        if (-not (Test-Path $senseCmPath)) {
            Write-Verbose "SenseCM not found, using fallback detection"
            return Get-MDEManagementTypeFallback
        }
        
        $senseCmInfo = Get-ItemProperty -Path $senseCmPath -ErrorAction SilentlyContinue
        
        if ($null -eq $senseCmInfo -or $null -eq $senseCmInfo.EnrollmentStatus) {
            return Get-MDEManagementTypeFallback
        }
        
        $enrollmentStatus = $senseCmInfo.EnrollmentStatus
        Write-Debug "SenseCM EnrollmentStatus = $enrollmentStatus"
        
        switch ($enrollmentStatus) {
            0 { return "Failed / Not Successfully Enrolled" }
            1 { return "Security Settings Management" }
            2 { return "Not Enrolled (never enrolled)" }
            3 { return "Intune" }
            4 { return "Configuration Manager (SCCM)" }
            default { return "Unknown Status ($enrollmentStatus)" }
        }
    }
    catch {
        Write-Verbose "Error retrieving management status: $_"
        return "Error retrieving status"
    }
}
