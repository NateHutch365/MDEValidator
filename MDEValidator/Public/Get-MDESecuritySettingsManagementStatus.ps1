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
        
        ManagedDefenderProductType values:
        - 6 = Intune Only
        - 7 = Mixed management (check EnrollmentStatus for details)
        
        Secondary Registry location: HKLM\SOFTWARE\Microsoft\SenseCM
        EnrollmentStatus REG_DWORD values and their return strings:
        0 = "Failed / Not Successfully Enrolled"
        1 = "Security Settings Management"
        2 = "Not Enrolled (never enrolled)"
        3 = "Intune"
        4 = "Configuration Manager (SCCM)"
        
        Fallback detection:
        - Access denied to Policy Manager path indicates Intune management
          (HideExclusionsFromLocalAdmins cannot be set via SSM or locally)
        - HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager (with entries) = Intune
        - HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender (with entries) = Security Settings Management
    #>
    [CmdletBinding()]
    param()
    
    try {
        # First, check the ManagedDefenderProductType (preferred method)
        $managedDefenderInfo = Get-MDEManagedDefenderProductType
        
        if ($null -ne $managedDefenderInfo.ManagedDefenderProductType) {
            # We have a ManagedDefenderProductType value, use its determination
            return $managedDefenderInfo.ManagementType
        }
        
        # Fall back to SenseCM EnrollmentStatus
        $senseCmPath = 'HKLM:\SOFTWARE\Microsoft\SenseCM'
        
        if (-not (Test-Path $senseCmPath)) {
            # SenseCM key not found - use fallback detection based on policy registry paths
            return Get-MDEManagementTypeFallback
        }
        
        $senseCmInfo = Get-ItemProperty -Path $senseCmPath -ErrorAction SilentlyContinue
        
        if ($null -eq $senseCmInfo -or $null -eq $senseCmInfo.EnrollmentStatus) {
            # EnrollmentStatus not set - use fallback detection
            return Get-MDEManagementTypeFallback
        }
        
        $enrollmentStatus = $senseCmInfo.EnrollmentStatus
        
        # Map enrollment status values to human-readable strings
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
        return "Error retrieving status"
    }
}