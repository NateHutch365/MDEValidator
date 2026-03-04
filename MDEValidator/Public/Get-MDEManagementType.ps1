function Get-MDEManagementType {
    <#
    .SYNOPSIS
        Gets the management type for the device based on enrollment status.
    
    .DESCRIPTION
        Determines how the device is managed (Intune, Security Settings Management, SCCM, GPO, or None)
        based on the ManagedDefenderProductType registry value (preferred) or falls back to 
        SenseCM EnrollmentStatus registry value.
    
    .OUTPUTS
        String containing the management type: 'Intune', 'SecuritySettingsManagement', 'SCCM', 'GPO', or 'None'
    
    .NOTES
        Primary Registry location: HKLM\SOFTWARE\Microsoft\Windows Defender\ManagedDefenderProductType
        Fallback Registry location: HKLM\SOFTWARE\Microsoft\SenseCM\EnrollmentStatus
        
        ManagedDefenderProductType REG_DWORD values (takes precedence):
        6 = Managed by Intune only
        7 = Mixed management (check EnrollmentStatus for details)
        
        EnrollmentStatus REG_DWORD values (fallback):
        0 = Failed / Not Successfully Enrolled -> GPO (fallback to GPO)
        1 = Enrolled to Security Settings Management
        2 = Not Enrolled (never enrolled) -> GPO (fallback to GPO)
        3 = Managed by Intune
        4 = Managed by Configuration Manager (SCCM)
    #>
    [CmdletBinding()]
    param()
    
    try {
        # First check the ManagedDefenderProductType registry value (preferred method)
        $defenderPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender'
        
        if (Test-Path $defenderPath) {
            $defenderInfo = Get-ItemProperty -Path $defenderPath -ErrorAction SilentlyContinue
            if ($null -ne $defenderInfo -and $defenderInfo.PSObject.Properties['ManagedDefenderProductType']) {
                $managedDefenderProductType = $defenderInfo.ManagedDefenderProductType
                
                # Check if this is Intune-only (value 6)
                if ($managedDefenderProductType -eq 6) {
                    return 'Intune'
                }
                
                # If value is 7, need to check EnrollmentStatus for more details
                if ($managedDefenderProductType -eq 7) {
                    $senseCmPath = 'HKLM:\SOFTWARE\Microsoft\SenseCM'
                    if (Test-Path $senseCmPath) {
                        $senseCmInfo = Get-ItemProperty -Path $senseCmPath -ErrorAction SilentlyContinue
                        if ($null -ne $senseCmInfo -and $senseCmInfo.PSObject.Properties['EnrollmentStatus']) {
                            $enrollmentStatus = $senseCmInfo.EnrollmentStatus
                            
                            # EnrollmentStatus 4 = Configuration Manager only
                            # EnrollmentStatus 3 = Co-managed (both Intune and ConfigMgr)
                            switch ($enrollmentStatus) {
                                3 { return 'Intune' }  # Co-managed, return Intune for policy path purposes
                                4 { return 'SCCM' }    # ConfigMgr only
                            }
                        }
                    }
                }
            }
        }
        
        # Fall back to the original SenseCM EnrollmentStatus check
        $senseCmPath = 'HKLM:\SOFTWARE\Microsoft\SenseCM'
        
        if (-not (Test-Path $senseCmPath)) {
            return 'None'
        }
        
        $senseCmInfo = Get-ItemProperty -Path $senseCmPath -ErrorAction SilentlyContinue
        
        if ($null -eq $senseCmInfo -or $null -eq $senseCmInfo.EnrollmentStatus) {
            return 'None'
        }
        
        $enrollmentStatus = $senseCmInfo.EnrollmentStatus
        
        switch ($enrollmentStatus) {
            0 { return 'GPO' }           # Failed enrollment - default to GPO path (standard policy location)
            1 { return 'SecuritySettingsManagement' }
            2 { return 'GPO' }           # Never enrolled - default to GPO path (standard policy location)
            3 { return 'Intune' }
            4 { return 'SCCM' }
            default { return 'None' }
        }
    }
    catch {
        return 'None'
    }
}