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
    
    Write-Verbose "Detecting device management type..."
    
    try {
        # First check the ManagedDefenderProductType registry value (preferred method)
        $defenderPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender'
        
        if (Test-Path $defenderPath) {
            $defenderInfo = Get-ItemProperty -Path $defenderPath -ErrorAction SilentlyContinue
            if ($null -ne $defenderInfo -and $defenderInfo.PSObject.Properties['ManagedDefenderProductType']) {
                $managedDefenderProductType = $defenderInfo.ManagedDefenderProductType
                Write-Debug "ManagedDefenderProductType = $managedDefenderProductType"
                
                if ($managedDefenderProductType -eq 6) {
                    Write-Verbose "Management type: Intune (ManagedDefenderProductType = 6)"
                    return 'Intune'
                }
                
                if ($managedDefenderProductType -eq 7) {
                    $senseCmPath = 'HKLM:\SOFTWARE\Microsoft\SenseCM'
                    if (Test-Path $senseCmPath) {
                        $senseCmInfo = Get-ItemProperty -Path $senseCmPath -ErrorAction SilentlyContinue
                        if ($null -ne $senseCmInfo -and $senseCmInfo.PSObject.Properties['EnrollmentStatus']) {
                            $enrollmentStatus = $senseCmInfo.EnrollmentStatus
                            Write-Debug "EnrollmentStatus = $enrollmentStatus (ManagedDefenderProductType = 7)"
                            
                            switch ($enrollmentStatus) {
                                3 { return 'Intune' }
                                4 { return 'SCCM' }
                            }
                        }
                    }
                }
            }
        }
        
        # Fall back to the original SenseCM EnrollmentStatus check
        $senseCmPath = 'HKLM:\SOFTWARE\Microsoft\SenseCM'
        
        if (-not (Test-Path $senseCmPath)) {
            Write-Verbose "SenseCM registry key not found, returning 'None'"
            return 'None'
        }
        
        $senseCmInfo = Get-ItemProperty -Path $senseCmPath -ErrorAction SilentlyContinue
        
        if ($null -eq $senseCmInfo -or $null -eq $senseCmInfo.EnrollmentStatus) {
            Write-Verbose "EnrollmentStatus not found, returning 'None'"
            return 'None'
        }
        
        $enrollmentStatus = $senseCmInfo.EnrollmentStatus
        Write-Debug "Fallback EnrollmentStatus = $enrollmentStatus"
        
        $result = switch ($enrollmentStatus) {
            0 { 'GPO' }
            1 { 'SecuritySettingsManagement' }
            2 { 'GPO' }
            3 { 'Intune' }
            4 { 'SCCM' }
            default { 'None' }
        }
        
        Write-Verbose "Management type: $result"
        return $result
    }
    catch {
        Write-Verbose "Error detecting management type: $_"
        return 'None'
    }
}
