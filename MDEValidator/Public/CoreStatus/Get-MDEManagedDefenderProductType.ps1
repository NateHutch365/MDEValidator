function Get-MDEManagedDefenderProductType {
    <#
    .SYNOPSIS
        Gets the ManagedDefenderProductType registry value to determine device management.
    
    .DESCRIPTION
        Checks the ManagedDefenderProductType registry value to determine if the device
        is managed by Intune only, Configuration Manager only, or co-managed.
        This is the preferred method for determining management status as it takes
        precedence over the SenseCM EnrollmentStatus.
    
    .OUTPUTS
        PSCustomObject with properties:
        - ManagedDefenderProductType: The registry value (6, 7, or null)
        - EnrollmentStatus: The SenseCM EnrollmentStatus value (or null)
        - ManagementType: Descriptive string of the management type
        - IsManagedForExclusions: Boolean indicating if device meets requirements for tamper-protected exclusions
    
    .NOTES
        Registry locations:
        - HKLM\SOFTWARE\Microsoft\Windows Defender\ManagedDefenderProductType (REG_DWORD)
        - HKLM\SOFTWARE\Microsoft\SenseCM\EnrollmentStatus (REG_DWORD)
        
        ManagedDefenderProductType values:
        - 6 = Managed by Intune only (meets requirement for tamper-protected exclusions)
        - 7 = Device using both Intune and Configuration Manager
          - If EnrollmentStatus = 4: Managed by Configuration Manager only (meets requirement)
          - If EnrollmentStatus = 3: Co-managed (does NOT meet requirement for tamper-protected exclusions)
        - Other values or not present = Not managed by Intune or Configuration Manager only
    #>
    [CmdletBinding()]
    param()
    
    Write-Verbose "Checking ManagedDefenderProductType registry value..."
    
    try {
        $defenderPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender'
        $senseCmPath = 'HKLM:\SOFTWARE\Microsoft\SenseCM'
        
        $managedDefenderProductType = $null
        $enrollmentStatus = $null
        $managementType = 'Unknown'
        $isManagedForExclusions = $false
        
        # Check ManagedDefenderProductType
        if (Test-Path $defenderPath) {
            $defenderInfo = Get-ItemProperty -Path $defenderPath -ErrorAction SilentlyContinue
            if ($null -ne $defenderInfo -and $defenderInfo.PSObject.Properties['ManagedDefenderProductType']) {
                $managedDefenderProductType = $defenderInfo.ManagedDefenderProductType
                Write-Debug "ManagedDefenderProductType = $managedDefenderProductType"
            }
        }
        
        # Check EnrollmentStatus
        if (Test-Path $senseCmPath) {
            $senseCmInfo = Get-ItemProperty -Path $senseCmPath -ErrorAction SilentlyContinue
            if ($null -ne $senseCmInfo -and $senseCmInfo.PSObject.Properties['EnrollmentStatus']) {
                $enrollmentStatus = $senseCmInfo.EnrollmentStatus
                Write-Debug "SenseCM EnrollmentStatus = $enrollmentStatus"
            }
        }
        
        # Determine management type based on registry values
        if ($managedDefenderProductType -eq 6) {
            $managementType = 'Intune Only'
            $isManagedForExclusions = $true
        }
        elseif ($managedDefenderProductType -eq 7) {
            if ($enrollmentStatus -eq 4) {
                $managementType = 'Configuration Manager Only'
                $isManagedForExclusions = $true
            }
            elseif ($enrollmentStatus -eq 3) {
                $managementType = 'Co-managed (Intune + Configuration Manager)'
                $isManagedForExclusions = $false
            }
            else {
                $managementType = 'Mixed Management (unknown configuration)'
                $isManagedForExclusions = $false
            }
        }
        else {
            if ($null -ne $enrollmentStatus) {
                switch ($enrollmentStatus) {
                    1 { $managementType = 'Security Settings Management' }
                    3 { $managementType = 'Intune (legacy detection)' }
                    4 { $managementType = 'Configuration Manager (legacy detection)' }
                    default { $managementType = 'Not managed by Intune or Configuration Manager' }
                }
            }
            else {
                $managementType = 'Not managed by Intune or Configuration Manager'
            }
            $isManagedForExclusions = $false
        }
        
        Write-Verbose "Management type determined: $managementType (IsManagedForExclusions: $isManagedForExclusions)"
        
        return [PSCustomObject]@{
            ManagedDefenderProductType = $managedDefenderProductType
            EnrollmentStatus = $enrollmentStatus
            ManagementType = $managementType
            IsManagedForExclusions = $isManagedForExclusions
        }
    }
    catch {
        Write-Verbose "Error retrieving management type: $_"
        return [PSCustomObject]@{
            ManagedDefenderProductType = $null
            EnrollmentStatus = $null
            ManagementType = 'Error retrieving management type'
            IsManagedForExclusions = $false
        }
    }
}
