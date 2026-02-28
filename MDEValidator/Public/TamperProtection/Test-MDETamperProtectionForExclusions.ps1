function Test-MDETamperProtectionForExclusions {
    <#
    .SYNOPSIS
        Tests if Tamper Protection for Exclusions is enabled and enforced.
    
    .DESCRIPTION
        Checks if Tamper Protection for Exclusions is enabled by verifying:
        1. Tamper Protection is enabled
        2. Microsoft Defender platform version is 4.18.2211.5 or later
        3. Device is managed by Intune only (ManagedDefenderProductType = 6) OR
           Configuration Manager only (ManagedDefenderProductType = 7 with EnrollmentStatus = 4)
        4. TPExclusions registry key is set to 1
        
        When all conditions are met, exclusions are protected from tampering by Tamper Protection.
    
    .PARAMETER MpComputerStatus
        Optional. A pre-fetched MpComputerStatus object from Get-MpComputerStatus.
        If not provided, the function will call Get-MpComputerStatus internally.
    
    .EXAMPLE
        Test-MDETamperProtectionForExclusions
        
        Tests if Tamper Protection for Exclusions is enabled.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        Requirements for Tamper Protection for Exclusions:
        1. Tamper Protection must be enabled
        2. Microsoft Defender platform version 4.18.2211.5 or later
        3. Device must be managed by:
           - Intune only (ManagedDefenderProductType = 6), OR
           - Configuration Manager only (ManagedDefenderProductType = 7 AND EnrollmentStatus = 4)
        4. TPExclusions registry value = 1
        
        Registry locations:
        - HKLM\SOFTWARE\Microsoft\Windows Defender\ManagedDefenderProductType (REG_DWORD)
        - HKLM\SOFTWARE\Microsoft\SenseCM\EnrollmentStatus (REG_DWORD)
        - HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TPExclusions (REG_DWORD)
        
        Co-managed devices (ManagedDefenderProductType = 7 with EnrollmentStatus = 3) do NOT
        support Tamper Protection for Exclusions.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSObject]$MpComputerStatus
    )
    
    $testName = 'Tamper Protection for Exclusions'
    Write-Verbose "Checking $testName..."
    
    try {
        # Check 1: Verify Tamper Protection is enabled
        if ($null -eq $MpComputerStatus) {
            $MpComputerStatus = Get-MpComputerStatus -ErrorAction Stop
        }
        $isTamperProtected = $MpComputerStatus.IsTamperProtected
        
        Write-Debug "IsTamperProtected: $isTamperProtected"
        
        if (-not $isTamperProtected) {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Tamper Protection is not enabled. Tamper Protection must be enabled for exclusions to be tamper protected." `
                -Recommendation "Enable Tamper Protection via Microsoft Defender for Endpoint portal, Intune, or Configuration Manager before enabling Tamper Protection for Exclusions."
            return
        }
        
        # Check 2: Verify platform version is 4.18.2211.5 or later
        $platformVersion = $MpComputerStatus.AMProductVersion
        
        Write-Debug "AMProductVersion: $platformVersion"
        
        if ($null -eq $platformVersion) {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Unable to determine Microsoft Defender platform version. Tamper Protection for Exclusions requires platform version 4.18.2211.5 or later." `
                -Recommendation "Ensure Microsoft Defender platform is up to date. Run 'Update-MpSignature' to update to the latest version."
            return
        }
        
        # Parse version string and compare
        try {
            $versionParts = $platformVersion -split '\.'
            if ($versionParts.Count -ge 4) {
                # Attempt to parse each version part as an integer
                # If any part is non-numeric, [int] will throw an exception that we catch below
                $major = [int]$versionParts[0]
                $minor = [int]$versionParts[1]
                $build = [int]$versionParts[2]
                $revision = [int]$versionParts[3]
                
                # Compare with minimum version 4.18.2211.5
                $meetsVersionRequirement = $false
                if ($major -gt 4) {
                    $meetsVersionRequirement = $true
                }
                elseif ($major -eq 4 -and $minor -gt 18) {
                    $meetsVersionRequirement = $true
                }
                elseif ($major -eq 4 -and $minor -eq 18 -and $build -gt 2211) {
                    $meetsVersionRequirement = $true
                }
                elseif ($major -eq 4 -and $minor -eq 18 -and $build -eq 2211 -and $revision -ge 5) {
                    $meetsVersionRequirement = $true
                }
                
                if (-not $meetsVersionRequirement) {
                    Write-ValidationResult -TestName $testName -Status 'Fail' `
                        -Message "Microsoft Defender platform version $platformVersion does not meet the minimum requirement of 4.18.2211.5 for Tamper Protection for Exclusions." `
                        -Recommendation "Update Microsoft Defender platform to version 4.18.2211.5 or later. Run 'Update-MpSignature' to update."
                    return
                }
            }
            else {
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "Unable to parse Microsoft Defender platform version '$platformVersion'. Cannot verify minimum version requirement." `
                    -Recommendation "Ensure Microsoft Defender platform version is 4.18.2211.5 or later."
                return
            }
        }
        catch {
            # Catch any exception during version parsing (e.g., non-numeric version parts)
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Error parsing Microsoft Defender platform version '$platformVersion': $_" `
                -Recommendation "Ensure Microsoft Defender platform version is 4.18.2211.5 or later."
            return
        }
        
        # Check 3: Verify device is managed by Intune only or Configuration Manager only
        $managedDefenderInfo = Get-MDEManagedDefenderProductType
        
        Write-Debug "IsManagedForExclusions: $($managedDefenderInfo.IsManagedForExclusions)"
        Write-Debug "ManagementType: $($managedDefenderInfo.ManagementType)"
        
        if (-not $managedDefenderInfo.IsManagedForExclusions) {
            $managementDetails = "Current management: $($managedDefenderInfo.ManagementType)"
            if ($null -ne $managedDefenderInfo.ManagedDefenderProductType) {
                $managementDetails += " (ManagedDefenderProductType: $($managedDefenderInfo.ManagedDefenderProductType)"
                if ($null -ne $managedDefenderInfo.EnrollmentStatus) {
                    $managementDetails += ", EnrollmentStatus: $($managedDefenderInfo.EnrollmentStatus)"
                }
                $managementDetails += ")"
            }
            
            Write-ValidationResult -TestName $testName -Status 'Info' `
                -Message "Device is not managed by Intune only or Configuration Manager only. Tamper Protection for Exclusions is not supported. $managementDetails" `
                -Recommendation "Tamper Protection for Exclusions requires the device to be managed by either Intune only (not co-managed) or Configuration Manager only. Co-managed devices are not supported for this feature."
            return
        }
        
        # Check 4: Verify TPExclusions registry value
        $featuresPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
        $tpExclusions = $null
        
        if (Test-Path $featuresPath) {
            $features = Get-ItemProperty -Path $featuresPath -ErrorAction SilentlyContinue
            if ($null -ne $features -and $features.PSObject.Properties['TPExclusions']) {
                $tpExclusions = $features.TPExclusions
            }
        }
        
        Write-Debug "TPExclusions: $tpExclusions"
        
        if ($tpExclusions -eq 1) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Tamper Protection for Exclusions is enabled and enforced. Exclusions are protected from tampering. Management: $($managedDefenderInfo.ManagementType). Platform version: $platformVersion."
        }
        elseif ($tpExclusions -eq 0) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Tamper Protection for Exclusions is not currently protecting exclusions (TPExclusions = 0). All requirements appear to be met, but the feature is not enabled." `
                -Recommendation "If all requirements are met and this state seems incorrect, contact Microsoft support. Verify that Tamper Protection policies are properly deployed via $($managedDefenderInfo.ManagementType)."
        }
        else {
            Write-ValidationResult -TestName $testName -Status 'Info' `
                -Message "TPExclusions registry value not found. All requirements for Tamper Protection for Exclusions are met (Tamper Protection enabled, platform version $platformVersion, management: $($managedDefenderInfo.ManagementType)), but TPExclusions is not configured." `
                -Recommendation "Tamper Protection for Exclusions may not be fully deployed yet. Verify that Tamper Protection policies are properly configured in $($managedDefenderInfo.ManagementType). The TPExclusions registry key should be set to 1 when the feature is active."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Tamper Protection for Exclusions status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and the Defender PowerShell module is available."
    }
}
