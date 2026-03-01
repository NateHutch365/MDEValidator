function Test-MDETamperProtection {
    <#
    .SYNOPSIS
        Tests if Tamper Protection is enabled.
    
    .DESCRIPTION
        Checks the Tamper Protection status and source of Windows Defender.
        Tamper Protection prevents malicious apps from changing important 
        Windows Defender Antivirus settings.
    
    .PARAMETER MpComputerStatus
        Optional. A pre-fetched MpComputerStatus object from Get-MpComputerStatus.
        If not provided, the function will call Get-MpComputerStatus internally.
    
    .EXAMPLE
        Test-MDETamperProtection
        
        Tests if Tamper Protection is enabled and reports the source.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        Tamper Protection source can be:
        - ATP (Microsoft Defender for Endpoint)
        - Intune (Microsoft Endpoint Manager)
        - ConfigMgr (Configuration Manager)
        - Admin (locally configured by admin)
        - Unknown
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSObject]$MpComputerStatus
    )
    
    $testName = 'Tamper Protection'
    Write-Verbose "Checking $testName..."
    
    try {
        if ($null -eq $MpComputerStatus) {
            $MpComputerStatus = Get-MpComputerStatus -ErrorAction Stop
        }
        
        $isTamperProtected = $MpComputerStatus.IsTamperProtected
        $tamperProtectionSource = $MpComputerStatus.TamperProtectionSource
        
        Write-Debug "IsTamperProtected: $isTamperProtected"
        Write-Debug "TamperProtectionSource: $tamperProtectionSource"
        
        # Build source information string
        $sourceInfo = if ([string]::IsNullOrEmpty($tamperProtectionSource)) {
            ''
        } else {
            " Source: $tamperProtectionSource."
        }
        
        if ($isTamperProtected -eq $true) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Tamper Protection is enabled.$sourceInfo"
        } else {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Tamper Protection is disabled.$sourceInfo" `
                -Recommendation "Enable Tamper Protection via Microsoft Defender for Endpoint portal, Intune, or Group Policy. Tamper Protection prevents malicious apps from changing important Windows Defender Antivirus settings."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Tamper Protection status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and the Defender PowerShell module is available."
    }
}
