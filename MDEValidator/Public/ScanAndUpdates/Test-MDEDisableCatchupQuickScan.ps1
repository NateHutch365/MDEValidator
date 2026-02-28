function Test-MDEDisableCatchupQuickScan {
    <#
    .SYNOPSIS
        Tests if Catchup Quick Scan is enabled.
    
    .DESCRIPTION
        Checks the DisableCatchupQuickScan setting in Windows Defender.
        When DisableCatchupQuickScan is False, catchup quick scan is enabled,
        which ensures missed scheduled scans are performed at the next opportunity.
    
    .PARAMETER MpPreference
        Optional. A pre-fetched MpPreference object from Get-MpPreference.
        If not provided, the function will call Get-MpPreference internally.
    
    .EXAMPLE
        Test-MDEDisableCatchupQuickScan
        
        Tests if Catchup Quick Scan is enabled.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        DisableCatchupQuickScan values:
        $false = Catchup Quick Scan is enabled (recommended)
        $true = Catchup Quick Scan is disabled
        
        When enabled, if the device is offline during a scheduled quick scan,
        the scan will be performed at the next opportunity when the device is online.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSObject]$MpPreference
    )
    
    $testName = 'Catchup Quick Scan'
    Write-Verbose "Checking $testName..."
    
    try {
        if ($null -eq $MpPreference) {
            $MpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        Write-Debug "DisableCatchupQuickScan: $($MpPreference.DisableCatchupQuickScan)"
        
        # DisableCatchupQuickScan: $false = Enabled (good), $true = Disabled (bad)
        if ($MpPreference.DisableCatchupQuickScan -eq $false) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Catchup Quick Scan is enabled. Missed scheduled quick scans will be performed at the next opportunity."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Catchup Quick Scan is disabled." `
                -Recommendation "Enable Catchup Quick Scan via Intune or Group Policy to ensure missed scans are performed."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Catchup Quick Scan status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}
