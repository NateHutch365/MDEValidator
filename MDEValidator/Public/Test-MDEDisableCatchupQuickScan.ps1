function Test-MDEDisableCatchupQuickScan {
    <#
    .SYNOPSIS
        Tests if Catchup Quick Scan is enabled.
    
    .DESCRIPTION
        Checks the DisableCatchupQuickScan setting in Windows Defender.
        When DisableCatchupQuickScan is False, catchup quick scan is enabled,
        which ensures missed scheduled scans are performed at the next opportunity.
    
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
    .PARAMETER MpPreference
        Optional Get-MpPreference snapshot. When supplied, the function uses it instead of
        querying Get-MpPreference itself, allowing the caller to share a single query across
        multiple tests. When omitted, the function queries Get-MpPreference directly.
    
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        $MpPreference
    )
    
    $testName = 'Catchup Quick Scan'
    
    try {
        if ($null -eq $MpPreference) {
            $mpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        # DisableCatchupQuickScan: $false = Enabled (good), $true = Disabled (bad)
        if ($mpPreference.DisableCatchupQuickScan -eq $false) {
            Write-ValidationResult -TestName $testName -Category 'Protection Settings' -Expected 'Enabled' -Actual 'Enabled' -Status 'Pass' `
                -Message "Catchup Quick Scan is enabled. Missed scheduled quick scans will be performed at the next opportunity."
        } else {
            Write-ValidationResult -TestName $testName -Category 'Protection Settings' -Expected 'Enabled' -Actual 'Disabled' -Status 'Fail' `
                -Message "Catchup Quick Scan is disabled." `
                -Recommendation "Enable Catchup Quick Scan via Intune or Group Policy to ensure missed scans are performed."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Category 'Protection Settings' -Expected 'Enabled' -Status 'Fail' `
            -Message "Unable to query Catchup Quick Scan status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}