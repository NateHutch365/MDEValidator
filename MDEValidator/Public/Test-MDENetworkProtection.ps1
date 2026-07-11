function Test-MDENetworkProtection {
    <#
    .SYNOPSIS
        Tests if network protection is enabled.
    
    .DESCRIPTION
        Checks the network protection status of Windows Defender Antivirus.
    
    .EXAMPLE
        Test-MDENetworkProtection
        
        Tests if network protection is enabled.
    
    .OUTPUTS
        PSCustomObject with validation results.
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
    
    $testName = 'Network Protection'
    
    try {
        if ($null -eq $MpPreference) {
            $mpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        # EnableNetworkProtection: 0 = Disabled, 1 = Enabled (Block), 2 = Audit mode
        switch ($mpPreference.EnableNetworkProtection) {
            0 {
                Write-ValidationResult -TestName $testName -Category 'Network Protection' -Expected 'Block' -Actual 'Disabled' -Status 'Fail' `
                    -Message "Network protection is disabled." `
                    -Recommendation "Enable network protection via Intune or Group Policy."
            }
            1 {
                Write-ValidationResult -TestName $testName -Category 'Network Protection' -Expected 'Block' -Actual 'Block' -Status 'Pass' `
                    -Message "Network protection is enabled in Block mode."
            }
            2 {
                Write-ValidationResult -TestName $testName -Category 'Network Protection' -Expected 'Block' -Actual 'Audit' -Status 'Warning' `
                    -Message "Network protection is in Audit mode only." `
                    -Recommendation "Consider enabling Block mode for full protection after validating Audit mode results."
            }
            default {
                Write-ValidationResult -TestName $testName -Category 'Network Protection' -Expected 'Block' -Actual "Unknown: $($mpPreference.EnableNetworkProtection)" -Status 'Warning' `
                    -Message "Network protection status is unknown: $($mpPreference.EnableNetworkProtection)" `
                    -Recommendation "Verify network protection configuration."
            }
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Category 'Network Protection' -Expected 'Block' -Status 'Fail' `
            -Message "Unable to query network protection status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}