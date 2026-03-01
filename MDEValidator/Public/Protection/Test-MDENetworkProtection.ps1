function Test-MDENetworkProtection {
    <#
    .SYNOPSIS
        Tests if network protection is enabled.
    
    .DESCRIPTION
        Checks the network protection status of Windows Defender Antivirus.
    
    .PARAMETER MpPreference
        Optional. A pre-fetched MpPreference object from Get-MpPreference.
        If not provided, the function will call Get-MpPreference internally.
    
    .EXAMPLE
        Test-MDENetworkProtection
        
        Tests if network protection is enabled.
    
    .OUTPUTS
        PSCustomObject with validation results.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSObject]$MpPreference
    )
    
    $testName = 'Network Protection'
    Write-Verbose "Checking $testName..."
    
    try {
        if ($null -eq $MpPreference) {
            $MpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        Write-Debug "EnableNetworkProtection: $($MpPreference.EnableNetworkProtection)"
        
        # EnableNetworkProtection: 0 = Disabled, 1 = Enabled (Block), 2 = Audit mode
        switch ($MpPreference.EnableNetworkProtection) {
            0 {
                Write-ValidationResult -TestName $testName -Status 'Fail' `
                    -Message "Network protection is disabled." `
                    -Recommendation "Enable network protection via Intune or Group Policy."
            }
            1 {
                Write-ValidationResult -TestName $testName -Status 'Pass' `
                    -Message "Network protection is enabled in Block mode."
            }
            2 {
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "Network protection is in Audit mode only." `
                    -Recommendation "Consider enabling Block mode for full protection after validating Audit mode results."
            }
            default {
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "Network protection status is unknown: $($MpPreference.EnableNetworkProtection)" `
                    -Recommendation "Verify network protection configuration."
            }
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query network protection status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}
