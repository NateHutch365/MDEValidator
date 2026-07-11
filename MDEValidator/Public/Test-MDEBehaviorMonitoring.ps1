function Test-MDEBehaviorMonitoring {
    <#
    .SYNOPSIS
        Tests if behavior monitoring is enabled.
    
    .DESCRIPTION
        Checks the behavior monitoring status of Windows Defender Antivirus.
    
    .EXAMPLE
        Test-MDEBehaviorMonitoring
        
        Tests if behavior monitoring is enabled.
    
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
    
    $testName = 'Behavior Monitoring'
    
    try {
        if ($null -eq $MpPreference) {
            $mpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        if ($mpPreference.DisableBehaviorMonitoring -eq $false) {
            Write-ValidationResult -TestName $testName -Category 'Device State' -Expected 'Enabled' -Actual 'Enabled' -Status 'Pass' `
                -Message "Behavior monitoring is enabled."
        } else {
            Write-ValidationResult -TestName $testName -Category 'Device State' -Expected 'Enabled' -Actual 'Disabled' -Status 'Fail' `
                -Message "Behavior monitoring is disabled." `
                -Recommendation "Enable behavior monitoring via Intune or Group Policy."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Category 'Device State' -Expected 'Enabled' -Status 'Fail' `
            -Message "Unable to query behavior monitoring status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}