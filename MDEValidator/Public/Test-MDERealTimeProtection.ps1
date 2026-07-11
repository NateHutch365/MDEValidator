function Test-MDERealTimeProtection {
    <#
    .SYNOPSIS
        Tests if real-time protection is enabled.
    
    .DESCRIPTION
        Checks the real-time protection status of Windows Defender Antivirus.
    
    .EXAMPLE
        Test-MDERealTimeProtection
        
        Tests if real-time protection is enabled.
    
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
    
    $testName = 'Real-Time Protection'
    
    try {
        if ($null -eq $MpPreference) {
            $mpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        if ($mpPreference.DisableRealtimeMonitoring -eq $false) {
            Write-ValidationResult -TestName $testName -Category 'Device State' -Expected 'Enabled' -Actual 'Enabled' -Status 'Pass' `
                -Message "Real-time protection is enabled."
        } else {
            Write-ValidationResult -TestName $testName -Category 'Device State' -Expected 'Enabled' -Actual 'Disabled' -Status 'Fail' `
                -Message "Real-time protection is disabled." `
                -Recommendation "Enable real-time protection via Intune or Group Policy."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Category 'Device State' -Expected 'Enabled' -Status 'Fail' `
            -Message "Unable to query real-time protection status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and the Defender PowerShell module is available."
    }
}