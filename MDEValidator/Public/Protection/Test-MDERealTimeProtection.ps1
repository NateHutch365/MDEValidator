function Test-MDERealTimeProtection {
    <#
    .SYNOPSIS
        Tests if real-time protection is enabled.
    
    .DESCRIPTION
        Checks the real-time protection status of Windows Defender Antivirus.
    
    .PARAMETER MpPreference
        Optional. A pre-fetched MpPreference object from Get-MpPreference.
        If not provided, the function will call Get-MpPreference internally.
    
    .EXAMPLE
        Test-MDERealTimeProtection
        
        Tests if real-time protection is enabled.
    
    .OUTPUTS
        PSCustomObject with validation results.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSObject]$MpPreference
    )
    
    $testName = 'Real-Time Protection'
    Write-Verbose "Checking $testName..."
    
    try {
        if ($null -eq $MpPreference) {
            $MpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        Write-Debug "DisableRealtimeMonitoring: $($MpPreference.DisableRealtimeMonitoring)"
        
        if ($MpPreference.DisableRealtimeMonitoring -eq $false) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Real-time protection is enabled."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Real-time protection is disabled." `
                -Recommendation "Enable real-time protection via Intune or Group Policy."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query real-time protection status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and the Defender PowerShell module is available."
    }
}
