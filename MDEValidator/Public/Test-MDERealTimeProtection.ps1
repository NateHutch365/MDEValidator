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
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Real-Time Protection'
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        if ($mpPreference.DisableRealtimeMonitoring -eq $false) {
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