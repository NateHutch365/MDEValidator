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
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Behavior Monitoring'
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        if ($mpPreference.DisableBehaviorMonitoring -eq $false) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Behavior monitoring is enabled."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Behavior monitoring is disabled." `
                -Recommendation "Enable behavior monitoring via Intune or Group Policy."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query behavior monitoring status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}