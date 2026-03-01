function Test-MDEBehaviorMonitoring {
    <#
    .SYNOPSIS
        Tests if behavior monitoring is enabled.
    
    .DESCRIPTION
        Checks the behavior monitoring status of Windows Defender Antivirus.
    
    .PARAMETER MpPreference
        Optional. A pre-fetched MpPreference object from Get-MpPreference.
        If not provided, the function will call Get-MpPreference internally.
    
    .EXAMPLE
        Test-MDEBehaviorMonitoring
        
        Tests if behavior monitoring is enabled.
    
    .OUTPUTS
        PSCustomObject with validation results.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSObject]$MpPreference
    )
    
    $testName = 'Behavior Monitoring'
    Write-Verbose "Checking $testName..."
    
    try {
        if ($null -eq $MpPreference) {
            $MpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        Write-Debug "DisableBehaviorMonitoring: $($MpPreference.DisableBehaviorMonitoring)"
        
        if ($MpPreference.DisableBehaviorMonitoring -eq $false) {
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
