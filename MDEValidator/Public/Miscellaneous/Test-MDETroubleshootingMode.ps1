function Test-MDETroubleshootingMode {
    <#
    .SYNOPSIS
        Tests if Microsoft Defender Troubleshooting Mode is enabled.
    
    .DESCRIPTION
        Checks the TroubleshootingMode property from Get-MpPreference to determine if
        Microsoft Defender Troubleshooting Mode is enabled. This is intended to be a
        temporary state and may affect the reliability of reported Defender configuration values.
        
        If Troubleshooting Mode is enabled, the control returns a Warning as this should be
        a temporary state. If disabled, the control returns a Pass.
    
    .PARAMETER MpPreference
        Optional. A pre-fetched MpPreference object from Get-MpPreference.
        If not provided, the function will call Get-MpPreference internally.
    
    .EXAMPLE
        Test-MDETroubleshootingMode
        
        Tests if Troubleshooting Mode is enabled.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        TroubleshootingMode values:
        Enabled = Troubleshooting Mode is active (temporary state, may affect reported values)
        Disabled = Normal operation
        
        Troubleshooting Mode is designed to be a temporary state for diagnostic purposes.
        When enabled, it may affect the reliability of certain reported configuration values,
        including threat default actions.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSObject]$MpPreference
    )
    
    $testName = 'Troubleshooting Mode'
    Write-Verbose "Checking $testName..."
    
    try {
        if ($null -eq $MpPreference) {
            $MpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        # Check TroubleshootingMode property
        $troubleshootingMode = $MpPreference.TroubleshootingMode
        
        Write-Debug "TroubleshootingMode: $troubleshootingMode"
        
        # Normalize the value for comparison
        $isEnabled = switch ($troubleshootingMode) {
            'Enabled' { $true }
            'Disabled' { $false }
            $true { $true }
            $false { $false }
            1 { $true }
            0 { $false }
            $null { $false }
            default { $false }
        }
        
        if ($null -eq $troubleshootingMode) {
            # Property not available or not set - treat as disabled
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Troubleshooting Mode is disabled (property not available or not set)."
        } elseif ($isEnabled) {
            # Troubleshooting Mode is enabled - Warning
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Troubleshooting Mode is enabled. This is intended to be a temporary state and may affect the reliability of reported Defender configuration values." `
                -Recommendation "Disable Troubleshooting Mode when diagnostic work is complete. Prolonged use of Troubleshooting Mode is not recommended for production systems."
        } else {
            # Troubleshooting Mode is disabled - Pass
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Troubleshooting Mode is disabled."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Troubleshooting Mode status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured. The TroubleshootingMode property may not be available on all versions of Windows Defender."
    }
}
