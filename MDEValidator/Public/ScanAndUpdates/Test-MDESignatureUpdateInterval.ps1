function Test-MDESignatureUpdateInterval {
    <#
    .SYNOPSIS
        Tests the Signature Update Interval configuration.
    
    .DESCRIPTION
        Checks the SignatureUpdateInterval setting that controls how frequently
        Windows Defender checks for signature updates. A lower value ensures
        more frequent delta updates.
    
    .PARAMETER MpPreference
        Optional. A pre-fetched MpPreference object from Get-MpPreference.
        If not provided, the function will call Get-MpPreference internally.
    
    .EXAMPLE
        Test-MDESignatureUpdateInterval
        
        Tests the Signature Update Interval configuration.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        SignatureUpdateInterval values:
        0 = Disabled (never checks for updates automatically) - Fail
        1-4 = Optimal interval for frequent delta updates - Pass
        5-24 = Less frequent updates - Warning
        
        Recommended: Set to 1 to ensure delta updates are applied frequently.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSObject]$MpPreference
    )
    
    $testName = 'Signature Update Interval'
    Write-Verbose "Checking $testName..."
    
    try {
        if ($null -eq $MpPreference) {
            $MpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        $signatureUpdateInterval = $MpPreference.SignatureUpdateInterval
        
        Write-Debug "SignatureUpdateInterval: $signatureUpdateInterval"
        
        # Handle null as not configured (treat as 0/disabled)
        if ($null -eq $signatureUpdateInterval) {
            $signatureUpdateInterval = 0
        }
        
        $message = "Signature Update Interval: $signatureUpdateInterval hour(s)"
        
        if ($signatureUpdateInterval -eq 0) {
            # Fail: Disabled
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "$message. Automatic signature update checking is disabled." `
                -Recommendation "Set Signature Update Interval to 1 hour via Intune or Group Policy to ensure delta updates are applied frequently."
        } elseif ($signatureUpdateInterval -ge 1 -and $signatureUpdateInterval -le 4) {
            # Pass: 1-4 hours
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "$message. Signature updates are checked frequently."
        } elseif ($signatureUpdateInterval -ge 5 -and $signatureUpdateInterval -le 24) {
            # Warning: 5-24 hours
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "$message. Signature updates are checked less frequently than recommended." `
                -Recommendation "Set Signature Update Interval to 1 hour via Intune or Group Policy to ensure delta updates are applied frequently."
        } else {
            # Unknown/invalid value - Warning
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "$message. Unexpected Signature Update Interval value." `
                -Recommendation "Set Signature Update Interval to 1 hour via Intune or Group Policy to ensure delta updates are applied frequently."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Signature Update Interval: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}
