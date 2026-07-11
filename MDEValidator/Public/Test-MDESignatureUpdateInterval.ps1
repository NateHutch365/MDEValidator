function Test-MDESignatureUpdateInterval {
    <#
    .SYNOPSIS
        Tests the Signature Update Interval configuration.
    
    .DESCRIPTION
        Checks the SignatureUpdateInterval setting that controls how frequently
        Windows Defender checks for signature updates. A lower value ensures
        more frequent delta updates.
    
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
    
    $testName = 'Signature Update Interval'
    
    try {
        if ($null -eq $MpPreference) {
            $mpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        $signatureUpdateInterval = $mpPreference.SignatureUpdateInterval
        
        # Handle null as not configured (treat as 0/disabled)
        if ($null -eq $signatureUpdateInterval) {
            $signatureUpdateInterval = 0
        }
        
        $message = "Signature Update Interval: $signatureUpdateInterval hour(s)"
        
        if ($signatureUpdateInterval -eq 0) {
            # Fail: Disabled
            Write-ValidationResult -TestName $testName -Category 'Protection Settings' -Expected '<= 4 hours' -Actual "$signatureUpdateInterval hour(s)" -Status 'Fail' `
                -Message "$message. Automatic signature update checking is disabled." `
                -Recommendation "Set Signature Update Interval to 1 hour via Intune or Group Policy to ensure delta updates are applied frequently."
        } elseif ($signatureUpdateInterval -ge 1 -and $signatureUpdateInterval -le 4) {
            # Pass: 1-4 hours
            Write-ValidationResult -TestName $testName -Category 'Protection Settings' -Expected '<= 4 hours' -Actual "$signatureUpdateInterval hour(s)" -Status 'Pass' `
                -Message "$message. Signature updates are checked frequently."
        } elseif ($signatureUpdateInterval -ge 5 -and $signatureUpdateInterval -le 24) {
            # Warning: 5-24 hours
            Write-ValidationResult -TestName $testName -Category 'Protection Settings' -Expected '<= 4 hours' -Actual "$signatureUpdateInterval hour(s)" -Status 'Warning' `
                -Message "$message. Signature updates are checked less frequently than recommended." `
                -Recommendation "Set Signature Update Interval to 1 hour via Intune or Group Policy to ensure delta updates are applied frequently."
        } else {
            # Unknown/invalid value - Warning
            Write-ValidationResult -TestName $testName -Category 'Protection Settings' -Expected '<= 4 hours' -Actual "$signatureUpdateInterval hour(s)" -Status 'Warning' `
                -Message "$message. Unexpected Signature Update Interval value." `
                -Recommendation "Set Signature Update Interval to 1 hour via Intune or Group Policy to ensure delta updates are applied frequently."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Category 'Protection Settings' -Expected '<= 4 hours' -Status 'Fail' `
            -Message "Unable to query Signature Update Interval: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}