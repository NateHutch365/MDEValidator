function Test-MDESampleSubmission {
    <#
    .SYNOPSIS
        Tests if automatic sample submission is enabled.
    
    .DESCRIPTION
        Checks the automatic sample submission status of Windows Defender Antivirus.
    
    .EXAMPLE
        Test-MDESampleSubmission
        
        Tests if automatic sample submission is enabled.
    
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
    
    $testName = 'Automatic Sample Submission'
    
    try {
        if ($null -eq $MpPreference) {
            $mpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        # SubmitSamplesConsent: 0 = Always Prompt, 1 = Send safe samples, 2 = Never send, 3 = Send all samples
        if ($mpPreference.SubmitSamplesConsent -eq 3) {
            Write-ValidationResult -TestName $testName -Category 'Protection Settings' -Expected 'Send safe samples' -Actual 'Send all samples automatically' -Status 'Pass' `
                -Message "Automatic sample submission is enabled: 'Send all samples automatically'."
        } elseif ($mpPreference.SubmitSamplesConsent -eq 1) {
            Write-ValidationResult -TestName $testName -Category 'Protection Settings' -Expected 'Send safe samples' -Actual 'Send safe samples' -Status 'Warning' `
                -Message "Automatic sample submission is set to 'Safe samples only'." `
                -Recommendation "Consider enabling 'Send all samples automatically' for better threat detection via Intune or Group Policy."
        } elseif ($mpPreference.SubmitSamplesConsent -eq 0) {
            Write-ValidationResult -TestName $testName -Category 'Protection Settings' -Expected 'Send safe samples' -Actual 'Always Prompt' -Status 'Warning' `
                -Message "Automatic sample submission is set to 'Always Prompt'." `
                -Recommendation "Consider enabling automatic sample submission for better threat detection via Intune or Group Policy."
        } else {
            Write-ValidationResult -TestName $testName -Category 'Protection Settings' -Expected 'Send safe samples' -Actual 'Disabled' -Status 'Fail' `
                -Message "Automatic sample submission is disabled." `
                -Recommendation "Enable automatic sample submission via Intune or Group Policy."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Category 'Protection Settings' -Expected 'Send safe samples' -Status 'Fail' `
            -Message "Unable to query sample submission status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}