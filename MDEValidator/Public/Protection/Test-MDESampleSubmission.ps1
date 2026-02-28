function Test-MDESampleSubmission {
    <#
    .SYNOPSIS
        Tests if automatic sample submission is enabled.
    
    .DESCRIPTION
        Checks the automatic sample submission status of Windows Defender Antivirus.
    
    .PARAMETER MpPreference
        Optional. A pre-fetched MpPreference object from Get-MpPreference.
        If not provided, the function will call Get-MpPreference internally.
    
    .EXAMPLE
        Test-MDESampleSubmission
        
        Tests if automatic sample submission is enabled.
    
    .OUTPUTS
        PSCustomObject with validation results.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSObject]$MpPreference
    )
    
    $testName = 'Automatic Sample Submission'
    Write-Verbose "Checking $testName..."
    
    try {
        if ($null -eq $MpPreference) {
            $MpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        Write-Debug "SubmitSamplesConsent: $($MpPreference.SubmitSamplesConsent)"
        
        # SubmitSamplesConsent: 0 = Always Prompt, 1 = Send safe samples, 2 = Never send, 3 = Send all samples
        if ($MpPreference.SubmitSamplesConsent -eq 3) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Automatic sample submission is enabled: 'Send all samples automatically'."
        } elseif ($MpPreference.SubmitSamplesConsent -eq 1) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Automatic sample submission is set to 'Safe samples only'." `
                -Recommendation "Consider enabling 'Send all samples automatically' for better threat detection via Intune or Group Policy."
        } elseif ($MpPreference.SubmitSamplesConsent -eq 0) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Automatic sample submission is set to 'Always Prompt'." `
                -Recommendation "Consider enabling automatic sample submission for better threat detection via Intune or Group Policy."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Automatic sample submission is disabled." `
                -Recommendation "Enable automatic sample submission via Intune or Group Policy."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query sample submission status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}
