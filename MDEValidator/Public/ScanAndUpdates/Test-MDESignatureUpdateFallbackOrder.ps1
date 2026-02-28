function Test-MDESignatureUpdateFallbackOrder {
    <#
    .SYNOPSIS
        Tests the Signature Update Fallback Order configuration.
    
    .DESCRIPTION
        Checks the SignatureFallbackOrder setting that controls the order in which
        signature update sources are used when the primary source is unavailable.
    
    .PARAMETER MpPreference
        Optional. A pre-fetched MpPreference object from Get-MpPreference.
        If not provided, the function will call Get-MpPreference internally.
    
    .EXAMPLE
        Test-MDESignatureUpdateFallbackOrder
        
        Tests the Signature Update Fallback Order configuration.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        The recommended SignatureFallbackOrder is:
        MMPC|MicrosoftUpdateServer|InternalDefinitionUpdateServer
        
        This ensures that Microsoft Malware Protection Center (MMPC) is tried first,
        followed by Microsoft Update Server, and then internal definition update servers.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSObject]$MpPreference
    )
    
    $testName = 'Signature Update Fallback Order'
    $recommendedOrder = 'MMPC|MicrosoftUpdateServer|InternalDefinitionUpdateServer'
    Write-Verbose "Checking $testName..."
    
    try {
        if ($null -eq $MpPreference) {
            $MpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        $fallbackOrder = $MpPreference.SignatureFallbackOrder
        
        Write-Debug "SignatureFallbackOrder: $fallbackOrder"
        
        # Handle null or empty value as not configured
        if ([string]::IsNullOrEmpty($fallbackOrder)) {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Signature Update Fallback Order is not configured." `
                -Recommendation "Configure Signature Update Fallback Order to '$recommendedOrder' via Intune or Group Policy."
            return
        }
        
        $message = "Signature Update Fallback Order: $fallbackOrder"
        
        if ($fallbackOrder -eq $recommendedOrder) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "$message. The recommended fallback order is configured."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "$message. This differs from the recommended order." `
                -Recommendation "Consider configuring Signature Update Fallback Order to '$recommendedOrder' via Intune or Group Policy."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Signature Update Fallback Order: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}
