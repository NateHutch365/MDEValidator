function Test-MDESignatureUpdateFallbackOrder {
    <#
    .SYNOPSIS
        Tests the Signature Update Fallback Order configuration.
    
    .DESCRIPTION
        Checks the SignatureFallbackOrder setting that controls the order in which
        signature update sources are used when the primary source is unavailable.
    
    .EXAMPLE
        Test-MDESignatureUpdateFallbackOrder
        
        Tests the Signature Update Fallback Order configuration.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        The check passes as long as MicrosoftUpdateServer and MMPC are both present and
        MicrosoftUpdateServer appears before MMPC. Additional sources such as
        InternalDefinitionUpdateServer may be present in any position without affecting the result.
        
        The recommended SignatureFallbackOrder is:
        MicrosoftUpdateServer|MMPC|InternalDefinitionUpdateServer
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Signature Update Fallback Order'
    $recommendedOrder = 'MicrosoftUpdateServer|MMPC|InternalDefinitionUpdateServer'
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        $fallbackOrder = $mpPreference.SignatureFallbackOrder
        
        # Handle null or empty value as not configured
        if ([string]::IsNullOrEmpty($fallbackOrder)) {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Signature Update Fallback Order is not configured." `
                -Recommendation "Configure Signature Update Fallback Order to '$recommendedOrder' via Intune or Group Policy."
            return
        }
        
        $message = "Signature Update Fallback Order: $fallbackOrder"
        $sources = $fallbackOrder -split '\|'
        $muIndex   = [Array]::IndexOf($sources, 'MicrosoftUpdateServer')
        $mmpcIndex = [Array]::IndexOf($sources, 'MMPC')
        
        $bothPresent   = ($muIndex -ge 0) -and ($mmpcIndex -ge 0)
        $correctOrder  = $bothPresent -and ($muIndex -lt $mmpcIndex)
        
        if ($correctOrder) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "$message. MicrosoftUpdateServer precedes MMPC as required."
        } elseif (-not $bothPresent) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "$message. One or both required sources (MicrosoftUpdateServer, MMPC) are missing." `
                -Recommendation "Configure Signature Update Fallback Order to '$recommendedOrder' via Intune or Group Policy."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "$message. MicrosoftUpdateServer must appear before MMPC." `
                -Recommendation "Configure Signature Update Fallback Order to '$recommendedOrder' via Intune or Group Policy."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Signature Update Fallback Order: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}