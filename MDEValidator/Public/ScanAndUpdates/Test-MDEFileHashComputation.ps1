function Test-MDEFileHashComputation {
    <#
    .SYNOPSIS
        Tests if File Hash Computation is enabled.
    
    .DESCRIPTION
        Checks the EnableFileHashComputation setting in Windows Defender.
        When enabled, Windows Defender computes file hashes for files that are scanned,
        which can be used for threat intelligence, hunting, and IoC matching.
    
    .PARAMETER MpPreference
        Optional. A pre-fetched MpPreference object from Get-MpPreference.
        If not provided, the function will call Get-MpPreference internally.
    
    .EXAMPLE
        Test-MDEFileHashComputation
        
        Tests if File Hash Computation is enabled.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        EnableFileHashComputation values:
        $true = File Hash Computation is enabled (recommended)
        $false or not configured = File Hash Computation is disabled
        
        When enabled, file hashes are computed for scanned files, enabling:
        - Threat intelligence matching
        - Indicator of Compromise (IoC) hunting
        - Enhanced threat detection via file hash reputation
        
        This can be configured via:
        - Group Policy: Computer Configuration > Administrative Templates > Windows Components > 
          Microsoft Defender Antivirus > Enable file hash computation feature
        - Intune/MEM: Endpoint Security > Antivirus
        - PowerShell: Set-MpPreference -EnableFileHashComputation $true
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSObject]$MpPreference
    )
    
    $testName = 'File Hash Computation'
    $enableRecommendation = "Enable File Hash Computation via Intune or Group Policy to enable file hash-based threat detection and IoC matching."
    Write-Verbose "Checking $testName..."
    
    try {
        if ($null -eq $MpPreference) {
            $MpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        $enableFileHashComputation = $MpPreference.EnableFileHashComputation
        
        Write-Debug "EnableFileHashComputation: $enableFileHashComputation"
        
        # Handle null as not configured (disabled by default)
        if ($null -eq $enableFileHashComputation) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "File Hash Computation is not configured (disabled by default)." `
                -Recommendation $enableRecommendation
        } elseif ($enableFileHashComputation -eq $true) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "File Hash Computation is enabled. File hashes are computed for scanned files."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "File Hash Computation is disabled." `
                -Recommendation $enableRecommendation
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query File Hash Computation setting: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}
