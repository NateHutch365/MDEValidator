function Test-MDEFileHashComputation {
    <#
    .SYNOPSIS
        Tests if File Hash Computation is enabled.
    
    .DESCRIPTION
        Checks the EnableFileHashComputation setting in Windows Defender.
        When enabled, Windows Defender computes file hashes for files that are scanned,
        which can be used for threat intelligence, hunting, and IoC matching.
    
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
    
    $testName = 'File Hash Computation'
    $enableRecommendation = "Enable File Hash Computation via Intune or Group Policy to enable file hash-based threat detection and IoC matching."
    
    try {
        if ($null -eq $MpPreference) {
            $mpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        $enableFileHashComputation = $mpPreference.EnableFileHashComputation
        
        # Handle null as not configured (disabled by default)
        if ($null -eq $enableFileHashComputation) {
            Write-ValidationResult -TestName $testName -Category 'Protection Settings' -Expected 'Enabled' -Actual 'Not configured (disabled by default)' -Status 'Warning' `
                -Message "File Hash Computation is not configured (disabled by default)." `
                -Recommendation $enableRecommendation
        } elseif ($enableFileHashComputation -eq $true) {
            Write-ValidationResult -TestName $testName -Category 'Protection Settings' -Expected 'Enabled' -Actual 'Enabled' -Status 'Pass' `
                -Message "File Hash Computation is enabled. File hashes are computed for scanned files."
        } else {
            Write-ValidationResult -TestName $testName -Category 'Protection Settings' -Expected 'Enabled' -Actual 'Disabled' -Status 'Warning' `
                -Message "File Hash Computation is disabled." `
                -Recommendation $enableRecommendation
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Category 'Protection Settings' -Expected 'Enabled' -Status 'Fail' `
            -Message "Unable to query File Hash Computation setting: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}