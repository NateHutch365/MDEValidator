function Test-MDECloudBlockLevel {
    <#
    .SYNOPSIS
        Tests the Cloud Block Level configuration.
    
    .DESCRIPTION
        Checks the Cloud Block Level (CloudBlockLevel) setting that controls
        how aggressively Microsoft Defender blocks suspicious files using cloud protection.
    
    .PARAMETER MpPreference
        Optional. A pre-fetched MpPreference object from Get-MpPreference.
        If not provided, the function will call Get-MpPreference internally.
    
    .EXAMPLE
        Test-MDECloudBlockLevel
        
        Tests the Cloud Block Level configuration.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        CloudBlockLevel values:
        0 = Default (Not Configured)
        1 = Moderate
        2 = High
        4 = High+ (High Plus)
        6 = Zero Tolerance
        
        Recommended: High (2), High+ (4), or Zero Tolerance (6) for enhanced protection.
        For Tier-0 assets such as Domain Controllers, Zero Tolerance or at minimum High+ 
        is recommended as these devices should typically run standard or native applications.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSObject]$MpPreference
    )
    
    $testName = 'Cloud Block Level'
    Write-Verbose "Checking $testName..."
    
    # Map Cloud Block Level values to human-readable names
    $cloudBlockLevelNames = @{
        0 = 'Default (Not Configured)'
        1 = 'Moderate'
        2 = 'High'
        4 = 'High+'
        6 = 'Zero Tolerance'
    }
    
    try {
        if ($null -eq $MpPreference) {
            $MpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        # Cast to int once for consistent comparison
        $cloudBlockLevelValue = [int]$MpPreference.CloudBlockLevel
        $levelName = if ($cloudBlockLevelNames.ContainsKey($cloudBlockLevelValue)) { 
            $cloudBlockLevelNames[$cloudBlockLevelValue] 
        } else { 
            'Unknown' 
        }
        
        $message = "Cloud Block Level: $cloudBlockLevelValue ($levelName)"
        Write-Debug "CloudBlockLevel value: $cloudBlockLevelValue ($levelName)"
        
        # Determine status based on the configured level
        switch ($cloudBlockLevelValue) {
            0 {
                # Default/Not Configured - Fail
                Write-ValidationResult -TestName $testName -Status 'Fail' `
                    -Message "$message. Cloud Block Level is not configured and using default settings." `
                    -Recommendation "Configure Cloud Block Level to High (2), High+ (4), or Zero Tolerance (6) via Group Policy or Intune. For Tier-0 assets such as Domain Controllers, aim for Zero Tolerance or at minimum High+ as these devices should typically run standard or native applications."
            }
            1 {
                # Moderate - Fail (insufficient)
                Write-ValidationResult -TestName $testName -Status 'Fail' `
                    -Message "$message. Moderate protection level may not provide sufficient protection." `
                    -Recommendation "Increase Cloud Block Level to High (2), High+ (4), or Zero Tolerance (6) via Group Policy or Intune. For Tier-0 assets such as Domain Controllers, aim for Zero Tolerance or at minimum High+ as these devices should typically run standard or native applications."
            }
            2 {
                # High - Pass
                Write-ValidationResult -TestName $testName -Status 'Pass' `
                    -Message "$message. High protection level is configured." `
                    -Recommendation "For Tier-0 assets such as Domain Controllers, consider increasing to High+ (4) or Zero Tolerance (6) as these devices should typically run standard or native applications."
            }
            4 {
                # High+ - Pass
                Write-ValidationResult -TestName $testName -Status 'Pass' `
                    -Message "$message. High+ protection level is configured, providing enhanced cloud protection."
            }
            6 {
                # Zero Tolerance - Pass
                Write-ValidationResult -TestName $testName -Status 'Pass' `
                    -Message "$message. Zero Tolerance protection level is configured, providing maximum cloud protection."
            }
            default {
                # Unknown value - Warning
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "$message. Unknown Cloud Block Level value detected." `
                    -Recommendation "Verify Cloud Block Level configuration via Group Policy or Intune. Recommended values are High (2), High+ (4), or Zero Tolerance (6)."
            }
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Cloud Block Level: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}
