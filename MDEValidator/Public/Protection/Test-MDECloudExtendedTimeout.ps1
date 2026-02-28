function Test-MDECloudExtendedTimeout {
    <#
    .SYNOPSIS
        Tests the Cloud Extended Timeout configuration.
    
    .DESCRIPTION
        Checks the Cloud Extended Timeout (CloudExtendedTimeout) setting that controls
        how long Windows Defender Antivirus can block a file while waiting for a 
        cloud-based determination. This is an extension to the default 10-second timeout.
    
    .PARAMETER MpPreference
        Optional. A pre-fetched MpPreference object from Get-MpPreference.
        If not provided, the function will call Get-MpPreference internally.
    
    .EXAMPLE
        Test-MDECloudExtendedTimeout
        
        Tests the Cloud Extended Timeout configuration.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        CloudExtendedTimeout values:
        0 = Not configured (uses default 10-second timeout only)
        1-50 = Additional seconds to wait for cloud verdict (on top of built-in 10 seconds)
        
        Recommended: 41-50 seconds for maximum cloud protection capability.
        This gives the cloud a total of 51-60 seconds (10 built-in + 41-50 extended) 
        to analyze suspicious files.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSObject]$MpPreference
    )
    
    $testName = 'Cloud Extended Timeout'
    Write-Verbose "Checking $testName..."
    
    try {
        if ($null -eq $MpPreference) {
            $MpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        $cloudExtendedTimeout = $MpPreference.CloudExtendedTimeout
        
        # Handle null or not configured
        if ($null -eq $cloudExtendedTimeout) {
            $cloudExtendedTimeout = 0
        }
        
        Write-Debug "CloudExtendedTimeout: $cloudExtendedTimeout"
        
        $recommendationNote = "This feature allows Windows Defender Antivirus to block a suspicious file for up to 60 seconds, and scan it in the cloud to make sure it's safe. The more time you provide, the better chance of blocking a suspicious file. 10 seconds is already built-in."
        
        if ($cloudExtendedTimeout -ge 41 -and $cloudExtendedTimeout -le 50) {
            # Pass: 41-50 seconds (total 51-60 seconds with built-in)
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Cloud Extended Timeout is set to $cloudExtendedTimeout seconds (total: $($cloudExtendedTimeout + 10) seconds including built-in 10 seconds)."
        } elseif ($cloudExtendedTimeout -ge 21 -and $cloudExtendedTimeout -le 40) {
            # Warning: 21-40 seconds
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Cloud Extended Timeout is set to $cloudExtendedTimeout seconds (total: $($cloudExtendedTimeout + 10) seconds including built-in 10 seconds)." `
                -Recommendation "Consider increasing CloudExtendedTimeout to 50 seconds via Intune or Group Policy. $recommendationNote"
        } else {
            # Fail: 0-20 seconds or not configured
            $message = if ($cloudExtendedTimeout -eq 0) {
                "Cloud Extended Timeout is not configured (using default 10 seconds only)."
            } else {
                "Cloud Extended Timeout is set to $cloudExtendedTimeout seconds (total: $($cloudExtendedTimeout + 10) seconds including built-in 10 seconds)."
            }
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message $message `
                -Recommendation "Configure CloudExtendedTimeout to 50 seconds via Intune or Group Policy. $recommendationNote"
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Cloud Extended Timeout: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}
