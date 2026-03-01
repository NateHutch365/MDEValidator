function Test-MDERealTimeScanDirection {
    <#
    .SYNOPSIS
        Tests the Real-Time Scan Direction configuration.
    
    .DESCRIPTION
        Checks the RealTimeScanDirection setting that controls which file operations
        are monitored by real-time protection.
    
    .PARAMETER MpPreference
        Optional. A pre-fetched MpPreference object from Get-MpPreference.
        If not provided, the function will call Get-MpPreference internally.
    
    .EXAMPLE
        Test-MDERealTimeScanDirection
        
        Tests the Real-Time Scan Direction configuration.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        RealTimeScanDirection values:
        0 = Monitor all files (bi-directional) - recommended
        1 = Monitor incoming files only
        2 = Monitor outgoing files only
        
        Bi-directional monitoring provides the most comprehensive protection.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSObject]$MpPreference
    )
    
    $testName = 'Real Time Scan Direction'
    Write-Verbose "Checking $testName..."
    
    # Map RealTimeScanDirection values to human-readable names
    $scanDirectionNames = @{
        0 = 'Monitor all files (bi-directional)'
        1 = 'Monitor incoming files'
        2 = 'Monitor outgoing files'
    }
    
    try {
        if ($null -eq $MpPreference) {
            $MpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        $scanDirection = $MpPreference.RealTimeScanDirection
        
        Write-Debug "RealTimeScanDirection: $scanDirection"
        
        # Handle null value as not configured
        if ($null -eq $scanDirection) {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Real Time Scan Direction is not configured." `
                -Recommendation "Configure Real Time Scan Direction to 'Monitor all files (bi-directional)' via Intune or Group Policy."
            return
        }
        
        $directionName = if ($scanDirectionNames.ContainsKey([int]$scanDirection)) { 
            $scanDirectionNames[[int]$scanDirection] 
        } else { 
            'Unknown' 
        }
        
        $message = "Real Time Scan Direction: $scanDirection ($directionName)"
        
        switch ([int]$scanDirection) {
            0 {
                # Bi-directional - Pass
                Write-ValidationResult -TestName $testName -Status 'Pass' `
                    -Message "$message. All file operations are monitored for threats."
            }
            1 {
                # Incoming only - Warning
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "$message. Only incoming files are monitored." `
                    -Recommendation "Configure Real Time Scan Direction to 'Monitor all files (bi-directional)' via Intune or Group Policy for comprehensive protection."
            }
            2 {
                # Outgoing only - Warning
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "$message. Only outgoing files are monitored." `
                    -Recommendation "Configure Real Time Scan Direction to 'Monitor all files (bi-directional)' via Intune or Group Policy for comprehensive protection."
            }
            default {
                # Unknown value - Warning
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "$message. Unknown Real Time Scan Direction value detected." `
                    -Recommendation "Verify Real Time Scan Direction configuration via Group Policy or Intune."
            }
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Real Time Scan Direction: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}
