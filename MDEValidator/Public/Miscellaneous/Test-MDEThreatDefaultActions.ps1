function Test-MDEThreatDefaultActions {
    <#
    .SYNOPSIS
        Tests the default actions configured for threat severity levels.
    
    .DESCRIPTION
        Checks the default actions (Quarantine, Remove, Ignore, etc.) configured for
        Low, Moderate, High, and Severe threat severity levels in Windows Defender.
        
        The control only fails if any default action is explicitly set to NoAction (9), 
        Allow (6), or UserDefined (8). It passes when all actions are set to acceptable 
        values including Clean (1), Quarantine (2), Remove (3), or Block (10).
        
        Unknown (0) values are treated as follows:
        - If Tamper Protection is enabled: Pass (Unknown is acceptable)
        - If Tamper Protection is not enabled: Warning (Unknown should be investigated)
        - If Troubleshooting Mode is active: Warning (may affect reported values)
    
    .PARAMETER MpPreference
        Optional. A pre-fetched MpPreference object from Get-MpPreference.
        If not provided, the function will call Get-MpPreference internally.
    
    .PARAMETER MpComputerStatus
        Optional. A pre-fetched MpComputerStatus object from Get-MpComputerStatus.
        If not provided, the function will call Get-MpComputerStatus internally.
    
    .EXAMPLE
        Test-MDEThreatDefaultActions
        
        Tests the default threat actions configuration.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        Threat action values:
        0 = Unknown (may indicate Tamper Protection is enabled or Troubleshooting Mode is active)
        1 = Clean (repairs infected files) - Pass
        2 = Quarantine - Pass
        3 = Remove (deletes the file) - Pass
        6 = Allow (Ignore) - Fail
        8 = UserDefined - Fail
        9 = NoAction - Fail
        10 = Block - Pass
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSObject]$MpPreference,

        [Parameter()]
        [PSObject]$MpComputerStatus
    )
    
    $testName = 'Threat Default Actions'
    Write-Verbose "Checking $testName..."
    
    # Map action values to human-readable names
    $actionNames = @{
        0 = 'Unknown'
        1 = 'Clean'
        2 = 'Quarantine'
        3 = 'Remove'
        6 = 'Allow'
        8 = 'UserDefined'
        9 = 'NoAction'
        10 = 'Block'
    }
    
    # Explicitly failing actions
    $failingActions = @(6, 8, 9)  # Allow (6), UserDefined (8), NoAction (9)
    
    try {
        if ($null -eq $MpPreference) {
            $MpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        $threatActions = @{
            'LowThreatDefaultAction' = $MpPreference.LowThreatDefaultAction
            'ModerateThreatDefaultAction' = $MpPreference.ModerateThreatDefaultAction
            'HighThreatDefaultAction' = $MpPreference.HighThreatDefaultAction
            'SevereThreatDefaultAction' = $MpPreference.SevereThreatDefaultAction
        }
        
        $failingIssues = @()
        $details = @()
        $unknownCount = 0
        $hasFailingActions = $false
        
        foreach ($threatLevel in @('LowThreatDefaultAction', 'ModerateThreatDefaultAction', 'HighThreatDefaultAction', 'SevereThreatDefaultAction')) {
            $actionValue = $threatActions[$threatLevel]
            $actionName = if ($actionNames.ContainsKey([int]$actionValue)) { $actionNames[[int]$actionValue] } else { 'Unknown' }
            $levelName = $threatLevel -replace 'ThreatDefaultAction', ''
            
            $details += "${levelName}: $actionValue ($actionName)"
            
            Write-Debug "${levelName}ThreatDefaultAction: $actionValue ($actionName)"
            
            # Track Unknown (0) values
            if ($actionValue -eq 0) {
                $unknownCount++
            }
            
            # Check for explicitly failing actions
            if ($actionValue -in $failingActions) {
                $hasFailingActions = $true
                $failingIssues += "$levelName threats are set to $actionValue ($actionName)"
            }
        }
        
        $message = "Threat default actions: $($details -join '; ')"
        
        # Get Tamper Protection status (handle failure gracefully)
        $isTamperProtected = $false
        try {
            if ($null -eq $MpComputerStatus) {
                $MpComputerStatus = Get-MpComputerStatus -ErrorAction Stop
            }
            $isTamperProtected = $MpComputerStatus.IsTamperProtected
            Write-Debug "IsTamperProtected: $isTamperProtected"
        }
        catch {
            # If we can't get Tamper Protection status, default to false and continue
            $isTamperProtected = $false
            Write-Debug "Unable to get Tamper Protection status, defaulting to false"
        }
        
        # Determine result based on logic
        if ($hasFailingActions) {
            # Explicit failure - any action set to NoAction, Allow, or UserDefined
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "$message. Critical issues found: $($failingIssues -join '; ')." `
                -Recommendation "Configure threat default actions to Clean (1), Quarantine (2), Remove (3), or Block (10) for all severity levels via Intune or Group Policy. Avoid NoAction (9), Allow (6), and UserDefined (8)."
        } elseif ($unknownCount -gt 0) {
            # Handle Unknown values based on Tamper Protection status
            if ($isTamperProtected) {
                # Pass when Tamper Protection is enabled
                Write-ValidationResult -TestName $testName -Status 'Pass' `
                    -Message "$message. $unknownCount threat default action(s) show as Unknown, which is acceptable when Tamper Protection is enabled. Tamper Protection: Enabled."
            } else {
                # Warning when Tamper Protection is not enabled
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "$message. $unknownCount threat default action(s) show as Unknown. Tamper Protection: Disabled." `
                    -Recommendation "Unknown values should be investigated. Review threat default action settings in Group Policy or Intune to ensure they are configured correctly."
            }
        } else {
            # All actions are acceptable (Clean, Quarantine, Block, or Remove)
            # No failing actions detected - Pass
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message $message
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query threat default actions: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}
