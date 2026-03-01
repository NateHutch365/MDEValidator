function Test-MDEAttackSurfaceReduction {
    <#
    .SYNOPSIS
        Tests if Attack Surface Reduction (ASR) rules are configured.
    
    .DESCRIPTION
        Checks the Attack Surface Reduction rules status of Windows Defender Antivirus.
        Reports each rule by its human-readable name and enforcement setting.
    
    .PARAMETER MpPreference
        Optional. A pre-fetched MpPreference object from Get-MpPreference.
        If not provided, the function will call Get-MpPreference internally.
    
    .EXAMPLE
        Test-MDEAttackSurfaceReduction
        
        Tests if ASR rules are configured.
    
    .OUTPUTS
        PSCustomObject with validation results.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSObject]$MpPreference
    )
    
    $testName = 'Attack Surface Reduction Rules'
    Write-Verbose "Checking $testName..."
    
    # Common ASR rule GUIDs and their descriptions
    $asrRuleNames = @{
        '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
        '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office applications from creating child processes'
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
        '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executable files from running unless they meet criteria'
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
        'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript or VBScript from launching downloaded executable content'
        '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office applications from creating executable content'
        '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office applications from injecting code into other processes'
        '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication application from creating child processes'
        'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
        'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations originating from PSExec and WMI commands'
        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted and unsigned processes that run from USB'
        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
        'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'
        'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = 'Block Webshell creation for Servers'
        '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Block rebooting machine in Safe Mode'
        'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Block use of copied or impersonated system tools'
    }
    
    # ASR rule action values and their human-readable names
    $asrActionNames = @{
        0 = 'Disabled'
        1 = 'Block'
        2 = 'Audit'
        6 = 'Warn'
    }
    
    try {
        if ($null -eq $MpPreference) {
            $MpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        $configuredRules = $MpPreference.AttackSurfaceReductionRules_Ids
        $ruleActions = $MpPreference.AttackSurfaceReductionRules_Actions
        
        Write-Debug "Configured ASR rules count: $(if ($null -ne $configuredRules) { $configuredRules.Count } else { 0 })"
        
        if ($null -eq $configuredRules -or $configuredRules.Count -eq 0) {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "No Attack Surface Reduction rules are configured." `
                -Recommendation "Configure ASR rules via Group Policy or Intune for enhanced protection."
            return
        }
        
        $enabledCount = 0
        $auditCount = 0
        $disabledCount = 0
        $warnCount = 0
        $ruleDetails = @()
        
        for ($i = 0; $i -lt $configuredRules.Count; $i++) {
            $ruleGuid = $configuredRules[$i].ToLower()
            $actionValue = if ($null -ne $ruleActions -and $i -lt $ruleActions.Count) { $ruleActions[$i] } else { $null }
            
            # Get human-readable rule name (fall back to GUID if unknown)
            $ruleName = if ($asrRuleNames.ContainsKey($ruleGuid)) { 
                $asrRuleNames[$ruleGuid] 
            } else { 
                "Unknown rule ($ruleGuid)" 
            }
            
            # Get human-readable action name
            $actionName = if ($null -ne $actionValue -and $asrActionNames.ContainsKey([int]$actionValue)) {
                $asrActionNames[[int]$actionValue]
            } else {
                'Unknown'
            }
            
            # Count actions
            if ($null -ne $actionValue) {
                switch ([int]$actionValue) {
                    0 { $disabledCount++ }
                    1 { $enabledCount++ }
                    2 { $auditCount++ }
                    6 { $warnCount++ }
                }
            }
            
            # Add to rule details with human-readable format
            $ruleDetails += "$ruleName ($actionName)"
        }
        
        $totalRules = $configuredRules.Count
        $summaryMessage = "ASR rules configured: $totalRules total ($enabledCount Block, $auditCount Audit, $warnCount Warn, $disabledCount Disabled)"
        
        Write-Debug "ASR summary: $summaryMessage"
        
        # Build detailed message with rule names and actions, each on its own line
        $detailedRules = ($ruleDetails | ForEach-Object { "  - $_" }) -join "`n"
        $fullMessage = "$summaryMessage`nRules:`n$detailedRules"
        
        if ($enabledCount -gt 0) {
            $result = Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message $fullMessage
        } elseif ($auditCount -gt 0 -or $warnCount -gt 0) {
            $result = Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "$fullMessage. No rules are in Block mode." `
                -Recommendation "Consider enabling Block mode for ASR rules after validating Audit mode results."
        } else {
            $result = Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "$fullMessage. All configured rules are disabled." `
                -Recommendation "Enable ASR rules for enhanced protection against common attack techniques."
        }
        
        # Add custom properties for HTML rendering
        $result | Add-Member -MemberType NoteProperty -Name 'ASRSummary' -Value $summaryMessage -Force
        $result | Add-Member -MemberType NoteProperty -Name 'ASRRuleDetails' -Value $ruleDetails -Force
        
        return $result
    }
    catch {
        return Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query ASR rules status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}
