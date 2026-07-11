function Test-MDEPassiveMode {
    <#
    .SYNOPSIS
        Tests if the device is in Passive Mode or EDR in Block Mode.
    
    .DESCRIPTION
        Checks whether Microsoft Defender Antivirus is running in Passive Mode
        (when another antivirus is the primary AV) or if EDR in Block Mode is enabled.
        Both modes should generate warnings as they indicate non-standard configurations.
    
    .EXAMPLE
        Test-MDEPassiveMode
        
        Tests if the device is in Passive Mode or EDR in Block Mode.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        Passive Mode: Defender runs alongside another AV, with limited real-time protection.
        EDR in Block Mode: Allows Defender to take remediation actions even when in passive mode.
        
        Detection methods:
        - Primary: Get-MpComputerStatus AMRunningMode property (Normal, Passive, EDR Block Mode, SxS Passive Mode)
        - Registry fallback for Passive Mode: HKLM:\SOFTWARE\Microsoft\Windows Defender\PassiveMode = 1
        - Registry for EDR Block Mode behavior: HKLM:\SOFTWARE\Microsoft\Windows Defender\Features\PassiveModeBehavior = 1
    .PARAMETER MpComputerStatus
        Optional Get-MpComputerStatus snapshot. When supplied, the function uses it instead of
        querying Get-MpComputerStatus itself, allowing the caller to share a single query across
        multiple tests. When omitted, the function queries Get-MpComputerStatus directly.
    
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        $MpComputerStatus
    )
    
    $testName = 'Passive Mode / EDR Block Mode'
    
    try {
        $isPassiveMode = $false
        $isEDRBlockMode = $false
        $runningMode = $null
        
        # Check for Passive Mode via Get-MpComputerStatus if available
        try {
            if ($null -eq $MpComputerStatus) {
                $mpStatus = Get-MpComputerStatus -ErrorAction Stop
            }
            else {
                $mpStatus = $MpComputerStatus
            }
            if ($null -ne $mpStatus.AMRunningMode) {
                # AMRunningMode can be: Normal, Passive, EDR Block Mode, SxS Passive Mode
                $runningMode = $mpStatus.AMRunningMode
                if ($runningMode -match 'Passive') {
                    $isPassiveMode = $true
                }
                if ($runningMode -match 'EDR Block') {
                    $isEDRBlockMode = $true
                }
            }
        }
        catch {
            # Intentionally suppressed: Get-MpComputerStatus unavailability is non-fatal; registry fallback follows
            Write-Verbose "Get-MpComputerStatus unavailable: $_"
        }
        
        # Check registry for Passive Mode indicator
        $passiveModeRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender'
        if (Test-Path $passiveModeRegPath) {
            $defenderReg = Get-ItemProperty -Path $passiveModeRegPath -ErrorAction SilentlyContinue
            if ($null -ne $defenderReg.PassiveMode -and $defenderReg.PassiveMode -eq 1) {
                $isPassiveMode = $true
            }
        }
        
        $featuresPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
        $passiveModeBehavior = $null

        if (Test-Path $featuresPath) {
            $features = Get-ItemProperty -Path $featuresPath -ErrorAction SilentlyContinue
            if ($null -ne $features.PassiveModeBehavior) {
                $passiveModeBehavior = $features.PassiveModeBehavior
            }
        }
        
        # EDR Block Mode detection via registry
        # EDR Block Mode allows Defender to perform remediation even when in passive mode
        # It's enabled when PassiveModeBehavior = 1 (block mode behavior is on) AND 
        # the device is in passive mode (either detected via AMRunningMode or PassiveMode registry)
        if ($passiveModeBehavior -eq 1 -and $isPassiveMode) {
            $isEDRBlockMode = $true
        }
        
        # Determine the result
        if ($isEDRBlockMode) {
            Write-ValidationResult -TestName $testName -Category 'Device State' -Expected 'Active or EDR Block' -Actual 'EDR Block Mode' -Status 'Warning' `
                -Message "Device is running in EDR Block Mode. Defender is in passive mode but can take remediation actions via EDR." `
                -Recommendation "EDR Block Mode is typically used when third-party antivirus is primary. Verify this is intentional and ensure the third-party AV provides adequate protection."
        } elseif ($isPassiveMode) {
            Write-ValidationResult -TestName $testName -Category 'Device State' -Expected 'Active or EDR Block' -Actual 'Passive Mode' -Status 'Warning' `
                -Message "Device is running in Passive Mode. Microsoft Defender Antivirus is not the primary antivirus solution." `
                -Recommendation "Passive Mode means another antivirus is active. Verify the third-party AV provides adequate protection, or consider enabling EDR Block Mode for additional remediation capabilities."
        } else {
            Write-ValidationResult -TestName $testName -Category 'Device State' -Expected 'Active or EDR Block' -Actual 'Active Mode' -Status 'Pass' `
                -Message "Device is running in Active Mode. Microsoft Defender Antivirus is the primary antivirus solution."
        }

        # Emit AMRunningMode as a separate result (per DEV-01)
        $amTestName = 'AM Running Mode'
        if ($null -ne $runningMode) {
            if ($runningMode -eq 'Normal') {
                Write-ValidationResult -TestName $amTestName -Category 'Device State' -Expected 'Normal' -Actual "$runningMode" -Status 'Pass' `
                    -Message "AMRunningMode is 'Normal' — Microsoft Defender Antivirus is the primary active protection."
            }
            else {
                Write-ValidationResult -TestName $amTestName -Category 'Device State' -Expected 'Normal' -Actual "$runningMode" -Status 'Warning' `
                    -Message "AMRunningMode is '$runningMode' — Defender is not running in its primary active mode." `
                    -Recommendation "Verify the running mode is expected for this device configuration."
            }
        }
        else {
            Write-ValidationResult -TestName $amTestName -Category 'Device State' -Expected 'Normal' -Status 'Info' `
                -Message "AMRunningMode value could not be determined (Get-MpComputerStatus unavailable or not supported)."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Category 'Device State' -Expected 'Active or EDR Block' -Status 'Fail' `
            -Message "Unable to determine Passive Mode / EDR Block Mode status: $_" `
            -Recommendation "Ensure you have appropriate permissions to query Windows Defender status."
        Write-ValidationResult -TestName 'AM Running Mode' -Category 'Device State' -Expected 'Normal' -Status 'Fail' `
            -Message "Unable to determine AM Running Mode: $_" `
            -Recommendation "Ensure you have appropriate permissions to query Windows Defender status."
    }
}