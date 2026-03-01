function Test-MDEPassiveMode {
    <#
    .SYNOPSIS
        Tests if the device is in Passive Mode or EDR in Block Mode.
    
    .DESCRIPTION
        Checks whether Microsoft Defender Antivirus is running in Passive Mode
        (when another antivirus is the primary AV) or if EDR in Block Mode is enabled.
        Both modes should generate warnings as they indicate non-standard configurations.
    
    .PARAMETER MpComputerStatus
        Optional. A pre-fetched MpComputerStatus object from Get-MpComputerStatus.
        If not provided, the function will call Get-MpComputerStatus internally.
    
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
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSObject]$MpComputerStatus
    )
    
    $testName = 'Passive Mode / EDR Block Mode'
    Write-Verbose "Checking $testName..."
    
    try {
        $isPassiveMode = $false
        $isEDRBlockMode = $false
        
        # Check for Passive Mode via Get-MpComputerStatus if available
        try {
            if ($null -eq $MpComputerStatus) {
                $MpComputerStatus = Get-MpComputerStatus -ErrorAction Stop
            }
            if ($null -ne $MpComputerStatus.AMRunningMode) {
                # AMRunningMode can be: Normal, Passive, EDR Block Mode, SxS Passive Mode
                $runningMode = $MpComputerStatus.AMRunningMode
                Write-Debug "AMRunningMode: $runningMode"
                if ($runningMode -match 'Passive') {
                    $isPassiveMode = $true
                }
                if ($runningMode -match 'EDR Block') {
                    $isEDRBlockMode = $true
                }
            }
        }
        catch {
            # Get-MpComputerStatus may not be available on non-Windows systems or if Defender is not installed
            # Fall back to registry checks below
            Write-Debug "Get-MpComputerStatus unavailable: $_"
        }
        
        # Check registry for Passive Mode indicator
        $passiveModeRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender'
        if (Test-Path $passiveModeRegPath) {
            $defenderReg = Get-ItemProperty -Path $passiveModeRegPath -ErrorAction SilentlyContinue
            if ($null -ne $defenderReg.PassiveMode -and $defenderReg.PassiveMode -eq 1) {
                $isPassiveMode = $true
            }
        }
        
        # Check for EDR Block Mode configuration
        # EDR Block Mode is when passive mode is forced but block mode behavior is enabled
        $atpPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
        $featuresPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
        
        $passiveModeBehavior = $null
        
        if (Test-Path $atpPolicyPath) {
            $atpPolicy = Get-ItemProperty -Path $atpPolicyPath -ErrorAction SilentlyContinue
            if ($null -ne $atpPolicy.ForceDefenderPassiveMode -and $atpPolicy.ForceDefenderPassiveMode -eq 1) {
                $isPassiveMode = $true
            }
        }
        
        if (Test-Path $featuresPath) {
            $features = Get-ItemProperty -Path $featuresPath -ErrorAction SilentlyContinue
            if ($null -ne $features.PassiveModeBehavior) {
                $passiveModeBehavior = $features.PassiveModeBehavior
            }
        }
        
        Write-Debug "isPassiveMode: $isPassiveMode, isEDRBlockMode: $isEDRBlockMode, passiveModeBehavior: $passiveModeBehavior"
        
        # EDR Block Mode detection via registry
        # EDR Block Mode allows Defender to perform remediation even when in passive mode
        # It's enabled when PassiveModeBehavior = 1 (block mode behavior is on) AND 
        # the device is in passive mode (either detected via AMRunningMode or PassiveMode registry)
        if ($passiveModeBehavior -eq 1 -and $isPassiveMode) {
            $isEDRBlockMode = $true
        }
        
        # Determine the result
        if ($isEDRBlockMode) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Device is running in EDR Block Mode. Defender is in passive mode but can take remediation actions via EDR." `
                -Recommendation "EDR Block Mode is typically used when third-party antivirus is primary. Verify this is intentional and ensure the third-party AV provides adequate protection."
        } elseif ($isPassiveMode) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Device is running in Passive Mode. Microsoft Defender Antivirus is not the primary antivirus solution." `
                -Recommendation "Passive Mode means another antivirus is active. Verify the third-party AV provides adequate protection, or consider enabling EDR Block Mode for additional remediation capabilities."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Device is running in Active Mode. Microsoft Defender Antivirus is the primary antivirus solution."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to determine Passive Mode / EDR Block Mode status: $_" `
            -Recommendation "Ensure you have appropriate permissions to query Windows Defender status."
    }
}
