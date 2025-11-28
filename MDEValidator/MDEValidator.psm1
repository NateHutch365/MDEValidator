#Requires -Version 5.1
<#
.SYNOPSIS
    MDEValidator - Microsoft Defender for Endpoint Configuration Validation Module

.DESCRIPTION
    This module provides functions to validate Microsoft Defender for Endpoint (MDE)
    configurations and security settings on Windows endpoints.

.NOTES
    Author: MDEValidator Team
    Version: 1.0.0
#>

#region Helper Functions

function ConvertTo-HtmlEncodedString {
    <#
    .SYNOPSIS
        HTML-encodes a string to prevent XSS vulnerabilities.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$InputString
    )
    
    if ([string]::IsNullOrEmpty($InputString)) {
        return $InputString
    }
    
    return [System.Net.WebUtility]::HtmlEncode($InputString)
}

function Write-ValidationResult {
    <#
    .SYNOPSIS
        Formats and outputs a validation result.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TestName,
        
        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')]
        [string]$Status,
        
        [Parameter()]
        [string]$Message = '',
        
        [Parameter()]
        [string]$Recommendation = ''
    )
    
    [PSCustomObject]@{
        TestName = $TestName
        Status = $Status
        Message = $Message
        Recommendation = $Recommendation
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    }
}

function Test-IsElevated {
    <#
    .SYNOPSIS
        Checks if the current PowerShell session is running with elevated privileges.
    #>
    [CmdletBinding()]
    param()
    
    # Only perform elevation check on Windows
    if ($IsWindows -or ([System.Environment]::OSVersion.Platform -eq 'Win32NT')) {
        try {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object Security.Principal.WindowsPrincipal($identity)
            return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }
        catch {
            # If we can't determine elevation status, assume not elevated
            return $false
        }
    }
    
    # On non-Windows platforms, check if running as root
    if ($IsLinux -or $IsMacOS) {
        try {
            return (& id -u) -eq 0
        }
        catch {
            return $false
        }
    }
    
    return $false
}

#endregion

#region Public Functions

function Test-MDEServiceStatus {
    <#
    .SYNOPSIS
        Tests the status of the Windows Defender service.
    
    .DESCRIPTION
        Checks if the Windows Defender Antivirus Service (WinDefend) is running
        and configured to start automatically.
    
    .EXAMPLE
        Test-MDEServiceStatus
        
        Tests if the Windows Defender service is running properly.
    
    .OUTPUTS
        PSCustomObject with validation results.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Windows Defender Service Status'
    
    try {
        $service = Get-Service -Name 'WinDefend' -ErrorAction Stop
        
        if ($service.Status -eq 'Running') {
            $startType = (Get-Service -Name 'WinDefend').StartType
            if ($startType -eq 'Automatic') {
                Write-ValidationResult -TestName $testName -Status 'Pass' `
                    -Message "Windows Defender service is running and set to start automatically."
            } else {
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "Windows Defender service is running but start type is '$startType'." `
                    -Recommendation "Set the service to start automatically for optimal protection."
            }
        } else {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Windows Defender service is not running. Current status: $($service.Status)" `
                -Recommendation "Start the Windows Defender service and ensure it's set to start automatically."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Windows Defender service: $_" `
            -Recommendation "Verify that Windows Defender is installed on this system."
    }
}

function Test-MDERealTimeProtection {
    <#
    .SYNOPSIS
        Tests if real-time protection is enabled.
    
    .DESCRIPTION
        Checks the real-time protection status of Windows Defender Antivirus.
    
    .EXAMPLE
        Test-MDERealTimeProtection
        
        Tests if real-time protection is enabled.
    
    .OUTPUTS
        PSCustomObject with validation results.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Real-Time Protection'
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        if ($mpPreference.DisableRealtimeMonitoring -eq $false) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Real-time protection is enabled."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Real-time protection is disabled." `
                -Recommendation "Enable real-time protection via Group Policy or 'Set-MpPreference -DisableRealtimeMonitoring `$false'."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query real-time protection status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and the Defender PowerShell module is available."
    }
}

function Test-MDECloudProtection {
    <#
    .SYNOPSIS
        Tests if cloud-delivered protection is enabled.
    
    .DESCRIPTION
        Checks the cloud-delivered protection (MAPS) status of Windows Defender Antivirus.
    
    .EXAMPLE
        Test-MDECloudProtection
        
        Tests if cloud-delivered protection is enabled.
    
    .OUTPUTS
        PSCustomObject with validation results.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Cloud-Delivered Protection'
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        # MAPSReporting: 0 = Disabled, 1 = Basic, 2 = Advanced
        if ($mpPreference.MAPSReporting -ge 1) {
            $level = switch ($mpPreference.MAPSReporting) {
                1 { 'Basic' }
                2 { 'Advanced' }
                default { 'Unknown' }
            }
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Cloud-delivered protection is enabled at '$level' level."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Cloud-delivered protection is disabled." `
                -Recommendation "Enable cloud-delivered protection via Group Policy or 'Set-MpPreference -MAPSReporting 2' for advanced protection."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query cloud-delivered protection status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}

function Test-MDESampleSubmission {
    <#
    .SYNOPSIS
        Tests if automatic sample submission is enabled.
    
    .DESCRIPTION
        Checks the automatic sample submission status of Windows Defender Antivirus.
    
    .EXAMPLE
        Test-MDESampleSubmission
        
        Tests if automatic sample submission is enabled.
    
    .OUTPUTS
        PSCustomObject with validation results.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Automatic Sample Submission'
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        # SubmitSamplesConsent: 0 = Always Prompt, 1 = Send safe samples, 2 = Never send, 3 = Send all samples
        if ($mpPreference.SubmitSamplesConsent -eq 3) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Automatic sample submission is enabled: 'Send all samples automatically'."
        } elseif ($mpPreference.SubmitSamplesConsent -eq 1) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Automatic sample submission is set to 'Safe samples only'." `
                -Recommendation "Consider enabling 'Send all samples automatically' for better threat detection via 'Set-MpPreference -SubmitSamplesConsent 3'."
        } elseif ($mpPreference.SubmitSamplesConsent -eq 0) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Automatic sample submission is set to 'Always Prompt'." `
                -Recommendation "Consider enabling automatic sample submission for better threat detection via 'Set-MpPreference -SubmitSamplesConsent 3'."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Automatic sample submission is disabled." `
                -Recommendation "Enable automatic sample submission via Group Policy or 'Set-MpPreference -SubmitSamplesConsent 3'."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query sample submission status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}

function Test-MDEBehaviorMonitoring {
    <#
    .SYNOPSIS
        Tests if behavior monitoring is enabled.
    
    .DESCRIPTION
        Checks the behavior monitoring status of Windows Defender Antivirus.
    
    .EXAMPLE
        Test-MDEBehaviorMonitoring
        
        Tests if behavior monitoring is enabled.
    
    .OUTPUTS
        PSCustomObject with validation results.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Behavior Monitoring'
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        if ($mpPreference.DisableBehaviorMonitoring -eq $false) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Behavior monitoring is enabled."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Behavior monitoring is disabled." `
                -Recommendation "Enable behavior monitoring via Group Policy or 'Set-MpPreference -DisableBehaviorMonitoring `$false'."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query behavior monitoring status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}

function Test-MDEOnboardingStatus {
    <#
    .SYNOPSIS
        Tests the MDE onboarding status.
    
    .DESCRIPTION
        Checks if the device is properly onboarded to Microsoft Defender for Endpoint
        by verifying the SENSE service status and registry settings.
    
    .EXAMPLE
        Test-MDEOnboardingStatus
        
        Tests if the device is onboarded to MDE.
    
    .OUTPUTS
        PSCustomObject with validation results.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'MDE Onboarding Status'
    
    try {
        # Check for SENSE service (Microsoft Defender for Endpoint Service)
        $senseService = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue
        
        if ($null -eq $senseService) {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Microsoft Defender for Endpoint service (Sense) is not installed." `
                -Recommendation "Onboard the device to Microsoft Defender for Endpoint using the onboarding package from the Security Center."
            return
        }
        
        if ($senseService.Status -ne 'Running') {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Microsoft Defender for Endpoint service is not running. Status: $($senseService.Status)" `
                -Recommendation "Start the SENSE service and verify the onboarding configuration."
            return
        }
        
        # Check onboarding state in registry
        $onboardingPath = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'
        if (Test-Path $onboardingPath) {
            $onboardingState = Get-ItemProperty -Path $onboardingPath -Name 'OnboardingState' -ErrorAction SilentlyContinue
            
            if ($onboardingState.OnboardingState -eq 1) {
                Write-ValidationResult -TestName $testName -Status 'Pass' `
                    -Message "Device is successfully onboarded to Microsoft Defender for Endpoint."
            } else {
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "Device appears to be partially onboarded. OnboardingState: $($onboardingState.OnboardingState)" `
                    -Recommendation "Re-run the onboarding script or check the device status in the Security Center."
            }
        } else {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "MDE onboarding registry key not found, but SENSE service is running." `
                -Recommendation "Verify the device's onboarding status in the Microsoft 365 Defender portal."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query MDE onboarding status: $_" `
            -Recommendation "Ensure you have appropriate permissions and MDE is properly configured."
    }
}

function Test-MDENetworkProtection {
    <#
    .SYNOPSIS
        Tests if network protection is enabled.
    
    .DESCRIPTION
        Checks the network protection status of Windows Defender Antivirus.
    
    .EXAMPLE
        Test-MDENetworkProtection
        
        Tests if network protection is enabled.
    
    .OUTPUTS
        PSCustomObject with validation results.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Network Protection'
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        # EnableNetworkProtection: 0 = Disabled, 1 = Enabled (Block), 2 = Audit mode
        switch ($mpPreference.EnableNetworkProtection) {
            0 {
                Write-ValidationResult -TestName $testName -Status 'Fail' `
                    -Message "Network protection is disabled." `
                    -Recommendation "Enable network protection via Group Policy or 'Set-MpPreference -EnableNetworkProtection Enabled'."
            }
            1 {
                Write-ValidationResult -TestName $testName -Status 'Pass' `
                    -Message "Network protection is enabled in Block mode."
            }
            2 {
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "Network protection is in Audit mode only." `
                    -Recommendation "Consider enabling Block mode for full protection after validating Audit mode results."
            }
            default {
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "Network protection status is unknown: $($mpPreference.EnableNetworkProtection)" `
                    -Recommendation "Verify network protection configuration."
            }
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query network protection status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}

function Test-MDEAttackSurfaceReduction {
    <#
    .SYNOPSIS
        Tests if Attack Surface Reduction (ASR) rules are configured.
    
    .DESCRIPTION
        Checks the Attack Surface Reduction rules status of Windows Defender Antivirus.
    
    .EXAMPLE
        Test-MDEAttackSurfaceReduction
        
        Tests if ASR rules are configured.
    
    .OUTPUTS
        PSCustomObject with validation results.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Attack Surface Reduction Rules'
    
    # Common ASR rule GUIDs and their descriptions
    $asrRules = @{
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
    }
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        $configuredRules = $mpPreference.AttackSurfaceReductionRules_Ids
        $ruleActions = $mpPreference.AttackSurfaceReductionRules_Actions
        
        if ($null -eq $configuredRules -or $configuredRules.Count -eq 0) {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "No Attack Surface Reduction rules are configured." `
                -Recommendation "Configure ASR rules via Group Policy or Intune for enhanced protection."
            return
        }
        
        $enabledCount = 0
        $auditCount = 0
        $disabledCount = 0
        
        for ($i = 0; $i -lt $configuredRules.Count; $i++) {
            if ($null -ne $ruleActions -and $i -lt $ruleActions.Count) {
                switch ($ruleActions[$i]) {
                    0 { $disabledCount++ }
                    1 { $enabledCount++ }
                    2 { $auditCount++ }
                }
            }
        }
        
        $totalRules = $configuredRules.Count
        $message = "ASR rules configured: $totalRules total ($enabledCount enabled/blocked, $auditCount audit, $disabledCount disabled)"
        
        if ($enabledCount -gt 0) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message $message
        } elseif ($auditCount -gt 0) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "$message. All configured rules are in Audit mode only." `
                -Recommendation "Consider enabling Block mode for ASR rules after validating Audit mode results."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "$message. All configured rules are disabled." `
                -Recommendation "Enable ASR rules for enhanced protection against common attack techniques."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query ASR rules status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}

function Test-MDESmartScreen {
    <#
    .SYNOPSIS
        Tests if SmartScreen is enabled in Microsoft Edge.
    
    .DESCRIPTION
        Checks the SmartScreen configuration for Microsoft Edge browser by querying
        registry settings and Edge policies.
    
    .EXAMPLE
        Test-MDESmartScreen
        
        Tests if SmartScreen is enabled in Edge.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        SmartScreen can be tested manually by visiting https://smartscreentestratings2.net/
        which should be blocked if SmartScreen is properly configured.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Edge SmartScreen'
    
    try {
        # Check Edge SmartScreen policy settings
        # Primary location: HKLM:\SOFTWARE\Policies\Microsoft\Edge
        # User location: HKCU:\SOFTWARE\Policies\Microsoft\Edge
        # Default settings: HKLM:\SOFTWARE\Microsoft\Edge
        
        $smartScreenEnabled = $null
        $smartScreenSource = ''
        
        # Check Group Policy settings first (takes precedence)
        $policyPaths = @(
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'SmartScreenEnabled'; Source = 'Group Policy (Machine)' },
            @{ Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'SmartScreenEnabled'; Source = 'Group Policy (User)' },
            @{ Path = 'HKLM:\SOFTWARE\Microsoft\Edge'; Name = 'SmartScreenEnabled'; Source = 'Edge Default Settings' }
        )
        
        foreach ($policy in $policyPaths) {
            if (Test-Path $policy.Path) {
                $value = Get-ItemProperty -Path $policy.Path -Name $policy.Name -ErrorAction SilentlyContinue
                $propertyValue = $value.($policy.Name)
                if ($null -ne $value -and $null -ne $propertyValue) {
                    $smartScreenEnabled = $propertyValue
                    $smartScreenSource = $policy.Source
                    break
                }
            }
        }
        
        # Also check Windows Defender SmartScreen settings
        $defenderSmartScreenPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
        $defenderSmartScreen = $null
        if (Test-Path $defenderSmartScreenPath) {
            $defenderValue = Get-ItemProperty -Path $defenderSmartScreenPath -Name 'SmartScreenEnabled' -ErrorAction SilentlyContinue
            if ($null -ne $defenderValue -and $null -ne $defenderValue.SmartScreenEnabled) {
                $defenderSmartScreen = $defenderValue.SmartScreenEnabled
            }
        }
        
        # Determine overall status
        if ($null -ne $smartScreenEnabled) {
            if ($smartScreenEnabled -eq 1) {
                Write-ValidationResult -TestName $testName -Status 'Pass' `
                    -Message "Edge SmartScreen is enabled via $smartScreenSource. Test URL: https://smartscreentestratings2.net/"
            } else {
                Write-ValidationResult -TestName $testName -Status 'Fail' `
                    -Message "Edge SmartScreen is disabled via $smartScreenSource." `
                    -Recommendation "Enable SmartScreen via Group Policy or Edge settings. Set 'SmartScreenEnabled' to 1. Test with https://smartscreentestratings2.net/"
            }
        } elseif ($null -ne $defenderSmartScreen) {
            # Fall back to Windows Defender SmartScreen check
            if ($defenderSmartScreen -eq 'RequireAdmin' -or $defenderSmartScreen -eq 'Prompt' -or $defenderSmartScreen -eq 'On') {
                Write-ValidationResult -TestName $testName -Status 'Pass' `
                    -Message "Windows Defender SmartScreen is enabled ('$defenderSmartScreen'). Edge inherits this setting. Test URL: https://smartscreentestratings2.net/"
            } elseif ($defenderSmartScreen -eq 'Off') {
                Write-ValidationResult -TestName $testName -Status 'Fail' `
                    -Message "Windows Defender SmartScreen is disabled." `
                    -Recommendation "Enable SmartScreen via Windows Security settings or Group Policy. Test with https://smartscreentestratings2.net/"
            } else {
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "Windows Defender SmartScreen setting is '$defenderSmartScreen'. Unable to determine if fully enabled." `
                    -Recommendation "Verify SmartScreen is properly configured. Test manually by visiting https://smartscreentestratings2.net/"
            }
        } else {
            # No explicit settings found - SmartScreen is typically enabled by default in modern Windows/Edge
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "No explicit SmartScreen policy found. SmartScreen may be using default settings (typically enabled)." `
                -Recommendation "Configure SmartScreen explicitly via Group Policy for consistent protection. Test manually by visiting https://smartscreentestratings2.net/"
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query SmartScreen status: $_" `
            -Recommendation "Ensure you have permissions to read registry settings. Test SmartScreen manually by visiting https://smartscreentestratings2.net/"
    }
}

function Test-MDEConfiguration {
    <#
    .SYNOPSIS
        Runs all MDE configuration validation tests.
    
    .DESCRIPTION
        Executes a comprehensive validation of Microsoft Defender for Endpoint
        configuration settings and returns the results.
    
    .PARAMETER IncludeOnboarding
        Include MDE onboarding status check (requires elevated privileges).
    
    .EXAMPLE
        Test-MDEConfiguration
        
        Runs all MDE configuration validation tests.
    
    .EXAMPLE
        Test-MDEConfiguration -IncludeOnboarding
        
        Runs all tests including MDE onboarding status check.
    
    .OUTPUTS
        Array of PSCustomObjects with validation results.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$IncludeOnboarding
    )
    
    $results = @()
    
    Write-Verbose "Starting MDE configuration validation..."
    
    # Check for elevation
    $isElevated = Test-IsElevated
    if (-not $isElevated) {
        Write-Warning "Some tests may require elevated privileges. Consider running as Administrator."
    }
    
    # Run all validation tests
    $results += Test-MDEServiceStatus
    $results += Test-MDERealTimeProtection
    $results += Test-MDECloudProtection
    $results += Test-MDESampleSubmission
    $results += Test-MDEBehaviorMonitoring
    $results += Test-MDENetworkProtection
    $results += Test-MDEAttackSurfaceReduction
    $results += Test-MDESmartScreen
    
    if ($IncludeOnboarding) {
        $results += Test-MDEOnboardingStatus
    }
    
    Write-Verbose "MDE configuration validation completed."
    
    return $results
}

function Get-MDEValidationReport {
    <#
    .SYNOPSIS
        Generates a formatted MDE validation report.
    
    .DESCRIPTION
        Runs all MDE configuration validation tests and generates a report
        in the specified format.
    
    .PARAMETER OutputFormat
        The format of the output report. Valid values are 'Console', 'HTML', or 'Object'.
        Default is 'Console'.
    
    .PARAMETER OutputPath
        The path to save the HTML report. Only used when OutputFormat is 'HTML'.
    
    .PARAMETER IncludeOnboarding
        Include MDE onboarding status check (requires elevated privileges).
    
    .EXAMPLE
        Get-MDEValidationReport
        
        Displays a console-formatted validation report.
    
    .EXAMPLE
        Get-MDEValidationReport -OutputFormat HTML -OutputPath "C:\Reports\MDEReport.html"
        
        Generates an HTML report and saves it to the specified path.
    
    .EXAMPLE
        Get-MDEValidationReport -OutputFormat Object
        
        Returns validation results as PowerShell objects.
    
    .OUTPUTS
        Console output, HTML file, or array of PSCustomObjects depending on OutputFormat.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('Console', 'HTML', 'Object')]
        [string]$OutputFormat = 'Console',
        
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$IncludeOnboarding
    )
    
    # Run all validation tests
    $results = Test-MDEConfiguration -IncludeOnboarding:$IncludeOnboarding
    
    switch ($OutputFormat) {
        'Object' {
            return $results
        }
        
        'Console' {
            Write-Host "`n========================================" -ForegroundColor Cyan
            Write-Host "  MDE Configuration Validation Report" -ForegroundColor Cyan
            Write-Host "  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
            Write-Host "  Computer: $env:COMPUTERNAME" -ForegroundColor Cyan
            Write-Host "========================================`n" -ForegroundColor Cyan
            
            foreach ($result in $results) {
                $statusColor = switch ($result.Status) {
                    'Pass' { 'Green' }
                    'Fail' { 'Red' }
                    'Warning' { 'Yellow' }
                    'Info' { 'Cyan' }
                    'NotApplicable' { 'Gray' }
                    default { 'White' }
                }
                
                $statusSymbol = switch ($result.Status) {
                    'Pass' { '[PASS]' }
                    'Fail' { '[FAIL]' }
                    'Warning' { '[WARN]' }
                    'Info' { '[INFO]' }
                    'NotApplicable' { '[N/A]' }
                    default { '[???]' }
                }
                
                Write-Host "$statusSymbol " -ForegroundColor $statusColor -NoNewline
                Write-Host "$($result.TestName)" -ForegroundColor White
                Write-Host "         $($result.Message)" -ForegroundColor Gray
                
                if ($result.Recommendation -and $result.Status -ne 'Pass') {
                    Write-Host "         Recommendation: $($result.Recommendation)" -ForegroundColor Yellow
                }
                Write-Host ""
            }
            
            # Summary
            $passCount = ($results | Where-Object { $_.Status -eq 'Pass' }).Count
            $failCount = ($results | Where-Object { $_.Status -eq 'Fail' }).Count
            $warnCount = ($results | Where-Object { $_.Status -eq 'Warning' }).Count
            $totalCount = $results.Count
            
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "  Summary: $passCount/$totalCount Passed" -ForegroundColor $(if ($failCount -eq 0) { 'Green' } else { 'Yellow' })
            Write-Host "  Passed: $passCount | Failed: $failCount | Warnings: $warnCount" -ForegroundColor Cyan
            Write-Host "========================================`n" -ForegroundColor Cyan
        }
        
        'HTML' {
            if ([string]::IsNullOrEmpty($OutputPath)) {
                $tempDir = if ($env:TEMP) { $env:TEMP } elseif ($env:TMPDIR) { $env:TMPDIR } else { '/tmp' }
                $OutputPath = Join-Path $tempDir "MDEValidationReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
            }
            
            $passCount = ($results | Where-Object { $_.Status -eq 'Pass' }).Count
            $failCount = ($results | Where-Object { $_.Status -eq 'Fail' }).Count
            $warnCount = ($results | Where-Object { $_.Status -eq 'Warning' }).Count
            $totalCount = $results.Count
            
            $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MDE Configuration Validation Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            padding: 30px;
        }
        h1 {
            color: #0078d4;
            border-bottom: 2px solid #0078d4;
            padding-bottom: 10px;
        }
        .meta {
            color: #666;
            margin-bottom: 20px;
        }
        .summary {
            display: flex;
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            flex: 1;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .summary-card.pass { background-color: #dff6dd; color: #107c10; }
        .summary-card.fail { background-color: #fde7e9; color: #d13438; }
        .summary-card.warn { background-color: #fff4ce; color: #797673; }
        .summary-card h2 { margin: 0; font-size: 2em; }
        .summary-card p { margin: 5px 0 0 0; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #0078d4;
            color: white;
        }
        tr:hover { background-color: #f5f5f5; }
        .status {
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.9em;
        }
        .status.pass { background-color: #dff6dd; color: #107c10; }
        .status.fail { background-color: #fde7e9; color: #d13438; }
        .status.warning { background-color: #fff4ce; color: #797673; }
        .status.info { background-color: #cce4f6; color: #0078d4; }
        .recommendation {
            font-size: 0.9em;
            color: #666;
            margin-top: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>MDE Configuration Validation Report</h1>
        <div class="meta">
            <p><strong>Computer:</strong> $(ConvertTo-HtmlEncodedString $env:COMPUTERNAME)</p>
            <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        </div>
        
        <div class="summary">
            <div class="summary-card pass">
                <h2>$passCount</h2>
                <p>Passed</p>
            </div>
            <div class="summary-card fail">
                <h2>$failCount</h2>
                <p>Failed</p>
            </div>
            <div class="summary-card warn">
                <h2>$warnCount</h2>
                <p>Warnings</p>
            </div>
        </div>
        
        <table>
            <tr>
                <th>Test</th>
                <th>Status</th>
                <th>Details</th>
            </tr>
"@
            
            foreach ($result in $results) {
                $statusClass = $result.Status.ToLower()
                $encodedTestName = ConvertTo-HtmlEncodedString $result.TestName
                $encodedMessage = ConvertTo-HtmlEncodedString $result.Message
                $encodedRecommendation = ConvertTo-HtmlEncodedString $result.Recommendation
                $recommendation = if ($result.Recommendation -and $result.Status -ne 'Pass') {
                    "<div class='recommendation'><strong>Recommendation:</strong> $encodedRecommendation</div>"
                } else { '' }
                
                $htmlContent += @"
            <tr>
                <td>$encodedTestName</td>
                <td><span class="status $statusClass">$($result.Status.ToUpper())</span></td>
                <td>$encodedMessage$recommendation</td>
            </tr>
"@
            }
            
            $htmlContent += @"
        </table>
    </div>
</body>
</html>
"@
            
            $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-Host "HTML report saved to: $OutputPath" -ForegroundColor Green
            return $OutputPath
        }
    }
}

#endregion

# Export public functions
Export-ModuleMember -Function @(
    'Test-MDEConfiguration',
    'Get-MDEValidationReport',
    'Test-MDEServiceStatus',
    'Test-MDERealTimeProtection',
    'Test-MDECloudProtection',
    'Test-MDESampleSubmission',
    'Test-MDEBehaviorMonitoring',
    'Test-MDEOnboardingStatus',
    'Test-MDENetworkProtection',
    'Test-MDEAttackSurfaceReduction',
    'Test-MDESmartScreen'
)
