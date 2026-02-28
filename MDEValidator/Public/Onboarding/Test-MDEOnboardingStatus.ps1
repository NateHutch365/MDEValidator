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
    Write-Verbose "Checking $testName..."
    
    try {
        # Check for SENSE service (Microsoft Defender for Endpoint Service)
        $senseService = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue
        
        Write-Debug "SENSE service found: $($null -ne $senseService)"
        
        if ($null -eq $senseService) {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Microsoft Defender for Endpoint service (Sense) is not installed." `
                -Recommendation "Onboard the device to Microsoft Defender for Endpoint using the onboarding package from the Security Center."
            return
        }
        
        Write-Debug "SENSE service status: $($senseService.Status)"
        
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
            
            Write-Debug "OnboardingState: $($onboardingState.OnboardingState)"
            
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
