function Get-MDEOnboardingStatusString {
    <#
    .SYNOPSIS
        Gets a simple string representation of the MDE onboarding status.
    
    .DESCRIPTION
        Retrieves the MDE onboarding status and returns a simple string
        suitable for display in report headers.
    
    .EXAMPLE
        Get-MDEOnboardingStatusString
        
        Returns a string like "Onboarded", "Not Onboarded", or "Partially Onboarded".
    
    .OUTPUTS
        String containing the onboarding status.
    #>
    [CmdletBinding()]
    param()
    
    Write-Verbose "Checking MDE onboarding status..."
    
    try {
        $senseService = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue
        
        if ($null -eq $senseService) {
            Write-Verbose "SENSE service not found"
            return "Not Onboarded"
        }
        
        if ($senseService.Status -ne 'Running') {
            Write-Verbose "SENSE service status: $($senseService.Status)"
            return "Not Onboarded (Service Not Running)"
        }
        
        $onboardingPath = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'
        if (Test-Path $onboardingPath) {
            $onboardingState = Get-ItemProperty -Path $onboardingPath -Name 'OnboardingState' -ErrorAction SilentlyContinue
            
            if ($null -ne $onboardingState -and ($onboardingState.PSObject.Properties.Name -contains 'OnboardingState')) {
                if ($onboardingState.OnboardingState -eq 1) {
                    Write-Verbose "Device is onboarded (OnboardingState = 1)"
                    return "Onboarded"
                } else {
                    return "Partially Onboarded (State: $($onboardingState.OnboardingState))"
                }
            }
        }
        
        return "Partially Onboarded (Service Running, Registry Key Not Found)"
    }
    catch {
        Write-Verbose "Error retrieving onboarding status: $_"
        return "Error retrieving status"
    }
}
