function Test-MDEOnboardingStatus {
    <#
    .SYNOPSIS
        Tests the MDE onboarding status.

    .DESCRIPTION
        Checks if the device is properly onboarded to Microsoft Defender for Endpoint
        by verifying the SENSE service status, registry settings, DiagTrack service,
        OrgId registry value, and WDATPOnboarding event log entries.

    .EXAMPLE
        Test-MDEOnboardingStatus

        Tests MDE onboarding status across all checks.

    .OUTPUTS
        PSCustomObject with validation results. Emits one result per check (4-5 total).
    #>
    [CmdletBinding()]
    param()

    $onboardingPath = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'

    # --- Check 1: SENSE service (existing behavior preserved, early return removed) ---
    $senseService = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue

    if ($null -eq $senseService) {
        Write-ValidationResult -TestName 'MDE Onboarding Status' -Status 'Fail' `
            -Message 'Microsoft Defender for Endpoint service (Sense) is not installed.' `
            -Recommendation 'Onboard the device to Microsoft Defender for Endpoint using the onboarding package from the Security Center.'
    } elseif ($senseService.Status -ne 'Running') {
        Write-ValidationResult -TestName 'MDE Onboarding Status' -Status 'Fail' `
            -Message "Microsoft Defender for Endpoint service is not running. Status: $($senseService.Status)" `
            -Recommendation 'Start the SENSE service and verify the onboarding configuration.'
    } else {
        Write-ValidationResult -TestName 'MDE Onboarding Status' -Status 'Pass' `
            -Message 'Microsoft Defender for Endpoint service (Sense) is running.'
    }

    # --- Check 2: OnboardingState registry (existing behavior preserved, early return removed) ---
    if (Test-Path $onboardingPath) {
        $onboardingState = Get-ItemProperty -Path $onboardingPath -Name 'OnboardingState' -ErrorAction SilentlyContinue

        if ($onboardingState.OnboardingState -eq 1) {
            Write-ValidationResult -TestName 'MDE Onboarding Registry State' -Status 'Pass' `
                -Message 'Device is successfully onboarded to Microsoft Defender for Endpoint.'
        } else {
            Write-ValidationResult -TestName 'MDE Onboarding Registry State' -Status 'Warning' `
                -Message "Device appears to be partially onboarded. OnboardingState: $($onboardingState.OnboardingState)" `
                -Recommendation 'Re-run the onboarding script or check the device status in the Security Center.'
        }
    } else {
        Write-ValidationResult -TestName 'MDE Onboarding Registry State' -Status 'Warning' `
            -Message 'MDE onboarding registry key not found, but SENSE service is running.' `
            -Recommendation 'Verify the device onboarding status in the Microsoft 365 Defender portal.'
    }

    # --- Check 3: DiagTrack service (ONBD-01, D-01, D-03) ---
    $diagTrackService = Get-Service -Name 'DiagTrack' -ErrorAction SilentlyContinue

    if ($null -eq $diagTrackService -or $diagTrackService.Status -ne 'Running') {
        Write-ValidationResult -TestName 'Connected User Experiences and Telemetry Service' -Status 'Warning' `
            -Message 'DiagTrack (Connected User Experiences and Telemetry) service is not running.' `
            -Recommendation 'Ensure the DiagTrack service is running for MDE telemetry delivery.'
    } else {
        Write-ValidationResult -TestName 'Connected User Experiences and Telemetry Service' -Status 'Pass' `
            -Message 'DiagTrack (Connected User Experiences and Telemetry) service is running.'
    }

    # --- Check 4: OrgId registry value (ONBD-02, D-02, D-04, D-06, D-07) ---
    if (Test-Path $onboardingPath) {
        $orgIdProp = Get-ItemProperty -Path $onboardingPath -Name 'OrgId' -ErrorAction SilentlyContinue

        if ($null -ne $orgIdProp -and $orgIdProp.OrgId) {
            Write-ValidationResult -TestName 'MDE Organization ID' -Status 'Info' `
                -Message "OrgId is registered: $($orgIdProp.OrgId)"
        } else {
            Write-ValidationResult -TestName 'MDE Organization ID' -Status 'Warning' `
                -Message 'OrgId is not present in the MDE registry key.' `
                -Recommendation 'Verify device is fully onboarded to Microsoft Defender for Endpoint.'
        }
    } else {
        Write-ValidationResult -TestName 'MDE Organization ID' -Status 'Warning' `
            -Message 'MDE registry key not found; OrgId cannot be read.' `
            -Recommendation 'Verify device is fully onboarded to Microsoft Defender for Endpoint.'
    }

    # --- Check 5: WDATPOnboarding event log (ONBD-03, D-05, D-08, D-09, D-10) ---
    try {
        $wdatpEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'WDATPOnboarding' } -ErrorAction Stop
        $latestEvent = $wdatpEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1
        Write-ValidationResult -TestName 'WDATPOnboarding Event Log' -Status 'Pass' `
            -Message "WDATPOnboarding events found: $($wdatpEvents.Count) event(s). Latest: $($latestEvent.TimeCreated)"
    } catch {
        Write-Verbose "WDATPOnboarding event log query returned no results: $_"
        Write-ValidationResult -TestName 'WDATPOnboarding Event Log' -Status 'Warning' `
            -Message 'No WDATPOnboarding events found in the Application event log.' `
            -Recommendation 'Verify device onboarding status in the Microsoft 365 Defender portal.'
    }
}