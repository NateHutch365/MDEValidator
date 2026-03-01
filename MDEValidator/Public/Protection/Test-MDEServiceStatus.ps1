function Test-MDEServiceStatus {
    <#
    .SYNOPSIS
        Tests the status of critical Microsoft Defender for Endpoint services.
    
    .DESCRIPTION
        Checks the status of both the Windows Defender Antivirus Service (WinDefend)
        and the Microsoft Defender for Endpoint sensor service (Sense).
        
        Both services must be running for full MDE functionality. A device with
        WinDefend running but Sense stopped is not onboarded to MDE.
    
    .EXAMPLE
        Test-MDEServiceStatus
        
        Tests if both the Windows Defender and MDE sensor services are running.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        Services checked:
        - WinDefend  : Microsoft Defender Antivirus Service
        - Sense      : Microsoft Defender for Endpoint sensor service (MDE onboarding)
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Windows Defender Service Status'
    Write-Verbose "Checking $testName..."
    
    $services = @(
        @{ Name = 'WinDefend'; DisplayName = 'Microsoft Defender Antivirus Service' },
        @{ Name = 'Sense';     DisplayName = 'Microsoft Defender for Endpoint Service' }
    )
    
    $allRunning      = $true
    $messages        = @()
    $recommendations = @()
    
    foreach ($svc in $services) {
        Write-Debug "Checking service: $($svc.Name) ($($svc.DisplayName))"
        try {
            $service = Get-Service -Name $svc.Name -ErrorAction Stop
            Write-Debug "Service '$($svc.Name)' status: $($service.Status)"
            
            if ($service.Status -eq 'Running') {
                $messages += "$($svc.DisplayName) ($($svc.Name)): Running"
            }
            else {
                $allRunning = $false
                $messages += "$($svc.DisplayName) ($($svc.Name)): $($service.Status)"
                $recommendations += "Start the $($svc.DisplayName) service: Start-Service $($svc.Name)"
            }
        }
        catch {
            Write-Debug "Failed to query service '$($svc.Name)': $_"
            $allRunning = $false
            $messages += "$($svc.DisplayName) ($($svc.Name)): Not found"
            $recommendations += "The $($svc.DisplayName) service was not found. MDE may not be installed or onboarded."
        }
    }
    
    if ($allRunning) {
        $status = 'Pass'
        $recommendation = 'Both MDE services are running correctly.'
    }
    else {
        $status = 'Fail'
        $recommendation = $recommendations -join ' '
    }
    
    $message = $messages -join ' | '
    
    Write-Verbose "Service status check result: $status"
    
    Write-ValidationResult -TestName $testName -Status $status `
        -Message $message -Recommendation $recommendation
}
