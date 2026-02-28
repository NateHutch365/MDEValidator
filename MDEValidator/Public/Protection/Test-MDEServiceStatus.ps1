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
    Write-Verbose "Checking $testName..."
    
    try {
        $service = Get-Service -Name 'WinDefend' -ErrorAction Stop
        Write-Debug "WinDefend service status: $($service.Status)"
        
        if ($service.Status -eq 'Running') {
            $startType = (Get-Service -Name 'WinDefend').StartType
            Write-Debug "WinDefend start type: $startType"
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
