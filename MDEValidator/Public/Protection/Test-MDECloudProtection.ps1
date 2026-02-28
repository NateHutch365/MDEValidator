function Test-MDECloudProtection {
    <#
    .SYNOPSIS
        Tests if cloud-delivered protection is enabled.
    
    .DESCRIPTION
        Checks the cloud-delivered protection (MAPS) status of Windows Defender Antivirus.
    
    .PARAMETER MpPreference
        Optional. A pre-fetched MpPreference object from Get-MpPreference.
        If not provided, the function will call Get-MpPreference internally.
    
    .EXAMPLE
        Test-MDECloudProtection
        
        Tests if cloud-delivered protection is enabled.
    
    .OUTPUTS
        PSCustomObject with validation results.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSObject]$MpPreference
    )
    
    $testName = 'Cloud-Delivered Protection'
    Write-Verbose "Checking $testName..."
    
    try {
        if ($null -eq $MpPreference) {
            $MpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        Write-Debug "MAPSReporting: $($MpPreference.MAPSReporting)"
        
        # MAPSReporting: 0 = Disabled, 1 = Basic, 2 = Advanced
        if ($MpPreference.MAPSReporting -ge 1) {
            $level = switch ($MpPreference.MAPSReporting) {
                1 { 'Basic' }
                2 { 'Advanced' }
                default { 'Unknown' }
            }
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Cloud-delivered protection is enabled at '$level' level."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Cloud-delivered protection is disabled." `
                -Recommendation "Enable cloud-delivered protection via Intune or Group Policy for advanced protection."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query cloud-delivered protection status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}
