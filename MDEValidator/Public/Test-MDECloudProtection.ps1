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
    .PARAMETER MpPreference
        Optional Get-MpPreference snapshot. When supplied, the function uses it instead of
        querying Get-MpPreference itself, allowing the caller to share a single query across
        multiple tests. When omitted, the function queries Get-MpPreference directly.
    
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        $MpPreference
    )
    
    $testName = 'Cloud-Delivered Protection'
    
    try {
        if ($null -eq $MpPreference) {
            $mpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        # MAPSReporting: 0 = Disabled, 1 = Basic, 2 = Advanced
        if ($mpPreference.MAPSReporting -ge 1) {
            $level = switch ($mpPreference.MAPSReporting) {
                1 { 'Basic' }
                2 { 'Advanced' }
                default { 'Unknown' }
            }
            Write-ValidationResult -TestName $testName -Category 'Protection Settings' -Expected 'Advanced' -Actual "$level" -Status 'Pass' `
                -Message "Cloud-delivered protection is enabled at '$level' level."
        } else {
            Write-ValidationResult -TestName $testName -Category 'Protection Settings' -Expected 'Advanced' -Actual 'Disabled' -Status 'Fail' `
                -Message "Cloud-delivered protection is disabled." `
                -Recommendation "Enable cloud-delivered protection via Intune or Group Policy for advanced protection."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Category 'Protection Settings' -Expected 'Advanced' -Status 'Fail' `
            -Message "Unable to query cloud-delivered protection status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}