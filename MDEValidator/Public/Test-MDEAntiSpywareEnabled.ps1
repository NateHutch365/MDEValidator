function Test-MDEAntiSpywareEnabled {
    <#
    .SYNOPSIS
        Tests if anti-spyware protection is enabled.

    .DESCRIPTION
        Checks whether Microsoft Defender's anti-spyware protection is enabled.
        This setting should be active on all MDE-managed devices.

    .EXAMPLE
        Test-MDEAntiSpywareEnabled

        Tests if anti-spyware protection is enabled.

    .OUTPUTS
        PSCustomObject with validation results.
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

    $testName = 'Anti-Spyware Protection'

    try {
        if ($null -eq $MpComputerStatus) {
            $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        }
        else {
            $mpStatus = $MpComputerStatus
        }

        if ($mpStatus.AntispywareEnabled -eq $true) {
            Write-ValidationResult -TestName $testName -Category 'Device State' -Expected 'Enabled' -Actual 'Enabled' -Status 'Pass' `
                -Message "Anti-spyware protection is enabled."
        }
        else {
            Write-ValidationResult -TestName $testName -Category 'Device State' -Expected 'Enabled' -Actual 'Disabled' -Status 'Warning' `
                -Message "Anti-spyware protection is disabled." `
                -Recommendation "Enable anti-spyware protection via Intune or Group Policy to ensure full malware coverage."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Category 'Device State' -Expected 'Enabled' -Status 'Fail' `
            -Message "Unable to query anti-spyware protection status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and the Defender PowerShell module is available."
    }
}
