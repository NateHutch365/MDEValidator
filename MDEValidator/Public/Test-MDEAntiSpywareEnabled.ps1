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
    #>
    [CmdletBinding()]
    param()

    $testName = 'Anti-Spyware Protection'

    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop

        if ($mpStatus.AntispywareEnabled -eq $true) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Anti-spyware protection is enabled."
        }
        else {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Anti-spyware protection is disabled." `
                -Recommendation "Enable anti-spyware protection via Intune or Group Policy to ensure full malware coverage."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query anti-spyware protection status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and the Defender PowerShell module is available."
    }
}
