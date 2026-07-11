function Test-MDEIoavProtectionEnabled {
    <#
    .SYNOPSIS
        Tests if IOAV (on-access internet-sourced file scanning) protection is enabled.

    .DESCRIPTION
        Checks whether IOAV protection — Windows Defender's on-access scanning of files
        downloaded from the internet — is enabled. This should be active on all MDE-managed
        devices.

    .EXAMPLE
        Test-MDEIoavProtectionEnabled

        Tests if IOAV protection is enabled.

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

    $testName = 'IOAV Protection'

    try {
        if ($null -eq $MpComputerStatus) {
            $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        }
        else {
            $mpStatus = $MpComputerStatus
        }

        $ioavEnabled = $mpStatus.IoavProtectionEnabled
        if ($null -eq $ioavEnabled) {
            Write-ValidationResult -TestName $testName -Category 'Device State' -Expected 'Enabled' -Status 'Warning' `
                -Message "IOAV protection status could not be determined." `
                -Recommendation "Verify Get-MpComputerStatus returns IoavProtectionEnabled on this build."
        }
        elseif ($ioavEnabled -eq $true) {
            Write-ValidationResult -TestName $testName -Category 'Device State' -Expected 'Enabled' -Actual 'Enabled' -Status 'Pass' `
                -Message "IOAV protection is enabled."
        }
        else {
            Write-ValidationResult -TestName $testName -Category 'Device State' -Expected 'Enabled' -Actual 'Disabled' -Status 'Warning' `
                -Message "IOAV protection is disabled." `
                -Recommendation "Enable IOAV protection via Intune or Group Policy to scan internet-sourced files on access."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Category 'Device State' -Expected 'Enabled' -Status 'Fail' `
            -Message "Unable to query IOAV protection status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and the Defender PowerShell module is available."
    }
}
