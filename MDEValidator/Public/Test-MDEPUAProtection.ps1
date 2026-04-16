function Test-MDEPUAProtection {
    <#
    .SYNOPSIS
        Tests if AV-engine PUA (Potentially Unwanted Application) protection is enabled.

    .DESCRIPTION
        Checks the PUAProtection setting in Windows Defender Antivirus preferences.
        PUA protection should be set to Enabled (Block mode) on all MDE-managed devices.

    .EXAMPLE
        Test-MDEPUAProtection

        Tests if AV-engine PUA protection is enabled.

    .OUTPUTS
        PSCustomObject with validation results.

    .NOTES
        PUAProtection values:
        0 = Disabled
        1 = Enabled (Block mode) — recommended
        6 = Audit mode
    #>
    [CmdletBinding()]
    param()

    $testName = 'AV-Engine PUA Protection'

    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop

        switch ($mpPreference.PUAProtection) {
            1 {
                Write-ValidationResult -TestName $testName -Status 'Pass' `
                    -Message "PUA protection is enabled in Block mode."
            }
            6 {
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "PUA protection is in Audit mode only." `
                    -Recommendation "Consider enabling Block mode for full PUA protection after validating Audit mode results."
            }
            0 {
                Write-ValidationResult -TestName $testName -Status 'Fail' `
                    -Message "PUA protection is disabled." `
                    -Recommendation "Enable PUA protection via Intune or Group Policy to block potentially unwanted applications."
            }
            default {
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "PUA protection status is unknown: $($mpPreference.PUAProtection)" `
                    -Recommendation "Verify PUA protection configuration."
            }
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query PUA protection status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}