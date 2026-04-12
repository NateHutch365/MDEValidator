function Test-MDENISEnabled {
    <#
    .SYNOPSIS
        Tests if Network Inspection System (NIS) is enabled.

    .DESCRIPTION
        Checks whether the Network Inspection System (NIS) component of Windows Defender
        is enabled. NIS provides network-based exploit protection and should be active
        on MDE-managed devices.

    .EXAMPLE
        Test-MDENISEnabled

        Tests if Network Inspection System is enabled.

    .OUTPUTS
        PSCustomObject with validation results.
    #>
    [CmdletBinding()]
    param()

    $testName = 'Network Inspection System (NIS)'

    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop

        if ($mpStatus.NISEnabled -eq $true) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Network Inspection System (NIS) is enabled."
        }
        else {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Network Inspection System (NIS) is disabled." `
                -Recommendation "Enable NIS via Intune or Group Policy. NIS provides network-based exploit detection on MDE-managed devices."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Network Inspection System status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and the Defender PowerShell module is available."
    }
}
