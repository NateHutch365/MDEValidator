function Test-MDESignatureAge {
    <#
    .SYNOPSIS
        Tests if antivirus and antispyware signatures are up to date.

    .DESCRIPTION
        Checks the age of both antivirus and antispyware signatures against
        defined thresholds. Signatures 0-1 days old pass, 2-3 days produce a
        warning, and signatures older than 3 days produce a failure.

    .EXAMPLE
        Test-MDESignatureAge

        Tests signature currency for both antivirus and antispyware definitions.

    .OUTPUTS
        Array of PSCustomObjects (one per signature type) with validation results.
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

    try {
        if ($null -eq $MpComputerStatus) {
            $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        }
        else {
            $mpStatus = $MpComputerStatus
        }

        # Antivirus Signature Age
        $avAge = $mpStatus.AntivirusSignatureAge
        if ($null -eq $avAge) {
            Write-ValidationResult -TestName 'Antivirus Signature Age' -Category 'Protection Settings' -Expected '0-1 days' -Status 'Warning' `
                -Message "Antivirus signature age could not be determined." `
                -Recommendation "Verify Get-MpComputerStatus returns AntivirusSignatureAge on this build."
        }
        elseif ($avAge -le 1) {
            Write-ValidationResult -TestName 'Antivirus Signature Age' -Category 'Protection Settings' -Expected '0-1 days' -Actual "$avAge day(s)" -Status 'Pass' `
                -Message "Antivirus signatures are current ($avAge day(s) old)."
        }
        elseif ($avAge -le 3) {
            Write-ValidationResult -TestName 'Antivirus Signature Age' -Category 'Protection Settings' -Expected '0-1 days' -Actual "$avAge day(s)" -Status 'Warning' `
                -Message "Antivirus signatures are $avAge day(s) old — update recommended." `
                -Recommendation "Run Update-MpSignature or verify automatic signature updates are configured."
        }
        else {
            Write-ValidationResult -TestName 'Antivirus Signature Age' -Category 'Protection Settings' -Expected '0-1 days' -Actual "$avAge day(s)" -Status 'Fail' `
                -Message "Antivirus signatures are $avAge day(s) old — significantly out of date." `
                -Recommendation "Run Update-MpSignature immediately and ensure automatic signature updates are enabled."
        }

        # Antispyware Signature Age
        $asAge = $mpStatus.AntispywareSignatureAge
        if ($null -eq $asAge) {
            Write-ValidationResult -TestName 'Antispyware Signature Age' -Category 'Protection Settings' -Expected '0-1 days' -Status 'Warning' `
                -Message "Antispyware signature age could not be determined." `
                -Recommendation "Verify Get-MpComputerStatus returns AntispywareSignatureAge on this build."
        }
        elseif ($asAge -le 1) {
            Write-ValidationResult -TestName 'Antispyware Signature Age' -Category 'Protection Settings' -Expected '0-1 days' -Actual "$asAge day(s)" -Status 'Pass' `
                -Message "Antispyware signatures are current ($asAge day(s) old)."
        }
        elseif ($asAge -le 3) {
            Write-ValidationResult -TestName 'Antispyware Signature Age' -Category 'Protection Settings' -Expected '0-1 days' -Actual "$asAge day(s)" -Status 'Warning' `
                -Message "Antispyware signatures are $asAge day(s) old — update recommended." `
                -Recommendation "Run Update-MpSignature or verify automatic signature updates are configured."
        }
        else {
            Write-ValidationResult -TestName 'Antispyware Signature Age' -Category 'Protection Settings' -Expected '0-1 days' -Actual "$asAge day(s)" -Status 'Fail' `
                -Message "Antispyware signatures are $asAge day(s) old — significantly out of date." `
                -Recommendation "Run Update-MpSignature immediately and ensure automatic signature updates are enabled."
        }
    }
    catch {
        Write-ValidationResult -TestName 'Antivirus Signature Age' -Category 'Protection Settings' -Expected '0-1 days' -Status 'Fail' `
            -Message "Unable to query signature age: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and the Defender PowerShell module is available."
        Write-ValidationResult -TestName 'Antispyware Signature Age' -Category 'Protection Settings' -Expected '0-1 days' -Status 'Fail' `
            -Message "Unable to query signature age: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and the Defender PowerShell module is available."
    }
}
