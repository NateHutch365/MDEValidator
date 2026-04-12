function Test-MDESignatureInfo {
    <#
    .SYNOPSIS
        Surfaces antivirus signature version and last-updated date as informational results.

    .DESCRIPTION
        Retrieves and surfaces the current antivirus signature version and the date/time
        signatures were last updated. These are informational only — no pass/fail threshold
        is applied to the values themselves.

    .EXAMPLE
        Test-MDESignatureInfo

        Surfaces signature version and last-updated date as Info results.

    .OUTPUTS
        Array of PSCustomObjects (one per property) with validation results.
    #>
    [CmdletBinding()]
    param()

    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop

        $signatureVersion = $mpStatus.AntivirusSignatureVersion
        $signatureVersionStr = if ($null -ne $signatureVersion) { $signatureVersion } else { 'Unknown' }
        Write-ValidationResult -TestName 'Antivirus Signature Version' -Status 'Info' `
            -Message "Current antivirus signature version: $signatureVersionStr"

        $lastUpdated = $mpStatus.AntivirusSignatureLastUpdated
        $lastUpdatedStr = if ($null -ne $lastUpdated) {
            $lastUpdated.ToString('yyyy-MM-dd HH:mm:ss')
        }
        else {
            'Unknown'
        }
        Write-ValidationResult -TestName 'Antivirus Signature Last Updated' -Status 'Info' `
            -Message "Antivirus signatures last updated: $lastUpdatedStr"
    }
    catch {
        Write-ValidationResult -TestName 'Antivirus Signature Version' -Status 'Fail' `
            -Message "Unable to query signature information: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and the Defender PowerShell module is available."
        Write-ValidationResult -TestName 'Antivirus Signature Last Updated' -Status 'Fail' `
            -Message "Unable to query signature information: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and the Defender PowerShell module is available."
    }
}
