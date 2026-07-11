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

        $signatureVersion = $mpStatus.AntivirusSignatureVersion
        $signatureVersionStr = if ($null -ne $signatureVersion) { $signatureVersion } else { 'Unknown' }
        Write-ValidationResult -TestName 'Antivirus Signature Version' -Category 'Protection Settings' -Expected 'Latest' -Actual "$signatureVersionStr" -Status 'Info' `
            -Message "Current antivirus signature version: $signatureVersionStr"

        $lastUpdated = $mpStatus.AntivirusSignatureLastUpdated
        $lastUpdatedStr = if ($null -ne $lastUpdated) {
            $lastUpdated.ToString('yyyy-MM-dd HH:mm:ss')
        }
        else {
            'Unknown'
        }
        Write-ValidationResult -TestName 'Antivirus Signature Last Updated' -Category 'Protection Settings' -Expected 'Recent' -Actual "$lastUpdatedStr" -Status 'Info' `
            -Message "Antivirus signatures last updated: $lastUpdatedStr"
    }
    catch {
        Write-ValidationResult -TestName 'Antivirus Signature Version' -Category 'Protection Settings' -Expected 'Latest' -Status 'Fail' `
            -Message "Unable to query signature information: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and the Defender PowerShell module is available."
        Write-ValidationResult -TestName 'Antivirus Signature Last Updated' -Category 'Protection Settings' -Expected 'Recent' -Status 'Fail' `
            -Message "Unable to query signature information: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and the Defender PowerShell module is available."
    }
}
