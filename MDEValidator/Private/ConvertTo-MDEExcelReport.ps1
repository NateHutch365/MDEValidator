function ConvertTo-MDEExcelReport {
    <#
    .SYNOPSIS
        Generates an Excel (XLSX) validation report using the ImportExcel module.

    .DESCRIPTION
        Takes the validation results array and report metadata and produces a formatted
        XLSX workbook with a Summary sheet and a Details sheet. Requires the ImportExcel
        module (Install-Module -Name ImportExcel). No Microsoft Office installation needed.

    .PARAMETER Results
        The array of validation result objects produced by Test-MDEConfiguration.

    .PARAMETER OutputPath
        The full path for the output XLSX file.

    .PARAMETER ComputerName
        The computer name shown in the report metadata.

    .PARAMETER OSInfo
        The operating system description shown in the report metadata.

    .PARAMETER ManagedByStatus
        The management status shown in the report metadata.

    .PARAMETER OnboardingStatus
        The MDE onboarding status shown in the report metadata.

    .OUTPUTS
        [string] The path to the generated XLSX file.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [object[]]$Results,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$OSInfo,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ManagedByStatus,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$OnboardingStatus
    )

    Import-Module ImportExcel -ErrorAction Stop

    # Ensure output directory exists
    $outputDirectory = Split-Path -Path $OutputPath -Parent
    if (-not [string]::IsNullOrEmpty($outputDirectory) -and -not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
    }

    # Remove existing file if present (Export-Excel appends by default)
    if (Test-Path -Path $OutputPath) {
        Remove-Item -Path $OutputPath -Force
    }

    # --- Summary Sheet ---
    $passCount = @($Results | Where-Object { $_.Status -eq 'Pass' }).Count
    $failCount = @($Results | Where-Object { $_.Status -eq 'Fail' }).Count
    $warnCount = @($Results | Where-Object { $_.Status -eq 'Warning' }).Count
    $infoCount = @($Results | Where-Object { $_.Status -eq 'Info' }).Count
    $totalCount = @($Results).Count

    $summaryData = @(
        [PSCustomObject]@{ Property = 'Computer'; Value = $ComputerName }
        [PSCustomObject]@{ Property = 'Operating System'; Value = $OSInfo }
        [PSCustomObject]@{ Property = 'Managed By'; Value = $ManagedByStatus }
        [PSCustomObject]@{ Property = 'MDE Onboarding'; Value = $OnboardingStatus }
        [PSCustomObject]@{ Property = 'Generated'; Value = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') }
        [PSCustomObject]@{ Property = ''; Value = '' }
        [PSCustomObject]@{ Property = 'Total Tests'; Value = $totalCount }
        [PSCustomObject]@{ Property = 'Passed'; Value = $passCount }
        [PSCustomObject]@{ Property = 'Failed'; Value = $failCount }
        [PSCustomObject]@{ Property = 'Warnings'; Value = $warnCount }
        [PSCustomObject]@{ Property = 'Informational'; Value = $infoCount }
    )

    $summaryData | Export-Excel -Path $OutputPath -WorksheetName 'Summary' `
        -AutoSize -BoldTopRow -Title 'MDE Validation Report Summary'

    # --- Details Sheet ---
    $detailData = $Results | ForEach-Object {
        [PSCustomObject]@{
            Category       = $_.Category
            TestName       = $_.TestName
            Status         = $_.Status
            Expected       = $_.Expected
            Actual         = if ($_.PSObject.Properties.Name -contains 'ASRSummary' -and $_.ASRSummary) { $_.ASRSummary } else { $_.Message }
            Recommendation = $_.Recommendation
            Timestamp      = $_.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')
        }
    }

    $detailData | Export-Excel -Path $OutputPath -WorksheetName 'Details' `
        -AutoSize -AutoFilter -BoldTopRow -FreezeTopRow `
        -ConditionalText $(
            New-ConditionalText -Text 'Pass' -BackgroundColor '#dcfce7' -ConditionalTextColor '#166534'
            New-ConditionalText -Text 'Fail' -BackgroundColor '#fee2e2' -ConditionalTextColor '#991b1b'
            New-ConditionalText -Text 'Warning' -BackgroundColor '#fef3c7' -ConditionalTextColor '#92400e'
            New-ConditionalText -Text 'Info' -BackgroundColor '#dbeafe' -ConditionalTextColor '#1e40af'
        )

    return $OutputPath
}
