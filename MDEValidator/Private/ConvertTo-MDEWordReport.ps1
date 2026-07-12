function ConvertTo-MDEWordReport {
    <#
    .SYNOPSIS
        Generates a Word (DOCX) validation report using the PSWriteWord module.

    .DESCRIPTION
        Takes the validation results array and report metadata and produces a formatted
        Word document with a title page, summary table, and per-category result tables.
        Requires the PSWriteWord module (Install-Module -Name PSWriteWord). No Microsoft
        Office installation needed.

    .PARAMETER Results
        The array of validation result objects produced by Test-MDEConfiguration.

    .PARAMETER OutputPath
        The full path for the output DOCX file.

    .PARAMETER ComputerName
        The computer name shown in the report header.

    .PARAMETER OSInfo
        The operating system description shown in the report header.

    .PARAMETER ManagedByStatus
        The management status shown in the report header.

    .PARAMETER OnboardingStatus
        The MDE onboarding status shown in the report header.

    .OUTPUTS
        [string] The path to the generated DOCX file.
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

    Import-Module PSWriteWord -ErrorAction Stop

    # Ensure output directory exists
    $outputDirectory = Split-Path -Path $OutputPath -Parent
    if (-not [string]::IsNullOrEmpty($outputDirectory) -and -not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
    }

    # Create a new Word document
    $wordDocument = New-WordDocument -FilePath $OutputPath

    # --- Title ---
    Add-WordText -WordDocument $wordDocument -Text 'Microsoft Defender for Endpoint' `
        -FontSize 24 -FontFamily 'Segoe UI' -Bold $true -Color '0f3460'
    Add-WordText -WordDocument $wordDocument -Text 'Configuration Validation Report' `
        -FontSize 16 -FontFamily 'Segoe UI' -Color '4a5568'
    Add-WordText -WordDocument $wordDocument -Text '' -FontSize 8

    # --- Metadata Table ---
    $metaData = @(
        @('Computer', $ComputerName),
        @('Operating System', $OSInfo),
        @('Managed By', $ManagedByStatus),
        @('MDE Onboarding', $OnboardingStatus),
        @('Generated', (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    )

    Add-WordTable -WordDocument $wordDocument -DataTable $metaData -Design 'LightShading' `
        -AutoFit 'Window'
    Add-WordText -WordDocument $wordDocument -Text '' -FontSize 8

    # --- Summary ---
    $passCount = @($Results | Where-Object { $_.Status -eq 'Pass' }).Count
    $failCount = @($Results | Where-Object { $_.Status -eq 'Fail' }).Count
    $warnCount = @($Results | Where-Object { $_.Status -eq 'Warning' }).Count
    $infoCount = @($Results | Where-Object { $_.Status -eq 'Info' }).Count
    $totalCount = @($Results).Count

    Add-WordText -WordDocument $wordDocument -Text 'Summary' `
        -FontSize 14 -FontFamily 'Segoe UI' -Bold $true -Color '0f3460'

    $summaryTable = @(
        @('Total', 'Passed', 'Failed', 'Warnings', 'Informational'),
        @($totalCount, $passCount, $failCount, $warnCount, $infoCount)
    )

    Add-WordTable -WordDocument $wordDocument -DataTable $summaryTable -Design 'LightGrid' `
        -AutoFit 'Window'
    Add-WordText -WordDocument $wordDocument -Text '' -FontSize 8

    # --- Results by Category ---
    $knownSectionOrder = @(
        'Device State', 'Protection Settings', 'Onboarding',
        'Network Protection', 'ASR Rules', 'Tamper Protection', 'Exclusion Settings'
    )

    $grouped = [ordered]@{}
    foreach ($r in $Results) {
        $sec = if ([string]::IsNullOrEmpty($r.Category)) { 'General / Other' } else { $r.Category }
        if (-not $grouped.Contains($sec)) {
            $grouped[$sec] = New-Object System.Collections.Generic.List[object]
        }
        $grouped[$sec].Add($r)
    }

    $sectionOrder = New-Object System.Collections.Generic.List[string]
    foreach ($s in $knownSectionOrder) {
        if ($grouped.Contains($s)) { $sectionOrder.Add($s) }
    }
    foreach ($key in $grouped.Keys) {
        if ($knownSectionOrder -notcontains $key) { $sectionOrder.Add($key) }
    }

    foreach ($section in $sectionOrder) {
        $sectionResults = $grouped[$section]
        if ($sectionResults.Count -eq 0) { continue }

        Add-WordText -WordDocument $wordDocument -Text $section `
            -FontSize 12 -FontFamily 'Segoe UI' -Bold $true -Color '0f3460'

        # Build table data: header + rows
        $tableData = @(, @('Test Name', 'Status', 'Expected', 'Actual', 'Recommendation'))
        foreach ($result in $sectionResults) {
            $actual = if ($result.PSObject.Properties.Name -contains 'ASRSummary' -and $result.ASRSummary) {
                $result.ASRSummary
            } else {
                $result.Message
            }
            $tableData += , @(
                $result.TestName,
                $result.Status,
                $(if ($result.Expected) { $result.Expected } else { '-' }),
                $actual,
                $(if ($result.Recommendation) { $result.Recommendation } else { '-' })
            )
        }

        Add-WordTable -WordDocument $wordDocument -DataTable $tableData -Design 'LightShading' `
            -AutoFit 'Window'
        Add-WordText -WordDocument $wordDocument -Text '' -FontSize 6
    }

    # Save the document
    Save-WordDocument -WordDocument $wordDocument

    return $OutputPath
}
