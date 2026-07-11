function ConvertTo-MDEHtmlReport {
    <#
    .SYNOPSIS
        Builds the complete self-contained HTML validation report string.

    .DESCRIPTION
        Takes the validation results array plus report header metadata and returns the full
        HTML document (gradient header, summary cards, section-grouped tables, print CSS).
        Section grouping and the Expected column are derived directly from each result's
        Category and Expected properties; the embedded Defender logo is supplied by a
        dedicated private helper function.

    .PARAMETER Results
        The array of validation result objects produced by Test-MDEConfiguration.

    .PARAMETER ComputerName
        The computer name shown in the report header.

    .PARAMETER OSInfo
        The operating system description shown in the report header.

    .PARAMETER ManagedByStatus
        The management status shown in the report header.

    .PARAMETER OnboardingStatus
        The MDE onboarding status shown in the report header.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [object[]]$Results,

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

    $results = $Results
    $passCount = @($results | Where-Object { $_.Status -eq 'Pass' }).Count
    $failCount = @($results | Where-Object { $_.Status -eq 'Fail' }).Count
    $warnCount = @($results | Where-Object { $_.Status -eq 'Warning' }).Count

    # Defender logo (Microsoft Defender 512x512 PNG) baked as base64 so reports are self-contained
    $defenderLogoBase64 = Get-MDEDefenderLogoBase64

            # Canonical ordering of the known report sections. Section membership is driven
            # entirely by each result's Category property (the single source of truth).
            # Unknown/new categories (e.g. 'Policy Verification') are rendered after the known
            # sections in first-seen order; results with an empty Category fall back to
            # the 'General / Other' bucket.
            $knownSectionOrder = @(
                'Device State',
                'Protection Settings',
                'Onboarding',
                'Network Protection',
                'ASR Rules',
                'Tamper Protection',
                'Exclusion Settings'
            )
            $fallbackSection = 'General / Other'

            $infoCount = @($results | Where-Object { $_.Status -eq 'Info' }).Count

            $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MDE Configuration Validation Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif; background: #f0f2f5; color: #1a1a2e; line-height: 1.5; padding: 2rem; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #0f3460 0%, #16213e 100%); color: white; padding: 2rem 2.5rem; border-radius: 12px; margin-bottom: 1.5rem; box-shadow: 0 4px 20px rgba(0,0,0,0.15); display: flex; align-items: center; justify-content: space-between; gap: 1.5rem; }
        .header-text { flex: 1; }
        .header h1 { font-size: 1.6rem; font-weight: 600; margin-bottom: 0.25rem; }
        .header .subtitle { font-size: 0.9rem; opacity: 0.8; }
        .header .meta { display: flex; flex-wrap: wrap; gap: 1.5rem; margin-top: 1rem; font-size: 0.85rem; opacity: 0.9; }
        .header-logo { width: 96px; height: 96px; flex-shrink: 0; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
        .summary-card { background: white; border-radius: 10px; padding: 1.25rem; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.06); border-top: 3px solid #e0e0e0; }
        .summary-card.pass { border-top-color: #22c55e; }
        .summary-card.pass .count { color: #22c55e; }
        .summary-card.fail { border-top-color: #ef4444; }
        .summary-card.fail .count { color: #ef4444; }
        .summary-card.warn { border-top-color: #f59e0b; }
        .summary-card.warn .count { color: #f59e0b; }
        .summary-card.info { border-top-color: #3b82f6; }
        .summary-card.info .count { color: #3b82f6; }
        .summary-card .count { font-size: 2rem; font-weight: 700; }
        .summary-card .label { font-size: 0.8rem; color: #666; text-transform: uppercase; letter-spacing: 0.05em; }
        .section { background: white; border-radius: 10px; padding: 1.5rem; margin-bottom: 1rem; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
        .section h2 { font-size: 1.1rem; font-weight: 600; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid #f0f2f5; color: #0f3460; }
        table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
        th { background: #f8f9fb; padding: 0.6rem 0.75rem; text-align: left; font-weight: 600; color: #4a5568; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.03em; }
        td { padding: 0.6rem 0.75rem; border-top: 1px solid #f0f2f5; vertical-align: top; }
        tr:hover { background: #fafbfc; }
        .status-pass { color: #22c55e; font-weight: 600; white-space: nowrap; }
        .status-fail { color: #ef4444; font-weight: 600; white-space: nowrap; }
        .status-warn { color: #f59e0b; font-weight: 600; white-space: nowrap; }
        .status-info { color: #3b82f6; font-weight: 600; white-space: nowrap; }
        .status-na   { color: #888; font-weight: 600; white-space: nowrap; }
        .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 12px; font-size: 0.7rem; font-weight: 600; vertical-align: middle; margin-left: 0.25rem; }
        .badge-pass { background: #dcfce7; color: #166534; }
        .badge-fail { background: #fee2e2; color: #991b1b; }
        .badge-warn { background: #fef3c7; color: #92400e; }
        .badge-info { background: #dbeafe; color: #1e40af; }
        .recommendation { font-size: 0.78rem; color: #4a5568; margin-top: 0.4rem; font-style: italic; }
        .expander { cursor: pointer; user-select: none; color: #0f3460; font-weight: bold; margin-top: 8px; display: inline-block; }
        .expander:hover { text-decoration: underline; }
        .expander::before { content: '\25B6 '; display: inline-block; transition: transform 0.2s; }
        .expander.expanded::before { transform: rotate(90deg); }
        .details-content { display: none; margin-top: 8px; padding: 10px; background-color: #f8f8f8; border-left: 3px solid #0f3460; border-radius: 4px; }
        .details-content.show { display: block; }
        .details-content ul { margin: 0; padding-left: 20px; }
        .details-content li { margin: 4px 0; }
        @media print { body { background: white; padding: 0.5rem; } .section { box-shadow: none; border: 1px solid #e0e0e0; } .header { box-shadow: none; } .expander { display: none; } .details-content { display: block !important; background: white; } }
    </style>
    <script>
        function toggleDetails(expanderId) {
            const expander = document.getElementById('expander-' + expanderId);
            const details = document.getElementById('details-' + expanderId);

            if (details.classList.contains('show')) {
                details.classList.remove('show');
                expander.classList.remove('expanded');
            } else {
                details.classList.add('show');
                expander.classList.add('expanded');
            }
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-text">
                <h1>Microsoft Defender for Endpoint - Validation Report</h1>
                <div class="subtitle">Protection state validation</div>
                <div class="meta">
                    <span><strong>Computer:</strong> $(ConvertTo-HtmlEncodedString $ComputerName)</span>
                    <span><strong>OS:</strong> $(ConvertTo-HtmlEncodedString $osInfo)</span>
                    <span><strong>Managed By:</strong> $(ConvertTo-HtmlEncodedString $managedByStatus)</span>
                    <span><strong>MDE Onboarding:</strong> $(ConvertTo-HtmlEncodedString $onboardingStatus)</span>
                    <span><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</span>
                </div>
            </div>
            <img class="header-logo" src="data:image/png;base64,$defenderLogoBase64" alt="Microsoft Defender">
        </div>
        <div class="summary-grid">
            <div class="summary-card pass"><div class="count">$passCount</div><div class="label">Passed</div></div>
            <div class="summary-card fail"><div class="count">$failCount</div><div class="label">Failed</div></div>
            <div class="summary-card warn"><div class="count">$warnCount</div><div class="label">Warnings</div></div>
            <div class="summary-card info"><div class="count">$infoCount</div><div class="label">Informational</div></div>
        </div>
"@

            # Group results by their Category property (the single source of truth).
            $grouped = [ordered]@{}
            foreach ($r in $results) {
                $sec = if ([string]::IsNullOrEmpty($r.Category)) { $fallbackSection } else { $r.Category }
                if (-not $grouped.Contains($sec)) {
                    $grouped[$sec] = New-Object System.Collections.Generic.List[object]
                }
                $grouped[$sec].Add($r)
            }

            # Render known sections first (canonical order), then any unknown/new categories
            # in first-seen order (the 'General / Other' fallback bucket is treated as unknown).
            $sectionOrder = New-Object System.Collections.Generic.List[string]
            foreach ($s in $knownSectionOrder) {
                if ($grouped.Contains($s)) { $sectionOrder.Add($s) }
            }
            foreach ($key in $grouped.Keys) {
                if ($knownSectionOrder -notcontains $key) { $sectionOrder.Add($key) }
            }

            # Status icon, CSS class, and label maps
            $statusIcon = @{
                'Pass'          = '&#10004;'
                'Fail'          = '&#10008;'
                'Warning'       = '&#9888;'
                'Info'          = '&#8505;'
                'NotApplicable' = '&mdash;'
            }
            $statusCssClass = @{
                'Pass' = 'status-pass'; 'Fail' = 'status-fail'; 'Warning' = 'status-warn'
                'Info' = 'status-info'; 'NotApplicable' = 'status-na'
            }
            $statusLabel = @{
                'Pass' = 'Pass'; 'Fail' = 'Fail'; 'Warning' = 'Warn'
                'Info' = 'Info'; 'NotApplicable' = 'N/A'
            }

            $expanderIndex = 0

            foreach ($s in $sectionOrder) {
                $sectionResults = $grouped[$s]
                if ($sectionResults.Count -eq 0) { continue }

                # Per-section badge counts (only show non-zero)
                $secPass = @($sectionResults | Where-Object { $_.Status -eq 'Pass' }).Count
                $secFail = @($sectionResults | Where-Object { $_.Status -eq 'Fail' }).Count
                $secWarn = @($sectionResults | Where-Object { $_.Status -eq 'Warning' }).Count
                $secInfo = @($sectionResults | Where-Object { $_.Status -eq 'Info' }).Count
                $badges = ''
                if ($secPass -gt 0) { $badges += " <span class=`"badge badge-pass`">$secPass Pass</span>" }
                if ($secFail -gt 0) { $badges += " <span class=`"badge badge-fail`">$secFail Fail</span>" }
                if ($secWarn -gt 0) { $badges += " <span class=`"badge badge-warn`">$secWarn Warn</span>" }
                if ($secInfo -gt 0) { $badges += " <span class=`"badge badge-info`">$secInfo Info</span>" }

                $htmlContent += @"
        <div class="section">
            <h2>$s$badges</h2>
            <table>
                <thead><tr><th>Test</th><th>Expected</th><th>Actual</th><th>Status</th></tr></thead>
                <tbody>
"@

                foreach ($result in $sectionResults) {
                    $icon = if ($statusIcon.ContainsKey($result.Status)) { $statusIcon[$result.Status] } else { '&mdash;' }
                    $css  = if ($statusCssClass.ContainsKey($result.Status)) { $statusCssClass[$result.Status] } else { 'status-na' }
                    $lbl  = if ($statusLabel.ContainsKey($result.Status)) { $statusLabel[$result.Status] } else { 'N/A' }

                    $encodedTestName = ConvertTo-HtmlEncodedString $result.TestName
                    $expectedValue = if (-not [string]::IsNullOrEmpty($result.Expected)) {
                        $result.Expected
                    } elseif ($result.TestName -like '* - Policy Registry Verification') {
                        'Matches policy/registry'
                    } else { 'See actual' }
                    $encodedExpected = ConvertTo-HtmlEncodedString $expectedValue

                    $encodedRecommendation = ConvertTo-HtmlEncodedString $result.Recommendation
                    $recommendationHtml = if ($result.Recommendation) {
                        "<div class=`"recommendation`"><strong>Recommendation:</strong> $encodedRecommendation</div>"
                    } else { '' }

                    # ASR rules row with expandable details
                    if ($result.PSObject.Properties.Name -contains 'ASRSummary' -and
                        $result.PSObject.Properties.Name -contains 'ASRRuleDetails' -and
                        $null -ne $result.ASRRuleDetails -and
                        $result.ASRRuleDetails.Count -gt 0) {

                        $encodedSummary = ConvertTo-HtmlEncodedString $result.ASRSummary
                        $expanderId = $expanderIndex++

                        $rulesListItems = $result.ASRRuleDetails | ForEach-Object {
                            $encodedRule = ConvertTo-HtmlEncodedString $_
                            "                    <li>$encodedRule</li>"
                        }
                        $rulesList = $rulesListItems -join "`n"

                        $htmlContent += @"
                <tr>
                    <td>$encodedTestName</td>
                    <td>$encodedExpected</td>
                    <td>$encodedSummary
                        <div class="expander" id="expander-$expanderId" onclick="toggleDetails($expanderId)">Show configured rules</div>
                        <div class="details-content" id="details-$expanderId">
                            <ul>
$rulesList
                            </ul>
                        </div>
                        $recommendationHtml
                    </td>
                    <td><span class="$css">$icon $lbl</span></td>
                </tr>
"@
                    } else {
                        # Normal result row
                        $encodedMessage = ConvertTo-HtmlEncodedString $result.Message
                        $htmlContent += @"
                <tr>
                    <td>$encodedTestName</td>
                    <td>$encodedExpected</td>
                    <td>$encodedMessage$recommendationHtml</td>
                    <td><span class="$css">$icon $lbl</span></td>
                </tr>
"@
                    }
                }

                $htmlContent += @"
                </tbody>
            </table>
        </div>
"@
            }

            $htmlContent += @"
    </div>
</body>
</html>
"@

    return $htmlContent
}
