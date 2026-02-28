function Get-MDEValidationReport {
    <#
    .SYNOPSIS
        Generates a formatted MDE validation report.
    
    .DESCRIPTION
        Runs all MDE configuration validation tests and generates a report
        in the specified format.
    
    .PARAMETER OutputFormat
        The format of the output report. Valid values are 'Console', 'HTML', or 'Object'.
        Default is 'Console'.
    
    .PARAMETER OutputPath
        The path to save the HTML report. Only used when OutputFormat is 'HTML'.
    
    .PARAMETER IncludeOnboarding
        Include MDE onboarding status check (requires elevated privileges).
    
    .PARAMETER IncludePolicyVerification
        Include policy registry verification sub-tests. These sub-tests verify that
        settings returned by Get-MpPreference match the corresponding registry/policy
        entries based on the device's management type (Intune vs Security Settings Management).
    
    .EXAMPLE
        Get-MDEValidationReport
        
        Displays a console-formatted validation report.
    
    .EXAMPLE
        Get-MDEValidationReport -OutputFormat HTML -OutputPath "C:\Reports\MDEReport.html"
        
        Generates an HTML report and saves it to the specified path.
    
    .EXAMPLE
        Get-MDEValidationReport -OutputFormat Object
        
        Returns validation results as PowerShell objects.
    
    .EXAMPLE
        Get-MDEValidationReport -IncludePolicyVerification
        
        Displays a validation report with policy registry verification sub-tests.
    
    .OUTPUTS
        Console output, HTML file, or array of PSCustomObjects depending on OutputFormat.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('Console', 'HTML', 'Object')]
        [string]$OutputFormat = 'Console',
        
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$IncludeOnboarding,
        
        [Parameter()]
        [switch]$IncludePolicyVerification
    )
    
    Write-Verbose "Generating MDE validation report (Format: $OutputFormat)..."

    # Run all validation tests
    $results = Test-MDEConfiguration -IncludeOnboarding:$IncludeOnboarding -IncludePolicyVerification:$IncludePolicyVerification
    
    Write-Verbose "Collected $($results.Count) test results"

    # Get OS information for the report header
    $osInfo = Get-MDEOperatingSystemInfo
    
    # Get management status for the report header
    $managedByStatus = Get-MDESecuritySettingsManagementStatus
    
    # Get MDE onboarding status for the report header
    $onboardingStatus = Get-MDEOnboardingStatusString
    
    # Compute pass/fail/warn counts for debug output and later use
    $passCount = @($results | Where-Object { $_.Status -eq 'Pass' }).Count
    $failCount = @($results | Where-Object { $_.Status -eq 'Fail' }).Count
    $warnCount = @($results | Where-Object { $_.Status -eq 'Warning' }).Count
    $totalCount = @($results).Count

    Write-Debug "Result counts - Pass: $passCount, Fail: $failCount, Warning: $warnCount, Total: $totalCount"

    switch ($OutputFormat) {
        'Object' {
            return $results
        }
        
        'Console' {
            Write-Host "`n========================================" -ForegroundColor Cyan
            Write-Host "  MDE Configuration Validation Report" -ForegroundColor Cyan
            Write-Host "  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
            Write-Host "  Computer: $env:COMPUTERNAME" -ForegroundColor Cyan
            Write-Host "  OS: $osInfo" -ForegroundColor Cyan
            Write-Host "  Managed By: $managedByStatus" -ForegroundColor Cyan
            Write-Host "  MDE Onboarding: $onboardingStatus" -ForegroundColor Cyan
            Write-Host "========================================`n" -ForegroundColor Cyan
            
            foreach ($result in $results) {
                $statusColor = switch ($result.Status) {
                    'Pass' { 'Green' }
                    'Fail' { 'Red' }
                    'Warning' { 'Yellow' }
                    'Info' { 'Cyan' }
                    'NotApplicable' { 'Gray' }
                    default { 'White' }
                }
                
                $statusSymbol = switch ($result.Status) {
                    'Pass' { '[PASS]' }
                    'Fail' { '[FAIL]' }
                    'Warning' { '[WARN]' }
                    'Info' { '[INFO]' }
                    'NotApplicable' { '[N/A]' }
                    default { '[???]' }
                }
                
                Write-Host "$statusSymbol " -ForegroundColor $statusColor -NoNewline
                Write-Host "$($result.TestName)" -ForegroundColor White
                Write-Host "         $($result.Message)" -ForegroundColor Gray
                
                if ($result.Recommendation) {
                    Write-Host "         Recommendation: $($result.Recommendation)" -ForegroundColor Yellow
                }
                Write-Host ""
            }
            
            # Summary
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "  Summary: $passCount/$totalCount Passed" -ForegroundColor $(if ($failCount -eq 0) { 'Green' } else { 'Yellow' })
            Write-Host "  Passed: $passCount | Failed: $failCount | Warnings: $warnCount" -ForegroundColor Cyan
            Write-Host "========================================`n" -ForegroundColor Cyan
        }
        
        'HTML' {
            if ([string]::IsNullOrEmpty($OutputPath)) {
                $tempDir = if ($env:TEMP) { $env:TEMP } elseif ($env:TMPDIR) { $env:TMPDIR } else { '/tmp' }
                $OutputPath = Join-Path $tempDir "MDEValidationReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
            }
            
            # Resolve to absolute path to ensure Split-Path works correctly
            $OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
            
            # Force create the output directory if it doesn't exist
            $outputDirectory = Split-Path -Path $OutputPath -Parent
            if (-not [string]::IsNullOrEmpty($outputDirectory) -and -not (Test-Path -Path $outputDirectory)) {
                try {
                    New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
                }
                catch {
                    Write-Error "Failed to create output directory: $outputDirectory. Error: $_"
                    return
                }
            }
            
            $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MDE Configuration Validation Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            padding: 30px;
        }
        h1 {
            color: #0078d4;
            border-bottom: 2px solid #0078d4;
            padding-bottom: 10px;
        }
        .meta {
            color: #666;
            margin-bottom: 20px;
        }
        .summary {
            display: flex;
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            flex: 1;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .summary-card.pass { background-color: #dff6dd; color: #107c10; }
        .summary-card.fail { background-color: #fde7e9; color: #d13438; }
        .summary-card.warn { background-color: #fff4ce; color: #797673; }
        .summary-card h2 { margin: 0; font-size: 2em; }
        .summary-card p { margin: 5px 0 0 0; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #0078d4;
            color: white;
        }
        tr:hover { background-color: #f5f5f5; }
        .status {
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.9em;
        }
        .status.pass { background-color: #dff6dd; color: #107c10; }
        .status.fail { background-color: #fde7e9; color: #d13438; }
        .status.warning { background-color: #fff4ce; color: #797673; }
        .status.info { background-color: #cce4f6; color: #0078d4; }
        .recommendation {
            font-size: 0.9em;
            color: #666;
            margin-top: 5px;
        }
        .expander {
            cursor: pointer;
            user-select: none;
            color: #0078d4;
            font-weight: bold;
            margin-top: 8px;
            display: inline-block;
        }
        .expander:hover {
            text-decoration: underline;
        }
        .expander::before {
            content: '▶ ';
            display: inline-block;
            transition: transform 0.2s;
        }
        .expander.expanded::before {
            transform: rotate(90deg);
        }
        .details-content {
            display: none;
            margin-top: 8px;
            padding: 10px;
            background-color: #f8f8f8;
            border-left: 3px solid #0078d4;
            border-radius: 4px;
        }
        .details-content.show {
            display: block;
        }
        .details-content ul {
            margin: 0;
            padding-left: 20px;
        }
        .details-content li {
            margin: 4px 0;
        }
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
        <h1>MDE Configuration Validation Report</h1>
        <div class="meta">
            <p><strong>Computer:</strong> $(ConvertTo-HtmlEncodedString $env:COMPUTERNAME)</p>
            <p><strong>OS:</strong> $(ConvertTo-HtmlEncodedString $osInfo)</p>
            <p><strong>Managed By:</strong> $(ConvertTo-HtmlEncodedString $managedByStatus)</p>
            <p><strong>MDE Onboarding:</strong> $(ConvertTo-HtmlEncodedString $onboardingStatus)</p>
            <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        </div>
        
        <div class="summary">
            <div class="summary-card pass">
                <h2>$passCount</h2>
                <p>Passed</p>
            </div>
            <div class="summary-card fail">
                <h2>$failCount</h2>
                <p>Failed</p>
            </div>
            <div class="summary-card warn">
                <h2>$warnCount</h2>
                <p>Warnings</p>
            </div>
        </div>
        
        <table>
            <tr>
                <th>Test</th>
                <th>Status</th>
                <th>Details</th>
            </tr>
"@
            
            $expanderIndex = 0
            foreach ($result in $results) {
                $statusClass = $result.Status.ToLower()
                $encodedTestName = ConvertTo-HtmlEncodedString $result.TestName
                $encodedRecommendation = ConvertTo-HtmlEncodedString $result.Recommendation
                $recommendation = if ($result.Recommendation) {
                    "<div class='recommendation'><strong>Recommendation:</strong> $encodedRecommendation</div>"
                } else { '' }
                
                # Special handling for ASR rules with expandable details
                if ($result.PSObject.Properties.Name -contains 'ASRSummary' -and 
                    $result.PSObject.Properties.Name -contains 'ASRRuleDetails' -and
                    $null -ne $result.ASRRuleDetails -and 
                    $result.ASRRuleDetails.Count -gt 0) {
                    
                    $encodedSummary = ConvertTo-HtmlEncodedString $result.ASRSummary
                    $expanderId = $expanderIndex++
                    
                    # Build the list of rules using array join for better performance
                    $rulesListItems = $result.ASRRuleDetails | ForEach-Object {
                        $encodedRule = ConvertTo-HtmlEncodedString $_
                        "                    <li>$encodedRule</li>"
                    }
                    $rulesList = $rulesListItems -join "`n"
                    
                    $htmlContent += @"
            <tr>
                <td>$encodedTestName</td>
                <td><span class="status $statusClass">$($result.Status.ToUpper())</span></td>
                <td>
                    $encodedSummary
                    <div class="expander" id="expander-$expanderId" onclick="toggleDetails($expanderId)">Show configured rules</div>
                    <div class="details-content" id="details-$expanderId">
                        <ul>
$rulesList
                        </ul>
                    </div>
                    $recommendation
                </td>
            </tr>
"@
                } else {
                    # Normal handling for other tests
                    $encodedMessage = ConvertTo-HtmlEncodedString $result.Message
                    $htmlContent += @"
            <tr>
                <td>$encodedTestName</td>
                <td><span class="status $statusClass">$($result.Status.ToUpper())</span></td>
                <td>$encodedMessage$recommendation</td>
            </tr>
"@
                }
            }
            
            $htmlContent += @"
        </table>
    </div>
</body>
</html>
"@
            
            $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-Host "HTML report saved to: $OutputPath" -ForegroundColor Green
            return $OutputPath
        }
    }
}
