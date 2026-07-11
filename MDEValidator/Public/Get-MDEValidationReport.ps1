function Get-MDEValidationReport {
    <#
    .SYNOPSIS
        Generates a formatted MDE validation report.
    
    .DESCRIPTION
        Runs all MDE configuration validation tests and generates a report
        in the specified format.
    
    .PARAMETER OutputFormat
        The format of the output report. Valid values are 'Console', 'HTML', 'JSON', or 'Object'.
        Default is 'Console'.
    
    .PARAMETER OutputPath
        The path to save the HTML or JSON report. Used when OutputFormat is 'HTML' or 'JSON'.
        When OutputFormat is 'JSON' and -OutputPath is omitted, the JSON string is returned to
        the pipeline instead.
    
    .PARAMETER IncludeOnboarding
        Include MDE onboarding status check (requires elevated privileges).
    
    .PARAMETER IncludePolicyVerification
        Include policy registry verification sub-tests. These sub-tests verify that
        settings returned by Get-MpPreference match the corresponding registry/policy
        entries based on the device's management type (Intune vs Security Settings Management).
    
    .PARAMETER AsExitCode
        When present, all format-specific side effects (console output, file writes) still occur
        normally, but the return value is replaced by [int] equal to the number of results with
        Status 'Fail' (0 = all clear). Designed for automation scenarios such as scheduled tasks
        and Intune remediation scripts where the caller needs a numeric exit code.
    
    .PARAMETER Category
        Restrict validation to one or more named categories. Forwarded to Test-MDEConfiguration.
        Valid values: 'Device State', 'Protection Settings', 'Onboarding', 'Network Protection',
        'ASR Rules', 'Tamper Protection', 'Exclusion Settings'.
    
    .PARAMETER ExcludeTest
        One or more TestName wildcard patterns to exclude from the results. Forwarded to
        Test-MDEConfiguration. Supports standard PowerShell wildcards (* ? []).
    
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
        Get-MDEValidationReport -OutputFormat JSON
        
        Returns the full validation report as a JSON string to the pipeline.
    
    .EXAMPLE
        Get-MDEValidationReport -OutputFormat JSON -OutputPath "C:\Reports\MDEReport.json"
        
        Generates a JSON report and saves it to the specified path. Returns the file path.
    
    .EXAMPLE
        Get-MDEValidationReport -IncludePolicyVerification
        
        Displays a validation report with policy registry verification sub-tests.
    
    .EXAMPLE
        exit (Get-MDEValidationReport -OutputFormat JSON -OutputPath report.json -AsExitCode)
        
        Writes a JSON report then returns the number of failed tests as an integer. Pass the
        result to exit() in a scheduled task or Intune remediation script so the platform can
        detect non-compliant state. Returns 0 when all tests pass.
    
    .EXAMPLE
        Get-MDEValidationReport -Category 'Device State', 'Tamper Protection'
        
        Runs only Device State and Tamper Protection tests and displays the console report.
    
    .EXAMPLE
        Get-MDEValidationReport -OutputFormat Object -ExcludeTest '*SmartScreen*'
        
        Returns result objects for all tests except those with SmartScreen in their TestName.
    
    .OUTPUTS
        Console output, HTML file path (string), JSON file path (string), JSON string,
        [int] fail count (when -AsExitCode is set), or array of PSCustomObjects depending
        on OutputFormat and switches.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('Console', 'HTML', 'JSON', 'Object')]
        [string]$OutputFormat = 'Console',
        
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$IncludeOnboarding,
        
        [Parameter()]
        [switch]$IncludePolicyVerification,
        
        [Parameter()]
        [switch]$AsExitCode,
        
        [Parameter()]
        [ValidateSet('Device State', 'Protection Settings', 'Onboarding',
                     'Network Protection', 'ASR Rules', 'Tamper Protection', 'Exclusion Settings')]
        [string[]]$Category,
        
        [Parameter()]
        [string[]]$ExcludeTest
    )
    
    # Build splatted args for Test-MDEConfiguration so optional arrays are omitted when empty
    $testParams = @{
        IncludeOnboarding        = $IncludeOnboarding.IsPresent
        IncludePolicyVerification = $IncludePolicyVerification.IsPresent
    }
    if ($Category.Count -gt 0) { $testParams['Category'] = $Category }
    if ($ExcludeTest.Count -gt 0) { $testParams['ExcludeTest'] = $ExcludeTest }
    
    # Run all validation tests
    $results = Test-MDEConfiguration @testParams
    
    # Get OS information for the report header
    $osInfo = Get-MDEOperatingSystemInfo
    
    # Get management status for the report header
    $managedByStatus = Get-MDESecuritySettingsManagementStatus
    
    # Get MDE onboarding status for the report header
    $onboardingStatus = Get-MDEOnboardingStatusString
    
    # $reportOutput holds the normal return value; overridden by -AsExitCode at the end.
    $reportOutput = $null
    
    switch ($OutputFormat) {
        'Object' {
            $reportOutput = $results
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
            $passCount  = @($results | Where-Object { $_.Status -eq 'Pass' }).Count
            $failCount  = @($results | Where-Object { $_.Status -eq 'Fail' }).Count
            $warnCount  = @($results | Where-Object { $_.Status -eq 'Warning' }).Count
            $totalCount = @($results).Count
            
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
            
            $htmlContent = ConvertTo-MDEHtmlReport -Results $results -ComputerName $env:COMPUTERNAME -OSInfo $osInfo -ManagedByStatus $managedByStatus -OnboardingStatus $onboardingStatus

            $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-Host "HTML report saved to: $OutputPath" -ForegroundColor Green
            $reportOutput = $OutputPath
        }
        
        'JSON' {
            $moduleVersion = try {
                $MyInvocation.MyCommand.Module.Version.ToString()
            }
            catch {
                '0.0.0'
            }
            
            $envelope = [ordered]@{
                metadata = [ordered]@{
                    computerName  = $env:COMPUTERNAME
                    os            = $osInfo
                    managedBy     = $managedByStatus
                    mdeOnboarding = $onboardingStatus
                    generated     = (Get-Date).ToString('o')
                    moduleVersion = $moduleVersion
                }
                summary  = [ordered]@{
                    total         = @($results).Count
                    pass          = @($results | Where-Object { $_.Status -eq 'Pass' }).Count
                    fail          = @($results | Where-Object { $_.Status -eq 'Fail' }).Count
                    warning       = @($results | Where-Object { $_.Status -eq 'Warning' }).Count
                    info          = @($results | Where-Object { $_.Status -eq 'Info' }).Count
                    notApplicable = @($results | Where-Object { $_.Status -eq 'NotApplicable' }).Count
                }
                results  = @($results | ForEach-Object {
                    [ordered]@{
                        TestName       = $_.TestName
                        Category       = $_.Category
                        Status         = $_.Status
                        Message        = $_.Message
                        Expected       = $_.Expected
                        Actual         = $_.Actual
                        Recommendation = $_.Recommendation
                        Timestamp      = $_.Timestamp.ToString('o')
                    }
                })
            }
            
            $jsonOutput = $envelope | ConvertTo-Json -Depth 5
            
            if (-not [string]::IsNullOrEmpty($OutputPath)) {
                $OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
                
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
                
                $jsonOutput | Out-File -FilePath $OutputPath -Encoding UTF8
                Write-Host "JSON report saved to: $OutputPath" -ForegroundColor Green
                $reportOutput = $OutputPath
            }
            else {
                $reportOutput = $jsonOutput
            }
        }
    }
    
    # When -AsExitCode is set, return the number of failed tests as [int] instead of
    # the normal format-specific output (0 = all clear; non-zero = remediation needed).
    if ($AsExitCode) {
        return [int]@($results | Where-Object { $_.Status -eq 'Fail' }).Count
    }
    
    if ($null -ne $reportOutput) {
        return $reportOutput
    }
}
