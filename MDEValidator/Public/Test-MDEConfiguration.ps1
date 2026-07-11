function Test-MDEConfiguration {
    <#
    .SYNOPSIS
        Runs all MDE configuration validation tests.
    
    .DESCRIPTION
        Executes a comprehensive validation of Microsoft Defender for Endpoint
        configuration settings and returns the results.
    
        Tests are organised into categories. Use -Category to run only specific
        categories and -ExcludeTest to skip individual tests by TestName wildcard.
        Write-Progress is displayed during the run and cleared on completion.
    
    .PARAMETER IncludeOnboarding
        Include MDE onboarding status check (requires elevated privileges).
    
    .PARAMETER IncludePolicyVerification
        Include policy registry verification sub-tests. These sub-tests verify that
        settings returned by Get-MpPreference match the corresponding registry/policy
        entries based on the device's management type (Intune vs Security Settings Management).
        
        Registry locations checked:
        - Intune: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager
        - SSM/GPO/SCCM: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender
        
        Note: Some tests (Edge SmartScreen, Exclusion Visibility) are not applicable
        for Security Settings Management as only Antivirus, ASR, EDR, and Firewall
        policies are supported.
        
        Policy verification sub-tests are only executed when their parent test runs.
        If a parent test is excluded via -Category or -ExcludeTest its corresponding
        policy verification sub-test is also skipped.
    
    .PARAMETER Category
        Restrict the run to one or more named categories. When omitted all categories
        are included. Valid values:
            'Device State', 'Protection Settings', 'Onboarding',
            'Network Protection', 'ASR Rules', 'Tamper Protection', 'Exclusion Settings'
    
    .PARAMETER ExcludeTest
        One or more TestName wildcard patterns. Any result whose TestName matches at
        least one pattern is removed from output. Patterns support standard PowerShell
        wildcards (* ? []).
        
        For tests that emit multiple results (e.g. Test-MDESignatureAge emits
        'Antivirus Signature Age' and 'Antispyware Signature Age'), each result is
        matched independently so you can exclude individual result TestNames.
        Filtering is applied after invocation to keep behaviour consistent across all
        single- and multi-result tests.
    
    .EXAMPLE
        Test-MDEConfiguration
        
        Runs all MDE configuration validation tests.
    
    .EXAMPLE
        Test-MDEConfiguration -IncludeOnboarding
        
        Runs all tests including MDE onboarding status check.
    
    .EXAMPLE
        Test-MDEConfiguration -IncludePolicyVerification
        
        Runs all tests with policy registry verification sub-tests.
    
    .EXAMPLE
        Test-MDEConfiguration -Category 'Device State', 'Tamper Protection'
        
        Runs only Device State and Tamper Protection category tests.
    
    .EXAMPLE
        Test-MDEConfiguration -ExcludeTest '*SmartScreen*', 'Antispyware Signature Age'
        
        Runs all tests but excludes any result whose TestName matches *SmartScreen* or
        equals 'Antispyware Signature Age'.
    
    .OUTPUTS
        Array of PSCustomObjects with validation results.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$IncludeOnboarding,
        
        [Parameter()]
        [switch]$IncludePolicyVerification,
        
        [Parameter()]
        [ValidateSet('Device State', 'Protection Settings', 'Onboarding',
                     'Network Protection', 'ASR Rules', 'Tamper Protection', 'Exclusion Settings')]
        [string[]]$Category,
        
        [Parameter()]
        [string[]]$ExcludeTest
    )
    
    $results = @()
    
    Write-Verbose "Starting MDE configuration validation..."
    
    # Check for elevation
    $isElevated = Test-IsElevated
    if (-not $isElevated) {
        Write-Warning "Some tests may require elevated privileges. Consider running as Administrator."
    }
    
    # Query the Defender CIM snapshots once and share them with every test that
    # accepts them. This avoids each test independently calling Get-MpPreference /
    # Get-MpComputerStatus (30-40 CIM round-trips reduced to 2). On failure the
    # snapshot is left as $null so the individual tests self-query and handle the
    # failure exactly as they do when called standalone.
    $mpPreference = $null
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
    }
    catch {
        Write-Verbose "Get-MpPreference unavailable; tests will self-query: $_"
    }
    
    $mpStatus = $null
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
    }
    catch {
        Write-Verbose "Get-MpComputerStatus unavailable; tests will self-query: $_"
    }
    
    # Each descriptor: Category, PrimaryTestName, ScriptBlock, PolicyVerification (hashtable or $null)
    # Category is used for -Category filter (BEFORE invocation).
    # PolicyVerification sub-test runs only when its descriptor's ScriptBlock was invoked AND
    # -IncludePolicyVerification is set.
    $testDescriptors = [System.Collections.Generic.List[hashtable]]::new()
    
    $testDescriptors.Add(@{
        Category        = 'Device State'
        PrimaryTestName = 'Service Status'
        ScriptBlock     = { Test-MDEServiceStatus }
        PolicyVerification = $null
    })
    $testDescriptors.Add(@{
        Category        = 'Device State'
        PrimaryTestName = 'Passive Mode'
        ScriptBlock     = { Test-MDEPassiveMode -MpComputerStatus $mpStatus }
        PolicyVerification = $null
    })
    $testDescriptors.Add(@{
        Category        = 'Device State'
        PrimaryTestName = 'Anti-Spyware Protection'
        ScriptBlock     = { Test-MDEAntiSpywareEnabled -MpComputerStatus $mpStatus }
        PolicyVerification = $null
    })
    $testDescriptors.Add(@{
        Category        = 'Device State'
        PrimaryTestName = 'IOAV Protection'
        ScriptBlock     = { Test-MDEIoavProtectionEnabled -MpComputerStatus $mpStatus }
        PolicyVerification = $null
    })
    $testDescriptors.Add(@{
        Category        = 'Device State'
        PrimaryTestName = 'Network Inspection System (NIS)'
        ScriptBlock     = { Test-MDENISEnabled -MpComputerStatus $mpStatus }
        PolicyVerification = $null
    })
    $testDescriptors.Add(@{
        Category        = 'Protection Settings'
        PrimaryTestName = 'Antivirus Signature Age'
        ScriptBlock     = { Test-MDESignatureAge -MpComputerStatus $mpStatus }
        PolicyVerification = $null
    })
    $testDescriptors.Add(@{
        Category        = 'Protection Settings'
        PrimaryTestName = 'Antivirus Signature Version'
        ScriptBlock     = { Test-MDESignatureInfo -MpComputerStatus $mpStatus }
        PolicyVerification = $null
    })
    $testDescriptors.Add(@{
        Category        = 'Device State'
        PrimaryTestName = 'Real-Time Protection'
        ScriptBlock     = { Test-MDERealTimeProtection -MpPreference $mpPreference }
        PolicyVerification = @{
            ParentTestName    = 'Real-Time Protection'
            SettingKey        = 'RealTimeProtection'
            IsApplicableToSSM = $true
        }
    })
    $testDescriptors.Add(@{
        Category        = 'Protection Settings'
        PrimaryTestName = 'Cloud-Delivered Protection'
        ScriptBlock     = { Test-MDECloudProtection -MpPreference $mpPreference }
        PolicyVerification = @{
            ParentTestName    = 'Cloud-Delivered Protection'
            SettingKey        = 'CloudProtection'
            IsApplicableToSSM = $true
        }
    })
    $testDescriptors.Add(@{
        Category        = 'Protection Settings'
        PrimaryTestName = 'Cloud Block Level'
        ScriptBlock     = { Test-MDECloudBlockLevel -MpPreference $mpPreference }
        PolicyVerification = @{
            ParentTestName    = 'Cloud Block Level'
            SettingKey        = 'CloudBlockLevel'
            IsApplicableToSSM = $true
        }
    })
    $testDescriptors.Add(@{
        Category        = 'Protection Settings'
        PrimaryTestName = 'Cloud Extended Timeout'
        ScriptBlock     = { Test-MDECloudExtendedTimeout -MpPreference $mpPreference }
        PolicyVerification = @{
            ParentTestName    = 'Cloud Extended Timeout'
            SettingKey        = 'CloudExtendedTimeout'
            IsApplicableToSSM = $true
        }
    })
    $testDescriptors.Add(@{
        Category        = 'Protection Settings'
        PrimaryTestName = 'Automatic Sample Submission'
        ScriptBlock     = { Test-MDESampleSubmission -MpPreference $mpPreference }
        PolicyVerification = @{
            ParentTestName    = 'Automatic Sample Submission'
            SettingKey        = 'SampleSubmission'
            IsApplicableToSSM = $true
        }
    })
    $testDescriptors.Add(@{
        Category        = 'Protection Settings'
        PrimaryTestName = 'Behavior Monitoring'
        ScriptBlock     = { Test-MDEBehaviorMonitoring -MpPreference $mpPreference }
        PolicyVerification = @{
            ParentTestName    = 'Behavior Monitoring'
            SettingKey        = 'BehaviorMonitoring'
            IsApplicableToSSM = $true
        }
    })
    $testDescriptors.Add(@{
        Category        = 'Network Protection'
        PrimaryTestName = 'Network Protection'
        ScriptBlock     = { Test-MDENetworkProtection -MpPreference $mpPreference }
        PolicyVerification = @{
            ParentTestName    = 'Network Protection'
            SettingKey        = 'NetworkProtection'
            IsApplicableToSSM = $true
        }
    })
    $testDescriptors.Add(@{
        Category        = 'Protection Settings'
        PrimaryTestName = 'PUA Protection'
        ScriptBlock     = { Test-MDEPUAProtection -MpPreference $mpPreference }
        PolicyVerification = $null
    })
    $testDescriptors.Add(@{
        Category        = 'Network Protection'
        PrimaryTestName = 'Network Protection (Windows Server)'
        ScriptBlock     = { Test-MDENetworkProtectionWindowsServer }
        PolicyVerification = $null
    })
    $testDescriptors.Add(@{
        Category        = 'Network Protection'
        PrimaryTestName = 'Datagram Processing (Windows Server)'
        ScriptBlock     = { Test-MDEDatagramProcessingWindowsServer }
        PolicyVerification = $null
    })
    $testDescriptors.Add(@{
        Category        = 'Exclusion Settings'
        PrimaryTestName = 'Auto Exclusions (Windows Server)'
        ScriptBlock     = { Test-MDEAutoExclusionsWindowsServer -MpPreference $mpPreference }
        PolicyVerification = $null
    })
    $testDescriptors.Add(@{
        Category        = 'ASR Rules'
        PrimaryTestName = 'Attack Surface Reduction Rules'
        ScriptBlock     = { Test-MDEAttackSurfaceReduction -MpPreference $mpPreference }
        PolicyVerification = @{
            ParentTestName    = 'Attack Surface Reduction Rules'
            SettingKey        = 'AttackSurfaceReduction'
            IsApplicableToSSM = $true
        }
    })
    $testDescriptors.Add(@{
        Category        = 'Protection Settings'
        PrimaryTestName = 'Threat Default Actions'
        ScriptBlock     = { Test-MDEThreatDefaultActions -MpPreference $mpPreference -MpComputerStatus $mpStatus }
        PolicyVerification = $null
    })
    $testDescriptors.Add(@{
        Category        = 'Tamper Protection'
        PrimaryTestName = 'Troubleshooting Mode'
        ScriptBlock     = { Test-MDETroubleshootingMode -MpPreference $mpPreference }
        PolicyVerification = $null
    })
    $testDescriptors.Add(@{
        Category        = 'Tamper Protection'
        PrimaryTestName = 'Tamper Protection'
        ScriptBlock     = { Test-MDETamperProtection -MpComputerStatus $mpStatus }
        PolicyVerification = $null
    })
    $testDescriptors.Add(@{
        Category        = 'Tamper Protection'
        PrimaryTestName = 'Tamper Protection for Exclusions'
        ScriptBlock     = { Test-MDETamperProtectionForExclusions -MpComputerStatus $mpStatus }
        PolicyVerification = $null
    })
    $testDescriptors.Add(@{
        Category        = 'Exclusion Settings'
        PrimaryTestName = 'Exclusion Visibility (Local Admins)'
        ScriptBlock     = { Test-MDEExclusionVisibilityLocalAdmins -MpPreference $mpPreference }
        PolicyVerification = @{
            ParentTestName    = 'Exclusion Visibility (Local Admins)'
            SettingKey        = 'HideExclusionsFromLocalAdmins'
            IsApplicableToSSM = $false
        }
    })
    $testDescriptors.Add(@{
        Category        = 'Exclusion Settings'
        PrimaryTestName = 'Exclusion Visibility (Local Users)'
        ScriptBlock     = { Test-MDEExclusionVisibilityLocalUsers -MpPreference $mpPreference }
        PolicyVerification = @{
            ParentTestName    = 'Exclusion Visibility (Local Users)'
            SettingKey        = 'HideExclusionsFromLocalUsers'
            IsApplicableToSSM = $false
        }
    })
    $testDescriptors.Add(@{
        Category        = 'Network Protection'
        PrimaryTestName = 'SmartScreen'
        ScriptBlock     = { Test-MDESmartScreen }
        PolicyVerification = $null
    })
    $testDescriptors.Add(@{
        Category        = 'Network Protection'
        PrimaryTestName = 'SmartScreen PUA'
        ScriptBlock     = { Test-MDESmartScreenPUA }
        PolicyVerification = $null
    })
    $testDescriptors.Add(@{
        Category        = 'Network Protection'
        PrimaryTestName = 'SmartScreen Prompt Override'
        ScriptBlock     = { Test-MDESmartScreenPromptOverride }
        PolicyVerification = $null
    })
    $testDescriptors.Add(@{
        Category        = 'Network Protection'
        PrimaryTestName = 'SmartScreen Download Override'
        ScriptBlock     = { Test-MDESmartScreenDownloadOverride }
        PolicyVerification = $null
    })
    $testDescriptors.Add(@{
        Category        = 'Network Protection'
        PrimaryTestName = 'SmartScreen Domain Exclusions'
        ScriptBlock     = { Test-MDESmartScreenDomainExclusions }
        PolicyVerification = $null
    })
    $testDescriptors.Add(@{
        Category        = 'Network Protection'
        PrimaryTestName = 'SmartScreen App Reputation Exclusions'
        ScriptBlock     = { Test-MDESmartScreenAppRepExclusions }
        PolicyVerification = $null
    })
    $testDescriptors.Add(@{
        Category        = 'Protection Settings'
        PrimaryTestName = 'Catchup Quick Scan'
        ScriptBlock     = { Test-MDEDisableCatchupQuickScan -MpPreference $mpPreference }
        PolicyVerification = @{
            ParentTestName    = 'Catchup Quick Scan'
            SettingKey        = 'CatchupQuickScan'
            IsApplicableToSSM = $true
        }
    })
    $testDescriptors.Add(@{
        Category        = 'Protection Settings'
        PrimaryTestName = 'Real Time Scan Direction'
        ScriptBlock     = { Test-MDERealTimeScanDirection -MpPreference $mpPreference }
        PolicyVerification = @{
            ParentTestName    = 'Real Time Scan Direction'
            SettingKey        = 'RealTimeScanDirection'
            IsApplicableToSSM = $true
        }
    })
    $testDescriptors.Add(@{
        Category        = 'Protection Settings'
        PrimaryTestName = 'Signature Update Fallback Order'
        ScriptBlock     = { Test-MDESignatureUpdateFallbackOrder -MpPreference $mpPreference }
        PolicyVerification = @{
            ParentTestName    = 'Signature Update Fallback Order'
            SettingKey        = 'SignatureFallbackOrder'
            IsApplicableToSSM = $true
        }
    })
    $testDescriptors.Add(@{
        Category        = 'Protection Settings'
        PrimaryTestName = 'Signature Update Interval'
        ScriptBlock     = { Test-MDESignatureUpdateInterval -MpPreference $mpPreference }
        PolicyVerification = @{
            ParentTestName    = 'Signature Update Interval'
            SettingKey        = 'SignatureUpdateInterval'
            IsApplicableToSSM = $true
        }
    })
    $testDescriptors.Add(@{
        Category        = 'Protection Settings'
        PrimaryTestName = 'Disable Local Admin Merge'
        ScriptBlock     = { Test-MDEDisableLocalAdminMerge }
        PolicyVerification = @{
            ParentTestName    = 'Disable Local Admin Merge'
            SettingKey        = 'DisableLocalAdminMerge'
            IsApplicableToSSM = $true
        }
    })
    $testDescriptors.Add(@{
        Category        = 'Protection Settings'
        PrimaryTestName = 'File Hash Computation'
        ScriptBlock     = { Test-MDEFileHashComputation -MpPreference $mpPreference }
        PolicyVerification = $null
    })
    
    if ($IncludeOnboarding) {
        $testDescriptors.Add(@{
            Category        = 'Onboarding'
            PrimaryTestName = 'MDE Onboarding Status'
            ScriptBlock     = { Test-MDEOnboardingStatus }
            PolicyVerification = $null
        })
    }
    
    $testDescriptors.Add(@{
        Category        = 'Onboarding'
        PrimaryTestName = 'MDE Device Tags'
        ScriptBlock     = { Test-MDEDeviceTags }
        PolicyVerification = $null
    })
    
    # Apply -Category filter before invocation
    $testsToRun = @(if ($Category.Count -gt 0) {
        $testDescriptors | Where-Object { $_.Category -in $Category }
    }
    else {
        $testDescriptors
    })
    
    $total = $testsToRun.Count
    
    for ($i = 0; $i -lt $total; $i++) {
        $descriptor = $testsToRun[$i]
        $pctComplete = if ($total -gt 0) { [int](($i / $total) * 100) } else { 0 }
        Write-Progress -Activity 'MDE Validation' -Status $descriptor.PrimaryTestName -PercentComplete $pctComplete
        
        $testResults = @(& $descriptor.ScriptBlock)
        
        # Apply -ExcludeTest filter after invocation (handles multi-result tests consistently)
        if ($ExcludeTest.Count -gt 0) {
            $testResults = @($testResults | Where-Object {
                $tn = $_.TestName
                -not ($ExcludeTest | Where-Object { $tn -like $_ })
            })
        }
        
        $results += $testResults
        
        # Run policy verification sub-test when the parent was invoked and the flag is set
        if ($IncludePolicyVerification -and $null -ne $descriptor.PolicyVerification) {
            $pv = $descriptor.PolicyVerification
            $pvResult = @(Test-MDEPolicyRegistryVerification -ParentTestName $pv.ParentTestName `
                -SettingKey $pv.SettingKey -IsApplicableToSSM $pv.IsApplicableToSSM)
            
            if ($ExcludeTest.Count -gt 0) {
                $pvResult = @($pvResult | Where-Object {
                    $tn = $_.TestName
                    -not ($ExcludeTest | Where-Object { $tn -like $_ })
                })
            }
            
            $results += $pvResult
        }
    }
    
    Write-Progress -Activity 'MDE Validation' -Completed
    
    Write-Verbose "MDE configuration validation completed."
    
    return $results
}